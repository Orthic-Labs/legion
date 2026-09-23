//! Port of `src/providers/security/packs/ics-ot.mjs` (B7-020): PLC/SCADA
//! source and network topology config text only — no PLC connection, no
//! live protocol traffic, no operational-network probe of any kind. Every
//! rule is a lexical (pattern-only) detector that never certifies an
//! operational deployment as safe.

use super::common::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.ics-ot";
pub const CANDIDATE_CLASS: &str = "ics-ot";

const STANDARD_SCOPE_DESCRIPTION: &str =
    "PLC/SCADA source and network topology config text only; no PLC, RTU, historian, or live operational-network connection was made.";

const STANDARD_AUTHORITY_LIMITS: [&str; 2] = [
    "This lens does not establish operational safety, process-safety adequacy, or regulatory adequacy for any standard.",
    "A finding here is an allegation requiring independent adjudication by a qualified OT/ICS engineer with authority over the physical process; it is never a substitute for that decision, and it never authorizes any live probe.",
];

struct Rule {
    id: &'static str,
    severity_hint: &'static str,
    claim: &'static str,
    pattern: fn() -> &'static Regex,
    suppress_window_pattern: fn() -> &'static Regex,
    hazard: &'static str,
    assumption: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
}

fn ics_file_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\.(js|mjs|ts|py|cs|st|scl)$|(^|/)(docker-compose\.ya?ml|.*\.topology\.ya?ml|network\.ya?ml)$",
        )
        .unwrap()
    })
}

fn unauthenticated_write_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\.(?:writeCoil|writeRegister|writeCoils|writeHoldingRegisters|writeTag|writeNode)\s*\(")
            .unwrap()
    })
}
fn unauthenticated_write_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)authenticate|checkRole|requireRole|isAuthorized|verifyOperator|require\s*\(\s*(?:role|user|operator)")
            .unwrap()
    })
}

fn ot_bridged_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)\b(?:plc|scada|rtu|historian|hmi)\b[\s\S]{0,300}?\b(?:corporate|internet|external|it_network|corp_lan)\b")
            .unwrap()
    })
}
fn ot_bridged_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)firewall|dmz|vlan|segmentation|air[- ]?gap|one[- ]?way|data[- ]?diode").unwrap()
    })
}

fn unsigned_firmware_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)\b(?:plc|rtu)[\s\S]{0,200}?\b(?:firmware|program|logic)[\s\S]{0,120}?\b(?:push|download|deploy|flash)\b")
            .unwrap()
    })
}
fn unsigned_firmware_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)verify|signature|signed|checksum|sha256|hmac").unwrap())
}

fn rules() -> [Rule; 3] {
    [
        Rule {
            id: "ics-ot.authorization.unauthenticated-write-command",
            severity_hint: "critical",
            claim: "A PLC/SCADA write command (coil, register, tag) is issued with no visible authentication or role check in the same window.",
            pattern: unauthenticated_write_pattern,
            suppress_window_pattern: unauthenticated_write_suppress,
            hazard: "An unauthenticated actor with network reach to the control channel can directly change a physical setpoint, coil, or actuator state, with no engineered check on operator authority.",
            assumption: "Authentication enforced at the transport layer (e.g. a VPN or protocol gateway) rather than in this call site is not visible to this lens and must be adjudicated against the actual deployment topology.",
            effect_kind: "principal-access",
            effect_action: "issue-unauthenticated-write",
            effect_scope: "control-channel",
            chain_roles: &["starter", "control-bypass", "impact"],
        },
        Rule {
            id: "ics-ot.segmentation.ot-bridged-to-corporate-network",
            severity_hint: "critical",
            claim: "A network/topology config connects an OT/PLC/SCADA service to a corporate or internet-facing network with no visible firewall/DMZ/VLAN reference.",
            pattern: ot_bridged_pattern,
            suppress_window_pattern: ot_bridged_suppress,
            hazard: "A compromise anywhere on the IT/corporate network can pivot directly into the operational network and reach process-control systems, with no engineered segmentation boundary observed.",
            assumption: "A segmentation control implemented outside the text scanned here (a separate firewall appliance config, a network diagram, or a physical air gap) is not visible to this lens and must be adjudicated against the real topology.",
            effect_kind: "network-reachability",
            effect_action: "bridge-it-to-ot",
            effect_scope: "network-segmentation",
            chain_roles: &["enabler", "control-bypass"],
        },
        Rule {
            id: "ics-ot.update-policy.unsigned-plc-firmware-push",
            severity_hint: "high",
            claim: "A PLC/RTU firmware or logic-program push path has no visible signature or integrity verification.",
            pattern: unsigned_firmware_pattern,
            suppress_window_pattern: unsigned_firmware_suppress,
            hazard: "An attacker able to reach the engineering/update channel can push unauthorized control logic to a PLC or RTU, directly altering physical-process behavior.",
            assumption: "Verification performed by the vendor engineering-workstation software outside this repository is not visible to this lens and must be adjudicated against the actual update tool.",
            effect_kind: "code-execution",
            effect_action: "push-unverified-logic",
            effect_scope: "plc-firmware-update",
            chain_roles: &["starter", "impact"],
        },
    ]
}

/// Ports `analyze(context)`: only files matching `ICS_FILE_PATTERN` are
/// scanned; every rule's pattern is applied with `exec`-style repeated
/// matching, each match gated by a 600-char suppression window.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        if !ics_file_pattern().is_match(file) {
            continue;
        }
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            for m in (rule.pattern)().find_iter(text) {
                let window = window_around(text, m.start(), m.len(), 600);
                if (rule.suppress_window_pattern)().is_match(window) {
                    continue;
                }
                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: Vec::new(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec![
                        "network-position-in-it-or-ot-segment".to_string(),
                        "engineering-workstation-access".to_string(),
                    ],
                    preconditions: vec![Fact {
                        kind: "network-reachability".to_string(),
                        subject: "actor:external".to_string(),
                        action: "reach-control-channel".to_string(),
                        object: None,
                        scope: None,
                        environment: "operational-technology".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "operational-technology".to_string(),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls: Vec::new(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, m.start()),
                        "matchDigest": digest(m.as_str()),
                        "scope": {
                            "static": true,
                            "runtime": false,
                            "description": STANDARD_SCOPE_DESCRIPTION,
                        },
                        "hazards": [rule.hazard],
                        "assumptions": [rule.assumption],
                        "authorityLimits": STANDARD_AUTHORITY_LIMITS,
                    }),
                    uncertainty: vec![
                        "Lexical pattern match only; not confirmed by any protocol capture, PLC connection, or live network probe (none was performed or permitted).".to_string(),
                        "Actual reachability, safety-instrumented-system independence, and process consequence must be adjudicated by a qualified OT engineer.".to_string(),
                    ],
                });
            }
        }
    }
    observations
}
