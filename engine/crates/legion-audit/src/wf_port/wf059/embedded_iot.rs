//! Port of `src/providers/security/packs/embedded-iot.mjs` (B7-020).
//!
//! Firmware and embedded source/config text only — no device flash, no
//! serial/USB connection, no radio, no network probe of any kind.

use super::common::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::LazyLock;

static FIRMWARE_FILE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(c|h|cpp|hpp|ino|rs)$|(^|/)(platformio\.ini|CMakeLists\.txt|sdkconfig)$").unwrap());

struct Rule {
    id: &'static str,
    severity_hint: &'static str,
    claim: &'static str,
    pattern: LazyLock<Regex>,
    suppress_window_pattern: LazyLock<Regex>,
    // 0 = "match" scope (test the match text itself), else the window radius.
    suppress_radius: usize,
    hazards: &'static [&'static str],
    assumptions: &'static [&'static str],
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
}

static RULE_FIRMWARE: Rule = Rule {
    id: "embedded-iot.firmware.update-without-signature-verification",
    severity_hint: "critical",
    claim: "A firmware/OTA update path downloads or applies an image with no visible signature or digest verification.",
    pattern: LazyLock::new(|| {
        Regex::new(r"(?is)(?:firmware|_ota_|ota[A-Z_]|fw_image|flash_image).{0,200}?(?:download|apply|write|flash)").unwrap()
    }),
    suppress_window_pattern: LazyLock::new(|| {
        Regex::new(r"(?i)verify|signature|signed|digest|sha256|hmac|secureboot|secure_boot").unwrap()
    }),
    suppress_radius: 600,
    hazards: &["A network- or supply-chain-positioned attacker can push an unsigned malicious firmware image that the device will accept and execute."],
    assumptions: &["Verification performed by a separate bootloader stage not visible in this source window is not detected and must be adjudicated against the actual boot chain."],
    effect_kind: "code-execution",
    effect_action: "flash-unverified-image",
    effect_scope: "firmware-update",
    chain_roles: &["starter", "impact"],
};

static RULE_DEBUG_INTERFACE: Rule = Rule {
    id: "embedded-iot.debug-interface.enabled-in-production-build",
    severity_hint: "high",
    claim: "A debug shell, UART console, or JTAG/SWD interface is enabled with no visible release-build guard.",
    pattern: LazyLock::new(|| {
        Regex::new(r"(?i)#define\s+(?:DEBUG_SHELL_ENABLED|DEBUG_UART_ENABLED|CONFIG_DEBUG_UART|ENABLE_JTAG|ENABLE_SWD)\s+1|debug[_-]?shell\s*[:=]\s*(?:true|enabled|1)").unwrap()
    }),
    suppress_window_pattern: LazyLock::new(|| {
        Regex::new(r"(?i)#ifndef\s+NDEBUG|#if\s+defined\s*\(\s*DEBUG\s*\)|#ifdef\s+DEBUG_BUILD|release_build\s*==\s*false").unwrap()
    }),
    suppress_radius: 600,
    hazards: &["Physical or adjacent access to the debug interface can grant a full memory/flash dump, credential extraction, or arbitrary code execution."],
    assumptions: &["A board-level fuse or jumper that physically disables the interface in production units is not visible in source text and must be adjudicated separately."],
    effect_kind: "code-execution",
    effect_action: "access-debug-interface",
    effect_scope: "debug-interface",
    chain_roles: &["enabler", "impact"],
};

static RULE_HARDCODED_SECRET: Rule = Rule {
    id: "embedded-iot.credentials.hardcoded-secret",
    severity_hint: "high",
    claim: "A credential-shaped literal (password, API key, or Wi-Fi PSK) is hardcoded in firmware source.",
    pattern: LazyLock::new(|| {
        Regex::new(r#"(?i)\b(?:char\s*\*?\s*)?(?:wifi_pass|wifi_psk|api_key|device_secret|admin_password|default_password)\s*(?:\[\s*\]\s*)?=\s*"[^"\n]{4,}""#).unwrap()
    }),
    suppress_window_pattern: LazyLock::new(|| {
        Regex::new(r"(?i)getenv|from_nvs|from_flash_config|provisioned_at_factory|read_from_secure_element").unwrap()
    }),
    suppress_radius: 0,
    hazards: &["A single extracted binary (or the public source itself) discloses a credential shared across every device of this build, enabling fleet-wide compromise."],
    assumptions: &["A build-time substitution (e.g. a CI secret injected into this literal before compilation) is not visible in source text and must be adjudicated against the build pipeline."],
    effect_kind: "credential-possession",
    effect_action: "extract-hardcoded-credential",
    effect_scope: "firmware-binary",
    chain_roles: &["starter", "pivot"],
};

static RULE_SHARED_DEVICE_KEY: Rule = Rule {
    id: "embedded-iot.identity.shared-static-device-key",
    severity_hint: "high",
    claim: "A device identity/secret constant is referenced with no visible per-device provisioning mechanism in the same file.",
    pattern: LazyLock::new(|| Regex::new(r#"(?i)\b(?:DEVICE_SECRET|DEVICE_KEY|SHARED_DEVICE_KEY)\s*"[^"\n]{4,}""#).unwrap()),
    suppress_window_pattern: LazyLock::new(|| {
        Regex::new(r"(?i)per[_-]?device|unique[_-]?id|serial[_-]?number|factory[_-]?provision|secure[_-]?element|atecc").unwrap()
    }),
    suppress_radius: 600,
    hazards: &["A key shared identically across every unit lets compromise of one device (or the firmware image) impersonate the entire fleet to backend services."],
    assumptions: &["Per-device provisioning performed by a separate factory-programming step not represented in source text is not detected and must be adjudicated against the manufacturing pipeline."],
    effect_kind: "principal-access",
    effect_action: "impersonate-device-fleet",
    effect_scope: "device-identity",
    chain_roles: &["starter", "privilege-escalation"],
};

fn rules() -> [&'static Rule; 4] {
    [&RULE_FIRMWARE, &RULE_DEBUG_INTERFACE, &RULE_HARDCODED_SECRET, &RULE_SHARED_DEVICE_KEY]
}

/// Faithful port of the module default export's `analyze(context)`.
pub fn analyze(ctx: &Context) -> Vec<Observation> {
    let mut out = Vec::new();
    for file in &ctx.files {
        if !FIRMWARE_FILE_PATTERN.is_match(file) {
            continue;
        }
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = ctx.find_artifact(file);
        for rule in rules() {
            for m in rule.pattern.find_iter(text) {
                let window = if rule.suppress_radius == 0 {
                    m.as_str()
                } else {
                    window_around(text, m.start(), m.len(), rule.suppress_radius)
                };
                if rule.suppress_window_pattern.is_match(window) {
                    continue;
                }
                out.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: "embedded-iot".to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: vec![],
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec![
                        "physical-device-access".to_string(),
                        "network-position-to-update-channel".to_string(),
                        "firmware-image-extraction".to_string(),
                    ],
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "obtain-device-or-image-access".to_string(),
                        object: None,
                        scope: None,
                        environment: "embedded".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "embedded".to_string(),
                        tenant: None,
                    }],
                    assets: vec![],
                    trust_boundary_crossings: vec![],
                    required_controls: vec![],
                    observed_controls: vec![],
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: Vec::new(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, m.start()),
                        "matchDigest": digest(m.as_str()),
                        "scope": {
                            "static": true,
                            "runtime": false,
                            "description": "Firmware/embedded source and build-config text only; no device, serial/USB, JTAG, or radio connection was made.",
                        },
                        "hazards": rule.hazards,
                        "assumptions": rule.assumptions,
                        "authorityLimits": [
                            "This lens does not establish device safety, firmware integrity at the flashed binary, or regulatory adequacy for any standard.",
                            "A finding here is an allegation requiring independent adjudication against the actual build/flash pipeline; it is never a substitute for a qualified embedded-security reviewer decision.",
                        ],
                    }),
                    uncertainty: vec![
                        "Lexical pattern match only; not confirmed by binary/flash extraction, a hardware trace, or a device-level test.".to_string(),
                        "Whether this build configuration ever ships to a production unit must be adjudicated independently.".to_string(),
                    ],
                });
            }
        }
    }
    out
}

pub const PACK_ID: &str = "security.embedded-iot";
pub const PACK_VERSION: &str = "1.0.0";
pub const SUPPORT_TIER: &str = "measured";
