//! Port of `src/providers/security/packs/smart-contract.mjs` (B7-020).
//! Solidity/Vyper source text only — no chain connection, no RPC call, no
//! transaction simulation, no deployed bytecode inspection. Every rule is a
//! lexical (pattern-only) detector that never certifies a contract as safe
//! and never emits a candidate without a stated scope/hazards/assumptions/
//! authority-limits block (mirrored here in `detectorMetadata`).

use super::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.smart-contract";
pub const CANDIDATE_CLASS: &str = "smart-contract";
pub const SUPPORT_TIER: &str = "measured";

const STANDARD_AUTHORITY_LIMITS: &[&str] = &[
    "This lens does not establish contract safety, audit completeness, or fitness for mainnet deployment under any standard.",
    "A finding here is an allegation requiring independent adjudication, ideally including a funded on-chain or fork-based proof; it is never a substitute for a qualified smart-contract auditor decision.",
];

fn solidity_or_vyper_file() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.(sol|vy)$").unwrap())
}

fn tx_origin_authorization() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)require\s*\(\s*tx\.origin\s*==|tx\.origin\s*==\s*owner").unwrap())
}

fn privileged_function_unprotected() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)function\s+(?:mint|burn|withdraw|pause|unpause|setOwner|setAdmin|sweep|rescue|selfdestruct|kill)\s*\([^)]*\)\s*(?:external|public)").unwrap()
    })
}

fn privileged_function_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==|AccessControl|Ownable").unwrap())
}

fn reentrancy_external_call() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.call\{\s*value\s*:[^}]*\}\s*\(|\.call\.value\s*\([^)]*\)\s*\(").unwrap())
}

fn reentrancy_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)nonReentrant|ReentrancyGuard|checks-effects-interactions").unwrap())
}

fn oracle_single_source() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.latestAnswer\s*\(\s*\)|\.latestRoundData\s*\(\s*\)|getPrice\s*\(\s*\)").unwrap())
}

fn oracle_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)updatedAt|heartbeat|deviation|TWAP|twap|require\s*\([^)]*(?:stale|fresh)").unwrap())
}

fn unprotected_upgrade_authorization() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)function\s+upgradeTo(?:AndCall)?\s*\([^)]*\)|_authorizeUpgrade\s*\([^)]*\)\s*(?:internal|override)").unwrap())
}

fn upgrade_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==").unwrap())
}

fn replay_missing_nonce() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)ecrecover\s*\(").unwrap())
}

fn replay_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)nonce|deadline|used\[|usedSignatures|EIP712|nonces\[").unwrap())
}

struct Rule {
    id: &'static str,
    severity_hint: &'static str,
    claim: &'static str,
    pattern: fn() -> &'static Regex,
    suppress_window_pattern: Option<fn() -> &'static Regex>,
    /// `"wide"` uses a 600-char radius; anything else (signature-and-body)
    /// uses 250, mirroring `rule.suppressScope === 'wide' ? 600 : 250`.
    wide_radius: bool,
    hazards: &'static [&'static str],
    assumptions: &'static [&'static str],
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
}

fn rules() -> [Rule; 6] {
    [
        Rule {
            id: "smart-contract.access-control.tx-origin-authorization",
            severity_hint: "high",
            claim: "A privileged check authorizes the caller using `tx.origin` instead of `msg.sender`.",
            pattern: tx_origin_authorization,
            suppress_window_pattern: None,
            wide_radius: false,
            hazards: &["A phishing contract can relay a privileged call through a victim EOA, since `tx.origin` reflects the original signer rather than the immediate caller."],
            assumptions: &["The comparison target is treated as a privileged/owner check; a non-privileged use of `tx.origin` would be a false positive requiring adjudication."],
            effect_kind: "principal-access",
            effect_action: "authorize",
            effect_scope: "tx-origin-check",
            chain_roles: &["starter", "control-bypass"],
        },
        Rule {
            id: "smart-contract.access-control.privileged-function-unprotected",
            severity_hint: "high",
            claim: "A privileged-looking function (mint/burn/withdraw/pause/setOwner/upgrade) has no visible access-control modifier or require check.",
            pattern: privileged_function_unprotected,
            suppress_window_pattern: Some(privileged_function_suppress),
            wide_radius: false,
            hazards: &["Any external account may call a state-changing privileged function directly, with no on-chain access gate observed."],
            assumptions: &["The function name heuristic is a naming convention, not a semantic guarantee; a differently-named privileged function is not detected, and a benign use of one of these names is a false positive requiring adjudication."],
            effect_kind: "principal-access",
            effect_action: "invoke-privileged-function",
            effect_scope: "unprotected-function",
            chain_roles: &["starter", "privilege-escalation"],
        },
        Rule {
            id: "smart-contract.reentrancy.external-call-before-guard",
            severity_hint: "high",
            claim: "An external value-transferring call is present with no visible reentrancy guard in the same function context.",
            pattern: reentrancy_external_call,
            suppress_window_pattern: Some(reentrancy_suppress),
            wide_radius: true,
            hazards: &["A malicious callee (including a fallback function) can re-enter the calling function before state is finalized, potentially draining funds or corrupting invariants."],
            assumptions: &["Checks-effects-interactions ordering performed without a named guard or comment is not detected by this lexical lens and must be adjudicated from the full function body."],
            effect_kind: "code-execution",
            effect_action: "reenter",
            effect_scope: "external-call",
            chain_roles: &["enabler", "impact"],
        },
        Rule {
            id: "smart-contract.oracle.single-source-price-trust",
            severity_hint: "high",
            claim: "A price/oracle read is used with no visible staleness or deviation check in the same window.",
            pattern: oracle_single_source,
            suppress_window_pattern: Some(oracle_suppress),
            wide_radius: true,
            hazards: &["An unchecked or manipulable price feed can be used to trigger favorable liquidations, mints, or trades against the protocol."],
            assumptions: &["Whether the oracle is a single source (spot) or an aggregated/TWAP feed configured elsewhere is not observed by this lens; only the local read-site check is examined."],
            effect_kind: "integrity-impact",
            effect_action: "trust-unchecked-price",
            effect_scope: "oracle-read",
            chain_roles: &["starter", "impact"],
        },
        Rule {
            id: "smart-contract.upgradeability.unprotected-upgrade-authorization",
            severity_hint: "critical",
            claim: "An upgrade entrypoint (`upgradeTo`/`_authorizeUpgrade`) has no visible access-control modifier or require check.",
            pattern: unprotected_upgrade_authorization,
            suppress_window_pattern: Some(upgrade_suppress),
            wide_radius: false,
            hazards: &["An unauthorized caller can point the proxy at an arbitrary implementation, taking full control of contract logic and stored funds."],
            assumptions: &["Access control enforced via a modifier applied at the contract level (rather than inline in the function) is not visible to a per-function window and must be adjudicated."],
            effect_kind: "code-execution",
            effect_action: "replace-implementation",
            effect_scope: "proxy-upgrade",
            chain_roles: &["starter", "privilege-escalation", "impact"],
        },
        Rule {
            id: "smart-contract.signature.replay-missing-nonce",
            severity_hint: "high",
            claim: "An `ecrecover`-based signature check is present with no visible nonce or deadline binding in the same window.",
            pattern: replay_missing_nonce,
            suppress_window_pattern: Some(replay_suppress),
            wide_radius: true,
            hazards: &["A previously valid signature can be resubmitted (replayed) on-chain or across chains to re-trigger the authorized action."],
            assumptions: &["Replay protection implemented via an external EIP-712 domain separator or a nonce contract not visible in this window is not detected and must be adjudicated."],
            effect_kind: "principal-access",
            effect_action: "replay-signature",
            effect_scope: "signature-check",
            chain_roles: &["starter", "impact"],
        },
    ]
}

pub fn rule_ids() -> Vec<&'static str> {
    rules().iter().map(|r| r.id).collect()
}

/// Ports `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        if !solidity_or_vyper_file().is_match(file) {
            continue;
        }
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            for m in (rule.pattern)().find_iter(text) {
                let radius = if rule.wide_radius { 600 } else { 250 };
                if let Some(suppress) = rule.suppress_window_pattern {
                    if (suppress)().is_match(window_around(text, m.start(), m.len(), radius)) {
                        continue;
                    }
                }

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: Vec::new(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec!["submit-transaction".to_string(), "deploy-malicious-contract".to_string()],
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "submit-transaction".to_string(),
                        object: None,
                        scope: None,
                        environment: "blockchain".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "blockchain".to_string(),
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
                            "description": "Contract source text only; no chain, RPC, mempool, or deployed-bytecode connection was made.",
                        },
                        "hazards": rule.hazards,
                        "assumptions": rule.assumptions,
                        "authorityLimits": STANDARD_AUTHORITY_LIMITS,
                    }),
                    uncertainty: vec![
                        "Lexical pattern match only; not confirmed by a fork simulation, static-analysis tool, or funded proof-of-concept.".to_string(),
                        "Reachability, attacker economic incentive, and value at risk must be adjudicated independently.".to_string(),
                    ],
                });
            }
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(body: &str) -> String {
        format!("pragma solidity ^0.8.0;\ncontract C {{\n  {body}\n}}")
    }

    fn find<'a>(obs: &'a [Observation], rule_id: &str) -> Option<&'a Observation> {
        obs.iter().find(|o| o.rule_id == rule_id)
    }

    #[test]
    fn each_rule_fires_on_its_positive_fixture_and_is_silent_on_its_mitigated_fixture() {
        let fixtures: [(&str, &str, &str); 6] = [
            (
                "smart-contract.access-control.tx-origin-authorization",
                "function withdraw() public { require(tx.origin == owner); payable(msg.sender).transfer(1); }",
                "function withdraw() public { require(msg.sender == owner); payable(msg.sender).transfer(1); }",
            ),
            (
                "smart-contract.access-control.privileged-function-unprotected",
                "function mint(address to, uint amount) external { _mint(to, amount); }",
                "function mint(address to, uint amount) external onlyOwner { _mint(to, amount); }",
            ),
            (
                "smart-contract.reentrancy.external-call-before-guard",
                "function withdraw() external { (bool ok, ) = msg.sender.call{value: balance}(\"\"); }",
                "function withdraw() external nonReentrant { (bool ok, ) = msg.sender.call{value: balance}(\"\"); }",
            ),
            (
                "smart-contract.oracle.single-source-price-trust",
                "function price() public view returns (int) { return feed.latestAnswer(); }",
                "function price() public view returns (int) { (, int p,, uint updatedAt,) = feed.latestRoundData(); require(block.timestamp - updatedAt < heartbeat); return p; }",
            ),
            (
                "smart-contract.upgradeability.unprotected-upgrade-authorization",
                "function _authorizeUpgrade(address newImpl) internal override {}",
                "function _authorizeUpgrade(address newImpl) internal override onlyOwner {}",
            ),
            (
                "smart-contract.signature.replay-missing-nonce",
                "function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { address signer = ecrecover(h, v, r, s); }",
                "function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s, uint nonce) external { require(!used[nonce]); address signer = ecrecover(h, v, r, s); }",
            ),
        ];

        for (rule_id, positive, mitigated) in fixtures {
            let positive_ctx = Context::new().with_file("Contract.sol", &wrap(positive));
            let positive_obs = analyze(&positive_ctx);
            let candidate = find(&positive_obs, rule_id);
            assert!(candidate.is_some(), "{rule_id} did not fire on its positive fixture");
            assert!(!candidate.unwrap().evidence_refs.is_empty());

            let mitigated_ctx = Context::new().with_file("Contract.sol", &wrap(mitigated));
            let mitigated_obs = analyze(&mitigated_ctx);
            assert!(find(&mitigated_obs, rule_id).is_none(), "{rule_id} still fired on its mitigated fixture");
        }
    }

    #[test]
    fn emits_nothing_for_a_non_solidity_file_even_with_a_risky_looking_pattern() {
        let context = Context::new().with_file("notes.md", "require(tx.origin == owner);");
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn emits_nothing_for_an_empty_contract() {
        let context = Context::new().with_file("contracts/Empty.sol", "pragma solidity ^0.8.0;\ncontract Empty {}");
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn every_candidate_carries_scope_hazards_assumptions_and_authority_limits() {
        let context = Context::new().with_file(
            "C.sol",
            "pragma solidity ^0.8.0;\ncontract C { function withdraw() public { require(tx.origin == owner); } }",
        );
        for candidate in analyze(&context) {
            let meta = &candidate.detector_metadata;
            assert_eq!(meta["scope"]["static"], json!(true));
            assert_eq!(meta["scope"]["runtime"], json!(false));
            assert!(meta["hazards"].as_array().unwrap().len() > 0);
            assert!(meta["assumptions"].as_array().unwrap().len() > 0);
            assert_eq!(meta["authorityLimits"].as_array().unwrap().len(), 2);
        }
    }

    #[test]
    fn rule_ids_match_the_six_documented_rule_ids() {
        assert_eq!(rule_ids().len(), 6);
    }
}
