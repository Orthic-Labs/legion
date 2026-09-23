//! Port of `src/providers/security/packs/supply-chain.mjs`: dependency and
//! lockfile integrity, package install scripts, plugin trust, committed
//! build output, and artifact/cache poisoning.
//!
//! Every rule is a lexical (pattern-only) detector operating on repository
//! text and file paths already present in the frozen denominator. Every
//! candidate's preconditions include an explicit `attacker-position` fact
//! naming the repository itself as the untrusted origin of the evidence
//! (`hostile_precondition`), and the one rule whose claim depends on an
//! execution chain actually running (`install-time-execution`) is always
//! gated through `sandbox_gate` — never a clean claim absent an external
//! sandbox execution receipt.
//!
//! Scope of this port (mirrors the precedent documented in the sibling
//! `wf060` chunk's `common.rs`): only `analyze(context)` — the pure lexical
//! detection producing `UNADJUDICATED` candidate observations — is ported.
//! The pack's `variantStrategies` (`rootCause`/`enumerate`) is coverage-
//! report bookkeeping over the same matches `analyze()` already finds and
//! is not ported here to keep this chunk bounded.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use super::common::{digest, line_of, raw_matches, Context, Fact, Observation};

pub const ID: &str = "security.supply-chain";
pub const CANDIDATE_CLASS: &str = "supply-chain";

fn package_manifest() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|/)package\.json$").unwrap())
}

fn lockfile() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$").unwrap())
}

fn npm_config() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|/)\.npmrc$").unwrap())
}

fn workflow_file() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|(^|/)azure-pipelines\.ya?ml$|(^|/)\.circleci/config\.ya?ml$",
        )
        .unwrap()
    })
}

fn build_output_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|/)(dist|build|out|\.next|target)/[^/]+").unwrap())
}

fn non_registry_source() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""[\w@/.-]+"\s*:\s*"(?:git\+[^"\n]+|https?://[^"\n]+|github:[^"\n]+)""#).unwrap()
    })
}

fn install_time_execution() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"(?:preinstall|install|postinstall)"\s*:\s*"[^"\n]*(?:curl|wget)[^"\n]*\|\s*(?:sh|bash)[^"\n]*""#)
            .unwrap()
    })
}

fn unpinned_remote_plugin() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"(?:plugins|extends)"\s*:\s*\[?[^\]}\n]*https?://[^"\n]+"#).unwrap()
    })
}

fn cache_poisoning_surface() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)cache[\s\S]{0,200}?key[\s\S]{0,80}?(?:github\.head_ref|github\.event\.pull_request|pull_request)")
            .unwrap()
    })
}

fn ignore_scripts_configured() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bignore-scripts\s*=\s*true\b").unwrap())
}

fn integrity_covered(text: &str) -> bool {
    static INTEGRITY: OnceLock<Regex> = OnceLock::new();
    static RESOLUTION_SHA: OnceLock<Regex> = OnceLock::new();
    let integrity = INTEGRITY.get_or_init(|| Regex::new(r"(?i)\bintegrity\b").unwrap());
    let resolution_sha = RESOLUTION_SHA.get_or_init(|| Regex::new(r"(?is)\bresolution\b.*sha(256|512)").unwrap());
    integrity.is_match(text) || resolution_sha.is_match(text)
}

/// Mirrors `hostilePrecondition(file, environment)`.
fn hostile_precondition(file: &str, environment: Option<&str>) -> Fact {
    Fact {
        kind: "attacker-position".to_string(),
        subject: "actor:repository-content".to_string(),
        action: "control-repository-content".to_string(),
        object: Some(file.to_string()),
        scope: None,
        environment: environment.unwrap_or("any").to_string(),
        tenant: None,
    }
}

/// Mirrors `sandboxGate(context)`.
struct SandboxGate {
    note: String,
}

fn sandbox_gate(context: &Context) -> SandboxGate {
    let has_receipt = context.audit_facts.sandbox_receipt;
    let note = if has_receipt {
        "An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.".to_string()
    } else {
        "BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this install-time chain actually executes remains unproven pending one.".to_string()
    };
    SandboxGate { note }
}

fn ignore_scripts_is_configured(context: &Context) -> bool {
    for file in &context.files {
        if !npm_config().is_match(file) {
            continue;
        }
        let text = context.read_file(file);
        if ignore_scripts_configured().is_match(text) {
            return true;
        }
    }
    false
}

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
    chain_roles: &'static [&'static str],
    environment: Option<&'static str>,
    execution_chain: bool,
    uncertainty: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "supply-chain.dependency.non-registry-source",
        claim: "A dependency is resolved from a direct git/URL source rather than the package registry, bypassing registry-level integrity and provenance checks.",
        severity_hint: "medium",
        authority: "package-manager",
        execution_path: "dependency resolution → non-registry source → installed package",
        effect_kind: "integrity-impact",
        effect_action: "substitute-dependency",
        effect_scope: "dependency-resolution",
        chain_roles: &["enabler"],
        environment: None,
        execution_chain: false,
        uncertainty: &["A direct-URL/git dependency is not automatically malicious; whether the source is pinned to an immutable commit and reviewed must be adjudicated."],
    },
    Rule {
        id: "supply-chain.lockfile.missing",
        claim: "A package manifest is present without a corresponding dependency lockfile, so transitive dependency versions are not pinned or hash-verified at install time.",
        severity_hint: "medium",
        authority: "package-manager",
        execution_path: "dependency install → unpinned resolution → arbitrary transitive package version",
        effect_kind: "integrity-impact",
        effect_action: "unpin-dependency-resolution",
        effect_scope: "dependency-resolution",
        chain_roles: &["enabler"],
        environment: None,
        execution_chain: false,
        uncertainty: &["A missing lockfile in this denominator slice does not prove no lockfile exists in the full repository; workspace-root lockfiles must be adjudicated."],
    },
    Rule {
        id: "supply-chain.lockfile.integrity-hash-absent",
        claim: "A dependency lockfile is present without integrity/hash fields for its resolved packages, so a tampered registry-hosted package would not be detected at install time.",
        severity_hint: "medium",
        authority: "package-manager",
        execution_path: "npm/yarn/pnpm install → lockfile resolution → unverified package fetch",
        effect_kind: "integrity-impact",
        effect_action: "accept-unverified-package",
        effect_scope: "dependency-resolution",
        chain_roles: &["enabler"],
        environment: None,
        execution_chain: false,
        uncertainty: &["Lockfile format variation means an absent literal \"integrity\" token is a lexical heuristic, not a parsed guarantee; the actual lockfile schema must be adjudicated."],
    },
    Rule {
        id: "supply-chain.package-script.install-time-execution",
        claim: "A package lifecycle script (preinstall/install/postinstall) downloads and executes remote content during dependency installation.",
        severity_hint: "high",
        authority: "package-manager",
        execution_path: "npm install → postinstall → shell",
        effect_kind: "code-execution",
        effect_action: "execute",
        effect_scope: "developer-machine-or-ci-install",
        chain_roles: &["starter", "impact"],
        environment: None,
        execution_chain: true,
        uncertainty: &["A remote-fetch-pipe-shell lifecycle script is not automatically compromised; its actual execution and payload can only be proven by independent sandboxed execution."],
    },
    Rule {
        id: "supply-chain.plugin.unpinned-remote-plugin",
        claim: "A build/lint plugin or extension is loaded from a remote URL rather than a pinned, registry-resolved package, so its content bypasses lockfile integrity checks.",
        severity_hint: "medium",
        authority: "build-toolchain",
        execution_path: "build/lint config → remote plugin URL → loaded into toolchain process",
        effect_kind: "code-execution",
        effect_action: "load-plugin",
        effect_scope: "build-toolchain",
        chain_roles: &["enabler"],
        environment: None,
        execution_chain: false,
        uncertainty: &["A remote plugin reference is not automatically malicious; whether it is actually loaded and what it can reach must be adjudicated."],
    },
    Rule {
        id: "supply-chain.artifact.committed-build-output",
        claim: "A build output directory is committed to the repository, so consumers may trust a prebuilt artifact that was not produced by the pinned, auditable build from source.",
        severity_hint: "medium",
        authority: "repository-content",
        execution_path: "committed build artifact → consumed directly → bypasses build-from-source verification",
        effect_kind: "integrity-impact",
        effect_action: "substitute-artifact",
        effect_scope: "build-output",
        chain_roles: &["enabler"],
        environment: None,
        execution_chain: false,
        uncertainty: &["A committed build-output path is not automatically malicious; whether it is actually consumed instead of a fresh build must be adjudicated."],
    },
    Rule {
        id: "supply-chain.cache.poisoning-surface",
        claim: "A CI build/dependency cache key is derived from untrusted pull-request or fork-controlled context, letting an external contributor poison a cache entry consumed by a later, more privileged run.",
        severity_hint: "high",
        authority: "ci-automation-identity",
        execution_path: "fork PR → cache key control → poisoned cache entry → consumed by later privileged workflow run",
        effect_kind: "integrity-impact",
        effect_action: "poison-cache",
        effect_scope: "ci-cache",
        chain_roles: &["starter", "pivot"],
        environment: Some("ci"),
        execution_chain: false,
        uncertainty: &["A PR-derived cache key is not automatically exploitable; whether the poisoned entry is later restored into a privileged job must be adjudicated."],
    },
];

/// Mirrors each rule's `matchesIn(context)`.
fn matches_for(rule: &Rule, context: &Context) -> Vec<Match> {
    match rule.id {
        "supply-chain.dependency.non-registry-source" => regex_matches(
            non_registry_source(),
            context,
            Some(package_manifest()),
            true,
        ),
        "supply-chain.lockfile.missing" => {
            let manifests: Vec<&String> = context.files.iter().filter(|f| package_manifest().is_match(f)).collect();
            if manifests.is_empty() {
                return vec![];
            }
            let has_lockfile = context.files.iter().any(|f| lockfile().is_match(f));
            if has_lockfile {
                return vec![];
            }
            manifests
                .into_iter()
                .map(|file| Match { file: file.clone(), line: 1, snippet: file.clone() })
                .collect()
        }
        "supply-chain.lockfile.integrity-hash-absent" => {
            let mut out = Vec::new();
            for file in &context.files {
                if !lockfile().is_match(file) {
                    continue;
                }
                let text = context.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if integrity_covered(text) {
                    continue;
                }
                out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
            }
            out
        }
        "supply-chain.package-script.install-time-execution" => {
            if ignore_scripts_is_configured(context) {
                return vec![];
            }
            regex_matches(install_time_execution(), context, Some(package_manifest()), true)
        }
        "supply-chain.plugin.unpinned-remote-plugin" => regex_matches(unpinned_remote_plugin(), context, None, true),
        "supply-chain.artifact.committed-build-output" => context
            .files
            .iter()
            .filter(|f| build_output_path().is_match(f))
            .map(|file| Match { file: file.clone(), line: 1, snippet: file.clone() })
            .collect(),
        "supply-chain.cache.poisoning-surface" => {
            regex_matches(cache_poisoning_surface(), context, Some(workflow_file()), false)
        }
        _ => vec![],
    }
}

fn regex_matches(pattern: &Regex, context: &Context, file_guard: Option<&Regex>, global: bool) -> Vec<Match> {
    let mut out = Vec::new();
    for file in &context.files {
        if let Some(guard) = file_guard {
            if !guard.is_match(file) {
                continue;
            }
        }
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in raw_matches(pattern, text, global) {
            out.push(Match { file: file.clone(), line: line_of(text, m.index), snippet: m.whole });
        }
    }
    out
}

/// Faithful port of `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for rule in RULES {
        for m in matches_for(rule, context) {
            let artifact = context.find_artifact(&m.file);
            let gate = if rule.execution_chain { Some(sandbox_gate(context)) } else { None };
            let mut uncertainty: Vec<String> = rule.uncertainty.iter().map(|s| s.to_string()).collect();
            if let Some(g) = &gate {
                uncertainty.push(g.note.clone());
            }

            let mut detector_metadata = json!({
                "file": m.file,
                "line": m.line,
                "authority": rule.authority,
                "executionPath": rule.execution_path,
                "matchDigest": digest(&m.snippet),
            });
            if gate.is_some() {
                detector_metadata["requiresSandboxReceipt"] = json!(true);
            }

            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                attacker_capabilities: vec!["read-repository".to_string(), "control-repository-content".to_string()],
                preconditions: vec![hostile_precondition(&m.file, rule.environment)],
                effects: vec![Fact {
                    kind: rule.effect_kind.to_string(),
                    subject: "actor:repository-content".to_string(),
                    action: rule.effect_action.to_string(),
                    object: artifact.map(|a| a.id.clone()),
                    scope: Some(rule.effect_scope.to_string()),
                    environment: rule.environment.unwrap_or("any").to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                detector_metadata,
                uncertainty,
            });
        }
    }
    observations
}

#[allow(dead_code)]
pub fn rule_ids() -> Vec<&'static str> {
    RULES.iter().map(|r| r.id).collect()
}

#[allow(dead_code)]
pub fn description() -> &'static str {
    "Dependency/lockfile integrity, package install scripts, plugin trust, committed build output, and artifact/cache poisoning."
}

#[allow(dead_code)]
pub fn pack_value() -> Value {
    json!({
        "id": ID,
        "version": "1.0.0",
        "candidateClass": CANDIDATE_CLASS,
        "description": description(),
        "rules": rule_ids(),
    })
}
