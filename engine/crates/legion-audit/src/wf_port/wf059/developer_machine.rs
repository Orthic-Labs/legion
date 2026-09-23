//! Port of `src/providers/security/packs/developer-machine.mjs` (B7-018).
//!
//! Local executable invocation, editor/tool config authority, credential-
//! store access, and agent/skill config execution paths. Repository content
//! is never a trusted input: every candidate's precondition names the
//! repository as the untrusted origin.

use super::common::{digest, line_of, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::LazyLock;

static EDITOR_AGENT_CONFIG_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(\.vscode|\.idea|\.cursor|\.claude|\.github/copilot|\.mcp\.json|mcp\.json|CLAUDE\.md|AGENTS\.md|\.husky|\.git/hooks)(/|$)").unwrap()
});
static SKILL_CONFIG_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|/)(SKILL\.md|\.claude/(agents|skills)/)").unwrap());
static MCP_JSON_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.mcp\.json$|mcp\.json$").unwrap());
static SANDBOX_BYPASS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)dangerouslySkipPermissions|--no-sandbox|bypassPermissions|trust\s*[:=]\s*(?:false|"?off"?|disabled)"#).unwrap()
});

static COMMAND_INVOCATION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bexec\s*\(|\bspawn\s*\(|child_process|Bash\s*\(|shell\s*=\s*true").unwrap());
static EDITOR_CONFIG_COMMAND_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)"command"\s*:\s*"[^"\n]+"|"runOptions"|postCreateCommand|"task"\s*:"#).unwrap());
static CREDENTIAL_STORE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bkeytar\b|security\s+find-generic-password|\.aws/credentials|\.ssh/id_(?:rsa|ed25519)|\.netrc\b|\bkeychain\b|credential-store").unwrap()
});
static AGENT_SKILL_TRIGGER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)"command"\s*:\s*"[^"\n]+"|"args"\s*:\s*\[|\bIgnore prior instructions\b"#).unwrap());

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
    execution_chain: bool,
    uncertainty: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "developer-machine.local-executable.command-invocation",
        claim: "Repository-controlled configuration invokes a local executable/shell command that will run with the invoking developer's own authority.",
        severity_hint: "high",
        authority: "developer-machine-user",
        execution_path: "repository config → local tool loader → child_process/shell invocation",
        effect_kind: "code-execution",
        effect_action: "execute",
        effect_scope: "developer-machine-process",
        chain_roles: &["starter", "impact"],
        execution_chain: true,
        uncertainty: &["A command-invocation pattern in configuration is not automatically executed; whether the surrounding tool actually runs it, and with what input, must be adjudicated."],
    },
    Rule {
        id: "developer-machine.editor-config.command-authority",
        claim: "An editor/agent configuration file defines a task, hook, or command that a developer's tool will run automatically under the developer's own authority.",
        severity_hint: "medium",
        authority: "developer-machine-user",
        execution_path: "editor/agent config load → task/hook definition → invoked by editor authority",
        effect_kind: "code-execution",
        effect_action: "define-command",
        effect_scope: "developer-machine-tooling",
        chain_roles: &["enabler"],
        execution_chain: false,
        uncertainty: &["A defined task/command is not automatically dangerous; whether it runs without confirmation and what it targets must be adjudicated."],
    },
    Rule {
        id: "developer-machine.credential-store.access-pattern",
        claim: "Repository-controlled configuration or code references an OS credential store, keychain, or well-known local secrets path.",
        severity_hint: "high",
        authority: "developer-machine-user",
        execution_path: "repository config/code → credential-store client → local secret material",
        effect_kind: "credential-possession",
        effect_action: "access-local-credential-store",
        effect_scope: "developer-machine-credentials",
        chain_roles: &["starter", "pivot"],
        execution_chain: false,
        uncertainty: &["A credential-store reference is not automatically an exfiltration path; whether the retrieved value ever leaves the local process must be adjudicated."],
    },
    Rule {
        id: "developer-machine.agent-skill-config.execution-path",
        claim: "An agent/skill configuration file (MCP server, skill, or agent definition) declares a command or entrypoint that will be executed as part of the agent's local tool authority.",
        severity_hint: "high",
        authority: "developer-machine-agent",
        execution_path: ".mcp.json/SKILL.md/.claude agent config → declared server/tool command → local process",
        effect_kind: "code-execution",
        effect_action: "execute-declared-tool-command",
        effect_scope: "developer-machine-agent-runtime",
        chain_roles: &["starter", "impact"],
        execution_chain: true,
        uncertainty: &["A declared agent/skill command is not automatically hostile; whether it is actually invoked and under what approval gate must be adjudicated."],
    },
    Rule {
        id: "developer-machine.sandbox-bypass.permission-override",
        claim: "Repository-controlled configuration disables a local sandbox or permission gate that would otherwise confirm before executing on the developer machine.",
        severity_hint: "high",
        authority: "developer-machine-user",
        execution_path: "repository config → sandbox/permission bypass flag → unconfirmed local execution",
        effect_kind: "control-bypass",
        effect_action: "disable-local-sandbox",
        effect_scope: "developer-machine-tooling",
        chain_roles: &["enabler", "control-bypass"],
        execution_chain: false,
        uncertainty: &["A bypass-shaped flag is not automatically active in the invoking tool's effective configuration; scope and precedence must be adjudicated."],
    },
];

/// JS's `rawMatches` (`src/providers/security/packs/developer-machine.mjs`)
/// returns at most one match per file for a non-global pattern (a bare
/// `.exec(text)` call, no `/g` flag) — none of these four rules' patterns
/// carry `/g`, so each contributes at most one `Match` per file, not every
/// non-overlapping hit. `find_iter` would over-report (e.g. a line
/// containing both "child_process" and "exec(" would double-count), so
/// each loop below takes only the first match, mirroring `pattern.exec`.
fn matches_for_rule(id: &str, ctx: &Context) -> Vec<Match> {
    let mut out = Vec::new();
    match id {
        "developer-machine.local-executable.command-invocation" => {
            for file in &ctx.files {
                if !EDITOR_AGENT_CONFIG_PATTERN.is_match(file) {
                    continue;
                }
                let text = ctx.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if let Some(m) = COMMAND_INVOCATION_PATTERN.find(text) {
                    out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
                }
            }
        }
        "developer-machine.editor-config.command-authority" => {
            for file in &ctx.files {
                if !EDITOR_AGENT_CONFIG_PATTERN.is_match(file) {
                    continue;
                }
                let text = ctx.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if let Some(m) = EDITOR_CONFIG_COMMAND_PATTERN.find(text) {
                    out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
                }
            }
        }
        "developer-machine.credential-store.access-pattern" => {
            for file in &ctx.files {
                let text = ctx.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if let Some(m) = CREDENTIAL_STORE_PATTERN.find(text) {
                    out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
                }
            }
        }
        "developer-machine.agent-skill-config.execution-path" => {
            for file in &ctx.files {
                if !SKILL_CONFIG_PATTERN.is_match(file) && !MCP_JSON_PATTERN.is_match(file) {
                    continue;
                }
                let text = ctx.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if !AGENT_SKILL_TRIGGER_PATTERN.is_match(text) {
                    continue;
                }
                out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
            }
        }
        "developer-machine.sandbox-bypass.permission-override" => {
            for file in &ctx.files {
                if !EDITOR_AGENT_CONFIG_PATTERN.is_match(file) {
                    continue;
                }
                let text = ctx.read_file(file);
                if text.is_empty() {
                    continue;
                }
                if let Some(m) = SANDBOX_BYPASS_PATTERN.find(text) {
                    out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
                }
            }
        }
        _ => {}
    }
    out
}

fn sandbox_gate_note(ctx: &Context) -> String {
    if ctx.sandbox_receipt_present {
        "An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.".to_string()
    } else {
        "BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this developer-machine chain actually executes remains unproven pending one.".to_string()
    }
}

/// Faithful port of the module default export's `analyze(context)`.
pub fn analyze(ctx: &Context) -> Vec<Observation> {
    let mut out = Vec::new();
    for rule in RULES {
        for m in matches_for_rule(rule.id, ctx) {
            let artifact = ctx.find_artifact(&m.file);
            let mut uncertainty: Vec<String> = rule.uncertainty.iter().map(|s| s.to_string()).collect();
            let requires_sandbox_receipt = rule.execution_chain;
            if requires_sandbox_receipt {
                uncertainty.push(sandbox_gate_note(ctx));
            }
            let mut metadata = json!({
                "file": m.file,
                "line": m.line,
                "authority": rule.authority,
                "executionPath": rule.execution_path,
                "matchDigest": digest(&m.snippet),
            });
            if requires_sandbox_receipt {
                if let serde_json::Value::Object(o) = &mut metadata {
                    o.insert("requiresSandboxReceipt".to_string(), json!(true));
                }
            }
            out.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: "developer-machine".to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                attacker_capabilities: vec!["read-repository".to_string(), "control-repository-content".to_string()],
                preconditions: vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:repository-content".to_string(),
                    action: "control-repository-content".to_string(),
                    object: Some(m.file.clone()),
                    scope: None,
                    environment: "developer-machine".to_string(),
                    tenant: None,
                }],
                effects: vec![Fact {
                    kind: rule.effect_kind.to_string(),
                    subject: "actor:repository-content".to_string(),
                    action: rule.effect_action.to_string(),
                    object: artifact.map(|a| a.id.clone()),
                    scope: Some(rule.effect_scope.to_string()),
                    environment: "developer-machine".to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs: Vec::new(),
                detector_metadata: metadata,
                uncertainty,
            });
        }
    }
    out
}

pub const PACK_ID: &str = "security.developer-machine";
pub const PACK_VERSION: &str = "1.0.0";
