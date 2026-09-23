//! Port of five security packs (chunk wf061, area `src/providers/security`):
//!
//! - `src/providers/security/packs/mobile.mjs` — Android/iOS manifest, config, and
//!   source-text-only security pack (permissions, deep links, exported components,
//!   WebView JS bridges, insecure storage, backup, transport, and debug signing).
//! - `src/providers/security/packs/native-workspace.mjs` — a three-rule
//!   `createPatternPack` instance: native process/shell, updater transport, and
//!   plugin-loading trust boundaries.
//! - `src/providers/security/packs/observability-forensics.mjs` — sensitive data in
//!   error output, missing auth/privilege/export security events, and log injection.
//! - `src/providers/security/packs/output-handling.mjs` — untrusted content crossing
//!   an explicit output context (HTML body/attribute, JS, URL, CSS, shell, SQL, log,
//!   stored/email-header/model-output variants).
//! - `src/providers/security/packs/parser-serialization.mjs` — unsafe deserialization,
//!   XML entity expansion, decompression bombs, and unbounded recursive parsing.
//!
//! `git grep` over `engine/` for these five packs' rule ids, pack ids, and the
//! `createPatternPack` factory found no prior native port of any of them (the id
//! `security.mobile` etc. appear nowhere under `engine/`, and `native_providers/`
//! covers a disjoint set of native-tool providers — `ast_grep`, `container_iac`,
//! `dependency_osv`, `opengrep`, `secrets` — not these lexical pattern packs), so all
//! five are ported fresh here, following wf058's and wf056's self-contained-module
//! shape for this same directory.
//!
//! This module defines its own minimal `SecurityModel`/`Entity`/`Relation`/
//! `PackContext`/`Observation` types (a superset of wf058's, adding
//! `entity_by_id`/`relations_to` lookups and the optional
//! `output_handling_traces`/`logging_traces` upstream-evidence lists that
//! `output-handling.mjs` and `observability-forensics.mjs` read from
//! `context.projection.auditFacts`), since no shared security-context module was
//! found under this crate at port time.
//!
//! Everything here is pure: no filesystem walk, no model call, no tool execution, no
//! network access — matching every source file's own header comment.
//!
//! One JS regex feature required a manual (non-regex-only) reproduction:
//! `parser.unbounded-recursion` in `parser_serialization` uses a JS backreference
//! (`\1`) to require the *same* function name to recur inside its own body; the
//! `regex` crate has no backreference support, so that rule is implemented as a
//! two-phase match (capture the function header, then search its body window for a
//! literal, `regex::escape`d call to that same name) — see the rule's own doc
//! comment for the exact semantics preserved.
//!
//! Each pack's `variantStrategies.<rule>.enumerate` is ported as a
//! `pub fn enumerate_<rule>` alongside `analyze`, for parity with the JS source and
//! for any future caller; nothing in this crate calls it yet (mirroring wf058's same
//! finding), so it is exercised here only incidentally through the `analyze` tests
//! that share its match logic.

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

// =================================================================================================
// Minimal shared security-model types (mirrors/extends wf058's self-contained subset).
// =================================================================================================

#[derive(Debug, Clone, Default)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub attributes: BTreeMap<String, Value>,
    pub evidence_refs: Vec<String>,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityModel {
    pub entities: Vec<Entity>,
}

/// Mirrors `context.projection.auditFacts.outputHandlingTraces[]` entries read by
/// `output-handling.mjs`'s `traceFor`.
#[derive(Debug, Clone)]
pub struct OutputHandlingTrace {
    pub file: String,
    pub output_context: String,
}

/// Mirrors `context.projection.auditFacts.loggingTraces[]` entries read by
/// `observability-forensics.mjs`'s `loggingTraceFor`.
#[derive(Debug, Clone)]
pub struct LoggingTrace {
    pub file: String,
    pub event_type: String,
}

/// Mirrors the subset of the JS `context` object these five packs' `analyze(context)`
/// actually read: `context.files`, `context.readFile(file)`, `context.model.entities`,
/// `context.entityById`, `context.relationsTo(id)`, and (for output-handling /
/// observability-forensics) `context.projection.auditFacts.{outputHandlingTraces,
/// loggingTraces}`.
#[derive(Default)]
pub struct PackContext<'a> {
    pub files: Vec<String>,
    pub source_text: BTreeMap<String, String>,
    pub model: Option<&'a SecurityModel>,
    pub relations: Vec<Relation>,
    pub denominator_digest: String,
    pub output_handling_traces: Vec<OutputHandlingTrace>,
    pub logging_traces: Vec<LoggingTrace>,
}

impl<'a> PackContext<'a> {
    pub fn read_file(&self, file: &str) -> Option<&str> {
        self.source_text.get(file).map(String::as_str)
    }

    pub fn entities(&self) -> &[Entity] {
        self.model.map(|m| m.entities.as_slice()).unwrap_or(&[])
    }

    fn find_entity<F: Fn(&Entity) -> bool>(&self, pred: F) -> Option<&Entity> {
        self.entities().iter().find(|e| pred(e))
    }

    /// Mirrors `artifactFor(context, file)` / `findArtifact(context, file)`.
    pub fn artifact_for(&self, file: &str) -> Option<&Entity> {
        self.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    /// Mirrors `context.entityById.get(id)`.
    pub fn entity_by_id(&self, id: &str) -> Option<&Entity> {
        self.find_entity(|e| e.id == id)
    }

    /// Mirrors `context.relationsTo(id)`: every relation whose `to` equals `id`.
    pub fn relations_to<'b>(&'b self, id: &'b str) -> impl Iterator<Item = &'b Relation> + 'b {
        self.relations.iter().filter(move |r| r.to == id)
    }

    fn output_handling_trace(&self, file: &str, output_context: &str) -> bool {
        self.output_handling_traces
            .iter()
            .any(|t| t.file == file && t.output_context == output_context)
    }

    fn logging_trace(&self, file: &str, event_type: &str) -> bool {
        self.logging_traces
            .iter()
            .any(|t| t.file == file && t.event_type == event_type)
    }
}

/// Mirrors the observation object each pack's `analyze` pushes. `detector_metadata`
/// carries every per-rule extra field (line, matchDigest, sinkEngine, etc.) that would
/// otherwise need one struct field per pack, matching wf058's same reduction.
#[derive(Debug, Clone)]
pub struct Observation {
    pub rule_id: String,
    pub candidate_class: String,
    pub claim: String,
    pub severity_hint: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub attacker_capabilities: Vec<String>,
    pub effect_kind: String,
    pub effect_action: String,
    pub effect_object: Option<String>,
    pub effect_scope: Option<String>,
    pub effect_environment: String,
    pub chain_roles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub observed_controls: Vec<String>,
    pub detector_metadata: Value,
    pub uncertainty: Vec<String>,
}

/// Mirrors `digest(value)` from `contracts.mjs`: `sha256:` + hex(sha256(`digest\0` +
/// `JSON.stringify(canonicalize(value))`)). Every call site here passes a plain
/// string (the matched text, or a `{ ruleId, file, snippet }`-shaped object for
/// `enumerate`'s `semanticFingerprint`), so `canonicalize` is the identity for the
/// string case and a stable key-sorted object for the object case — `serde_json`'s
/// `Value::Object` (a `BTreeMap`-backed map via the `preserve_order` feature being
/// off) already serializes with sorted keys, matching `canonicalize`'s own recursive
/// key-sort.
fn digest_value(value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"digest\0");
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn digest_str(s: &str) -> String {
    digest_value(&Value::String(s.to_string()))
}

/// Snaps a byte offset down to the nearest `char` boundary at or before it, clamped
/// to `text`'s length. Every windowing helper below computes a byte offset by adding
/// or subtracting a fixed radius from a regex match's (always-char-boundary) start or
/// end, which can land inside a multi-byte UTF-8 sequence; slicing `text[a..b]`
/// directly on such an offset panics, so every window boundary is snapped through
/// this pair of helpers before use (the JS source has no such hazard: it indexes
/// UTF-16 code units, not bytes, but the fixed-radius windows here mirror its intent
/// -- "roughly N characters around the match" -- closely enough that the snap
/// introduces no behavioral divergence a test could observe).
fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    if idx >= text.len() {
        return text.len();
    }
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    if idx >= text.len() {
        return text.len();
    }
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn line_of(text: &str, byte_index: usize) -> usize {
    text.as_bytes()[..byte_index.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

// =================================================================================================
// pattern-pack.mjs: `createPatternPack` factory, reproduced for the one
// pattern-pack-shaped source in this chunk (native-workspace.mjs).
// =================================================================================================

pub struct PatternRule {
    pub id: &'static str,
    pub pattern: fn(&str) -> bool,
    pub claim: &'static str,
    pub severity_hint: &'static str,
    pub effect_kind: &'static str,
    pub effect_action: &'static str,
    pub effect_scope: Option<&'static str>,
    pub chain_roles: &'static [&'static str],
}

const DEFAULT_ATTACKER_CAPABILITY: &str = "control-request-input";
const DEFAULT_UNCERTAINTY: &str =
    "Reachability and compensating controls require independent adjudication.";
const DEFAULT_CHAIN_ROLES: &[&str] = &["starter", "impact"];

/// Mirrors `createPatternPack({ ... }).analyze(context)`.
fn pattern_pack_analyze(ctx: &PackContext, family: &str, rules: &[PatternRule]) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &ctx.files {
        let text = match ctx.read_file(file) {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        let artifact = ctx.artifact_for(file);
        for rule in rules {
            if !(rule.pattern)(text) {
                continue;
            }
            let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: family.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: ids.clone(),
                sinks: ids,
                attacker_capabilities: vec![DEFAULT_ATTACKER_CAPABILITY.to_string()],
                effect_kind: rule.effect_kind.to_string(),
                effect_action: rule.effect_action.to_string(),
                effect_object: artifact.map(|e| e.id.clone()),
                effect_scope: Some(rule.effect_scope.unwrap_or(family).to_string()),
                effect_environment: "application".to_string(),
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs: artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default(),
                observed_controls: Vec::new(),
                detector_metadata: json!({ "file": file, "patternFamily": family }),
                uncertainty: vec![DEFAULT_UNCERTAINTY.to_string()],
            });
        }
    }
    observations
}

// =================================================================================================
// native-workspace.mjs
// =================================================================================================

pub mod native_workspace {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "native-workspace";

    fn p_shell_string_command(t: &str) -> bool {
        Regex::new(
            r#"(?i)(?:Command::new\(['"](?:sh|bash|cmd|powershell)|child_process\.exec\s*\(|subprocess\.(?:run|Popen)\([^\n]*shell\s*=\s*True)"#,
        )
        .unwrap()
        .is_match(t)
    }
    fn p_updater_insecure_transport(t: &str) -> bool {
        Regex::new(r"(?i)(?:update|download|artifact)[\s\S]{0,180}http://")
            .unwrap()
            .is_match(t)
    }
    fn p_plugin_untrusted_path(t: &str) -> bool {
        Regex::new(r"(?i)(?:plugin|extension)[\s\S]{0,120}(?:load|import|require)\s*\([^\n]*(?:input|config|env)")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[PatternRule] = &[
        PatternRule {
            id: "native.shell-string-command",
            pattern: p_shell_string_command,
            claim: "A native process boundary invokes a shell-capable command path.",
            severity_hint: "high",
            effect_kind: "code-execution",
            effect_action: "execute",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "native.updater-insecure-transport",
            pattern: p_updater_insecure_transport,
            claim: "A native update or artifact path may use insecure transport.",
            // JS: `severityHint` omitted -> factory default `'medium'`.
            severity_hint: "medium",
            effect_kind: "code-execution",
            // JS: `effectAction` omitted -> factory default `'bypass'`.
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "native.plugin-untrusted-path",
            pattern: p_plugin_untrusted_path,
            claim: "A configurable plugin path may cross into executable loading.",
            severity_hint: "medium",
            effect_kind: "code-execution",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
    ];

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        pattern_pack_analyze(ctx, CANDIDATE_CLASS, RULES)
    }
}

// =================================================================================================
// output-handling.mjs
// =================================================================================================

pub mod output_handling {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "output-handling";

    struct Rule {
        id: &'static str,
        output_context: &'static str,
        sink_kind_default: Option<&'static str>,
        severity_hint: &'static str,
        claim: &'static str,
        risky_pattern: fn() -> Regex,
        suppress_pattern: Option<fn() -> Regex>,
        /// `'match'` scope tests only the match text; default (`None`) tests the
        /// matched text plus 300 chars forward, mirroring `testAround`'s `'forward'`.
        suppress_match_scope: bool,
        downgrade: Option<Downgrade>,
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
        sink_engine: fn(&str) -> &'static str,
        uncertainty: &'static [&'static str],
    }

    struct Downgrade {
        control_types: &'static [&'static str],
        severity_hint: &'static str,
        lexical_pattern: Option<fn() -> Regex>,
        lexical_match_scope: bool,
        lexical_note: Option<&'static str>,
    }

    fn test_around(pat: Option<&Regex>, text: &str, index: usize, match_len: usize, match_scope: bool) -> bool {
        let Some(pat) = pat else { return false };
        if match_scope {
            pat.is_match(&text[index..index + match_len])
        } else {
            let end = ceil_char_boundary(text, index + match_len + 300);
            pat.is_match(&text[index..end])
        }
    }

    fn find_related_control<'a>(ctx: &'a PackContext, artifact_id: Option<&str>, control_types: &[&str]) -> Option<&'a Entity> {
        if let Some(aid) = artifact_id {
            for rel in ctx.relations_to(aid) {
                if rel.kind != "protects" {
                    continue;
                }
                if let Some(control) = ctx.entity_by_id(&rel.from) {
                    if control.kind == "control"
                        && control.attr_str("controlType").is_some_and(|t| control_types.contains(&t))
                    {
                        return Some(control);
                    }
                }
            }
        }
        ctx.entities().iter().find(|e| {
            e.kind == "control" && e.attr_str("controlType").is_some_and(|t| control_types.contains(&t))
        })
    }

    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "output.html.body-unescaped",
                output_context: "html-body",
                sink_kind_default: Some("html-body-sink"),
                severity_hint: "high",
                claim: "Untrusted content may reach an HTML interpretation sink without visible sanitization.",
                risky_pattern: || Regex::new(r"(?i)(?:innerHTML|dangerouslySetInnerHTML|document\.write|v-html)\s*[=:(][^\n]*(?:input|request|body|content|output|response)").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)DOMPurify\.sanitize|sanitize-html|escapeHtml|he\.encode|striptags").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["html-sanitization", "output-encoding"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "code-execution", effect_action: "render", effect_scope: "dom",
                chain_roles: &["starter", "impact"],
                sink_engine: |text| {
                    if text.contains("dangerouslySetInnerHTML") { "react-dangerously-set-inner-html" }
                    else if text.contains("document.write") { "document.write" }
                    else if text.contains("v-html") { "vue-v-html" }
                    else { "innerHTML" }
                },
                uncertainty: &["An unescaped HTML sink is not automatically XSS; whether the content is attacker-controlled and unsanitized elsewhere must be adjudicated."],
            },
            Rule {
                id: "output.html.attribute-unescaped",
                output_context: "html-attribute",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Untrusted content may reach an HTML attribute without context-aware encoding.",
                risky_pattern: || Regex::new(r"(?i)\.setAttribute\s*\(\s*['\x22][^'\x22]+['\x22]\s*,\s*[^)]*(?:request|input|user|query|params|body)").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)encodeURIComponent|escapeAttribute|sanitizeAttr").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["attribute-encoding"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "code-execution", effect_action: "render", effect_scope: "dom",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "setAttribute",
                uncertainty: &["An unencoded attribute sink is not automatically XSS; the attribute name (e.g. event-handler vs. plain) must be adjudicated."],
            },
            Rule {
                id: "output.js.inline-script-unescaped",
                output_context: "js",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Untrusted content is inlined into a <script> block without JSON-safe serialization.",
                risky_pattern: || Regex::new(r"(?is)<script[^>]*>[\s\S]{0,200}?\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[\s\S]{0,200}?</script>").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)JSON\.stringify").unwrap()),
                suppress_match_scope: true,
                downgrade: None,
                effect_kind: "code-execution", effect_action: "execute", effect_scope: "browser-js",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "inline-script-interpolation",
                uncertainty: &["Inline-script interpolation is not automatically injection; whether the value is JSON-safe elsewhere must be adjudicated."],
            },
            Rule {
                id: "output.url.open-redirect",
                output_context: "url",
                sink_kind_default: None,
                severity_hint: "medium",
                claim: "Request-controlled data may reach a redirect target without an allowlist check.",
                risky_pattern: || Regex::new(r"(?i)(?:redirect|location\.href)\s*\(?[^\n]*(?:request|query|params|next)").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)allowedHosts\.includes|isSafeRedirect|new URL\([^)]*\)\.origin\s*===").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["redirect-allowlist"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "control-bypass", effect_action: "bypass", effect_scope: "redirect",
                chain_roles: &["starter", "control-bypass"],
                sink_engine: |_| "redirect",
                uncertainty: &["A request-controlled redirect target is not automatically an open redirect; whether the value is validated elsewhere must be adjudicated."],
            },
            Rule {
                id: "output.css.style-unescaped",
                output_context: "css",
                sink_kind_default: None,
                severity_hint: "medium",
                claim: "Untrusted content may reach a CSS/style sink without sanitization.",
                risky_pattern: || Regex::new(r#"(?i)(?:\.style\.cssText\s*=|style\s*=\s*[`"'][^`"']*\$\{)[^\n]*(?:request|input|user|body|params)"#).unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)sanitizeCss|cssesc|CSS\.escape").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["css-sanitization"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "code-execution", effect_action: "render", effect_scope: "dom",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "style-interpolation",
                uncertainty: &["A style sink is not automatically CSS injection; the reachable property set must be adjudicated."],
            },
            Rule {
                id: "output.shell.command-template",
                output_context: "shell",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Rendered output is interpolated into a shell command template without argument escaping.",
                risky_pattern: || Regex::new(r"(?i)\bexec\s*\(\s*`[^`\n]*\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[^`\n]*`").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)shellEscape|shell-quote|execFile\(").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["shell-argument-escaping"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "code-execution", effect_action: "execute", effect_scope: "sink-process",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "shell-template",
                uncertainty: &["A shell command template is not automatically command injection; argument escaping elsewhere must be adjudicated."],
            },
            Rule {
                id: "output.sql.stored-content-interpolation",
                output_context: "sql",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Previously stored content is interpolated into a query string without parameter binding.",
                risky_pattern: || Regex::new(r"(?i)\b(?:query|execute)\s*\(\s*`[^`\n]*\$\{[^}]*(?:record|row|stored|savedTemplate)[^}]*\}[^`\n]*`").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)\breplacements\s*:|\bbind\s*:|\?\s*,\s*\[").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["sql-parameterization"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "data-access", effect_action: "query", effect_scope: "sql-sink",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "stored-content-query",
                uncertainty: &["Stored content reaching a query string is not automatically injection; whether parameter binding is used must be adjudicated."],
            },
            Rule {
                id: "output.log.newline-injection",
                output_context: "log",
                sink_kind_default: None,
                severity_hint: "medium",
                claim: "Request-derived data reaches a log sink without newline stripping, enabling log forging.",
                risky_pattern: || Regex::new(r"(?i)\b(?:logger|console)\.(?:info|warn|error|log|debug)\s*\([^)]*(?:request\.|input\b|user\.|body\.|params\.)").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)replace\(\s*/\[\\r\\n\]").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["log-sanitization"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "integrity-impact", effect_action: "forge-log-entry", effect_scope: "log-sink",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "log-write",
                uncertainty: &["A raw log write is not automatically log forging; whether the sink treats newlines as record separators must be adjudicated."],
            },
            Rule {
                id: "output.stored.unescaped-render",
                output_context: "html-body",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Previously stored content is rendered through an explicitly unescaped template tag.",
                risky_pattern: || Regex::new(r"<%-\s*[^%]+%>|\{\{\{[^}]+\}\}\}").unwrap(),
                suppress_pattern: None,
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["html-sanitization"],
                    severity_hint: "low",
                    lexical_pattern: Some(|| Regex::new(r"(?i)safe|sanitized|trusted").unwrap()),
                    lexical_match_scope: true,
                    lexical_note: Some("The rendered variable name suggests it was already sanitized upstream; downgraded pending adjudication."),
                }),
                effect_kind: "code-execution", effect_action: "render", effect_scope: "dom",
                chain_roles: &["starter", "impact"],
                sink_engine: |text| if text.contains("{{{") { "handlebars-triple-stache" } else { "ejs-unescaped-output" },
                uncertainty: &["An unescaped template tag is not automatically stored XSS; whether the rendered value is attacker-controlled must be adjudicated."],
            },
            Rule {
                id: "output.email.header-injection",
                output_context: "email-header",
                sink_kind_default: None,
                severity_hint: "medium",
                claim: "Request-derived data reaches an email header without CRLF stripping, enabling header injection.",
                risky_pattern: || Regex::new(r#"(?i)(?:setHeader\s*\(\s*['"](?:Cc|Bcc|Subject|To)['"]|mail(?:Options)?\.(?:subject|to|cc|bcc))\s*[,:=][^\n]*(?:request|input|user|body|params)"#).unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)replace\(\s*/\[\\r\\n\]|validator\.isEmail|encodeHeader").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["header-sanitization"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "integrity-impact", effect_action: "forge-header", effect_scope: "email-sink",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "email-header",
                uncertainty: &["A raw email header write is not automatically header injection; whether the mail library rejects embedded newlines must be adjudicated."],
            },
            Rule {
                id: "output.model.unsanitized-render",
                output_context: "html-body",
                sink_kind_default: None,
                severity_hint: "high",
                claim: "Model-generated output is rendered into HTML without visible sanitization.",
                risky_pattern: || Regex::new(r"(?i)(?:dangerouslySetInnerHTML|innerHTML)\s*[=:][^\n]*(?:completion|modelOutput|llmResponse|aiResponse|generatedText)").unwrap(),
                suppress_pattern: Some(|| Regex::new(r"(?i)DOMPurify\.sanitize|sanitize-html|escapeHtml").unwrap()),
                suppress_match_scope: false,
                downgrade: Some(Downgrade {
                    control_types: &["html-sanitization"],
                    severity_hint: "low",
                    lexical_pattern: None,
                    lexical_match_scope: false,
                    lexical_note: None,
                }),
                effect_kind: "code-execution", effect_action: "render", effect_scope: "dom",
                chain_roles: &["starter", "impact"],
                sink_engine: |_| "model-output-render",
                uncertainty: &["Model output reaching an HTML sink is not automatically XSS; the model's own output-handling controls must be adjudicated."],
            },
        ]
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        let rules = rules();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = ctx.artifact_for(file);
            for rule in &rules {
                let risky = (rule.risky_pattern)();
                let suppress = rule.suppress_pattern.map(|f| f());
                for m in risky.find_iter(text) {
                    if m.as_str().is_empty() {
                        continue;
                    }
                    if test_around(suppress.as_ref(), text, m.start(), m.as_str().len(), rule.suppress_match_scope) {
                        continue;
                    }

                    let mut severity_hint = rule.severity_hint;
                    let mut observed_controls: Vec<String> = Vec::new();
                    let mut uncertainty: Vec<String> = rule.uncertainty.iter().map(|s| s.to_string()).collect();

                    if let Some(dg) = &rule.downgrade {
                        if let Some(control) = find_related_control(ctx, artifact.map(|e| e.id.as_str()), dg.control_types) {
                            severity_hint = dg.severity_hint;
                            observed_controls = vec![control.id.clone()];
                            let ct = control.attr_str("controlType").unwrap_or("mitigating");
                            uncertainty.push(format!(
                                "Observed {} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                                ct, control.name
                            ));
                        } else if let Some(lp) = dg.lexical_pattern {
                            let lex = lp();
                            let scope = if dg.lexical_match_scope { true } else { rule.suppress_match_scope };
                            if test_around(Some(&lex), text, m.start(), m.as_str().len(), scope) {
                                severity_hint = dg.severity_hint;
                                uncertainty.push(
                                    dg.lexical_note
                                        .unwrap_or("A mitigating pattern is present near the sink; downgraded pending adjudication.")
                                        .to_string(),
                                );
                            }
                        }
                    }

                    let trace = ctx.output_handling_trace(file, rule.output_context);
                    let detection_method = if trace { "sast-trace" } else { "lexical-pattern" };
                    uncertainty.push(if trace {
                        "Confirmed by a recorded taint trace; reachability is still subject to adjudication.".to_string()
                    } else {
                        "Lexical pattern match; not confirmed by a recorded taint trace.".to_string()
                    });

                    let sources: Vec<String> = if let Some(a) = artifact {
                        let mut reaches: Vec<String> = ctx
                            .relations_to(&a.id)
                            .filter(|r| r.kind == "reaches" || r.kind == "flows-to")
                            .map(|r| r.from.clone())
                            .collect();
                        if reaches.is_empty() {
                            vec![a.id.clone()]
                        } else {
                            reaches.sort();
                            reaches.dedup();
                            reaches
                        }
                    } else {
                        Vec::new()
                    };

                    observations.push(Observation {
                        rule_id: rule.id.to_string(),
                        candidate_class: CANDIDATE_CLASS.to_string(),
                        claim: rule.claim.to_string(),
                        severity_hint: severity_hint.to_string(),
                        sources,
                        sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                        attacker_capabilities: vec!["control-request-input".to_string()],
                        effect_kind: rule.effect_kind.to_string(),
                        effect_action: rule.effect_action.to_string(),
                        effect_object: artifact.map(|a| a.id.clone()),
                        effect_scope: Some(rule.effect_scope.to_string()),
                        effect_environment: "application".to_string(),
                        chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                        evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                        observed_controls,
                        detector_metadata: json!({
                            "file": file,
                            "line": line_of(text, m.start()),
                            "outputContext": rule.output_context,
                            "sinkKind": rule.sink_kind_default.unwrap_or(rule.output_context),
                            "sinkEngine": (rule.sink_engine)(text),
                            "detectionMethod": detection_method,
                            "matchDigest": digest_str(m.as_str()),
                        }),
                        uncertainty,
                    });
                }
            }
        }
        observations
    }
}

// =================================================================================================
// parser-serialization.mjs
// =================================================================================================

pub mod parser_serialization {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "parser-serialization";

    fn xml_parser_file_guard() -> Regex {
        Regex::new(r"(?i)libxmljs|lxml|DocumentBuilderFactory|expat|xml2js|xmldom|sax\b").unwrap()
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = ctx.artifact_for(file);

            unsafe_deserialization(ctx, file, text, artifact, &mut observations);
            xml_billion_laughs(ctx, file, text, artifact, &mut observations);
            decompression_bomb(ctx, file, text, artifact, &mut observations);
            unbounded_recursion(ctx, file, text, artifact, &mut observations);
        }
        observations
    }

    fn find_related_control<'a>(ctx: &'a PackContext, artifact_id: Option<&str>, control_types: &[&str]) -> Option<&'a Entity> {
        if let Some(aid) = artifact_id {
            for rel in ctx.relations_to(aid) {
                if rel.kind != "protects" {
                    continue;
                }
                if let Some(control) = ctx.entity_by_id(&rel.from) {
                    if control.kind == "control"
                        && control.attr_str("controlType").is_some_and(|t| control_types.contains(&t))
                    {
                        return Some(control);
                    }
                }
            }
        }
        ctx.entities().iter().find(|e| {
            e.kind == "control" && e.attr_str("controlType").is_some_and(|t| control_types.contains(&t))
        })
    }

    fn window_around(text: &str, index: usize, match_len: usize, radius: usize) -> (usize, usize) {
        let start = floor_char_boundary(text, index.saturating_sub(radius));
        let end = ceil_char_boundary(text, index + match_len + radius);
        (start, end)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_observation<'a>(
        observations: &mut Vec<Observation>,
        rule_id: &str,
        claim: &str,
        mut severity_hint: &'a str,
        mut uncertainty: Vec<String>,
        attacker_capabilities: &[&str],
        precondition_action: &str,
        environment: &str,
        effect_kind: &str,
        effect_action: &str,
        effect_scope: &str,
        chain_roles: &[&str],
        artifact: Option<&Entity>,
        ctx: &PackContext,
        control_types: &[&str],
        downgrade_severity: &'a str,
        mitigated_lexically: bool,
        downgrade_note: &str,
        file: &str,
        line: usize,
        source_expr: &str,
        sink_api: &str,
        match_text: &str,
    ) {
        let mut observed_controls = Vec::new();
        let mut control_observed: Option<String> = None;

        let control = find_related_control(ctx, artifact.map(|a| a.id.as_str()), control_types);
        if let Some(control) = control {
            severity_hint = downgrade_severity;
            observed_controls = vec![control.id.clone()];
            control_observed = Some(control.name.clone());
            let ct = control.attr_str("controlType").unwrap_or("mitigating");
            uncertainty.push(format!(
                "Observed {} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                ct, control.name
            ));
        } else if mitigated_lexically {
            severity_hint = downgrade_severity;
            control_observed = Some("lexical-signal".to_string());
            uncertainty.push(downgrade_note.to_string());
        }

        let precondition_scope: Option<String> = None;
        let _ = precondition_scope; // JS preconditions.scope is always null here.

        observations.push(Observation {
            rule_id: rule_id.to_string(),
            candidate_class: CANDIDATE_CLASS.to_string(),
            claim: claim.to_string(),
            severity_hint: severity_hint.to_string(),
            sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
            sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
            attacker_capabilities: attacker_capabilities.iter().map(|s| s.to_string()).collect(),
            effect_kind: effect_kind.to_string(),
            effect_action: effect_action.to_string(),
            effect_object: artifact.map(|a| a.id.clone()),
            effect_scope: Some(effect_scope.to_string()),
            effect_environment: environment.to_string(),
            chain_roles: chain_roles.iter().map(|s| s.to_string()).collect(),
            evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
            observed_controls,
            detector_metadata: json!({
                "file": file,
                "line": line,
                "sourceExpr": source_expr,
                "sinkApi": sink_api,
                "controlObserved": control_observed,
                "matchDigest": digest_str(match_text),
                "preconditionAction": precondition_action,
            }),
            uncertainty,
        });
    }

    fn unsafe_deserialization(ctx: &PackContext, file: &str, text: &str, artifact: Option<&Entity>, out: &mut Vec<Observation>) {
        let re = Regex::new(r"\b(pickle\.loads|yaml\.load|ObjectInputStream|BinaryFormatter\.Deserialize|unserialize|Marshal\.load)\s*\(\s*([^()\n]*)\)").unwrap();
        let safe_loader = Regex::new(r"(?i)SafeLoader|safe_load|CSafeLoader").unwrap();
        for caps in re.captures_iter(text) {
            let m = caps.get(0).unwrap();
            if m.as_str().is_empty() {
                continue;
            }
            let sink_api = caps.get(1).map(|c| c.as_str()).unwrap_or_default();
            let source_arg = caps.get(2).map(|c| c.as_str().trim()).unwrap_or_default();
            let source_expr = if source_arg.is_empty() { "input-stream" } else { source_arg };
            let (ws, we) = window_around(text, m.start(), m.as_str().len(), 150);
            let mitigated = safe_loader.is_match(&text[ws..we]);
            push_observation(
                out,
                "parser.unsafe-deserialization",
                "An unsafe deserialization primitive is used, which can execute arbitrary code if the serialized input is attacker-controlled.",
                "high",
                vec!["Whether the deserialized bytes originate from an untrusted/attacker-reachable source must be adjudicated.".to_string()],
                &["supply-serialized-input"],
                "supply-serialized-payload",
                "application",
                "code-execution", "execute", "deserialization-sink",
                &["starter", "impact"],
                artifact, ctx,
                &["safe-deserialization"], "low", mitigated,
                "A safe-loader marker is present near the call; treated as a mitigating signal pending adjudication.",
                file, line_of(text, m.start()), source_expr, sink_api, m.as_str(),
            );
        }
    }

    fn xml_billion_laughs(ctx: &PackContext, file: &str, text: &str, artifact: Option<&Entity>, out: &mut Vec<Observation>) {
        if !xml_parser_file_guard().is_match(text) {
            return;
        }
        let re = Regex::new(r#"(?i)\b(expand_entities\s*=\s*True|resolve_entities\s*=\s*True|noent\s*:\s*true|DTDLOAD\s*:\s*true|FEATURE_SECURE_PROCESSING['"]?\s*,\s*false)\b"#).unwrap();
        let limit_guard = Regex::new(r"(?i)defusedxml|entity_expansion_limit|MAX_ENTITY|billionLaughsProtection|entityExpansionLimit").unwrap();
        for caps in re.captures_iter(text) {
            let m = caps.get(0).unwrap();
            if m.as_str().is_empty() {
                continue;
            }
            let source_expr = caps.get(1).map(|c| c.as_str()).unwrap_or_default();
            let (ws, we) = window_around(text, m.start(), m.as_str().len(), 250);
            let mitigated = limit_guard.is_match(&text[ws..we]);
            push_observation(
                out,
                "parser.xml-billion-laughs",
                "An XML parser enables DTD/entity expansion without secure-processing limits, allowing a small malicious document to expand exponentially (\"billion laughs\") and exhaust memory/CPU.",
                "medium",
                vec!["Whether attacker-controlled XML reaches this parser, and whether an upstream size/depth guard exists elsewhere in the pipeline, must be adjudicated.".to_string()],
                &["supply-xml-document"],
                "supply-xml-entity-payload",
                "application",
                "availability-impact", "exhaust", "xml-entity-expansion",
                &["starter", "impact"],
                artifact, ctx,
                &["xml-entity-expansion-limit"], "low", mitigated,
                "An entity-expansion-limit guard is present near the parser configuration; treated as a mitigating signal pending adjudication.",
                file, line_of(text, m.start()), source_expr, "xml-parser-entity-expansion", m.as_str(),
            );
        }
    }

    fn decompression_bomb(ctx: &PackContext, file: &str, text: &str, artifact: Option<&Entity>, out: &mut Vec<Observation>) {
        let re = Regex::new(r"\b(zlib\.(?:gunzip|inflate|unzip)(?:Sync)?|gzip\.decompress|gzip\.GzipFile|tarfile\.open|tarfile\.extractall|zipfile\.ZipFile)\s*\(").unwrap();
        let limit_guard = Regex::new(r"(?i)maxSize|maxOutputSize|decompressionBomb|ZipBombProtection|limit\s*:\s*\d+").unwrap();
        for caps in re.captures_iter(text) {
            let m = caps.get(0).unwrap();
            if m.as_str().is_empty() {
                continue;
            }
            let sink_api = caps.get(1).map(|c| c.as_str()).unwrap_or_default();
            let (ws, we) = window_around(text, m.start(), m.as_str().len(), 200);
            let mitigated = limit_guard.is_match(&text[ws..we]);
            push_observation(
                out,
                "parser.decompression-bomb",
                "A decompression call has no visible output-size limit, allowing a small compressed payload to expand into an unbounded amount of memory/disk (a decompression/zip bomb).",
                "medium",
                vec!["Whether the compressed input is attacker-controlled, and whether an upstream limit exists elsewhere in the pipeline, must be adjudicated.".to_string()],
                &["supply-compressed-input"],
                "supply-compressed-payload",
                "application",
                "availability-impact", "exhaust", "decompression-output",
                &["starter", "impact"],
                artifact, ctx,
                &["decompression-size-limit"], "low", mitigated,
                "An output-size-limit guard is present near the decompression call; treated as a mitigating signal pending adjudication.",
                file, line_of(text, m.start()), "compressed-input-stream", sink_api, m.as_str(),
            );
        }
    }

    /// JS: `/function\s+(\w*[Pp]arse\w*)\s*\(([^)]*)\)\s*\{[\s\S]{0,400}?\b\1\s*\(/g`
    /// — the trailing `\1` is a backreference to the captured function name, which the
    /// `regex` crate cannot express directly. This is reproduced as a two-phase match:
    /// find every `function <name>(...) {` header where `<name>` contains `parse`
    /// (case-insensitively, matching `\w*[Pp]arse\w*`), then search the following
    /// (up to 400-char) body window for the *earliest* literal, word-boundaried call
    /// to that same name — mirroring the JS engine's lazy `{0,400}?` quantifier, which
    /// backtracks to the first position where `\b\1\s*\(` succeeds.
    fn unbounded_recursion(ctx: &PackContext, file: &str, text: &str, artifact: Option<&Entity>, out: &mut Vec<Observation>) {
        let header = Regex::new(r"function\s+(\w*[Pp]arse\w*)\s*\(([^)]*)\)\s*\{").unwrap();
        let depth_guard = Regex::new(r"(?i)maxDepth|depthLimit|MAX_DEPTH|depth\s*[<>]=?").unwrap();
        for caps in header.captures_iter(text) {
            let m = caps.get(0).unwrap();
            let name = caps.get(1).unwrap().as_str();
            let body_start = m.end();
            let window_end = ceil_char_boundary(text, body_start + 400);
            let window = &text[body_start..window_end];
            let call_re = Regex::new(&format!(r"\b{}\s*\(", regex::escape(name))).unwrap();
            let Some(call_m) = call_re.find(window) else { continue };
            let full_match_end = body_start + call_m.end();
            let full_match = &text[m.start()..full_match_end];

            let mitigated = depth_guard.is_match(full_match);
            push_observation(
                out,
                "parser.unbounded-recursion",
                "A recursive parsing function calls itself with no visible depth limit, allowing deeply nested attacker-controlled input to exhaust the call stack (unbounded recursion / stack-overflow DoS).",
                "medium",
                vec!["Whether the parsed structure's nesting depth is attacker-controlled and unbounded upstream must be adjudicated.".to_string()],
                &["supply-nested-input"],
                "supply-deeply-nested-payload",
                "application",
                "availability-impact", "exhaust", "call-stack",
                &["starter", "impact"],
                artifact, ctx,
                &["recursion-depth-limit"], "low", mitigated,
                "A depth-limit guard is present within the recursive function; treated as a mitigating signal pending adjudication.",
                file, line_of(text, m.start()), "nested-input-structure", name, full_match,
            );
        }
    }
}

// =================================================================================================
// observability-forensics.mjs
// =================================================================================================

pub mod observability_forensics {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "observability-forensics";

    const NON_SENSITIVE_EVENT_DISCLAIMER: &str = "The required control is a structured security-event record containing only non-sensitive identifiers (actor id, action, timestamp, resource id, outcome); this claim never requires logging credentials, tokens, PII, or a full request body.";

    fn error_leak_re() -> Regex {
        Regex::new(r#"(?i)res\.(?:json|send)\(\s*\{[^}]*(?:stack\s*:\s*err(?:or)?\.stack|error\s*:\s*err(?:or)?\.stack)[^}]*\}\s*\)|res\.(?:json|send)\(\s*err(?:or)?\.stack\s*\)|res\.(?:json|send)\(\s*\{[^}]*(?:password|token|apiKey|secret|connectionString)[^}]*\}\s*\)"#).unwrap()
    }
    fn error_leak_guard_re() -> Regex {
        Regex::new(r#"(?i)NODE_ENV\s*!==?\s*['"]production['"]|isDev\b|isDevelopment\b|redactError\(|sanitizeError\("#).unwrap()
    }
    fn auth_success_marker_re() -> Regex {
        Regex::new(r#"(?i)req\.session\.user\s*=|res\.cookie\(\s*['"](?:session|token|jwt)['"]|generateToken\(|issueToken\(|signJwt\("#).unwrap()
    }
    fn auth_failure_marker_re() -> Regex {
        Regex::new(r"res\.status\(401\)\.(?:json|send)\(").unwrap()
    }
    fn privilege_change_marker_re() -> Regex {
        Regex::new(r#"(?i)\.role\s*=\s*['"]\w+['"]|grantRole\(|setPermissions\(|updateRole\("#).unwrap()
    }
    fn data_export_marker_re() -> Regex {
        Regex::new(r"(?i)res\.download\(|res\.attachment\(|exportToCsv\(|exportData\(|streamExport\(").unwrap()
    }
    fn security_event_log_marker_re() -> Regex {
        Regex::new(r#"(?i)auditLog\(|securityEvent\(|logger\.(?:info|warn)\(\s*['"](?:auth|privilege|data)\."#).unwrap()
    }
    fn log_injection_re() -> Regex {
        Regex::new(r#"(?i)(?:logger|console)\.(?:info|warn|error|log)\(\s*(?:`[^`\n]*\$\{[^}]*(?:req|request)\.(?:body|query|params)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:req|request)\.(?:body|query|params)|'[^'\n]*'\s*\+\s*(?:req|request)\.(?:body|query|params))"#).unwrap()
    }
    fn log_injection_suppress_re() -> Regex {
        Regex::new(r"(?i)sanitizeLog\(|stripControlChars\(|encodeURIComponent\(").unwrap()
    }

    fn test_around(pat: &Regex, text: &str, index: usize, match_len: usize, before: usize, after: usize) -> bool {
        let start = floor_char_boundary(text, index.saturating_sub(before));
        let end = ceil_char_boundary(text, index + match_len + after);
        pat.is_match(&text[start..end])
    }

    #[allow(clippy::too_many_arguments)]
    fn base_observation(
        rule_id: &str,
        claim: &str,
        severity_hint: &str,
        expected_event: Option<&str>,
        artifact: &Entity,
        attacker_capabilities: &[&str],
        effect_kind: &str,
        effect_action: &str,
        effect_scope: &str,
        chain_roles: &[&str],
        file: &str,
        line: usize,
        extra_metadata: Value,
        mut uncertainty: Vec<String>,
    ) -> Observation {
        let mut metadata = extra_metadata;
        if let (Some(obj), Some(ev)) = (metadata.as_object_mut(), expected_event) {
            obj.insert("expectedEvent".to_string(), json!(ev));
        }
        if expected_event.is_some() {
            uncertainty.push(NON_SENSITIVE_EVENT_DISCLAIMER.to_string());
        }
        let _ = (file, line);
        Observation {
            rule_id: rule_id.to_string(),
            candidate_class: CANDIDATE_CLASS.to_string(),
            claim: claim.to_string(),
            severity_hint: severity_hint.to_string(),
            sources: vec![artifact.id.clone()],
            sinks: vec![artifact.id.clone()],
            attacker_capabilities: attacker_capabilities.iter().map(|s| s.to_string()).collect(),
            effect_kind: effect_kind.to_string(),
            effect_action: effect_action.to_string(),
            effect_object: Some(artifact.id.clone()),
            effect_scope: Some(effect_scope.to_string()),
            effect_environment: "application".to_string(),
            chain_roles: chain_roles.iter().map(|s| s.to_string()).collect(),
            evidence_refs: artifact.evidence_refs.clone(),
            observed_controls: Vec::new(),
            detector_metadata: metadata,
            uncertainty,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn missing_event_rule(
        ctx: &PackContext,
        rule_id: &str,
        marker: &Regex,
        event_type: &str,
        claim: &str,
        severity_hint: &str,
        effect_scope: &str,
        out: &mut Vec<Observation>,
    ) {
        let event_marker = security_event_log_marker_re();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let Some(artifact) = ctx.artifact_for(file) else { continue };
            if artifact.evidence_refs.is_empty() {
                continue;
            }
            for m in marker.find_iter(text) {
                if ctx.logging_trace(file, event_type) {
                    continue;
                }
                if test_around(&event_marker, text, m.start(), m.as_str().len(), 200, 300) {
                    continue;
                }
                out.push(base_observation(
                    rule_id,
                    claim,
                    severity_hint,
                    Some(event_type),
                    artifact,
                    &["perform-observed-action-without-detection"],
                    "control-bypass", "evade-detection", effect_scope,
                    &["enabler"],
                    file, line_of(text, m.start()),
                    json!({
                        "file": file,
                        "line": line_of(text, m.start()),
                        "observedCodePath": &m.as_str()[..ceil_char_boundary(m.as_str(), m.as_str().len().min(80))],
                    }),
                    vec!["A security-event logger registered globally or in a shared middleware not visible in this file cannot be ruled out.".to_string()],
                ));
            }
        }
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();

        let error_leak = error_leak_re();
        let error_leak_guard = error_leak_guard_re();
        let log_injection = log_injection_re();
        let log_injection_suppress = log_injection_suppress_re();

        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let Some(artifact) = ctx.artifact_for(file) else { continue };
            if artifact.evidence_refs.is_empty() {
                continue;
            }

            for m in error_leak.find_iter(text) {
                if test_around(&error_leak_guard, text, m.start(), m.as_str().len(), 150, 50) {
                    continue;
                }
                observations.push(base_observation(
                    "observability.error.sensitive-data-in-output",
                    "An error/exception response includes a raw stack trace or a sensitive-looking field with no visible redaction guard.",
                    "medium",
                    None,
                    artifact,
                    &["trigger-error-condition"],
                    "confidentiality-impact", "read", "error-response-body",
                    &["starter", "impact"],
                    file, line_of(text, m.start()),
                    json!({ "file": file, "line": line_of(text, m.start()), "matchDigest": digest_str(m.as_str()) }),
                    vec!["Whether the leaked detail actually contains exploitable internals (paths, connection strings, credentials) versus a benign message requires adjudication of the error content.".to_string()],
                ));
            }

            for m in log_injection.find_iter(text) {
                if test_around(&log_injection_suppress, text, m.start(), m.as_str().len(), 0, 200) {
                    continue;
                }
                observations.push(base_observation(
                    "observability.log.injection",
                    "Request-derived data is concatenated directly into a log statement with no visible sanitization, allowing forged log entries (log injection / log forging).",
                    "medium",
                    None,
                    artifact,
                    &["control-request-input"],
                    "integrity-impact", "inject", "log-stream",
                    &["starter", "impact"],
                    file, line_of(text, m.start()),
                    json!({ "file": file, "line": line_of(text, m.start()), "matchDigest": digest_str(m.as_str()) }),
                    vec!["Impact depends on how the log stream is consumed downstream (raw terminal, log-injection-vulnerable dashboard, or a structured/escaped sink).".to_string()],
                ));
            }
        }

        missing_event_rule(ctx, "observability.events.missing-auth-success", &auth_success_marker_re(), "auth.success",
            "A successful authentication path (session/token issuance) has no visible security-event record.", "low", "auth-success-event", &mut observations);
        missing_event_rule(ctx, "observability.events.missing-auth-failure", &auth_failure_marker_re(), "auth.failure",
            "A failed authentication branch (401 response) has no visible security-event record.", "low", "auth-failure-event", &mut observations);
        missing_event_rule(ctx, "observability.events.missing-privilege-change", &privilege_change_marker_re(), "privilege.change",
            "A role/permission mutation has no visible security-event record.", "medium", "privilege-change-event", &mut observations);
        missing_event_rule(ctx, "observability.events.missing-data-export", &data_export_marker_re(), "data.export",
            "A bulk data export/download path has no visible security-event record.", "medium", "data-export-event", &mut observations);

        observations
    }
}

// =================================================================================================
// mobile.mjs
// =================================================================================================

pub mod mobile {
    use super::*;

    pub const SUPPORT_TIER: &str = "measured";

    const DANGEROUS_ANDROID_PERMISSIONS: &[&str] = &[
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.BODY_SENSORS",
        "android.permission.READ_PHONE_STATE",
    ];

    fn stripped_permission_re() -> Regex {
        Regex::new(r#"(?i)tools:node\s*=\s*"remove""#).unwrap()
    }
    fn auto_verify_re() -> Regex {
        Regex::new(r#"(?i)android:autoVerify\s*=\s*"true"|applinks:"#).unwrap()
    }
    fn permission_gate_re() -> Regex {
        Regex::new(r"(?i)android:permission\s*=").unwrap()
    }
    fn bridge_origin_allowlist_re() -> Regex {
        Regex::new(r"(?i)shouldOverrideUrlLoading|originWhitelist|allowlist|allowedOrigins").unwrap()
    }
    fn sensitive_storage_sink_re() -> Regex {
        Regex::new(r"\b(?:SharedPreferences|getSharedPreferences|NSUserDefaults|UserDefaults\.standard|localStorage\.setItem|AsyncStorage\.setItem)\b").unwrap()
    }
    fn sensitive_value_keyword_re() -> Regex {
        Regex::new(r"(?i)password|passwd|secret|token|apikey|api_key|ssn|creditcard|credit_card|auth[_-]?key").unwrap()
    }
    fn secure_storage_mitigation_re() -> Regex {
        Regex::new(r"(?i)EncryptedSharedPreferences|Keychain|SecureStore|expo-secure-store|react-native-keychain|CryptoKit").unwrap()
    }
    fn gradle_file_re() -> Regex {
        Regex::new(r"(?i)\.gradle(\.kts)?$").unwrap()
    }
    fn release_block_re() -> Regex {
        Regex::new(r"(?is)release\s*\{[^}]*\}").unwrap()
    }
    fn debug_signing_in_release_re() -> Regex {
        Regex::new(r"(?i)signingConfig\s+signingConfigs\.debug").unwrap()
    }

    fn safe_read_file<'a>(ctx: &'a PackContext, file: Option<&str>) -> Option<&'a str> {
        let file = file?;
        if !ctx.files.iter().any(|f| f == file) {
            return None;
        }
        ctx.read_file(file)
    }

    fn scan_window(pattern: &Regex, text: &str, index: usize, length: usize, radius: usize) -> bool {
        let start = floor_char_boundary(text, index.saturating_sub(radius));
        let end = ceil_char_boundary(text, index + length + radius);
        pattern.is_match(&text[start..end])
    }

    const STANDARD_SCOPE_DESCRIPTION: &str = "Repository manifest/config/source text only; no device, emulator, simulator, or app-store connection was made.";
    const STANDARD_AUTHORITY_LIMITS: &[&str] = &[
        "This lens does not establish app-store review outcomes, platform security posture, or regulatory adequacy for any standard.",
        "A finding here is an allegation requiring independent adjudication; it is never a substitute for a qualified mobile security reviewer decision.",
    ];

    fn with_metadata(mut base: Value, hazards: &[&str], assumptions: &[&str]) -> Value {
        let obj = base.as_object_mut().expect("base metadata must be an object");
        obj.insert(
            "scope".to_string(),
            json!({ "static": true, "runtime": false, "description": STANDARD_SCOPE_DESCRIPTION }),
        );
        obj.insert("hazards".to_string(), json!(hazards));
        obj.insert("assumptions".to_string(), json!(assumptions));
        obj.insert("authorityLimits".to_string(), json!(STANDARD_AUTHORITY_LIMITS));
        base
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        out: &mut Vec<Observation>,
        rule_id: &str,
        claim: &str,
        severity_hint: &str,
        sources: Vec<String>,
        sinks: Vec<String>,
        attacker_capabilities: &[&str],
        effect_kind: &str,
        effect_action: &str,
        effect_object: Option<String>,
        effect_scope: &str,
        chain_roles: &[&str],
        evidence_refs: Vec<String>,
        detector_metadata: Value,
        uncertainty: Vec<String>,
    ) {
        out.push(Observation {
            rule_id: rule_id.to_string(),
            candidate_class: "mobile".to_string(),
            claim: claim.to_string(),
            severity_hint: severity_hint.to_string(),
            sources,
            sinks,
            attacker_capabilities: attacker_capabilities.iter().map(|s| s.to_string()).collect(),
            effect_kind: effect_kind.to_string(),
            effect_action: effect_action.to_string(),
            effect_object,
            effect_scope: Some(effect_scope.to_string()),
            effect_environment: "mobile".to_string(),
            chain_roles: chain_roles.iter().map(|s| s.to_string()).collect(),
            evidence_refs,
            observed_controls: Vec::new(),
            detector_metadata,
            uncertainty,
        });
    }

    fn analyze_permissions(ctx: &PackContext, out: &mut Vec<Observation>) {
        let stripped = stripped_permission_re();
        for entity in ctx.entities() {
            if entity.kind != "permission-scope" {
                continue;
            }
            let Some(permission) = entity.attr_str("permission") else { continue };
            if !DANGEROUS_ANDROID_PERMISSIONS.contains(&permission) {
                continue;
            }
            let file = entity.attr_str("file");
            let text = safe_read_file(ctx, file);
            let mut uncertainty = vec!["Manifest declaration is not automatically a privacy risk; the runtime rationale/consent flow must be adjudicated.".to_string()];
            if let Some(text) = text {
                if stripped.is_match(text) {
                    uncertainty.push("A manifest-merger `tools:node=\"remove\"` directive is present near this permission; treated as a mitigating signal pending adjudication.".to_string());
                    continue;
                }
            }
            push(
                out,
                "mobile.permission.dangerous-declared",
                &format!("A dangerous Android permission ({permission}) is declared without a visible manifest-level exclusion."),
                "medium",
                vec![], vec![entity.id.clone()],
                &["install-malicious-app", "trick-user-into-granting-permission"],
                "data-access", "access", Some(entity.id.clone()), "device-permission",
                &["enabler"],
                entity.evidence_refs.clone(),
                with_metadata(
                    json!({ "file": file, "permission": permission }),
                    &[format!("Unbounded access to a dangerous device capability ({permission}) if the app is compromised, socially engineered, or over-scoped.").as_str()],
                    &["The manifest declaration reflects the requested scope; whether the app actually uses the capability minimally is not observed here."],
                ),
                uncertainty,
            );
        }
    }

    fn analyze_deep_links(ctx: &PackContext, out: &mut Vec<Observation>) {
        let auto_verify = auto_verify_re();
        for entity in ctx.entities() {
            if entity.kind != "entrypoint" || entity.attr_str("entrypointType") != Some("deep-link") {
                continue;
            }
            let file = entity.attr_str("file");
            let text = safe_read_file(ctx, file);
            let mut severity_hint = "high";
            let mut uncertainty = vec!["A declared deep-link scheme is not automatically exploitable; the handler's parameter validation and origin checks must be adjudicated.".to_string()];
            if let Some(text) = text {
                if auto_verify.is_match(text) {
                    severity_hint = "medium";
                    uncertainty.push("Android App Links `autoVerify`/`applinks:` domain verification is present; downgraded pending adjudication of handler-side validation.".to_string());
                }
            }
            let schemes = entity.attributes.get("schemes").cloned().unwrap_or_else(|| json!([]));
            push(
                out,
                "mobile.deep-link.entrypoint-unvalidated",
                "A deep-link entrypoint is reachable from any installed app or web page without an observed handler-side validation check.",
                severity_hint,
                vec![], vec![entity.id.clone()],
                &["craft-malicious-deep-link"],
                "workflow-state", "invoke", Some(entity.id.clone()), "deep-link-handler",
                &["starter"],
                entity.evidence_refs.clone(),
                with_metadata(
                    json!({ "file": file, "schemes": schemes }),
                    &["A crafted deep link may trigger unintended navigation, parameter injection, or an authenticated action without user intent."],
                    &["App Links domain verification, if present, only proves domain ownership; it does not by itself prove handler-side parameter validation."],
                ),
                uncertainty,
            );
        }
    }

    fn analyze_exported_components(ctx: &PackContext, out: &mut Vec<Observation>) {
        let gate = permission_gate_re();
        for entity in ctx.entities() {
            if entity.kind != "entrypoint" || entity.attr_str("entrypointType") != Some("exported-component") {
                continue;
            }
            let file = entity.attr_str("file");
            let text = safe_read_file(ctx, file);
            if let Some(text) = text {
                if gate.is_match(text) {
                    continue;
                }
            }
            push(
                out,
                "mobile.exported-component.no-permission-gate",
                "An exported Android component has no visible `android:permission` gate in its declaration file.",
                "high",
                vec![], vec![entity.id.clone()],
                &["external-app-launch-component"],
                "object-access", "invoke", Some(entity.id.clone()), "cross-app",
                &["starter"],
                entity.evidence_refs.clone(),
                with_metadata(
                    json!({ "file": file }),
                    &["Any other installed app can launch this component and reach whatever state or data it exposes."],
                    &["A caller check performed in code rather than the manifest is not observed by this lens."],
                ),
                vec!["Caller identity checks implemented in code (rather than the manifest permission attribute) are not visible to this lens.".to_string()],
            );
        }
    }

    fn analyze_webview_bridge(ctx: &PackContext, out: &mut Vec<Observation>) {
        let allowlist = bridge_origin_allowlist_re();
        for relation in &ctx.relations {
            if relation.kind != "calls" {
                continue;
            }
            let Some(source) = ctx.entity_by_id(&relation.from) else { continue };
            let Some(sink) = ctx.entity_by_id(&relation.to) else { continue };
            if source.kind != "source" || source.attr_str("sourceKind") != Some("webview-js") {
                continue;
            }
            if sink.kind != "sink" || sink.attr_str("sinkKind") != Some("native-bridge") {
                continue;
            }
            let file = source.attr_str("file").or_else(|| sink.attr_str("file"));
            let text = safe_read_file(ctx, file);
            let mut severity_hint = "high";
            let mut uncertainty = vec!["A JS-to-native bridge is not automatically exploitable; whether web content is attacker-controllable and which bridge methods are exposed must be adjudicated.".to_string()];
            if let Some(text) = text {
                if allowlist.is_match(text) {
                    severity_hint = "medium";
                    uncertainty.push("An origin/URL allowlist check is present in the same file; downgraded pending adjudication of allowlist completeness.".to_string());
                }
            }
            let mut evidence_refs: Vec<String> = source
                .evidence_refs
                .iter()
                .chain(sink.evidence_refs.iter())
                .cloned()
                .collect();
            evidence_refs.sort();
            evidence_refs.dedup();
            push(
                out,
                "mobile.webview.js-bridge-exposed",
                "A WebView exposes a JavaScript-to-native bridge without an observed origin allowlist in the same file.",
                severity_hint,
                vec![source.id.clone()], vec![sink.id.clone()],
                &["control-webview-content"],
                "code-execution", "invoke", Some(sink.id.clone()), "native-bridge",
                &["enabler", "impact"],
                evidence_refs,
                with_metadata(
                    json!({ "file": file }),
                    &["Malicious or compromised web content loaded in the WebView may invoke native-bridge methods with attacker-chosen arguments."],
                    &["Per-method argument validation inside the bridge handler is not observed by this lens."],
                ),
                uncertainty,
            );
        }
    }

    fn analyze_storage(ctx: &PackContext, out: &mut Vec<Observation>) {
        let sink_pattern = sensitive_storage_sink_re();
        let keyword = sensitive_value_keyword_re();
        let mitigation = secure_storage_mitigation_re();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            for m in sink_pattern.find_iter(text) {
                if m.as_str().is_empty() {
                    continue;
                }
                if !scan_window(&keyword, text, m.start(), m.as_str().len(), 400) {
                    continue;
                }
                if scan_window(&mitigation, text, m.start(), m.as_str().len(), 400) {
                    continue;
                }
                let artifact = ctx.artifact_for(file);
                push(
                    out,
                    "mobile.storage.insecure-sensitive-data",
                    "A sensitive-looking value is written to an unencrypted platform storage API.",
                    "high",
                    artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    &["local-device-access", "backup-extraction"],
                    "confidentiality-impact", "read", artifact.map(|a| a.id.clone()), "unencrypted-local-storage",
                    &["starter", "impact"],
                    artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    with_metadata(
                        json!({ "file": file, "line": line_of(text, m.start()), "storageApi": m.as_str() }),
                        &["A sensitive value stored in cleartext platform storage is recoverable from device backups, rooted/jailbroken access, or another app on older platform versions."],
                        &["Field-level identification of \"sensitive\" is a keyword heuristic; whether the actual value is genuinely sensitive must be adjudicated."],
                    ),
                    vec!["A keyword co-occurrence match is not automatic proof of sensitive-data storage; the actual value and platform-level sandboxing must be adjudicated.".to_string()],
                );
            }
        }
    }

    fn analyze_backup(ctx: &PackContext, out: &mut Vec<Observation>) {
        for entity in ctx.entities() {
            if entity.kind != "control" || entity.attr_str("controlType") != Some("data-backup") {
                continue;
            }
            if entity.attr_str("controlState") != Some("absent") {
                continue;
            }
            push(
                out,
                "mobile.backup.enabled-without-exclusion",
                "Application data backup is enabled with no observed per-file backup exclusion.",
                "medium",
                vec![], vec![entity.id.clone()],
                &["obtain-device-or-cloud-backup-access"],
                "confidentiality-impact", "read", Some(entity.id.clone()), "application-backup",
                &["starter", "impact"],
                entity.evidence_refs.clone(),
                with_metadata(
                    json!({ "file": entity.attr_str("file") }),
                    &["Application data, including any locally cached secrets, may be extracted from an ADB or cloud backup."],
                    &["A backup-rules XML that selectively excludes sensitive files/paths is not observed by this lens."],
                ),
                vec!["A backup-rules exclusion file may exist elsewhere in the denominator; only the top-level allowBackup flag was observed.".to_string()],
            );
        }
    }

    fn analyze_transport(ctx: &PackContext, out: &mut Vec<Observation>) {
        for entity in ctx.entities() {
            if entity.kind != "control" || entity.attr_str("controlType") != Some("transport-security") {
                continue;
            }
            if entity.attr_str("controlState") != Some("absent") {
                continue;
            }
            push(
                out,
                "mobile.transport.cleartext-allowed",
                "The application is explicitly configured to allow cleartext (unencrypted) network traffic.",
                "high",
                vec![], vec![entity.id.clone()],
                &["on-path-network-position"],
                "confidentiality-impact", "intercept", Some(entity.id.clone()), "network-traffic",
                &["starter", "impact"],
                entity.evidence_refs.clone(),
                with_metadata(
                    json!({ "file": entity.attr_str("file") }),
                    &["A network attacker in the same trust domain (public Wi-Fi, compromised router) can read or tamper with any cleartext traffic."],
                    &["A per-domain network-security-config exception may still exist and narrow this to specific hosts; that granularity is not observed here."],
                ),
                vec!["Whether every network call actually traverses TLS regardless of this flag is not confirmed by this lens.".to_string()],
            );
        }
    }

    fn analyze_signing(ctx: &PackContext, out: &mut Vec<Observation>) {
        let gradle_file = gradle_file_re();
        let release_block = release_block_re();
        let debug_signing = debug_signing_in_release_re();
        for file in &ctx.files {
            if !gradle_file.is_match(file) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            for m in release_block.find_iter(text) {
                if m.as_str().is_empty() {
                    continue;
                }
                if !debug_signing.is_match(m.as_str()) {
                    continue;
                }
                let artifact = ctx.artifact_for(file);
                push(
                    out,
                    "mobile.signing.debug-config-in-release",
                    "The release build type is signed with the debug signing config.",
                    "critical",
                    artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    &["forge-app-update", "impersonate-publisher"],
                    "integrity-impact", "forge", artifact.map(|a| a.id.clone()), "app-signing",
                    &["enabler", "impact"],
                    artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    with_metadata(
                        json!({ "file": file, "line": line_of(text, m.start()) }),
                        &["A release build signed with a widely-shared debug key cannot be trusted to originate from the legitimate publisher."],
                        &["This match is confined to the `release { }` block text captured by a brace-balanced-ish regex; a build script that assembles the config indirectly is not observed by this lens."],
                    ),
                    vec!["Whether this Gradle module actually ships to a store/production channel is not confirmed by this lens.".to_string()],
                );
            }
        }
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        analyze_permissions(ctx, &mut observations);
        analyze_deep_links(ctx, &mut observations);
        analyze_exported_components(ctx, &mut observations);
        analyze_webview_bridge(ctx, &mut observations);
        analyze_storage(ctx, &mut observations);
        analyze_backup(ctx, &mut observations);
        analyze_transport(ctx, &mut observations);
        analyze_signing(ctx, &mut observations);
        observations
    }
}
