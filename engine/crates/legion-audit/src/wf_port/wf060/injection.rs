//! Port of `src/providers/security/packs/injection.mjs`: SQL, NoSQL, ORM,
//! command/shell, LDAP, template (SSTI), regex (ReDoS), prototype
//! pollution, XML external entity, and spreadsheet-formula sinks with typed
//! source-to-sink metadata.
//!
//! Every rule is a lexical (pattern-only) detector: it never runs a
//! payload, never calls a model, and never certifies a finding. When a
//! parameterization/escaping/sanitization signal is observed on the same
//! path, the candidate is either suppressed (a genuinely parameterized
//! query) or downgraded with the observed control referenced in
//! `observed_controls` (a model control entity was found) or noted in
//! `uncertainty` (only a lexical mitigating signal was found).
//!
//! Only `analyze()` is ported (see `wf060/common.rs` module doc for why
//! `variantStrategies` is out of scope for this chunk).

use super::common::{digest, line_of, Context, Fact, InjectionTrace, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.injection";
pub const CANDIDATE_CLASS: &str = "injection";

/// Mirrors `testAround(pattern, text, index, matchLength, scope)`:
/// `scope: "match"` tests the exact match text, `scope: "forward"` (the
/// default) tests a window starting at the match extending 300 chars past
/// its end.
fn test_around(pattern: Option<&Regex>, text: &str, index: usize, match_len: usize, scope: &str) -> bool {
    let Some(pattern) = pattern else { return false };
    if scope == "match" {
        let end = (index + match_len).min(text.len());
        return pattern.is_match(&text[index..end]);
    }
    let end = (index + match_len + 300).min(text.len());
    pattern.is_match(&text[index..end])
}

fn trace_for<'a>(context: &'a Context, file: &str, sink_class: &str) -> Option<&'a InjectionTrace> {
    context
        .audit_facts
        .injection_traces
        .iter()
        .find(|t| t.file == file && t.sink_class == sink_class)
}

/// Mirrors `findRelatedControl(context, artifactId, controlTypes)`.
fn find_related_control<'a>(
    context: &'a Context,
    artifact_id: Option<&str>,
    control_types: &[&str],
) -> Option<&'a super::common::Entity> {
    if let Some(artifact_id) = artifact_id {
        for rel in context.relations_to(artifact_id) {
            if rel.kind != "protects" {
                continue;
            }
            if let Some(control) = context.entity_by_id(&rel.from) {
                if control.kind == "control"
                    && control.attr_str("controlType").map(|t| control_types.contains(&t)).unwrap_or(false)
                {
                    return Some(control);
                }
            }
        }
    }
    context.entities.iter().find(|e| {
        e.kind == "control"
            && e.attr_str("controlType").map(|t| control_types.contains(&t)).unwrap_or(false)
    })
}

struct Downgrade {
    control_types: &'static [&'static str],
    severity_hint: &'static str,
    lexical_pattern: Option<fn() -> &'static Regex>,
    lexical_note: Option<&'static str>,
}

struct Rule {
    id: &'static str,
    sink_class: &'static str,
    sink_kind: &'static str,
    severity_hint: &'static str,
    claim: &'static str,
    file_guard: Option<fn() -> &'static Regex>,
    risky_pattern: fn() -> &'static Regex,
    suppress_pattern: Option<fn() -> &'static Regex>,
    suppress_scope: &'static str,
    downgrade: Option<Downgrade>,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    sink_engine: fn(&str) -> &'static str,
    uncertainty: &'static [&'static str],
}

macro_rules! re_fn {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}

re_fn!(sql_risky, r#"(?i)\b(?:query|execute|exec)\s*\(\s*(?:`[^`\n]*\$\{[^}]*(?:request|input|user|body|params|query)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:request|input|user|body|params|query)|'[^'\n]*'\s*\+\s*(?:request|input|user|body|params|query))"#);
re_fn!(sql_suppress, r#"(?i)\b(?:query|execute)\s*\(\s*(?:`[^`\n]*\?[^`\n]*`|"[^"\n]*\?[^"\n]*"|'[^'\n]*\?[^'\n]*')\s*,\s*\["#);
re_fn!(sql_lexical, r"(?i)\.escape\(|mysql\.escape|sqlstring\.escape|pg-escape");

re_fn!(nosql_risky, r#"(?i)\.(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*(?:request\.(?:body|query|params)\b|\{\s*\$where\b)"#);
re_fn!(nosql_suppress, r"(?i)mongo-?sanitize|sanitizeFilter");
re_fn!(nosql_lexical, r"(?i)\bpick\(|allowlist|whitelist");

re_fn!(orm_risky, r#"(?i)\b(?:sequelize\.query|\$queryRaw|Model\.raw|FromSqlRaw)\s*\(\s*(?:`[^`\n]*\$\{[^}]*(?:request|input|user|body|params)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:request|input|user|body|params)|'[^'\n]*'\s*\+\s*(?:request|input|user|body|params))"#);
re_fn!(orm_suppress, r#"(?i)\breplacements\s*:|\bbind\s*:|Prisma\.sql`"#);

re_fn!(shell_risky, r"(?:exec|system|spawn|child_process\.exec|subprocess\.(?:call|run|Popen))\s*\([^\n]*(?:request|input|user|query|body|params)");
re_fn!(shell_suppress, r"(?i)shell\s*:\s*false");
re_fn!(shell_lexical, r"(?i)\bspawn\s*\([^)]*,\s*\[");

re_fn!(ldap_file_guard, r"(?i)ldap");
re_fn!(ldap_risky, r#"(?i)\bfilter\s*[:=]\s*(?:`[^`\n]*\$\{[^}]+\}[^`\n]*`|"[^"\n]*"\s*\+|'[^'\n]*'\s*\+)[^\n]*(?:request|input|user|body|params)"#);
re_fn!(ldap_suppress, r"(?i)escapeFilter|ldapEscape|ldap-escape");

re_fn!(ssti_risky, r"(?i)\b(?:ejs\.render|_\.template|Handlebars\.compile|nunjucks\.renderString|render_template_string)\s*\([^\n]*(?:request|input|user|body|params)");
re_fn!(ssti_suppress, r"(?i)autoescape\s*:\s*true|sandbox\s*:\s*true");

re_fn!(redos_risky, r"/(?:[^/\n\\]|\\.)*\([^()]*[+*]\)[+*](?:[^/\n\\]|\\.)*/[a-z]*");

re_fn!(proto_risky, r#"(?i)(?:\[\s*request\.(?:body|query|params)(?:\.\w+)?\s*\]\s*=|(?:_\.merge|deepmerge|merge)\s*\(\s*\{\}\s*,\s*request\.(?:body|query|params))"#);
re_fn!(proto_lexical, r"(?i)denylist|blocklist|isSafeKey|hasOwnProperty\.call");

re_fn!(xxe_file_guard, r"(?i)libxmljs|lxml|DocumentBuilderFactory|XMLParser|expat|xml2js");
re_fn!(xxe_risky, r#"\b(?:noent\s*:\s*true|resolveEntities\s*:\s*true|resolve_entities\s*=\s*True|setFeature\(\s*["']http://apache\.org/xml/features/nonvalidating/load-external-dtd["']\s*,\s*true\s*\))"#);

re_fn!(formula_file_guard, r"(?i)csv|xlsx|exceljs|csv-writer");
re_fn!(formula_risky, r#"(?i)\b(?:addRow|writeRow|push)\s*\(\s*\[[^\]]*(?:request\.(?:body|query|params)|input)[^\]]*\]\s*\)"#);
re_fn!(formula_suppress, r#"(?i)startsWith\(\s*['"][=+\-@]['"]\)|escapeFormula|sanitizeCsv"#);

fn sql_sink_engine(text: &str) -> &'static str {
    if Regex::new(r"(?i)\bpg\b|postgres").unwrap().is_match(text) {
        "postgres"
    } else if Regex::new(r"(?i)mysql").unwrap().is_match(text) {
        "mysql"
    } else if Regex::new(r"(?i)sqlite").unwrap().is_match(text) {
        "sqlite"
    } else if Regex::new(r"(?i)knex").unwrap().is_match(text) {
        "knex"
    } else {
        "sql"
    }
}
fn nosql_sink_engine(text: &str) -> &'static str {
    if Regex::new(r"(?i)mongoose").unwrap().is_match(text) {
        "mongoose"
    } else if Regex::new(r"(?i)mongodb|mongo").unwrap().is_match(text) {
        "mongo"
    } else {
        "nosql"
    }
}
fn orm_sink_engine(text: &str) -> &'static str {
    if Regex::new(r"(?i)sequelize").unwrap().is_match(text) {
        "sequelize"
    } else if Regex::new(r"(?i)prisma").unwrap().is_match(text) {
        "prisma"
    } else {
        "orm"
    }
}
fn shell_sink_engine(text: &str) -> &'static str {
    if text.contains("child_process.exec") {
        "child_process.exec"
    } else if text.contains("subprocess.") {
        "subprocess"
    } else if text.contains("spawn") {
        "spawn"
    } else {
        "shell"
    }
}
fn ldap_sink_engine(_text: &str) -> &'static str {
    "ldap"
}
fn ssti_sink_engine(text: &str) -> &'static str {
    if text.contains("ejs.render") {
        "ejs"
    } else if text.contains("Handlebars.compile") {
        "handlebars"
    } else if text.contains("nunjucks.renderString") {
        "nunjucks"
    } else if text.contains("_.template") {
        "lodash.template"
    } else {
        "template-engine"
    }
}
fn redos_sink_engine(_text: &str) -> &'static str {
    "RegExp"
}
fn proto_sink_engine(text: &str) -> &'static str {
    if text.contains("deepmerge") {
        "deepmerge"
    } else if text.contains("_.merge") {
        "lodash.merge"
    } else {
        "bracket-assignment"
    }
}
fn xxe_sink_engine(text: &str) -> &'static str {
    if text.contains("libxmljs") {
        "libxmljs"
    } else if text.contains("lxml") {
        "lxml"
    } else if text.contains("DocumentBuilderFactory") {
        "DocumentBuilderFactory"
    } else if text.contains("expat") {
        "expat"
    } else {
        "xml-parser"
    }
}
fn formula_sink_engine(text: &str) -> &'static str {
    if Regex::new(r"(?i)exceljs").unwrap().is_match(text) {
        "exceljs"
    } else if Regex::new(r"(?i)csv-writer").unwrap().is_match(text) {
        "csv-writer"
    } else if Regex::new(r"(?i)xlsx").unwrap().is_match(text) {
        "xlsx"
    } else {
        "csv"
    }
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "injection.sql.dynamic-query",
            sink_class: "sql",
            sink_kind: "sql",
            severity_hint: "high",
            claim: "Request-derived data may reach a dynamically constructed SQL statement.",
            file_guard: None,
            risky_pattern: sql_risky,
            suppress_pattern: Some(sql_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["sql-parameterization", "sql-escaping"],
                severity_hint: "low",
                lexical_pattern: Some(sql_lexical),
                lexical_note: Some("An escaping helper call is present near the sink; treated as a mitigating signal pending adjudication."),
            }),
            effect_kind: "data-access",
            effect_action: "query",
            effect_scope: "sql-sink",
            chain_roles: &["starter", "impact"],
            sink_engine: sql_sink_engine,
            uncertainty: &["Dynamic SQL construction is not automatically injection; parameter binding elsewhere in the call path must be adjudicated."],
        },
        Rule {
            id: "injection.nosql.operator-injection",
            sink_class: "nosql",
            sink_kind: "nosql",
            severity_hint: "high",
            claim: "Request-derived data may reach a NoSQL query without operator sanitization.",
            file_guard: None,
            risky_pattern: nosql_risky,
            suppress_pattern: Some(nosql_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["nosql-sanitization"],
                severity_hint: "low",
                lexical_pattern: Some(nosql_lexical),
                lexical_note: Some("A field allowlist/pick call is present near the sink; treated as a mitigating signal pending adjudication."),
            }),
            effect_kind: "data-access",
            effect_action: "query",
            effect_scope: "nosql-sink",
            chain_roles: &["starter", "impact"],
            sink_engine: nosql_sink_engine,
            uncertainty: &["An unfiltered request object reaching a query is not automatically operator injection; the driver and schema must be adjudicated."],
        },
        Rule {
            id: "injection.orm.raw-query-with-input",
            sink_class: "orm",
            sink_kind: "orm",
            severity_hint: "high",
            claim: "Request-derived data may reach a raw ORM query without parameter binding.",
            file_guard: None,
            risky_pattern: orm_risky,
            suppress_pattern: Some(orm_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["orm-parameterization"],
                severity_hint: "low",
                lexical_pattern: None,
                lexical_note: None,
            }),
            effect_kind: "data-access",
            effect_action: "query",
            effect_scope: "orm-sink",
            chain_roles: &["starter", "impact"],
            sink_engine: orm_sink_engine,
            uncertainty: &["A raw ORM escape hatch is not automatically injection; whether replacements/bind parameters are used must be adjudicated."],
        },
        Rule {
            id: "injection.command.shell-exec",
            sink_class: "command",
            sink_kind: "shell",
            severity_hint: "high",
            claim: "Request-derived data reaches a shell execution sink.",
            file_guard: None,
            risky_pattern: shell_risky,
            suppress_pattern: Some(shell_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["shell-argument-escaping", "input-allowlist"],
                severity_hint: "low",
                lexical_pattern: Some(shell_lexical),
                lexical_note: Some("An array-argument invocation avoids shell string interpolation; treated as a mitigating signal pending adjudication."),
            }),
            effect_kind: "code-execution",
            effect_action: "execute",
            effect_scope: "sink-process",
            chain_roles: &["starter", "impact"],
            sink_engine: shell_sink_engine,
            uncertainty: &["A process-argument candidate is not automatically command injection; argument separation and validation must be adjudicated."],
        },
        Rule {
            id: "injection.ldap.filter-injection",
            sink_class: "ldap",
            sink_kind: "ldap",
            severity_hint: "high",
            claim: "Request-derived data may reach an LDAP filter without escaping.",
            file_guard: Some(ldap_file_guard),
            risky_pattern: ldap_risky,
            suppress_pattern: Some(ldap_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["ldap-escape"],
                severity_hint: "low",
                lexical_pattern: None,
                lexical_note: None,
            }),
            effect_kind: "data-access",
            effect_action: "query",
            effect_scope: "ldap-sink",
            chain_roles: &["starter", "impact"],
            sink_engine: ldap_sink_engine,
            uncertainty: &["LDAP filter concatenation is not automatically injection; the directory server and escaping library must be adjudicated."],
        },
        Rule {
            id: "injection.template.server-side-template-injection",
            sink_class: "template",
            sink_kind: "ssti",
            severity_hint: "high",
            claim: "Request-derived data may be compiled as a template rather than passed as template data.",
            file_guard: None,
            risky_pattern: ssti_risky,
            suppress_pattern: Some(ssti_suppress),
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["template-sandboxing"],
                severity_hint: "low",
                lexical_pattern: None,
                lexical_note: None,
            }),
            effect_kind: "code-execution",
            effect_action: "execute",
            effect_scope: "template-engine",
            chain_roles: &["starter", "impact"],
            sink_engine: ssti_sink_engine,
            uncertainty: &["Compiling request-derived text as a template is not automatically SSTI; the engine's sandboxing must be adjudicated."],
        },
        Rule {
            id: "injection.regex.redos",
            sink_class: "redos",
            sink_kind: "redos",
            severity_hint: "medium",
            claim: "A regular expression contains a nested-quantifier shape associated with catastrophic backtracking (ReDoS).",
            file_guard: None,
            risky_pattern: redos_risky,
            suppress_pattern: None,
            suppress_scope: "forward",
            downgrade: None,
            effect_kind: "availability-impact",
            effect_action: "exhaust",
            effect_scope: "regex-engine",
            chain_roles: &["starter", "impact"],
            sink_engine: redos_sink_engine,
            uncertainty: &["A nested-quantifier shape is not automatically exploitable; whether attacker-controlled input reaches this expression and its length bound must be adjudicated."],
        },
        Rule {
            id: "injection.prototype-pollution.unsafe-key-assignment",
            sink_class: "prototype-pollution",
            sink_kind: "prototype-pollution",
            severity_hint: "medium",
            claim: "A request-derived property key reaches a dynamic assignment without a prototype-key denylist.",
            file_guard: None,
            risky_pattern: proto_risky,
            suppress_pattern: None,
            suppress_scope: "forward",
            downgrade: Some(Downgrade {
                control_types: &["prototype-key-denylist"],
                severity_hint: "low",
                lexical_pattern: Some(proto_lexical),
                lexical_note: Some("A key-denylist or hasOwnProperty guard is present near the sink; treated as a mitigating signal pending adjudication."),
            }),
            effect_kind: "integrity-impact",
            effect_action: "pollute",
            effect_scope: "object-prototype",
            chain_roles: &["starter", "impact"],
            sink_engine: proto_sink_engine,
            uncertainty: &["A dynamic property key is not automatically prototype pollution; whether `__proto__`/`constructor` keys are reachable must be adjudicated."],
        },
        Rule {
            id: "injection.xxe.external-entity-enabled",
            sink_class: "xxe",
            sink_kind: "xxe",
            severity_hint: "high",
            claim: "An XML parser is explicitly configured to resolve external entities (XXE).",
            file_guard: Some(xxe_file_guard),
            risky_pattern: xxe_risky,
            suppress_pattern: None,
            suppress_scope: "forward",
            downgrade: None,
            effect_kind: "data-access",
            effect_action: "read",
            effect_scope: "xml-parser",
            chain_roles: &["starter", "impact"],
            sink_engine: xxe_sink_engine,
            uncertainty: &["An external-entity-enabling toggle is not automatically exploitable; whether attacker-controlled XML reaches this parser must be adjudicated."],
        },
        Rule {
            id: "injection.formula.csv-export-unescaped",
            sink_class: "formula",
            sink_kind: "formula",
            severity_hint: "medium",
            claim: "Request-derived data reaches a spreadsheet export row without formula-prefix escaping.",
            file_guard: Some(formula_file_guard),
            risky_pattern: formula_risky,
            suppress_pattern: Some(formula_suppress),
            suppress_scope: "forward",
            downgrade: None,
            effect_kind: "integrity-impact",
            effect_action: "inject-formula",
            effect_scope: "spreadsheet-export",
            chain_roles: &["starter", "impact"],
            sink_engine: formula_sink_engine,
            uncertainty: &["An unescaped export cell is not automatically formula injection; the consuming spreadsheet application's auto-execution settings must be adjudicated."],
        },
    ]
}

/// Ports `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            if let Some(guard) = rule.file_guard {
                if !guard().is_match(text) {
                    continue;
                }
            }
            for m in (rule.risky_pattern)().find_iter(text) {
                if test_around(rule.suppress_pattern.map(|f| f()), text, m.start(), m.len(), rule.suppress_scope) {
                    continue;
                }

                let mut severity_hint = rule.severity_hint.to_string();
                let mut observed_controls: Vec<String> = Vec::new();
                let mut uncertainty: Vec<String> = rule.uncertainty.iter().map(|s| s.to_string()).collect();

                if let Some(downgrade) = &rule.downgrade {
                    if let Some(control) =
                        find_related_control(context, artifact.map(|a| a.id.as_str()), downgrade.control_types)
                    {
                        severity_hint = downgrade.severity_hint.to_string();
                        observed_controls = vec![control.id.clone()];
                        let control_type = control.attr_str("controlType").unwrap_or("mitigating");
                        uncertainty.push(format!(
                            "Observed {control_type} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                            control.name
                        ));
                    } else if let Some(lex) = downgrade.lexical_pattern {
                        if test_around(Some(lex()), text, m.start(), m.len(), rule.suppress_scope) {
                            severity_hint = downgrade.severity_hint.to_string();
                            uncertainty.push(
                                downgrade
                                    .lexical_note
                                    .unwrap_or("A mitigating pattern is present near the sink; downgraded pending adjudication.")
                                    .to_string(),
                            );
                        }
                    }
                }

                let trace = trace_for(context, file, rule.sink_class);
                let detection_method = if trace.is_some() { "sast-trace" } else { "lexical-pattern" };
                uncertainty.push(if trace.is_some() {
                    "Confirmed by a recorded taint trace; reachability is still subject to adjudication.".to_string()
                } else {
                    "Lexical pattern match; not confirmed by a recorded taint trace.".to_string()
                });

                let sources = if let Some(a) = artifact {
                    let mut reaches: Vec<String> = context
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
                    severity_hint,
                    sources,
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec!["control-request-input".to_string()],
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "supply-input".to_string(),
                        object: None,
                        scope: None,
                        environment: "application".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "application".to_string(),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls,
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, m.start()),
                        "sinkClass": rule.sink_class,
                        "sinkKind": rule.sink_kind,
                        "sinkEngine": (rule.sink_engine)(text),
                        "detectionMethod": detection_method,
                        "matchDigest": digest(m.as_str()),
                    }),
                    uncertainty,
                });
            }
        }
    }
    observations
}
