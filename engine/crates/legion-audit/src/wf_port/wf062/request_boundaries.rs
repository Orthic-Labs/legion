//! Port of `src/providers/security/packs/request-boundaries.mjs`:
//! type/length/format validation gaps, body size limits, mass-assignment of
//! unexpected fields, and response header injection. Every rule is a
//! lexical (pattern-only) detector: it never sends a request, never runs a
//! payload, never calls a model, and never certifies a finding. When a
//! validation/allowlist/sanitization signal is observed on the same path,
//! the candidate is downgraded with the observed control referenced in
//! `observedControls` (a model control entity was found) or noted in
//! `uncertainty` (only a lexical mitigating signal was found) — it is never
//! silently hidden once a match exists.
//!
//! `request.unvalidated-input-to-sink`'s JS pattern uses a negative
//! lookahead (`\b(?!${NOT_KEYWORD}\b)(...)`) to exclude control-flow
//! keywords (`if`/`for`/`while`/`switch`/`catch`/`function`/`return`) from
//! matching as a sink call name, e.g. so `if (request.query.x)` is not read
//! as a call to a sink named `if`. The Rust `regex` crate has no lookaround
//! support, so this is ported as an equivalent post-match filter: the same
//! pattern without the lookahead, followed by rejecting any match whose
//! captured sink-name group is exactly one of those keywords (which is
//! exactly what the JS lookahead excludes, since `\b` after the keyword in
//! the lookahead requires an exact token match, not a prefix — `iffy(` is
//! not excluded).
//!
//! `request.mass-assignment-unfiltered`'s JS pattern uses `(?<name>...)`
//! named-group syntax, ported verbatim to Rust's `(?P<name>...)` syntax
//! with identical group names and alternation structure.

use super::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use std::sync::OnceLock;

pub const CANDIDATE_CLASS: &str = "request-boundaries";

const NOT_KEYWORDS: &[&str] = &["if", "for", "while", "switch", "catch", "function", "return"];

fn unvalidated_input_to_sink() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\(\s*([^()\n]*\b(?:request|req)\.(?:query|body|params)(?:\.[\w]+)?\b[^()\n]*)\)",
        )
        .unwrap()
    })
}

fn body_size_unbounded() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(\s*(\{[^{}]*\})?\s*\)").unwrap()
    })
}

fn body_size_limit_present() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\blimit\s*:").unwrap())
}

fn mass_assignment_unfiltered() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?P<sinkAssign>Object\.assign)\s*\(\s*(?P<target>[\w.$]+)\s*,\s*(?P<srcAssign>(?:request|req)\.body)\s*\)|\.(?P<sinkMethod>update|create)\s*\(\s*(?P<srcMethod>(?:request|req)\.body)\s*\)|(?P<sinkSpread>\{\s*\.\.\.(?P<srcSpread>(?:request|req)\.body)\s*\})",
        )
        .unwrap()
    })
}

fn header_injection() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bres\.(setHeader|header|set)\s*\(\s*[^,()\n]+,\s*((?:request|req)\.(?:query|body|params|headers)(?:\.[\w]+)?)[^)]*\)")
            .unwrap()
    })
}

fn schema_validation_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:joi|zod|yup|ajv|celebrate|schema\.(?:parse|validate)|validate\()").unwrap())
}

fn allowlist_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:pick\(|omit\(|only\(|allowlist|whitelist)\b").unwrap())
}

fn header_encoding_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)encodeURIComponent|sanitizeHeader").unwrap())
}

struct Downgrade {
    control_types: &'static [&'static str],
    severity_hint: &'static str,
    lexical_pattern: fn() -> &'static Regex,
    lexical_note: &'static str,
    radius: usize,
}

/// One in-file match this pack's `analyze` produced, before the generic
/// downgrade/observation-building step below.
struct Hit {
    index: usize,
    len: usize,
    source_expr: String,
    sink_api: String,
}

fn find_unvalidated_input_hits(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for cap in unvalidated_input_to_sink().captures_iter(text) {
        let whole = cap.get(0).unwrap();
        let sink_name = cap.get(1).unwrap().as_str();
        if NOT_KEYWORDS.contains(&sink_name) {
            continue;
        }
        out.push(Hit {
            index: whole.start(),
            len: whole.len(),
            source_expr: cap.get(2).unwrap().as_str().trim().to_string(),
            sink_api: sink_name.to_string(),
        });
    }
    out
}

fn find_body_size_hits(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for cap in body_size_unbounded().captures_iter(text) {
        let whole = cap.get(0).unwrap();
        // Mirrors `customSuppress`: `Boolean(m[2] && /\blimit\s*:/.test(m[2]))`.
        if let Some(opts) = cap.get(2) {
            if body_size_limit_present().is_match(opts.as_str()) {
                continue;
            }
        }
        out.push(Hit {
            index: whole.start(),
            len: whole.len(),
            source_expr: "http-request-body".to_string(),
            sink_api: cap.get(1).unwrap().as_str().to_string(),
        });
    }
    out
}

fn find_mass_assignment_hits(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for cap in mass_assignment_unfiltered().captures_iter(text) {
        let whole = cap.get(0).unwrap();
        let sink_api = cap
            .name("sinkAssign")
            .map(|m| m.as_str().to_string())
            .or_else(|| cap.name("sinkMethod").map(|m| format!(".{}", m.as_str())))
            .unwrap_or_else(|| "object-spread".to_string());
        let source_expr = cap
            .name("srcAssign")
            .or_else(|| cap.name("srcMethod"))
            .or_else(|| cap.name("srcSpread"))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        out.push(Hit { index: whole.start(), len: whole.len(), source_expr, sink_api });
    }
    out
}

fn find_header_injection_hits(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for cap in header_injection().captures_iter(text) {
        let whole = cap.get(0).unwrap();
        out.push(Hit {
            index: whole.start(),
            len: whole.len(),
            source_expr: cap.get(2).unwrap().as_str().to_string(),
            sink_api: format!("res.{}", cap.get(1).unwrap().as_str()),
        });
    }
    out
}

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    attacker_capabilities: &'static [&'static str],
    precondition_action: &'static str,
    environment: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    uncertainty: &'static str,
    downgrade: Option<Downgrade>,
    find_hits: fn(&str) -> Vec<Hit>,
}

fn rules() -> [Rule; 4] {
    [
        Rule {
            id: "request.unvalidated-input-to-sink",
            claim: "Request-derived data reaches an operation without a visible type/length/format validation step.",
            severity_hint: "medium",
            attacker_capabilities: &["control-request-input"],
            precondition_action: "supply-input",
            environment: "application",
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: "input-validation-boundary",
            chain_roles: &["starter", "enabler"],
            uncertainty: "An unvalidated call argument is not automatically exploitable; the sink's own handling of malformed input must be adjudicated.",
            downgrade: Some(Downgrade {
                control_types: &["request-schema-validation", "input-validation"],
                severity_hint: "low",
                lexical_pattern: schema_validation_lexical,
                lexical_note: "A schema-validation call is present near this input use; treated as a mitigating signal pending adjudication.",
                radius: 300,
            }),
            find_hits: find_unvalidated_input_hits,
        },
        Rule {
            id: "request.body-size-unbounded",
            claim: "A request body parser is configured without a visible size limit, allowing an oversized request body to be accepted.",
            severity_hint: "medium",
            attacker_capabilities: &["control-request-input"],
            precondition_action: "supply-oversized-body",
            environment: "application",
            effect_kind: "availability-impact",
            effect_action: "exhaust",
            effect_scope: "request-body-parsing",
            chain_roles: &["starter", "impact"],
            uncertainty: "Whether an upstream proxy or platform default already enforces a body size cap is not visible from source.",
            downgrade: None,
            find_hits: find_body_size_hits,
        },
        Rule {
            id: "request.mass-assignment-unfiltered",
            claim: "Request body data is assigned directly onto a model/object without a field allowlist, risking mass assignment of unexpected fields.",
            severity_hint: "medium",
            attacker_capabilities: &["control-request-input"],
            precondition_action: "supply-unexpected-fields",
            environment: "application",
            effect_kind: "integrity-impact",
            effect_action: "assign",
            effect_scope: "object-model-fields",
            chain_roles: &["starter", "impact"],
            uncertainty: "Whether the target model/schema restricts which fields are actually persisted is not visible from this call alone.",
            downgrade: Some(Downgrade {
                control_types: &["mass-assignment-allowlist", "field-allowlist"],
                severity_hint: "low",
                lexical_pattern: allowlist_lexical,
                lexical_note: "A field allowlist/pick call is present near the assignment; treated as a mitigating signal pending adjudication.",
                radius: 250,
            }),
            find_hits: find_mass_assignment_hits,
        },
        Rule {
            id: "request.header-injection",
            claim: "A response header value is set directly from request-controlled data without a visible CRLF-sanitization step, risking header/response splitting.",
            severity_hint: "high",
            attacker_capabilities: &["control-request-input"],
            precondition_action: "supply-header-value",
            environment: "application",
            effect_kind: "control-bypass",
            effect_action: "inject",
            effect_scope: "http-response-header",
            chain_roles: &["starter", "impact"],
            uncertainty: "Modern HTTP libraries often reject raw CR/LF in header values at the framework level; whether this framework does so must be adjudicated.",
            downgrade: Some(Downgrade {
                control_types: &["header-sanitization"],
                severity_hint: "low",
                lexical_pattern: header_encoding_lexical,
                lexical_note: "A header-encoding call is present near the sink; treated as a mitigating signal pending adjudication.",
                radius: 200,
            }),
            find_hits: find_header_injection_hits,
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
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            for hit in (rule.find_hits)(text) {
                let mut severity_hint = rule.severity_hint.to_string();
                let mut observed_controls = Vec::new();
                let mut control_observed: Option<String> = None;
                let mut uncertainty = vec![rule.uncertainty.to_string()];

                if let Some(downgrade) = &rule.downgrade {
                    if let Some(control) = context.find_related_control(artifact.map(|a| a.id.as_str()), downgrade.control_types) {
                        severity_hint = downgrade.severity_hint.to_string();
                        observed_controls = vec![control.id.clone()];
                        control_observed = Some(control.name.clone());
                        let control_type = control.attr_str("controlType").unwrap_or("mitigating");
                        uncertainty.push(format!(
                            "Observed {control_type} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                            control.name
                        ));
                    } else if (downgrade.lexical_pattern)()
                        .is_match(window_around(text, hit.index, hit.len, downgrade.radius))
                    {
                        severity_hint = downgrade.severity_hint.to_string();
                        control_observed = Some("lexical-signal".to_string());
                        uncertainty.push(downgrade.lexical_note.to_string());
                    }
                }

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint,
                    sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: rule.attacker_capabilities.iter().map(|s| s.to_string()).collect(),
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.precondition_action.to_string(),
                        object: None,
                        scope: None,
                        environment: rule.environment.to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: rule.environment.to_string(),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls,
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: serde_json::json!({
                        "file": file,
                        "line": line_of(text, hit.index),
                        "sourceExpr": hit.source_expr,
                        "sinkApi": hit.sink_api,
                        "controlObserved": control_observed,
                        "matchDigest": digest(text.get(hit.index..hit.index + hit.len).unwrap_or("")),
                    }),
                    uncertainty,
                });
            }
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Entity, Relation};

    fn find<'a>(obs: &'a [Observation], rule_id: &str) -> Option<&'a Observation> {
        obs.iter().find(|o| o.rule_id == rule_id)
    }

    #[test]
    fn unvalidated_input_to_sink_fires_on_a_direct_fetch_of_request_query() {
        let context = Context::new().with_file("handler.mjs", "fetch(request.query.url)");
        let obs = analyze(&context);
        let candidate = find(&obs, "request.unvalidated-input-to-sink").unwrap();
        assert_eq!(candidate.severity_hint, "medium");
        assert_eq!(candidate.observed_controls, Vec::<String>::new());
        assert_eq!(candidate.detector_metadata["sinkApi"], "fetch");
    }

    #[test]
    fn unvalidated_input_to_sink_does_not_misread_an_if_condition_as_a_sink_call() {
        let context = Context::new().with_file("handler.mjs", "if(request.query.x) { doSomething(); }");
        let obs = analyze(&context);
        assert!(find(&obs, "request.unvalidated-input-to-sink").is_none());
    }

    #[test]
    fn an_observed_schema_validation_control_downgrades_the_candidate_and_references_it() {
        let context = Context::new()
            .with_file("handler.mjs", "fetch(request.query.url)")
            .with_entity(Entity::control("ctrl:1", "request-schema-validation", "joi request schema", vec!["ev:control".into()]))
            .with_relation(Relation { kind: "protects".to_string(), from: "ctrl:1".to_string(), to: "artifact:handler.mjs".to_string() });
        let obs = analyze(&context);
        let candidate = find(&obs, "request.unvalidated-input-to-sink").unwrap();
        assert_ne!(candidate.severity_hint, "medium");
        assert_eq!(candidate.observed_controls, vec!["ctrl:1".to_string()]);
        assert!(candidate.uncertainty.iter().any(|u| u.to_lowercase().contains("observed") && u.to_lowercase().contains("control")));
    }

    #[test]
    fn a_nearby_lexical_schema_validation_call_downgrades_the_candidate_without_a_model_control() {
        let context = Context::new().with_file("handler.mjs", "const body = zod.parse(x); fetch(request.query.url)");
        let obs = analyze(&context);
        let candidate = find(&obs, "request.unvalidated-input-to-sink").unwrap();
        assert_eq!(candidate.severity_hint, "low");
        assert!(candidate.observed_controls.is_empty());
    }

    #[test]
    fn a_size_capped_body_parser_produces_no_body_size_unbounded_candidate() {
        let context = Context::new().with_file("app.mjs", "app.use(express.json({ limit: '100kb' }));");
        let obs = analyze(&context);
        assert!(find(&obs, "request.body-size-unbounded").is_none());
    }

    #[test]
    fn an_unbounded_body_parser_fires() {
        let context = Context::new().with_file("app.mjs", "app.use(express.json());");
        let obs = analyze(&context);
        assert!(find(&obs, "request.body-size-unbounded").is_some());
    }

    #[test]
    fn mass_assignment_fires_on_object_assign_update_and_spread_forms() {
        let context = Context::new()
            .with_file("a.mjs", "Object.assign(user, request.body)")
            .with_file("b.mjs", "model.update(request.body)")
            .with_file("c.mjs", "const patch = { ...request.body }");
        let obs = analyze(&context);
        assert_eq!(obs.iter().filter(|o| o.rule_id == "request.mass-assignment-unfiltered").count(), 3);
    }

    #[test]
    fn header_injection_fires_on_a_direct_response_header_set_from_request_data() {
        let context = Context::new().with_file("h.mjs", "res.setHeader('X-Forward', request.query.dest)");
        let obs = analyze(&context);
        let candidate = find(&obs, "request.header-injection").unwrap();
        assert_eq!(candidate.severity_hint, "high");
        assert_eq!(candidate.detector_metadata["sinkApi"], "res.setHeader");
    }

    #[test]
    fn every_candidate_names_exact_file_line_source_expr_sink_api_and_control_observed() {
        let context = Context::new().with_file("app.mjs", "fetch(request.query.url)");
        for candidate in analyze(&context) {
            let meta = &candidate.detector_metadata;
            assert_eq!(meta["file"], "app.mjs");
            assert!(meta["line"].is_number());
            assert!(meta["sourceExpr"].as_str().unwrap_or("").len() > 0);
            assert!(meta["sinkApi"].as_str().unwrap_or("").len() > 0);
            assert!(meta.get("controlObserved").is_some());
        }
    }

    #[test]
    fn a_neutral_source_produces_no_candidates() {
        let context = Context::new().with_file("neutral.mjs", "export const value = 1;");
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn rule_ids_match_the_four_documented_rule_ids() {
        assert_eq!(
            rule_ids(),
            vec![
                "request.unvalidated-input-to-sink",
                "request.body-size-unbounded",
                "request.mass-assignment-unfiltered",
                "request.header-injection",
            ]
        );
    }
}
