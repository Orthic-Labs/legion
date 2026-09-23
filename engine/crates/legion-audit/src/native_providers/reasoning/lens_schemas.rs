//! Full report-schema bodies (one JSON Schema value per lens) and
//! reconciliation-path validation of lens findings against them.
//!
//! `lens_plan.rs` only carries a schema *id* (e.g. `"audit.lens.minimize.v1"`)
//! in the packet; this module supplies the schema *body* that id names, and
//! a validator the reconciliation path (`mod.rs::verify_response`) runs
//! against a host's returned findings before they are folded into the
//! `ProviderResult` the audit accepts. Every lens shares one finding shape
//! per `manual.md`'s reconciliation contract: `id`, `lens`, `severity`,
//! `confidence`, `file:line` evidence, failure scenario, action, verify
//! status. Lens-specific extras (`minimize`'s ponytail tag,
//! `variant-analysis`'s parent finding id) extend the shared shape rather
//! than replacing it.
//!
//! Dependency-free by design: no `jsonschema`/`valico` crate. The schema
//! bodies are genuine JSON Schema (draft 2020-12 shaped, `$id`/`type`/
//! `required`/`properties`/`enum`) so a real validator could consume them
//! unchanged; `validate_finding` below is a small hand-rolled structural
//! checker over the same rules, which is what actually gates the
//! reconciliation path here.

use serde_json::{json, Value};

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
const CONFIDENCES: &[&str] = &["confirmed", "likely", "speculative"];
const VERIFY_STATUSES: &[&str] = &["verified", "unverified", "not-applicable"];

/// The finding fields every lens schema requires: `id`, `lens`, `severity`,
/// `confidence`, `evidence` (`file:line`), `failureScenario`, `action`,
/// `verifyStatus`.
fn base_properties() -> Value {
    json!({
        "id": { "type": "string", "minLength": 1 },
        "lens": { "type": "string", "minLength": 1 },
        "severity": { "type": "string", "enum": SEVERITIES },
        "confidence": { "type": "string", "enum": CONFIDENCES },
        "evidence": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                // "path:line" or "path:start-end"
                "pattern": "^[^:]+:[0-9]+(-[0-9]+)?$"
            }
        },
        "failureScenario": { "type": "string", "minLength": 1 },
        "action": { "type": "string", "minLength": 1 },
        "verifyStatus": { "type": "string", "enum": VERIFY_STATUSES }
    })
}

fn base_required() -> Vec<&'static str> {
    vec![
        "id",
        "lens",
        "severity",
        "confidence",
        "evidence",
        "failureScenario",
        "action",
        "verifyStatus",
    ]
}

/// Builds the base finding schema (no lens-specific extras), used for every
/// lens that does not add fields beyond the shared shape.
fn base_schema(schema_id: &str, lens: &str) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("https://legion.audit/schemas/{schema_id}"),
        "title": format!("{lens} finding"),
        "type": "object",
        "properties": base_properties(),
        "required": base_required(),
        "additionalProperties": true
    })
}

/// `minimize`: adds the required `ponytailTag` (one of the five tags from
/// `ponytail-lens.md`, carried in `lens_plan.rs::MINIMIZE_TAGS`).
fn minimize_schema() -> Value {
    let mut properties = base_properties();
    properties["ponytailTag"] = json!({
        "type": "string",
        "enum": ["delete", "stdlib", "native", "yagni", "shrink"]
    });
    let mut required = base_required();
    required.push("ponytailTag");
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://legion.audit/schemas/audit.lens.minimize.v1",
        "title": "minimize finding",
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true
    })
}

/// `correctness`: adds `verifyStatus` restricted to exclude `not-applicable`
/// (every correctness finding must survive reproduction or a skeptic pass —
/// `not-applicable` would mean it never rendered per the verify-pass rule)
/// and a required `verificationMethod`.
fn correctness_schema() -> Value {
    let mut properties = base_properties();
    properties["verifyStatus"] = json!({ "type": "string", "enum": ["verified"] });
    properties["verificationMethod"] = json!({
        "type": "string",
        "enum": ["deterministic-reproduction", "adversarial-skeptic-pass"]
    });
    let mut required = base_required();
    required.push("verificationMethod");
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://legion.audit/schemas/audit.lens.correctness.v1",
        "title": "correctness finding",
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true
    })
}

/// `variant-analysis`: adds a required `parentFindingId` linking back to
/// the confirmed security-adjudication verdict that triggered it.
fn variant_analysis_schema() -> Value {
    let mut properties = base_properties();
    properties["parentFindingId"] = json!({ "type": "string", "minLength": 1 });
    let mut required = base_required();
    required.push("parentFindingId");
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://legion.audit/schemas/audit.lens.variant-analysis.v1",
        "title": "variant-analysis finding",
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true
    })
}

/// Returns the full JSON Schema value for `lens`'s report shape, or `None`
/// for a lens id this module does not own a schema for.
pub fn lens_report_schema(lens: &str) -> Option<Value> {
    Some(match lens {
        "minimize" => minimize_schema(),
        "correctness" => correctness_schema(),
        "variant-analysis" => variant_analysis_schema(),
        "doc-drift" => base_schema("audit.lens.doc-drift.v1", lens),
        "architecture" => base_schema("audit.lens.architecture.v1", lens),
        "ai-slop" => base_schema("audit.lens.ai-slop.v1", lens),
        "naming" => base_schema("audit.lens.naming.v1", lens),
        "dead-file" => base_schema("audit.lens.dead-file.v1", lens),
        "schema" => base_schema("audit.lens.schema.v1", lens),
        "security" => base_schema("audit.lens.security.v1", lens),
        "performance" => base_schema("audit.lens.performance.v1", lens),
        "a11y" => base_schema("audit.lens.a11y.v1", lens),
        "data-safety" => base_schema("audit.lens.data-safety.v1", lens),
        "resilience" => base_schema("audit.lens.resilience.v1", lens),
        "platform-parity" => base_schema("audit.lens.platform-parity.v1", lens),
        "release-readiness" => base_schema("audit.lens.release-readiness.v1", lens),
        _ => return None,
    })
}

/// One structural validation failure: a JSON-Pointer-ish field path plus a
/// human-readable reason, mirroring what a real JSON Schema validator would
/// report so the message is useful without needing the schema alongside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub field: String,
    pub reason: String,
}

fn evidence_entry_valid(entry: &str) -> bool {
    match entry.rsplit_once(':') {
        Some((path, line_part)) if !path.is_empty() => {
            let mut parts = line_part.splitn(2, '-');
            let start = parts.next().unwrap_or_default();
            let end = parts.next();
            let start_ok = !start.is_empty() && start.chars().all(|c| c.is_ascii_digit());
            let end_ok = end.is_none_or(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()));
            start_ok && end_ok
        }
        _ => false,
    }
}

fn require_enum(
    finding: &Value,
    field: &'static str,
    allowed: &[&str],
    errors: &mut Vec<ValidationError>,
) {
    match finding.get(field).and_then(Value::as_str) {
        Some(value) if allowed.contains(&value) => {}
        Some(other) => errors.push(ValidationError {
            field: field.into(),
            reason: format!("`{other}` is not one of {allowed:?}"),
        }),
        None => errors.push(ValidationError {
            field: field.into(),
            reason: "missing or not a string".into(),
        }),
    }
}

fn require_nonempty_string(finding: &Value, field: &'static str, errors: &mut Vec<ValidationError>) {
    match finding.get(field).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => {}
        Some(_) => errors.push(ValidationError {
            field: field.into(),
            reason: "must not be empty".into(),
        }),
        None => errors.push(ValidationError {
            field: field.into(),
            reason: "missing or not a string".into(),
        }),
    }
}

/// Validates one finding `Value` against `lens`'s schema. Returns every
/// violation found (not just the first) so a caller can report a complete
/// picture. Unknown lens ids are treated as a validation failure rather
/// than silently accepted, since an unschematized lens finding must not
/// pass reconciliation unexamined.
pub fn validate_finding(lens: &str, finding: &Value) -> Result<(), Vec<ValidationError>> {
    if lens_report_schema(lens).is_none() {
        return Err(vec![ValidationError {
            field: "lens".into(),
            reason: format!("no report schema is registered for lens `{lens}`"),
        }]);
    }
    let mut errors = Vec::new();
    if !finding.is_object() {
        return Err(vec![ValidationError {
            field: "$".into(),
            reason: "finding must be a JSON object".into(),
        }]);
    }

    require_nonempty_string(finding, "id", &mut errors);
    match finding.get("lens").and_then(Value::as_str) {
        Some(value) if value == lens => {}
        Some(other) => errors.push(ValidationError {
            field: "lens".into(),
            reason: format!("finding.lens `{other}` does not match the invoking lens `{lens}`"),
        }),
        None => errors.push(ValidationError {
            field: "lens".into(),
            reason: "missing or not a string".into(),
        }),
    }
    require_enum(finding, "severity", SEVERITIES, &mut errors);
    require_enum(finding, "confidence", CONFIDENCES, &mut errors);
    require_nonempty_string(finding, "failureScenario", &mut errors);
    require_nonempty_string(finding, "action", &mut errors);

    match finding.get("evidence").and_then(Value::as_array) {
        Some(entries) if !entries.is_empty() => {
            for entry in entries {
                match entry.as_str() {
                    Some(text) if evidence_entry_valid(text) => {}
                    Some(text) => errors.push(ValidationError {
                        field: "evidence".into(),
                        reason: format!("`{text}` is not `file:line` or `file:start-end`"),
                    }),
                    None => errors.push(ValidationError {
                        field: "evidence".into(),
                        reason: "evidence entries must be strings".into(),
                    }),
                }
            }
        }
        Some(_) => errors.push(ValidationError {
            field: "evidence".into(),
            reason: "must contain at least one file:line entry".into(),
        }),
        None => errors.push(ValidationError {
            field: "evidence".into(),
            reason: "missing or not an array".into(),
        }),
    }

    let verify_allowed: &[&str] = if lens == "correctness" {
        &["verified"]
    } else {
        VERIFY_STATUSES
    };
    require_enum(finding, "verifyStatus", verify_allowed, &mut errors);

    if lens == "correctness" {
        match finding.get("verificationMethod").and_then(Value::as_str) {
            Some("deterministic-reproduction") | Some("adversarial-skeptic-pass") => {}
            Some(other) => errors.push(ValidationError {
                field: "verificationMethod".into(),
                reason: format!("`{other}` is not a recognized verification method"),
            }),
            None => errors.push(ValidationError {
                field: "verificationMethod".into(),
                reason: "correctness findings require verificationMethod".into(),
            }),
        }
    }
    if lens == "minimize" {
        require_enum(
            finding,
            "ponytailTag",
            &["delete", "stdlib", "native", "yagni", "shrink"],
            &mut errors,
        );
    }
    if lens == "variant-analysis" {
        require_nonempty_string(finding, "parentFindingId", &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validates every finding a lens returned. The reconciliation path
/// (`mod.rs::verify_response`) calls this over the host result's declared
/// findings array before folding it into the accepted `ProviderResult`, so
/// a malformed finding fails closed rather than propagating into the
/// report.
pub fn validate_lens_output(lens: &str, findings: &[Value]) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        if let Err(finding_errors) = validate_finding(lens, finding) {
            for error in finding_errors {
                errors.push(ValidationError {
                    field: format!("findings[{index}].{}", error.field),
                    reason: error.reason,
                });
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_finding(lens: &str) -> Value {
        json!({
            "id": "f-1",
            "lens": lens,
            "severity": "high",
            "confidence": "likely",
            "evidence": ["src/x.rs:12-18"],
            "failureScenario": "a null pointer deref on the error path",
            "action": "add the missing null check",
            "verifyStatus": "unverified"
        })
    }

    #[test]
    fn every_lens_has_a_schema_except_unowned_ids() {
        for lens in [
            "doc-drift", "architecture", "correctness", "ai-slop", "naming", "dead-file",
            "schema", "security", "minimize", "performance", "a11y", "data-safety",
            "resilience", "platform-parity", "release-readiness", "variant-analysis",
        ] {
            assert!(lens_report_schema(lens).is_some(), "missing schema for {lens}");
        }
        assert!(lens_report_schema("not-a-lens").is_none());
    }

    #[test]
    fn base_finding_validates_for_a_plain_lens() {
        assert!(validate_finding("naming", &valid_finding("naming")).is_ok());
    }

    #[test]
    fn missing_required_field_fails_closed() {
        let mut finding = valid_finding("naming");
        finding.as_object_mut().unwrap().remove("failureScenario");
        let errors = validate_finding("naming", &finding).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "failureScenario"));
    }

    #[test]
    fn evidence_must_be_file_colon_line_shaped() {
        let mut finding = valid_finding("naming");
        finding["evidence"] = json!(["not-a-location"]);
        let errors = validate_finding("naming", &finding).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "evidence"));
    }

    #[test]
    fn correctness_requires_verified_status_and_method() {
        let finding = valid_finding("correctness");
        // valid_finding uses "unverified" and no verificationMethod: both
        // must fail for the correctness lens's verify-pass rule.
        let errors = validate_finding("correctness", &finding).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "verifyStatus"));
        assert!(errors.iter().any(|error| error.field == "verificationMethod"));

        let mut good = finding.clone();
        good["verifyStatus"] = json!("verified");
        good["verificationMethod"] = json!("deterministic-reproduction");
        assert!(validate_finding("correctness", &good).is_ok());
    }

    #[test]
    fn minimize_requires_a_ponytail_tag() {
        let finding = valid_finding("minimize");
        let errors = validate_finding("minimize", &finding).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "ponytailTag"));

        let mut good = finding.clone();
        good["ponytailTag"] = json!("yagni");
        assert!(validate_finding("minimize", &good).is_ok());
    }

    #[test]
    fn lens_mismatch_is_rejected() {
        let finding = valid_finding("naming");
        let errors = validate_finding("architecture", &finding).unwrap_err();
        assert!(errors.iter().any(|error| error.field == "lens"));
    }

    #[test]
    fn validate_lens_output_aggregates_indexed_errors() {
        let findings = vec![valid_finding("naming"), json!({"id": "bad"})];
        let errors = validate_lens_output("naming", &findings).unwrap_err();
        assert!(errors.iter().any(|error| error.field.starts_with("findings[1].")));
        assert!(!errors.iter().any(|error| error.field.starts_with("findings[0].")));
    }
}
