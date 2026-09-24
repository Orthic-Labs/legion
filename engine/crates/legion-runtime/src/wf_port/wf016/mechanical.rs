//! Port of `src/lib/remediation/mechanical.mjs`.
//!
//! Mechanical fix producers per SNIP-FIX-01 and SNIP-16 (B7-031). Only
//! qualified, rule-specific, low-risk transforms live here. A producer
//! proposes and previews; it never applies, and it never verifies its own
//! result. Anything unsupported or ambiguous becomes a MANUAL proposal
//! rather than a guess.
//!
//! `STRUCTURAL_PRODUCERS` (`src/lib/remediation/producers/structural.mjs`) is
//! ported natively at [`crate::wf_port::wf017::structural`] (packet wf017)
//! and is wired into [`all_producers`]/[`render_preview`] below via a small
//! per-producer adapter (`structural_adapted_producers`), closing the r55
//! port-completeness gap this module's doc comment used to flag.

use serde_json::{json, Value};

use super::config_producer::{config_producers, render_config_preview};
use super::util::digest_of;
use super::fix_contract::{fix_proposal, FixProposalInput};
use crate::wf_port::wf017::structural::{
    find_producer as find_structural_producer, render_structural_preview, ProducerRisk, StructuralEdit, StructuralPreview,
};

/// The JS source is untyped: a `preview.edits` entry is `{keyPath, value,
/// previous}` for a config producer or `{line, before, after}` for a
/// structural one, and `createMechanicalProposal`/`renderPreview` pass the
/// array through without caring which. This enum mirrors that duality
/// faithfully while keeping each shape's fields typed.
#[derive(Debug, Clone, PartialEq)]
pub enum Edit {
    Config { key_path: Vec<String>, value: Value, previous: Value },
    Structural { line: usize, before: String, after: String },
}

impl Edit {
    fn to_json(&self) -> Value {
        match self {
            Edit::Config { key_path, value, previous } => json!({ "keyPath": key_path, "value": value, "previous": previous }),
            Edit::Structural { line, before, after } => json!({ "line": line, "before": before, "after": after }),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PreviewResult {
    pub edits: Vec<Edit>,
    pub public_surface_changes: Vec<String>,
    pub unsupported: Option<String>,
}

/// A qualified mechanical producer. `preview` is a plain function pointer
/// (not a closure) because every producer in this chunk needs only its own
/// constants, matching the JS module-level `keySetProducer(...)` factories.
#[derive(Clone)]
pub struct Producer {
    pub id: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub risk: &'static str,
    pub rule_ids: Vec<&'static str>,
    pub description: &'static str,
    pub preconditions: Vec<&'static str>,
    pub expected_behavior: Vec<&'static str>,
    pub affected_families: Vec<&'static str>,
    pub validation_plan: Vec<&'static str>,
    pub preview: fn(text: &str, finding: &Value) -> PreviewResult,
}

/// Extracts `finding.location.path`, i.e. what `mechanical.mjs`'s caller
/// (`planMechanicalRemediation`) resolves before ever calling
/// `producer.preview`. A structural producer's JS `preview({ path, text,
/// finding })` only reads `path`/`text`, so this is the one piece of
/// `finding` a structural producer's `fn(text, finding)` adapter needs.
fn path_from_finding(finding: &Value) -> String {
    finding.get("location").and_then(|l| l.get("path")).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn structural_result(preview: StructuralPreview) -> PreviewResult {
    PreviewResult {
        edits: preview
            .edits
            .into_iter()
            .map(|e| Edit::Structural { line: e.line, before: e.before, after: e.after })
            .collect(),
        public_surface_changes: preview.public_surface_changes,
        unsupported: None,
    }
}

fn preview_structural_tls_reject_unauthorized(text: &str, finding: &Value) -> PreviewResult {
    let path = path_from_finding(finding);
    let producer = find_structural_producer("structural.tls-reject-unauthorized").expect("registered in STRUCTURAL_PRODUCERS");
    structural_result(producer.preview(&path, text))
}

fn preview_structural_dom_innerhtml_to_textcontent(text: &str, finding: &Value) -> PreviewResult {
    let path = path_from_finding(finding);
    let producer = find_structural_producer("structural.dom-innerhtml-to-textcontent").expect("registered in STRUCTURAL_PRODUCERS");
    structural_result(producer.preview(&path, text))
}

fn structural_risk(risk: ProducerRisk) -> &'static str {
    match risk {
        ProducerRisk::Low => "low",
        ProducerRisk::Medium => "medium",
        ProducerRisk::High => "high",
    }
}

/// Adapts `wf017::structural::STRUCTURAL_PRODUCERS` into this module's
/// `Producer` shape (metadata copied verbatim; `preview` routed through the
/// two per-producer function-pointer adapters above, since `Producer.preview`
/// is a plain `fn`, not a closure — see the struct doc comment).
fn structural_adapted_producers() -> Vec<Producer> {
    vec![
        {
            let source = find_structural_producer("structural.tls-reject-unauthorized").expect("registered in STRUCTURAL_PRODUCERS");
            Producer {
                id: source.id,
                version: source.version,
                kind: source.kind,
                risk: structural_risk(source.risk),
                rule_ids: source.rule_ids.to_vec(),
                description: source.description,
                preconditions: source.preconditions.to_vec(),
                expected_behavior: source.expected_behavior.to_vec(),
                affected_families: source.affected_families.to_vec(),
                validation_plan: source.validation_plan.to_vec(),
                preview: preview_structural_tls_reject_unauthorized,
            }
        },
        {
            let source = find_structural_producer("structural.dom-innerhtml-to-textcontent").expect("registered in STRUCTURAL_PRODUCERS");
            Producer {
                id: source.id,
                version: source.version,
                kind: source.kind,
                risk: structural_risk(source.risk),
                rule_ids: source.rule_ids.to_vec(),
                description: source.description,
                preconditions: source.preconditions.to_vec(),
                expected_behavior: source.expected_behavior.to_vec(),
                affected_families: source.affected_families.to_vec(),
                validation_plan: source.validation_plan.to_vec(),
                preview: preview_structural_dom_innerhtml_to_textcontent,
            }
        },
    ]
}

/// `const ALL_PRODUCERS = Object.freeze([...STRUCTURAL_PRODUCERS, ...CONFIG_PRODUCERS]);`
pub fn all_producers() -> Vec<Producer> {
    let mut producers = structural_adapted_producers();
    producers.extend(config_producers());
    producers
}

fn registry_qualification_digest(producer: &Producer) -> String {
    digest_of(
        "mechanical-producer-qualification",
        &json!({
            "id": producer.id,
            "version": producer.version,
            "kind": producer.kind,
            "ruleIds": producer.rule_ids,
            "preconditions": producer.preconditions,
            "validationPlan": producer.validation_plan,
        }),
    )
}

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub id: String,
    pub producer_version: String,
    pub kind: String,
    pub risk: String,
    pub rule_ids: Vec<String>,
    pub description: String,
    pub qualification_digest: String,
}

/// `export const MECHANICAL_REGISTRY = Object.freeze({...});` — this returns
/// the `producers` list (sorted by `id`, as the JS `.sort((a, b) =>
/// a.id.localeCompare(b.id))` does); the surrounding `schemaVersion`/`kind`/
/// `source`/`generator` envelope fields are fixed constants reproduced in
/// [`mechanical_registry_json`].
pub fn mechanical_registry() -> Vec<RegistryEntry> {
    let mut entries: Vec<RegistryEntry> = all_producers()
        .iter()
        .map(|p| RegistryEntry {
            id: p.id.to_string(),
            producer_version: p.version.to_string(),
            kind: p.kind.to_string(),
            risk: p.risk.to_string(),
            rule_ids: p.rule_ids.iter().map(|s| s.to_string()).collect(),
            description: p.description.to_string(),
            qualification_digest: registry_qualification_digest(p),
        })
        .collect();
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

pub fn mechanical_registry_json() -> Value {
    let producers: Vec<Value> = mechanical_registry()
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id,
                "producerVersion": e.producer_version,
                "kind": e.kind,
                "risk": e.risk,
                "ruleIds": e.rule_ids,
                "description": e.description,
                "qualificationDigest": e.qualification_digest,
            })
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-mechanical-remediation-registry",
        "source": "src/lib/remediation/producers/",
        "generator": "src/lib/remediation/mechanical.mjs",
        "producers": producers,
    })
}

pub fn producer_for(rule_id: &str) -> Option<Producer> {
    all_producers().into_iter().find(|p| p.rule_ids.contains(&rule_id))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct MechanicalError(pub String);

impl std::fmt::Display for MechanicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn assert_producer_qualified(producer: &Producer, rule_id: &str) -> Result<(), MechanicalError> {
    let registry = mechanical_registry();
    let Some(entry) = registry.iter().find(|e| e.id == producer.id) else {
        return Err(MechanicalError(format!("producer {} is not in the mechanical registry", producer.id)));
    };
    if entry.producer_version != producer.version {
        return Err(MechanicalError(format!(
            "producer {} version {} is not the qualified version {}",
            producer.id, producer.version, entry.producer_version
        )));
    }
    if !entry.rule_ids.iter().any(|id| id == rule_id) {
        return Err(MechanicalError(format!("producer {} is not qualified for rule {rule_id}", producer.id)));
    }
    Ok(())
}

fn assert_sandbox(sandbox: &Value) -> Result<(), MechanicalError> {
    if sandbox.get("kind").and_then(Value::as_str) != Some("legion-remediation-sandbox") {
        return Err(MechanicalError("mechanical producers run only inside a remediation sandbox".to_string()));
    }
    if sandbox.get("primaryRepositoryMutated").and_then(Value::as_bool) != Some(false) {
        return Err(MechanicalError("refusing to produce against a sandbox that reports the primary repository mutated".to_string()));
    }
    Ok(())
}

/// Faithful port of `manualProposal`.
pub fn manual_proposal(finding: &Value, reason: &str, binding: &Value, target_paths: Vec<String>) -> Value {
    let mut sorted_paths = target_paths;
    sorted_paths.sort();
    let finding_id = finding.get("id").cloned().unwrap_or(Value::Null);
    let mut body = json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-proposal",
        "findingIds": [finding_id],
        "owner": "manual",
        "producer": {},
        "targetPaths": sorted_paths,
        "preconditions": Vec::<Value>::new(),
        "patch": Value::Null,
        "expectedBehavior": Vec::<Value>::new(),
        "publicSurfaceChanges": Vec::<Value>::new(),
        "affectedFamilies": Vec::<Value>::new(),
        "validationPlan": Vec::<Value>::new(),
        "rollback": {},
        "tier": "MANUAL",
        "reason": reason,
        "binding": binding,
    });
    let id = digest_of("remediation-proposal", &body);
    body.as_object_mut().unwrap().insert("id".to_string(), Value::String(id));
    body
}

/// Faithful port of `createMechanicalProposal`. `target_path` mirrors the JS
/// `finding.location?.path ?? null` — `None` serializes as JSON `null`,
/// exactly as an absent finding location would in JS.
pub fn create_mechanical_proposal(finding: &Value, producer: &Producer, preview: &PreviewResult, target_path: Option<&str>, binding: &Value) -> Value {
    let target_path_json: Value = target_path.map(Value::from).unwrap_or(Value::Null);
    let edits_json: Vec<Value> = preview.edits.iter().map(Edit::to_json).collect();
    let render_key = if producer.kind == "config" { "config" } else { "structural" };
    let patch_body = json!({
        "producer": producer.id,
        "path": target_path_json,
        "render": render_key,
        "edits": edits_json,
    });
    let finding_id = finding.get("id").cloned().unwrap_or(Value::Null);
    let mut body = json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-proposal",
        "findingIds": [finding_id],
        "owner": "code",
        "producer": { "id": producer.id, "kind": producer.kind, "version": producer.version, "self": "producer-only" },
        "targetPaths": [target_path_json],
        "preconditions": producer.preconditions,
        "patch": {
            "path": format!("patches/{}.patch", producer.id),
            "digest": digest_of("remediation-patch", &patch_body),
            "format": "legion-preview-edits",
            "edits": edits_json,
        },
        "expectedBehavior": producer.expected_behavior,
        "publicSurfaceChanges": preview.public_surface_changes,
        "affectedFamilies": producer.affected_families,
        "validationPlan": producer.validation_plan,
        "rollback": {
            "reversePatch": { "strategy": "restore-checkpoint-then-reverse-edits", "edits": preview.edits.iter().map(Edit::to_json).collect::<Vec<_>>() },
            "checkpointRequired": true,
        },
        "tier": "MECHANICAL",
        "binding": binding,
    });
    let id = digest_of("remediation-proposal", &body);
    body.as_object_mut().unwrap().insert("id".to_string(), Value::String(id));
    body
}

/// Plan one mechanical remediation. Returns a SNIP-16 proposal, or a MANUAL
/// proposal when no qualified producer applies or the target is ambiguous.
///
/// `read_file` mirrors the JS synchronous `readFile(path)` callback; it
/// returns the file text as `String` (the JS caller is expected to throw on
/// its own if the read fails — that is out of this function's contract in
/// both languages).
pub fn plan_mechanical_remediation<F: Fn(&str) -> String>(finding: &Value, sandbox: &Value, read_file: F, binding: &Value) -> Result<Value, MechanicalError> {
    assert_sandbox(sandbox)?;
    let rule_id = finding.get("ruleId").and_then(Value::as_str).unwrap_or_default();
    let Some(producer) = producer_for(rule_id) else {
        return Ok(manual_proposal(finding, &format!("no qualified mechanical producer for rule {rule_id}"), binding, vec![]));
    };
    assert_producer_qualified(&producer, rule_id)?;

    let target_path = finding.get("location").and_then(|l| l.get("path")).and_then(Value::as_str);
    let text = target_path.map(|p| read_file(p)).unwrap_or_default();
    let preview = (producer.preview)(&text, finding);

    if let Some(unsupported) = &preview.unsupported {
        return Ok(manual_proposal(
            finding,
            &format!("unsupported target: {unsupported}"),
            binding,
            target_path.map(|p| vec![p.to_string()]).unwrap_or_default(),
        ));
    }
    if preview.edits.is_empty() {
        return Ok(manual_proposal(
            finding,
            "no mechanical edit applies to the finding target",
            binding,
            target_path.map(|p| vec![p.to_string()]).unwrap_or_default(),
        ));
    }
    let has_location = finding.get("location").is_some();
    if !has_location && preview.edits.len() > 1 {
        return Ok(manual_proposal(
            finding,
            &format!("ambiguous target: {} candidate sites and no unique finding location", preview.edits.len()),
            binding,
            vec![],
        ));
    }
    Ok(create_mechanical_proposal(finding, &producer, &preview, target_path, binding))
}

/// Faithful port of `renderPreview`: `kind === 'config' ? renderConfigPreview
/// (text, edits) : renderStructuralPreview(text, edits)`.
pub fn render_preview(producer: &Producer, text: &str, edits: &[Edit]) -> Result<String, MechanicalError> {
    if producer.kind == "config" {
        render_config_preview(text, edits).map_err(|e| MechanicalError(format!("invalid config JSON: {e}")))
    } else {
        let structural_edits: Vec<StructuralEdit> = edits
            .iter()
            .filter_map(|edit| match edit {
                Edit::Structural { line, before, after } => {
                    Some(StructuralEdit { line: *line, before: before.clone(), after: after.clone() })
                }
                Edit::Config { .. } => None,
            })
            .collect();
        Ok(render_structural_preview(text, &structural_edits))
    }
}

// ---------------------------------------------------------------------------
// Pre-existing producer helpers retained for their existing callers.
// ---------------------------------------------------------------------------

pub fn mechanical_ast_grep_proposal(finding: &Value, edits: &[Value]) -> Value {
    let mut files: Vec<String> = edits.iter().filter_map(|e| e.get("file").and_then(Value::as_str).map(str::to_owned)).collect();
    files.sort();
    files.dedup();
    fix_proposal(FixProposalInput {
        finding_id: finding.get("id").cloned().unwrap_or(Value::Null),
        root_cause_digest: finding.get("rootCauseDigest").cloned().unwrap_or(Value::Null),
        producer: json!({ "kind": "mechanical", "engine": "ast-grep", "version": "1" }),
        target_paths: files,
        preconditions: vec!["rewrite preview is parse-clean".to_string(), "patch is idempotent".to_string()],
        patch: json!({ "path": "patches/fix.patch", "digest": Value::Null }),
        expected_behavior: vec!["rewritten sites no longer match the finding rule".to_string()],
        risks: vec!["behavioral change to covered call sites".to_string()],
        validation_commands: vec!["parse-check".to_string(), "affected-provider-rerun".to_string()],
        tier: json!("MECHANICAL"),
    })
}

pub fn mechanical_config_proposal(finding: &Value, config_path: &str) -> Value {
    fix_proposal(FixProposalInput {
        finding_id: finding.get("id").cloned().unwrap_or(Value::Null),
        root_cause_digest: finding.get("rootCauseDigest").cloned().unwrap_or(Value::Null),
        producer: json!({ "kind": "mechanical", "engine": "config-transform", "version": "1" }),
        target_paths: vec![config_path.to_string()],
        preconditions: vec!["configuration value is validated by schema".to_string()],
        patch: json!({ "path": "patches/config.patch", "digest": Value::Null }),
        expected_behavior: vec!["configuration no longer matches the finding rule".to_string()],
        risks: vec!["deployment behavior change".to_string()],
        validation_commands: vec!["config-schema-check".to_string(), "affected-provider-rerun".to_string()],
        tier: json!("MECHANICAL"),
    })
}

pub fn mechanical_dependency_proposal(finding: &Value, manifest_path: &str) -> Value {
    fix_proposal(FixProposalInput {
        finding_id: finding.get("id").cloned().unwrap_or(Value::Null),
        root_cause_digest: finding.get("rootCauseDigest").cloned().unwrap_or(Value::Null),
        producer: json!({ "kind": "mechanical", "engine": "dependency-policy", "version": "1" }),
        target_paths: vec![manifest_path.to_string()],
        preconditions: vec!["lockfile update is offline-safe".to_string()],
        patch: json!({ "path": "patches/dependency.patch", "digest": Value::Null }),
        expected_behavior: vec!["dependency satisfies the policy".to_string()],
        risks: vec!["transitive breakage".to_string()],
        validation_commands: vec!["lockfile-reconcile".to_string(), "affected-provider-rerun".to_string()],
        tier: json!("MECHANICAL"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Value {
        json!({ "kind": "legion-remediation-sandbox", "primaryRepositoryMutated": false })
    }

    #[test]
    fn registry_lists_config_producers_sorted_by_id() {
        let entries = mechanical_registry();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "config.content-type-nosniff",
                "config.cookie-samesite",
                "structural.dom-innerhtml-to-textcontent",
                "structural.tls-reject-unauthorized",
            ]
        );
        for entry in &entries {
            assert!(entry.qualification_digest.starts_with("sha256:"));
        }
    }

    #[test]
    fn producer_for_finds_by_rule_id() {
        let producer = producer_for("browser-http.cookie-samesite").expect("found");
        assert_eq!(producer.id, "config.cookie-samesite");
        assert!(producer_for("no-such-rule").is_none());
    }

    #[test]
    fn assert_producer_qualified_rejects_version_drift() {
        let mut producer = producer_for("browser-http.cookie-samesite").unwrap();
        producer.version = "9.9.9";
        let err = assert_producer_qualified(&producer, "browser-http.cookie-samesite").unwrap_err();
        assert!(err.0.contains("is not the qualified version"));
    }

    #[test]
    fn assert_producer_qualified_rejects_unqualified_rule() {
        let producer = producer_for("browser-http.cookie-samesite").unwrap();
        let err = assert_producer_qualified(&producer, "some-other-rule").unwrap_err();
        assert!(err.0.contains("is not qualified for rule"));
    }

    #[test]
    fn plan_mechanical_remediation_produces_config_proposal() {
        let finding = json!({
            "id": "finding-1",
            "ruleId": "browser-http.cookie-samesite",
            "location": { "path": "config.json" },
        });
        let proposal = plan_mechanical_remediation(&finding, &sandbox(), |_path| "{\n  \"cookie\": {}\n}".to_string(), &json!({ "runId": "r1" })).unwrap();
        assert_eq!(proposal["tier"], json!("MECHANICAL"));
        assert_eq!(proposal["owner"], json!("code"));
        assert_eq!(proposal["targetPaths"], json!(["config.json"]));
        assert!(proposal["id"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn plan_mechanical_remediation_falls_back_to_manual_for_unknown_rule() {
        let finding = json!({ "id": "finding-2", "ruleId": "no-such-rule" });
        let proposal = plan_mechanical_remediation(&finding, &sandbox(), |_| String::new(), &json!({})).unwrap();
        assert_eq!(proposal["tier"], json!("MANUAL"));
        assert!(proposal["reason"].as_str().unwrap().contains("no qualified mechanical producer"));
    }

    #[test]
    fn plan_mechanical_remediation_falls_back_to_manual_when_no_edit_applies() {
        let finding = json!({
            "id": "finding-3",
            "ruleId": "browser-http.cookie-samesite",
            "location": { "path": "config.json" },
        });
        let proposal =
            plan_mechanical_remediation(&finding, &sandbox(), |_| "{\n  \"cookie\": { \"sameSite\": \"lax\" }\n}".to_string(), &json!({})).unwrap();
        assert_eq!(proposal["tier"], json!("MANUAL"));
        assert!(proposal["reason"].as_str().unwrap().contains("no mechanical edit applies"));
    }

    #[test]
    fn plan_mechanical_remediation_falls_back_to_manual_for_invalid_json() {
        let finding = json!({
            "id": "finding-4",
            "ruleId": "browser-http.cookie-samesite",
            "location": { "path": "config.json" },
        });
        let proposal = plan_mechanical_remediation(&finding, &sandbox(), |_| "not json".to_string(), &json!({})).unwrap();
        assert_eq!(proposal["tier"], json!("MANUAL"));
        assert!(proposal["reason"].as_str().unwrap().contains("unsupported target"));
    }

    #[test]
    fn plan_mechanical_remediation_rejects_mutated_sandbox() {
        let finding = json!({ "id": "f", "ruleId": "browser-http.cookie-samesite" });
        let bad_sandbox = json!({ "kind": "legion-remediation-sandbox", "primaryRepositoryMutated": true });
        let err = plan_mechanical_remediation(&finding, &bad_sandbox, |_| String::new(), &json!({})).unwrap_err();
        assert!(err.0.contains("primary repository mutated"));
    }

    #[test]
    fn render_preview_structural_kind_applies_line_edits() {
        let producer = Producer {
            id: "structural.stub",
            version: "1",
            kind: "structural",
            risk: "low",
            rule_ids: vec![],
            description: "",
            preconditions: vec![],
            expected_behavior: vec![],
            affected_families: vec![],
            validation_plan: vec![],
            preview: |_text, _finding| PreviewResult::default(),
        };
        let edits = vec![Edit::Structural { line: 1, before: "rejectUnauthorized: false".to_string(), after: "rejectUnauthorized: true".to_string() }];
        let rendered = render_preview(&producer, "rejectUnauthorized: false", &edits).unwrap();
        assert_eq!(rendered, "rejectUnauthorized: true");
    }

    #[test]
    fn structural_producers_are_wired_into_the_registry_and_planner() {
        let entries = mechanical_registry();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"structural.tls-reject-unauthorized"));
        assert!(ids.contains(&"structural.dom-innerhtml-to-textcontent"));

        let finding = json!({
            "id": "finding-5",
            "ruleId": "insecure-defaults.tls-reject-unauthorized",
            "location": { "path": "agent.js" },
        });
        let proposal = plan_mechanical_remediation(
            &finding,
            &sandbox(),
            |_path| "const agent = new https.Agent({ rejectUnauthorized: false });".to_string(),
            &json!({ "runId": "r1" }),
        )
        .unwrap();
        assert_eq!(proposal["tier"], json!("MECHANICAL"));
        assert_eq!(proposal["producer"]["id"], json!("structural.tls-reject-unauthorized"));
        // Mirrors JS `createMechanicalProposal`: "render" only exists on the
        // ephemeral `patchBody` used to compute `patch.digest`, never on the
        // `patch` object itself.
        assert_eq!(proposal["patch"]["format"], json!("legion-preview-edits"));
        assert!(proposal["patch"]["digest"].is_string());
        assert_eq!(proposal["patch"]["edits"][0]["after"], json!("rejectUnauthorized: true"));
    }

    #[test]
    fn legacy_mechanical_config_proposal_matches_fix_proposal_shape() {
        let finding = json!({ "id": "f1", "rootCauseDigest": "sha256:aa" });
        let proposal = mechanical_config_proposal(&finding, "config.json");
        assert_eq!(proposal["kind"], json!("legion-fix-proposal"));
        assert_eq!(proposal["tier"], json!("MECHANICAL"));
        assert_eq!(proposal["targetPaths"], json!(["config.json"]));
    }

    #[test]
    fn legacy_mechanical_ast_grep_proposal_dedupes_and_sorts_files() {
        let finding = json!({ "id": "f1" });
        let edits = vec![json!({ "file": "b.js" }), json!({ "file": "a.js" }), json!({ "file": "a.js" })];
        let proposal = mechanical_ast_grep_proposal(&finding, &edits);
        assert_eq!(proposal["targetPaths"], json!(["a.js", "b.js"]));
    }
}
