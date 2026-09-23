//! Port of src/lib/content/{brief,claim-proof-ledger,extract,identity,
//! inventory,lineage,skill-compiler,text-lock,voice-context}.mjs.

use super::sha256_hex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

// ---- identity.mjs ----

pub fn text_digest(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

#[derive(Debug, Clone, Default)]
pub struct ContentSource {
    pub file: Option<String>,
}
#[derive(Debug, Clone, Default)]
pub struct ContentSurface {
    pub route: Option<String>,
    pub kind: Option<String>,
}

pub fn content_id(text: &str, source: &ContentSource, surface: &ContentSurface) -> String {
    let joined = [
        text,
        source.file.as_deref().unwrap_or(""),
        surface.route.as_deref().unwrap_or(""),
        surface.kind.as_deref().unwrap_or(""),
    ]
    .join("\0");
    sha256_hex(joined.as_bytes())
}

// ---- brief.mjs ----

pub fn create_content_brief(explicit: &Value, inferred: &Value) -> Value {
    let explicit_len = explicit.as_object().map(|o| o.len()).unwrap_or(0);
    json!({
        "schemaVersion": 1,
        "kind": "legion-content-brief",
        "explicit": explicit,
        "inferred": inferred,
        "status": if explicit_len > 0 { "pass" } else { "review-required" },
        "coverageGaps": if explicit_len > 0 { json!([]) } else { json!(["content-intent-missing"]) },
    })
}

// ---- claim-proof-ledger.mjs ----

pub fn build_claim_proof_ledger(claims: &[Value], evidence: &[Value]) -> Value {
    let source: std::collections::HashMap<String, &Value> = evidence
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item)))
        .collect();
    let out_claims: Vec<Value> = claims
        .iter()
        .map(|claim| {
            let refs: Vec<Value> = claim
                .get("evidenceRefs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let proof: Vec<Value> = refs
                .iter()
                .filter_map(|id| id.as_str().and_then(|s| source.get(s)).cloned().cloned())
                .collect();
            let bound = !refs.is_empty()
                && refs
                    .iter()
                    .all(|id| id.as_str().is_some_and(|s| source.contains_key(s)));
            let mut merged = claim.clone();
            if let Value::Object(ref mut map) = merged {
                map.insert("proof".into(), json!(proof));
                map.insert(
                    "disposition".into(),
                    json!(if bound { "bound" } else { "unproven" }),
                );
            }
            merged
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-claim-proof-ledger",
        "claims": out_claims,
        "evidence": evidence,
    })
}

// ---- lineage.mjs ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentLineageItem {
    pub id: String,
    #[serde(rename = "textDigest")]
    pub text_digest: String,
    pub source: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentLineageEntry {
    pub id: String,
    pub disposition: String,
    #[serde(rename = "priorId")]
    pub prior_id: Option<String>,
}

pub fn classify_content_lineage(
    previous: &[ContentLineageItem],
    current: &[ContentLineageItem],
) -> Vec<ContentLineageEntry> {
    current
        .iter()
        .map(|item| {
            let by_id = previous.iter().find(|p| p.id == item.id);
            let by_digest = previous.iter().find(|p| p.text_digest == item.text_digest);
            let old = by_id.or(by_digest);
            let disposition = match old {
                None => "new".to_string(),
                Some(old) if old.text_digest == item.text_digest => {
                    let old_file = old.source.as_ref().and_then(|s| s.get("file"));
                    let new_file = item.source.as_ref().and_then(|s| s.get("file"));
                    if old_file == new_file { "unchanged" } else { "moved" }.to_string()
                }
                Some(_) => "revised".to_string(),
            };
            ContentLineageEntry {
                id: item.id.clone(),
                disposition,
                prior_id: old.map(|o| o.id.clone()),
            }
        })
        .collect()
}

// ---- voice-context.mjs ----

pub fn create_voice_context(terms: &Value, prohibited: &Value, source: Option<&Value>) -> Value {
    let term_entries: Vec<Value> = terms
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(canonical, aliases)| {
                    let alias_list = if aliases.is_array() {
                        aliases.clone()
                    } else {
                        json!([aliases])
                    };
                    json!({"canonical": canonical, "aliases": alias_list})
                })
                .collect()
        })
        .unwrap_or_default();
    let has_source = source.is_some();
    json!({
        "schemaVersion": 1,
        "kind": "legion-voice-context",
        "terms": term_entries,
        "prohibited": prohibited,
        "authoritative": has_source,
        "status": if has_source { "pass" } else { "unproven" },
    })
}

// ---- text-lock.mjs ----

#[derive(Debug, thiserror::Error)]
#[error("contentId, text, approver, reason, and approvedAt are required")]
pub struct TextLockError;

#[allow(clippy::too_many_arguments)]
pub fn create_text_lock(
    content_id: &str,
    text: &str,
    approver: &str,
    reason: &str,
    approved_at: &str,
    scope: Option<&str>,
    supersedes: Option<&str>,
) -> Result<Value, TextLockError> {
    if content_id.is_empty() || text.is_empty() || approver.is_empty() || reason.is_empty() || approved_at.is_empty()
    {
        return Err(TextLockError);
    }
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-text-lock",
        "contentId": content_id,
        "textDigest": text_digest(text),
        "approver": approver,
        "reason": reason,
        "approvedAt": approved_at,
        "scope": scope,
        "supersedes": supersedes,
    }))
}

pub fn verify_text_lock(lock: &Value, text: &str) -> Value {
    let matches = lock.get("textDigest").and_then(Value::as_str) == Some(text_digest(text).as_str());
    if matches {
        json!({"status": "pass"})
    } else {
        json!({"status": "reopened", "reason": "approved-text-changed"})
    }
}

// ---- inventory.mjs ----

pub fn create_content_inventory(items: &[Value], binding: &Value) -> Value {
    let normalized: Vec<Value> = items
        .iter()
        .map(|item| {
            let text = item.get("text").and_then(Value::as_str).unwrap_or("");
            let source = item.get("source").cloned().unwrap_or(json!({}));
            let surface = item.get("surface").cloned().unwrap_or(json!({}));
            let file = item.get("source").and_then(ContentSource::from_json_file);
            let route = item.get("surface").and_then(|s| s.get("route")).and_then(Value::as_str).map(String::from);
            let kind = item.get("surface").and_then(|s| s.get("kind")).and_then(Value::as_str).map(String::from);
            let id = item
                .get("id")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| {
                    content_id(
                        text,
                        &ContentSource { file: file.clone() },
                        &ContentSurface { route, kind },
                    )
                });
            let mut merged = item.clone();
            if let Value::Object(ref mut map) = merged {
                map.insert("schemaVersion".into(), json!(1));
                map.insert("kind".into(), json!("legion-content-item"));
                map.insert("id".into(), json!(id));
                map.insert("textDigest".into(), json!(text_digest(text)));
                map.insert("source".into(), source);
                map.insert("surface".into(), surface);
                map.insert(
                    "evidenceRefs".into(),
                    item.get("evidenceRefs").cloned().unwrap_or(json!([])),
                );
                map.insert("binding".into(), binding.clone());
            }
            merged
        })
        .collect();
    let complete = normalized.iter().all(|item| {
        item.get("text").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && item
                .get("source")
                .and_then(|s| s.get("file"))
                .and_then(Value::as_str)
                .is_some()
    });
    let coverage_gaps: Vec<Value> = normalized
        .iter()
        .filter(|item| {
            item.get("source")
                .and_then(|s| s.get("file"))
                .and_then(Value::as_str)
                .is_none()
        })
        .map(|item| json!(format!("source-missing:{}", item.get("id").and_then(Value::as_str).unwrap_or(""))))
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-content-inventory",
        "items": normalized,
        "binding": binding,
        "complete": complete,
        "coverageGaps": coverage_gaps,
    })
}

impl ContentSource {
    fn from_json_file(v: &Value) -> Option<String> {
        v.get("file").and_then(Value::as_str).map(String::from)
    }
}

// ---- extract.mjs ----

static TEXT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r">\s*([^<>{}\n][^<>{}]*?)\s*<").unwrap());
static QUOTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:title|label|placeholder|aria-label|accessibilityLabel|message)\s*[:=]\s*["'`]([^"'`]+)["'`]"#).unwrap()
});

#[derive(Debug, Clone, Default)]
pub struct Artifact {
    pub text: Option<String>,
    pub path: Option<String>,
    pub kind: Option<String>,
    pub route: Option<String>,
    pub surface_type: Option<String>,
    pub evidence_refs: Vec<String>,
}

pub fn extract_visible_content(artifacts: &[Artifact], binding: &Value) -> Value {
    let mut items = Vec::new();
    for artifact in artifacts {
        let Some(text) = &artifact.text else { continue };
        for caps in TEXT_RE.captures_iter(text) {
            items.push(extract_item(&caps[1], artifact));
        }
        for caps in QUOTED_RE.captures_iter(text) {
            items.push(extract_item(&caps[1], artifact));
        }
    }
    create_content_inventory(&items, binding)
}

fn extract_item(text: &str, artifact: &Artifact) -> Value {
    json!({
        "text": text.trim(),
        "source": {"file": artifact.path, "kind": artifact.kind.clone().unwrap_or_else(|| "unknown".into())},
        "surface": {"route": artifact.route, "type": artifact.surface_type.clone().unwrap_or_else(|| "unknown".into())},
        "evidenceRefs": artifact.evidence_refs,
    })
}

// ---- skill-compiler.mjs ----

static AUTHORING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:write|rewrite|publish|send|create|delete)\b").unwrap());

#[derive(Debug, Clone, Default)]
pub struct SkillEntry {
    pub id: Option<String>,
    pub text: Option<String>,
    pub audit: Option<bool>,
    pub family: Option<String>,
    pub kind: Option<String>,
    pub evidence_requirement: Option<String>,
    pub remediation_owner: Option<String>,
    pub source_uri: Option<String>,
}

pub fn compile_writing_audit_profile(entries: &[SkillEntry], source_uri: &str) -> Value {
    let mut rules = Vec::new();
    let mut exclusions = Vec::new();
    for entry in entries {
        let (Some(id), Some(text)) = (&entry.id, &entry.text) else {
            exclusions.push(json!({"id": entry.id, "reason": "skill-entry-incomplete"}));
            continue;
        };
        if AUTHORING_RE.is_match(text) || entry.audit == Some(false) {
            exclusions.push(json!({"id": id, "reason": "authoring-instruction-excluded"}));
            continue;
        }
        rules.push(json!({
            "id": format!("writing.{id}"),
            "family": entry.family.clone().unwrap_or_else(|| "copy".into()),
            "kind": entry.kind.clone().unwrap_or_else(|| "interpretive".into()),
            "evidenceRequirement": entry.evidence_requirement.clone().unwrap_or_else(|| "content-inventory".into()),
            "remediationOwner": entry.remediation_owner.clone().unwrap_or_else(|| "writing".into()),
            "sourceUri": entry.source_uri.clone().unwrap_or_else(|| source_uri.to_string()),
        }));
    }
    json!({
        "schemaVersion": 1,
        "kind": "legion-writing-audit-profile",
        "sourceUri": source_uri,
        "rules": rules,
        "exclusions": exclusions,
        "status": if entries.is_empty() { "unproven" } else { "pass" },
        "coverageGaps": if entries.is_empty() { json!(["writing-skill-bundle-missing"]) } else { json!([]) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_brief_requires_explicit_intent() {
        let brief = create_content_brief(&json!({}), &json!({}));
        assert_eq!(brief["status"], "review-required");
        assert_eq!(brief["coverageGaps"][0], "content-intent-missing");
    }

    #[test]
    fn content_brief_passes_with_explicit_intent() {
        let brief = create_content_brief(&json!({"goal": "x"}), &json!({}));
        assert_eq!(brief["status"], "pass");
    }

    #[test]
    fn claim_proof_ledger_binds_when_all_evidence_present() {
        let claims = vec![json!({"id": "c1", "evidenceRefs": ["e1"]})];
        let evidence = vec![json!({"id": "e1", "text": "proof"})];
        let ledger = build_claim_proof_ledger(&claims, &evidence);
        assert_eq!(ledger["claims"][0]["disposition"], "bound");
    }

    #[test]
    fn claim_proof_ledger_unproven_when_evidence_missing() {
        let claims = vec![json!({"id": "c1", "evidenceRefs": ["missing"]})];
        let ledger = build_claim_proof_ledger(&claims, &[]);
        assert_eq!(ledger["claims"][0]["disposition"], "unproven");
    }

    #[test]
    fn content_lineage_classifies_new_unchanged_moved_revised() {
        let previous = vec![
            ContentLineageItem { id: "a".into(), text_digest: "d1".into(), source: Some(json!({"file": "f1"})) },
            ContentLineageItem { id: "b".into(), text_digest: "d2".into(), source: Some(json!({"file": "f2"})) },
            ContentLineageItem { id: "c".into(), text_digest: "d3".into(), source: Some(json!({"file": "f3"})) },
        ];
        let current = vec![
            ContentLineageItem { id: "a".into(), text_digest: "d1".into(), source: Some(json!({"file": "f1"})) }, // unchanged
            ContentLineageItem { id: "b".into(), text_digest: "d2".into(), source: Some(json!({"file": "f2-moved"})) }, // moved
            ContentLineageItem { id: "c".into(), text_digest: "d3-new".into(), source: Some(json!({"file": "f3"})) }, // revised
            ContentLineageItem { id: "d".into(), text_digest: "d4".into(), source: Some(json!({"file": "f4"})) }, // new
        ];
        let entries = classify_content_lineage(&previous, &current);
        assert_eq!(entries[0].disposition, "unchanged");
        assert_eq!(entries[1].disposition, "moved");
        assert_eq!(entries[2].disposition, "revised");
        assert_eq!(entries[3].disposition, "new");
    }

    #[test]
    fn text_lock_round_trips_and_reopens_on_edit() {
        let lock = create_text_lock("c1", "hello", "adrian", "approved", "2026-01-01", None, None).unwrap();
        assert_eq!(verify_text_lock(&lock, "hello")["status"], "pass");
        assert_eq!(verify_text_lock(&lock, "hello!")["status"], "reopened");
    }

    #[test]
    fn text_lock_requires_all_fields() {
        assert!(create_text_lock("", "hello", "a", "r", "t", None, None).is_err());
    }

    #[test]
    fn content_inventory_flags_missing_source() {
        let items = vec![json!({"text": "hi", "source": {}, "surface": {}})];
        let inv = create_content_inventory(&items, &json!({}));
        assert_eq!(inv["complete"], false);
        assert!(inv["coverageGaps"][0].as_str().unwrap().starts_with("source-missing:"));
    }

    #[test]
    fn extract_visible_content_finds_jsx_text_and_quoted_labels() {
        let artifacts = vec![Artifact {
            text: Some(r#"<div>Hello world</div><Button title="Save now" />"#.to_string()),
            path: Some("a.tsx".into()),
            ..Default::default()
        }];
        let inv = extract_visible_content(&artifacts, &json!({}));
        let texts: Vec<&str> = inv["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["text"].as_str().unwrap())
            .collect();
        assert!(texts.contains(&"Hello world"));
        assert!(texts.contains(&"Save now"));
    }

    #[test]
    fn skill_compiler_excludes_authoring_instructions() {
        let entries = vec![
            SkillEntry { id: Some("s1".into()), text: Some("write the changelog".into()), ..Default::default() },
            SkillEntry { id: Some("s2".into()), text: Some("check tone consistency".into()), ..Default::default() },
        ];
        let profile = compile_writing_audit_profile(&entries, "legion-skill://writing/");
        assert_eq!(profile["exclusions"].as_array().unwrap().len(), 1);
        assert_eq!(profile["rules"].as_array().unwrap().len(), 1);
        assert_eq!(profile["rules"][0]["id"], "writing.s2");
    }
}
