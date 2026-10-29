//! Packet-local graph hints backed by the complete frozen provider context.
//! Graph metadata never establishes source review or exhaustive coverage.
use std::collections::BTreeSet;

use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};

use crate::{
    error::AuditError,
    inventory::InventoryEnvelope,
    plan::{AuditProvider, FrozenPlan},
};

use super::excerpts::{redact_text, SourceReader};

const GRAPH_RECORD_BYTES: usize = 2048;

/// Documentation context ceilings: per document, per packet, and document count.
/// Every packet part of the lens carries the same context, so the budget stays small.
pub(super) const DOC_CONTEXT_FILE_BYTES: usize = 4096;
pub(super) const DOC_CONTEXT_TOTAL_BYTES: usize = 12 * 1024;
pub(super) const DOC_CONTEXT_MAX_DOCS: usize = 6;
const DOC_CONTEXT_READ_BYTES: usize = 256 * 1024;
const ARCHITECTURE_PROVIDER_ID: &str = "reasoning.architecture";

fn digest(value: &Value) -> Result<String, AuditError> {
    canonical_digest(value).map_err(|error| AuditError::Invalid(error.to_string()))
}

fn relevant(row: &Value, paths: &BTreeSet<&str>) -> bool {
    if row.get("cause").is_some() {
        return row
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|path| paths.contains(path));
    }
    ["from", "to"]
        .into_iter()
        .filter_map(|key| row.get(key).and_then(Value::as_str))
        .chain(row.pointer("/evidence/path").and_then(Value::as_str))
        .any(|path| paths.contains(path))
}

fn project_records(
    source: &Value,
    field: &str,
    paths: &BTreeSet<&str>,
    remaining: &mut usize,
) -> Result<(Value, Value), AuditError> {
    let rows = source
        .get(field)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut relevant_count = 0usize;
    for row in rows.iter().filter(|row| relevant(row, paths)) {
        relevant_count += 1;
        if !seen.insert(digest(row)?) {
            continue;
        }
        let bytes = row.to_string().len();
        if bytes <= *remaining {
            *remaining -= bytes;
            selected.push(row.clone());
        }
    }
    let counts = json!({"available": rows.len(), "relevant": relevant_count,
        "included": selected.len(), "omitted": rows.len().saturating_sub(selected.len())});
    Ok((json!(selected), counts))
}

fn scalar_context(source: &Value) -> Map<String, Value> {
    [
        "contractVersion",
        "blueprintVersion",
        "scopedBytesDigest",
        "coveredFilesDigest",
        "resolverConfigDigest",
        "coverageFloor",
        "input",
        "freshness",
        "artifact",
        "truncated",
    ]
    .into_iter()
    .filter_map(|key| source.get(key).map(|value| (key.to_owned(), value.clone())))
    .collect()
}

pub(super) fn review_context(
    plan: &FrozenPlan,
    provider: &AuditProvider,
    selected_paths: &[String],
) -> Result<Value, AuditError> {
    let mut context = provider
        .configuration
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("reviewContext"))
        .cloned()
        .unwrap_or(Value::Null);
    let Some(graph) = context
        .get("graphContext")
        .filter(|graph| graph.is_object())
    else {
        return Ok(context);
    };
    let provider_index = plan
        .providers()
        .iter()
        .position(|item| item.id == provider.id)
        .ok_or_else(|| AuditError::Invalid("packet provider missing from frozen plan".into()))?;
    let paths: BTreeSet<&str> = selected_paths.iter().map(String::as_str).collect();
    // Repeated unknowns cannot consume every slot before useful neighbor
    // relationships. Preserve uncertainty plus a separate edge allowance.
    let mut unknown_remaining = GRAPH_RECORD_BYTES / 4;
    let mut projection = Value::Object(scalar_context(graph));
    let (unknowns, unknown_counts) =
        project_records(graph, "unknowns", &paths, &mut unknown_remaining)?;
    let mut remaining = GRAPH_RECORD_BYTES - GRAPH_RECORD_BYTES / 4 + unknown_remaining;
    projection["unknowns"] = unknowns;
    let mut counts = json!({"unknowns": unknown_counts});
    if let Some(blast) = graph.get("blastRadius").filter(|value| value.is_object()) {
        let mut local = Value::Object(scalar_context(blast));
        for field in ["certain", "inferred", "unknowns"] {
            let (rows, count) = project_records(blast, field, &paths, &mut remaining)?;
            local[field] = rows;
            counts[format!("blastRadius.{field}")] = count;
        }
        // A partial graph, including a fresh one with zero callers, never
        // proves dead code. Removed records stay in the frozen full ledger.
        local["provesDeadCode"] = json!(false);
        local["truncated"] = json!(true);
        projection["blastRadius"] = local;
    }
    projection["projection"] = json!({
        "scope": "packet-selected-paths",
        "selectedPathsDigest": canonical_digest(&selected_paths)
            .map_err(|error| AuditError::Invalid(error.to_string()))?,
        "recordCounts": counts,
        "fullContextRef": {
            "artifact": "plan.json",
            "pointer": format!("/nativePlan/plan/providers/{provider_index}/configuration/reasoning/reviewContext/graphContext"),
            "digest": digest(graph)?,
            "planDigest": plan.digest(),
        },
        "incomplete": true,
        "provesDeadCode": false,
        "note": "Graph hints only; omitted records remain in frozen full context. Missing relationships are unknown, not proof of absence or reviewed source.",
    });
    projection["truncated"] = json!(true);
    context["graphContext"] = projection;
    Ok(context)
}

/// Rank of a repository documentation path that declares architecture rules
/// (`ARCHITECTURE.md`, `docs/architecture/**`, ADR directories). `None` for
/// every other path. Lower ranks are admitted first.
fn architecture_doc_rank(path: &str) -> Option<u8> {
    let lower = path.to_ascii_lowercase();
    let prose = ["md", "markdown", "mdx", "rst", "txt", "adoc"]
        .iter()
        .any(|extension| {
            lower
                .rsplit_once('.')
                .is_some_and(|(_, ext)| ext == *extension)
        });
    if !prose || lower.starts_with("docs/provenance/") {
        return None;
    }
    if lower == "architecture.md" {
        return Some(0);
    }
    if lower.starts_with("docs/architecture/") {
        return Some(1);
    }
    if lower.starts_with("adr/")
        || lower.starts_with("docs/adr/")
        || lower.starts_with("docs/decisions/")
    {
        return Some(2);
    }
    None
}

/// Bounded documentation context for `reasoning.architecture`: the repository's
/// written dependency rules and decisions, read from the frozen source and
/// redacted. It is context only: these paths are not in the source denominator,
/// never enter `excerptCoverage`, and never count as reviewed source. `None`
/// for other providers or when the inventory declares no such document.
pub(super) fn doc_context(
    source: &SourceReader<'_>,
    inventory: &InventoryEnvelope,
    provider_id: &str,
) -> Option<Value> {
    if provider_id != ARCHITECTURE_PROVIDER_ID {
        return None;
    }
    let mut candidates: Vec<(u8, &str)> = inventory
        .entries
        .iter()
        .filter_map(|entry| {
            architecture_doc_rank(&entry.path).map(|rank| (rank, entry.path.as_str()))
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort();
    candidates.dedup();
    let available = candidates.len();
    let mut remaining = DOC_CONTEXT_TOTAL_BYTES;
    let mut docs = Vec::new();
    for (_, path) in candidates {
        if docs.len() >= DOC_CONTEXT_MAX_DOCS || remaining == 0 {
            break;
        }
        let Ok((bytes, _)) = source.read(path, DOC_CONTEXT_READ_BYTES) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let (redacted, _) = redact_text(&text);
        let original_bytes = redacted.len();
        let limit = DOC_CONTEXT_FILE_BYTES.min(remaining);
        let mut content = String::new();
        for line in redacted.split_inclusive('\n') {
            if content.len() + line.len() > limit {
                break;
            }
            content.push_str(line);
        }
        if content.is_empty() {
            continue;
        }
        remaining -= content.len();
        docs.push(json!({
            "path": path,
            "truncated": content.len() < original_bytes,
            "originalBytes": original_bytes,
            "content": content,
        }));
    }
    Some(json!({
        "kind": "documentation-context",
        "countedAsCoverage": false,
        "note": "Repository architecture documents supplied as bounded context for judging the reviewed source against its declared rules. They are not source under review: never cite them as reviewed source or as coverage; findings still need source evidence.",
        "available": available,
        "included": docs.len(),
        "omitted": available - docs.len(),
        "documents": docs,
    }))
}
