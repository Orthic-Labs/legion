//! Packet-local graph hints backed by the complete frozen provider context.
//! Graph metadata never establishes source review or exhaustive coverage.
use std::collections::BTreeSet;

use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};

use crate::{
    error::AuditError,
    plan::{AuditProvider, FrozenPlan},
};

const GRAPH_RECORD_BYTES: usize = 2048;

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
