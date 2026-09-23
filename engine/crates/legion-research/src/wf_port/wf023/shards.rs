//! Port of `research-core/shards.py`: deterministic shard planning,
//! checkpointing, resume, and ledger merge.
//!
//! `shards.py` is not itself one of this chunk's assigned files, but
//! `control.py` (assigned) depends on it for `shard-init`/`shard-checkpoint`/
//! `shard-resume`. It is ported here, self-contained, so `control.rs`'s
//! shard commands are faithful; if a canonical `shards.py` port lands
//! elsewhere under `legion-research`, this module should be deleted and
//! `control.rs` rewired to it (see the wf023 report).

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest, Sha256};
use serde_json::{Map, Value};

/// `shards.VALID_STATES`.
pub const VALID_STATES: &[&str] = &["pending", "running", "done", "failed"];

/// `shards.shard_id`.
pub fn shard_id(run_id: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(run_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(key.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("shard-{}", &digest[..12])
}

/// One work item to plan, mirroring `item.get('key')`/`item.get('payload')`.
#[derive(Debug, Clone)]
pub struct WorkItem {
    pub key: String,
    pub payload: Value,
}

/// One planned shard row.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardRow {
    pub id: String,
    pub key: String,
    pub payload: Value,
    pub status: String,
    pub attempts: u64,
    pub artifacts: Map<String, Value>,
}

/// The plan document, mirroring `{'schema_version': 1, 'run_id', 'shards'}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardPlan {
    pub schema_version: u32,
    pub run_id: String,
    pub shards: Vec<ShardRow>,
}

/// `shards.plan`. Errors with the same message shape as the Python
/// `ValueError` for a missing or duplicate shard key.
pub fn plan(run_id: &str, work_items: &[WorkItem]) -> Result<ShardPlan, String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::with_capacity(work_items.len());
    for item in work_items {
        let key = item.key.trim().to_string();
        if key.is_empty() || seen.contains(&key) {
            return Err(format!("missing or duplicate shard key: {key:?}"));
        }
        seen.insert(key.clone());
        let payload = match &item.payload {
            Value::Null => Value::Object(Map::new()),
            other => other.clone(),
        };
        rows.push(ShardRow {
            id: shard_id(run_id, &key),
            key,
            payload,
            status: "pending".to_string(),
            attempts: 0,
            artifacts: Map::new(),
        });
    }
    Ok(ShardPlan { schema_version: 1, run_id: run_id.to_string(), shards: rows })
}

/// `shards.checkpoint`. `artifacts`, when given, is merged into the shard's
/// existing artifacts map (matches `dict.update`).
pub fn checkpoint(
    plan_doc: &mut ShardPlan,
    shard: &str,
    status: &str,
    artifacts: Option<&Map<String, Value>>,
) -> Result<(), String> {
    if !VALID_STATES.contains(&status) {
        return Err(format!("invalid shard status: {status}"));
    }
    let matches: Vec<usize> = plan_doc
        .shards
        .iter()
        .enumerate()
        .filter(|(_, row)| row.id == shard)
        .map(|(i, _)| i)
        .collect();
    if matches.len() != 1 {
        return Err(format!("unknown shard: {shard}"));
    }
    let row = &mut plan_doc.shards[matches[0]];
    if status == "running" {
        row.attempts += 1;
    }
    row.status = status.to_string();
    if let Some(artifacts) = artifacts {
        if !artifacts.is_empty() {
            for (k, v) in artifacts {
                row.artifacts.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(())
}

/// `shards.resumable`.
pub fn resumable(plan_doc: &ShardPlan) -> Vec<&ShardRow> {
    plan_doc
        .shards
        .iter()
        .filter(|row| row.status == "pending" || row.status == "failed")
        .collect()
}

/// Receipt returned by `merge_jsonl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReceipt {
    pub rows: usize,
    pub sha256: String,
    pub output: String,
}

/// `shards.merge_jsonl`. `id_field` defaults to `"id"` in the Python
/// signature; callers here pass it explicitly.
pub fn merge_jsonl(paths: &[&Path], output: &Path, id_field: &str) -> std::io::Result<MergeReceipt> {
    let mut rows: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeMap<String, &Path> = std::collections::BTreeMap::new();
    for path in paths.iter().copied() {
        let text = std::fs::read_to_string(path)?;
        for (number, line) in text.lines().enumerate() {
            let number = number + 1;
            if line.trim().is_empty() {
                continue;
            }
            let row: Value = serde_json::from_str(line).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}:{number}: {e}", path.display()))
            })?;
            let key = row
                .get(id_field)
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            if key.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}:{number}: missing {id_field}", path.display()),
                ));
            }
            if let Some(prior) = seen.get(&key) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("duplicate {id_field} {key:?} in {} and {}", prior.display(), path.display()),
                ));
            }
            seen.insert(key, path);
            rows.push(row);
        }
    }
    rows.sort_by(|a, b| {
        let ka = a.get(id_field).map(|v| v.to_string()).unwrap_or_default();
        let kb = b.get(id_field).map(|v| v.to_string()).unwrap_or_default();
        ka.cmp(&kb)
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = String::new();
    for row in &rows {
        text.push_str(&serde_json_canonical(row));
        text.push('\n');
    }
    std::fs::write(output, &text)?;
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    };
    Ok(MergeReceipt { rows: rows.len(), sha256, output: output.display().to_string() })
}

/// Matches `json.dumps(row, sort_keys=True, ensure_ascii=False)`: keys
/// sorted, no extra whitespace.
fn serde_json_canonical(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut sorted_map = Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    sorted_map.insert(k.clone(), sorted(&map[k]));
                }
                Value::Object(sorted_map)
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sorted(value)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn items() -> Vec<WorkItem> {
        vec![
            WorkItem { key: "pricing".into(), payload: json!({"query": "price"}) },
            WorkItem { key: "privacy".into(), payload: json!({"query": "privacy"}) },
        ]
    }

    // Ported from research-core/tests/test_research_shards.py.
    #[test]
    fn plan_checkpoint_resume_and_merge_are_deterministic() {
        let mut plan_doc = plan("run-1", &items()).unwrap();
        assert_eq!(
            plan_doc.shards.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            vec![shard_id("run-1", "pricing"), shard_id("run-1", "privacy")]
        );
        let first = plan_doc.shards[0].id.clone();
        let second = plan_doc.shards[1].id.clone();

        checkpoint(&mut plan_doc, &first, "running", None).unwrap();
        let mut artifacts = Map::new();
        artifacts.insert("evidence".into(), json!("pricing.jsonl"));
        checkpoint(&mut plan_doc, &first, "done", Some(&artifacts)).unwrap();
        checkpoint(&mut plan_doc, &second, "running", None).unwrap();
        checkpoint(&mut plan_doc, &second, "failed", None).unwrap();

        assert_eq!(resumable(&plan_doc).iter().map(|r| r.id.clone()).collect::<Vec<_>>(), vec![second]);
        assert_eq!(plan_doc.shards[0].attempts, 1);

        let dir = std::env::temp_dir().join(format!("legion-wf023-shards-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let one = dir.join("one.jsonl");
        let two = dir.join("two.jsonl");
        let out = dir.join("merged.jsonl");
        std::fs::write(&one, format!("{}\n", json!({"id": "b", "value": 2}))).unwrap();
        std::fs::write(&two, format!("{}\n", json!({"id": "a", "value": 1}))).unwrap();

        let receipt = merge_jsonl(&[one.as_path(), two.as_path()], &out, "id").unwrap();
        assert_eq!(receipt.rows, 2);
        let merged = std::fs::read_to_string(&out).unwrap();
        let ids: Vec<String> = merged
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec!["a", "b"]);

        std::fs::write(&two, format!("{}\n", json!({"id": "b", "value": 3}))).unwrap();
        let err = merge_jsonl(&[one.as_path(), two.as_path()], &out, "id").unwrap_err();
        assert!(err.to_string().contains("duplicate id"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_rejects_duplicate_keys() {
        let items = vec![
            WorkItem { key: "a".into(), payload: Value::Null },
            WorkItem { key: "a".into(), payload: Value::Null },
        ];
        let err = plan("run-1", &items).unwrap_err();
        assert!(err.contains("duplicate shard key"));
    }

    #[test]
    fn checkpoint_rejects_unknown_shard() {
        let mut plan_doc = plan("run-1", &items()).unwrap();
        let err = checkpoint(&mut plan_doc, "shard-nope", "running", None).unwrap_err();
        assert!(err.contains("unknown shard"));
    }

    #[test]
    fn checkpoint_rejects_invalid_status() {
        let mut plan_doc = plan("run-1", &items()).unwrap();
        let id = plan_doc.shards[0].id.clone();
        let err = checkpoint(&mut plan_doc, &id, "bogus", None).unwrap_err();
        assert!(err.contains("invalid shard status"));
    }
}
