//! Typed Audit finding store: a port of the lifecycle half of the historical
//! `tools/audit/audit_store.py` (`AuditFindingV1` records in a JSONL store).
//!
//! Status lifecycle: `open` -> `resolved` | `dismissed` | `superseded`. Only
//! `open` findings are active. The state rules are the Python's:
//!
//! * `set_status` accepts `open`, `resolved` and `dismissed` only; any other
//!   target (including `superseded`) is refused, as is an unknown finding id.
//!   Terminal targets stamp `resolvedGeneration`/`resolvedAt`; `open` clears
//!   them.
//! * `supersede` retires an existing finding in favour of a successor record
//!   and links both sides (`supersededBy` / `supersedes`).
//! * `upsert` re-emits a finding under its stable id: immutable first-seen
//!   metadata and supersession links are preserved, `lastSeen*` is refreshed.
//!
//! Persistence differs from the Python in one deliberate way: the file is
//! append-only. Every write appends the new snapshot of each touched record;
//! loading folds the file so the last snapshot per id wins (ids keep their
//! first-seen order, like the Python's dictionary). The state functions are
//! pure over record lists; [`FindingStore`] is the thin file wrapper.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{canonicalize, derive_finding_id, locus_content_hash, FindingLocus};

pub const SCHEMA_VERSION: i64 = 1;
pub const ACTIVE_STATUSES: [&str; 1] = ["open"];
pub const TERMINAL_STATUSES: [&str; 3] = ["resolved", "dismissed", "superseded"];
pub const ALL_STATUSES: [&str; 4] = ["open", "resolved", "dismissed", "superseded"];
pub const PROVENANCE_KINDS: [&str; 3] = ["deterministic_scanner", "reasoning_lens", "manual"];

const REQUIRED_FIELDS: [&str; 17] = [
    "schemaVersion",
    "id",
    "repositoryId",
    "scopeId",
    "auditGeneration",
    "linkedGraphGeneration",
    "severity",
    "category",
    "title",
    "evidenceLoci",
    "confidence",
    "status",
    "firstSeenGeneration",
    "lastSeenGeneration",
    "firstSeenAt",
    "lastSeenAt",
    "provenance",
];

/// Why a store operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A record or transition violates the store's rules (Python `ValueError`).
    Invalid(String),
    /// The named finding is not in the store (Python `KeyError`).
    Unknown(String),
    /// The backing file could not be read or written.
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Invalid(message) | StoreError::Io(message) => f.write_str(message),
            StoreError::Unknown(id) => write!(f, "unknown finding: {id}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::Invalid(message.into())
}

/// Non-empty string value, mirroring Python truthiness for string fields.
fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn field_text(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn is_null_or_missing(record: &Value, key: &str) -> bool {
    record.get(key).map_or(true, Value::is_null)
}

/// `_coerce_locus`: validates a locus and adds its `contentSha256`.
pub fn coerce_locus(locus: &Value) -> Result<Value, StoreError> {
    let object = locus
        .as_object()
        .ok_or_else(|| invalid("evidence locus must be an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| invalid("evidence locus requires non-empty path"))?;
    let start = object
        .get("startLine")
        .and_then(Value::as_i64)
        .filter(|n| *n >= 1)
        .ok_or_else(|| invalid("evidence locus requires positive integer startLine"))?;
    let end = object
        .get("endLine")
        .and_then(Value::as_i64)
        .filter(|n| *n >= start)
        .ok_or_else(|| invalid("evidence locus requires endLine >= startLine >= 1"))?;
    Ok(json!({
        "path": path,
        "startLine": start,
        "endLine": end,
        "contentSha256": locus_content_hash(path, start, end),
    }))
}

/// `_validate`: light structural validation of a finding record.
pub fn validate(record: &Value) -> Result<(), StoreError> {
    let object = record
        .as_object()
        .ok_or_else(|| invalid("finding record must be an object"))?;
    for key in REQUIRED_FIELDS {
        if !object.contains_key(key) {
            return Err(invalid(format!(
                "finding record missing required field: {key}"
            )));
        }
    }
    if object["schemaVersion"].as_i64() != Some(SCHEMA_VERSION) {
        return Err(invalid(format!(
            "unexpected schemaVersion: {}",
            object["schemaVersion"]
        )));
    }
    if text(object.get("id")).is_none() {
        return Err(invalid("finding record id must be a non-empty string"));
    }
    match object["status"].as_str() {
        Some(status) if ALL_STATUSES.contains(&status) => {}
        _ => {
            return Err(invalid(format!("invalid status: {}", object["status"])));
        }
    }
    match object["evidenceLoci"].as_array() {
        Some(loci) if !loci.is_empty() => {
            for locus in loci {
                coerce_locus(locus)?;
            }
        }
        _ => return Err(invalid("evidenceLoci must be a non-empty list")),
    }
    Ok(())
}

fn record_id(record: &Value) -> Option<&str> {
    record.get("id").and_then(Value::as_str)
}

/// Folds an append-only snapshot list into the current state: the last
/// snapshot per id wins, ids keep first-seen order.
pub fn fold(records: &[Value]) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut latest: HashMap<String, Value> = HashMap::new();
    for record in records {
        if let Some(id) = record_id(record) {
            if !latest.contains_key(id) {
                order.push(id.to_owned());
            }
            latest.insert(id.to_owned(), record.clone());
        }
    }
    order
        .into_iter()
        .filter_map(|id| latest.remove(&id))
        .collect()
}

/// Current snapshot of `id` in a (possibly unfolded) record list.
pub fn find<'a>(records: &'a [Value], id: &str) -> Option<&'a Value> {
    records.iter().rev().find(|r| record_id(r) == Some(id))
}

/// `active`: `open` records, optionally for one repository.
pub fn active(records: &[Value], repository_id: Option<&str>) -> Vec<Value> {
    fold(records)
        .into_iter()
        .filter(|record| {
            record
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| ACTIVE_STATUSES.contains(&status))
        })
        .filter(|record| {
            repository_id.map_or(true, |repo| {
                record.get("repositoryId").and_then(Value::as_str) == Some(repo)
            })
        })
        .collect()
}

/// In-memory draft used to construct an `AuditFindingV1` record.
#[derive(Debug, Clone)]
pub struct FindingDraft {
    pub repository_id: String,
    pub scope_id: String,
    pub rule_id: String,
    pub category: String,
    pub title: String,
    pub evidence_loci: Vec<Value>,
    pub severity: String,
    pub confidence: f64,
    pub provenance: Option<Value>,
    pub audit_generation: String,
    pub linked_graph_generation: Option<String>,
    pub provenance_kind: String,
    pub provenance_version: String,
}

impl FindingDraft {
    /// A draft with the Python defaults (`medium`, confidence 1.0, scanner).
    pub fn new(
        repository_id: &str,
        scope_id: &str,
        rule_id: &str,
        category: &str,
        title: &str,
        evidence_loci: Vec<Value>,
    ) -> Self {
        Self {
            repository_id: repository_id.to_owned(),
            scope_id: scope_id.to_owned(),
            rule_id: rule_id.to_owned(),
            category: category.to_owned(),
            title: title.to_owned(),
            evidence_loci,
            severity: "medium".to_owned(),
            confidence: 1.0,
            provenance: None,
            audit_generation: String::new(),
            linked_graph_generation: None,
            provenance_kind: "deterministic_scanner".to_owned(),
            provenance_version: "1".to_owned(),
        }
    }
}

/// `make_finding`: builds a fully typed record from a draft.
pub fn make_finding(
    draft: &FindingDraft,
    audit_generation: Option<&str>,
    linked_graph_generation: Option<&str>,
    status: &str,
    now: &str,
) -> Result<Value, StoreError> {
    if !ALL_STATUSES.contains(&status) {
        return Err(invalid(format!("invalid status: {status:?}")));
    }
    let loci = draft
        .evidence_loci
        .iter()
        .map(coerce_locus)
        .collect::<Result<Vec<_>, _>>()?;
    let first = loci
        .first()
        .ok_or_else(|| invalid("finding requires at least one evidence locus"))?;
    let locus = FindingLocus {
        path: field_text(first, "path"),
        start_line: first["startLine"].as_i64().unwrap_or(0),
        end_line: first["endLine"].as_i64().unwrap_or(0),
    };
    let id = derive_finding_id(&draft.repository_id, &draft.rule_id, Some(&locus))
        .map_err(StoreError::Invalid)?;
    let generation = audit_generation
        .filter(|g| !g.is_empty())
        .unwrap_or(draft.audit_generation.as_str())
        .to_owned();
    let linked = linked_graph_generation
        .or(draft.linked_graph_generation.as_deref())
        .unwrap_or_default()
        .to_owned();
    let provenance = match &draft.provenance {
        Some(provenance) => provenance.clone(),
        None => {
            if !PROVENANCE_KINDS.contains(&draft.provenance_kind.as_str()) {
                return Err(invalid(format!(
                    "invalid provenance kind: {:?}",
                    draft.provenance_kind
                )));
            }
            json!({
                "kind": draft.provenance_kind,
                "name": draft.rule_id,
                "version": draft.provenance_version,
                "ruleId": draft.rule_id,
            })
        }
    };
    Ok(json!({
        "schemaVersion": SCHEMA_VERSION,
        "id": id,
        "repositoryId": draft.repository_id,
        "scopeId": draft.scope_id,
        "auditGeneration": generation,
        "linkedGraphGeneration": linked,
        "severity": draft.severity,
        "category": draft.category,
        "title": draft.title,
        "evidenceLoci": loci,
        "confidence": draft.confidence,
        "status": status,
        "supersedes": [],
        "supersededBy": null,
        "firstSeenGeneration": generation,
        "lastSeenGeneration": generation,
        "firstSeenAt": now,
        "lastSeenAt": now,
        "resolvedGeneration": null,
        "resolvedAt": null,
        "provenance": provenance,
    }))
}

fn object_of(record: &Value) -> Map<String, Value> {
    record.as_object().cloned().unwrap_or_default()
}

fn set_default(map: &mut Map<String, Value>, key: &str, value: Value) {
    if !map.contains_key(key) {
        map.insert(key.to_owned(), value);
    }
}

/// `upsert`: the snapshot to append when `record` is (re-)emitted.
pub fn upsert(records: &[Value], record: &Value, now: &str) -> Result<Value, StoreError> {
    validate(record)?;
    let id = field_text(record, "id");
    let audit_generation = field_text(record, "auditGeneration");
    match find(records, &id) {
        None => {
            let mut fresh = object_of(record);
            set_default(
                &mut fresh,
                "firstSeenGeneration",
                json!(audit_generation.clone()),
            );
            fresh.insert("lastSeenGeneration".into(), json!(audit_generation));
            set_default(&mut fresh, "firstSeenAt", json!(now));
            let last_seen = text(record.get("lastSeenAt")).unwrap_or(now).to_owned();
            fresh.insert("lastSeenAt".into(), json!(last_seen));
            Ok(Value::Object(fresh))
        }
        Some(prior) => {
            let mut merged = object_of(prior);
            for (key, value) in object_of(record) {
                merged.insert(key, value);
            }
            merged.insert("id".into(), json!(id));
            merged.insert(
                "firstSeenGeneration".into(),
                prior
                    .get("firstSeenGeneration")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            merged.insert(
                "firstSeenAt".into(),
                prior.get("firstSeenAt").cloned().unwrap_or(Value::Null),
            );
            let last_generation = text(record.get("auditGeneration"))
                .map(str::to_owned)
                .unwrap_or_else(|| field_text(prior, "lastSeenGeneration"));
            merged.insert("lastSeenGeneration".into(), json!(last_generation));
            let last_seen = text(record.get("lastSeenAt")).unwrap_or(now).to_owned();
            merged.insert("lastSeenAt".into(), json!(last_seen));
            if is_null_or_missing(record, "supersededBy") {
                merged.insert(
                    "supersededBy".into(),
                    prior.get("supersededBy").cloned().unwrap_or(Value::Null),
                );
            }
            if record.get("supersedes").is_none() {
                merged.insert(
                    "supersedes".into(),
                    prior
                        .get("supersedes")
                        .cloned()
                        .unwrap_or_else(|| json!([])),
                );
            }
            for key in ["resolvedGeneration", "resolvedAt"] {
                if is_null_or_missing(record, key) && !is_null_or_missing(prior, key) {
                    merged.insert(key.into(), prior[key].clone());
                }
            }
            Ok(Value::Object(merged))
        }
    }
}

/// `supersede`: the snapshots to append (retired old record, then successor).
///
/// Unlike the Python, a finding may not supersede itself: the Python's two
/// writes then collapse into one and silently reopen the retired record.
pub fn supersede(
    records: &[Value],
    old_id: &str,
    new_record: &Value,
    now: &str,
) -> Result<Vec<Value>, StoreError> {
    validate(new_record)?;
    let old = find(records, old_id).ok_or_else(|| StoreError::Unknown(old_id.to_owned()))?;
    let new_id = field_text(new_record, "id");
    if new_id == old_id {
        return Err(invalid(format!(
            "finding {old_id} cannot supersede itself; supply a successor with a new id"
        )));
    }
    let new_generation = field_text(new_record, "auditGeneration");
    // An already-superseded record is retired again; the successor still links.
    let mut retired = object_of(old);
    retired.insert("status".into(), json!("superseded"));
    retired.insert("supersededBy".into(), json!(new_id));
    let resolved_generation = if new_generation.is_empty() {
        field_text(old, "lastSeenGeneration")
    } else {
        new_generation.clone()
    };
    retired.insert("resolvedGeneration".into(), json!(resolved_generation));
    retired.insert("resolvedAt".into(), json!(now));
    retired.insert("lastSeenAt".into(), json!(now));

    let mut successor = object_of(new_record);
    let mut supersedes = successor
        .get("supersedes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !supersedes.iter().any(|item| item.as_str() == Some(old_id)) {
        supersedes.push(json!(old_id));
    }
    successor.insert("supersedes".into(), Value::Array(supersedes));
    set_default(
        &mut successor,
        "firstSeenGeneration",
        json!(new_generation.clone()),
    );
    successor.insert("lastSeenGeneration".into(), json!(new_generation));
    set_default(&mut successor, "firstSeenAt", json!(now));
    successor.insert("lastSeenAt".into(), json!(now));
    Ok(vec![Value::Object(retired), Value::Object(successor)])
}

/// `set_status`: the snapshot to append when a finding moves to
/// `resolved`, `dismissed` or back to `open`. `superseded` is refused.
pub fn set_status(
    records: &[Value],
    id: &str,
    status: &str,
    generation: Option<&str>,
    now: &str,
) -> Result<Value, StoreError> {
    if !ALL_STATUSES.contains(&status) || status == "superseded" {
        return Err(invalid(
            "use supersede to retire by supersession; set_status accepts resolved/dismissed/open",
        ));
    }
    let prior = find(records, id).ok_or_else(|| StoreError::Unknown(id.to_owned()))?;
    let mut updated = object_of(prior);
    updated.insert("status".into(), json!(status));
    if TERMINAL_STATUSES.contains(&status) {
        let resolved_generation = generation
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .or_else(|| text(prior.get("auditGeneration")).map(str::to_owned))
            .unwrap_or_else(|| field_text(prior, "lastSeenGeneration"));
        updated.insert("resolvedGeneration".into(), json!(resolved_generation));
        updated.insert("resolvedAt".into(), json!(now));
    } else {
        updated.insert("resolvedGeneration".into(), Value::Null);
        updated.insert("resolvedAt".into(), Value::Null);
    }
    updated.insert("lastSeenAt".into(), json!(now));
    Ok(Value::Object(updated))
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    format_utc(seconds)
}

/// Formats Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian).
pub fn format_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Thin file wrapper: `<repo>/.audit/audit/findings.jsonl`, append-only.
#[derive(Debug, Clone)]
pub struct FindingStore {
    path: PathBuf,
}

impl FindingStore {
    pub fn new(repo: &Path) -> Self {
        Self {
            path: repo.join(".audit").join("audit").join("findings.jsonl"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every snapshot in file order, each validated.
    fn read_snapshots(&self) -> Result<Vec<Value>, StoreError> {
        if !self.path.is_file() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&self.path).map_err(|error| {
            StoreError::Io(format!("cannot read {}: {error}", self.path.display()))
        })?;
        let mut records = Vec::new();
        for (index, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let record: Value = serde_json::from_str(line).map_err(|error| {
                invalid(format!(
                    "corrupt JSONL at {}:{}: {error}",
                    self.path.display(),
                    index + 1
                ))
            })?;
            validate(&record)?;
            records.push(record);
        }
        Ok(records)
    }

    fn append(&self, snapshots: &[Value]) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                StoreError::Io(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        let mut buffer = String::new();
        for snapshot in snapshots {
            let line = serde_json::to_string(&canonicalize(snapshot))
                .map_err(|error| StoreError::Io(error.to_string()))?;
            buffer.push_str(&line);
            buffer.push('\n');
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| {
                StoreError::Io(format!("cannot open {}: {error}", self.path.display()))
            })?;
        file.write_all(buffer.as_bytes()).map_err(|error| {
            StoreError::Io(format!("cannot write {}: {error}", self.path.display()))
        })
    }

    /// Current record per id.
    pub fn load(&self) -> Result<Vec<Value>, StoreError> {
        Ok(fold(&self.read_snapshots()?))
    }

    pub fn get(&self, id: &str) -> Result<Option<Value>, StoreError> {
        Ok(find(&self.read_snapshots()?, id).cloned())
    }

    pub fn active(&self, repository_id: Option<&str>) -> Result<Vec<Value>, StoreError> {
        Ok(active(&self.read_snapshots()?, repository_id))
    }

    pub fn upsert(&self, record: &Value, now: Option<&str>) -> Result<Value, StoreError> {
        let now = now.map(str::to_owned).unwrap_or_else(utc_now);
        let snapshot = upsert(&self.read_snapshots()?, record, &now)?;
        self.append(std::slice::from_ref(&snapshot))?;
        Ok(snapshot)
    }

    pub fn supersede(
        &self,
        old_id: &str,
        new_record: &Value,
        now: Option<&str>,
    ) -> Result<Value, StoreError> {
        let now = now.map(str::to_owned).unwrap_or_else(utc_now);
        let snapshots = supersede(&self.read_snapshots()?, old_id, new_record, &now)?;
        self.append(&snapshots)?;
        Ok(snapshots.into_iter().last().unwrap_or(Value::Null))
    }

    pub fn set_status(
        &self,
        id: &str,
        status: &str,
        generation: Option<&str>,
        now: Option<&str>,
    ) -> Result<Value, StoreError> {
        let now = now.map(str::to_owned).unwrap_or_else(utc_now);
        let snapshot = set_status(&self.read_snapshots()?, id, status, generation, &now)?;
        self.append(std::slice::from_ref(&snapshot))?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-01-01T00:00:00Z";
    const T1: &str = "2026-02-01T00:00:00Z";

    fn locus(path: &str, start: i64, end: i64) -> Value {
        json!({"path": path, "startLine": start, "endLine": end})
    }

    fn finding(rule: &str, path: &str, generation: &str) -> Value {
        let mut draft = FindingDraft::new(
            "repo-1",
            "scope-1",
            rule,
            "security",
            "a finding",
            vec![locus(path, 3, 5)],
        );
        draft.audit_generation = generation.to_owned();
        make_finding(&draft, None, None, "open", T0).unwrap()
    }

    fn temp_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-finding-store-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn make_finding_is_valid_and_open_with_a_stable_id() {
        let first = finding("R1", "src/a.rs", "g1");
        validate(&first).unwrap();
        assert_eq!(first["status"], "open");
        assert_eq!(first["firstSeenGeneration"], "g1");
        assert!(first["id"].as_str().unwrap().starts_with("audit:rule:"));
        assert_eq!(first["id"], finding("R1", "src/a.rs", "g2")["id"]);
        assert_ne!(first["id"], finding("R2", "src/a.rs", "g1")["id"]);
    }

    #[test]
    fn invalid_records_and_loci_are_refused() {
        let mut record = finding("R1", "src/a.rs", "g1");
        record.as_object_mut().unwrap().remove("title");
        assert!(validate(&record).unwrap_err().to_string().contains("title"));

        let mut record = finding("R1", "src/a.rs", "g1");
        record["status"] = json!("bogus");
        assert!(validate(&record).is_err());
        let mut record = finding("R1", "src/a.rs", "g1");
        record["evidenceLoci"] = json!([]);
        assert!(validate(&record).is_err());
        assert!(coerce_locus(&locus("", 1, 1)).is_err());
        assert!(coerce_locus(&locus("a", 0, 1)).is_err());
        assert!(coerce_locus(&locus("a", 5, 4)).is_err());
    }

    #[test]
    fn resolve_stamps_terminal_fields_and_open_clears_them() {
        let record = finding("R1", "src/a.rs", "g1");
        let id = record["id"].as_str().unwrap().to_owned();
        let stored = vec![upsert(&[], &record, T0).unwrap()];
        let resolved = set_status(&stored, &id, "resolved", Some("g2"), T1).unwrap();
        assert_eq!(resolved["status"], "resolved");
        assert_eq!(resolved["resolvedGeneration"], "g2");
        assert_eq!(resolved["resolvedAt"], T1);
        assert_eq!(resolved["lastSeenAt"], T1);

        let dismissed = set_status(&stored, &id, "dismissed", None, T1).unwrap();
        assert_eq!(dismissed["resolvedGeneration"], "g1");

        let after = vec![resolved];
        let reopened = set_status(&after, &id, "open", None, T1).unwrap();
        assert_eq!(reopened["status"], "open");
        assert!(reopened["resolvedGeneration"].is_null());
        assert!(reopened["resolvedAt"].is_null());
    }

    #[test]
    fn set_status_refuses_superseded_unknown_status_and_unknown_id() {
        let record = finding("R1", "src/a.rs", "g1");
        let id = record["id"].as_str().unwrap().to_owned();
        let stored = vec![upsert(&[], &record, T0).unwrap()];
        assert!(matches!(
            set_status(&stored, &id, "superseded", None, T1),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            set_status(&stored, &id, "weird", None, T1),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(
            set_status(&stored, "audit:rule:none", "resolved", None, T1),
            Err(StoreError::Unknown("audit:rule:none".into()))
        );
    }

    #[test]
    fn supersede_links_both_sides_and_rejects_unknown_or_self() {
        let old = finding("R1", "src/a.rs", "g1");
        let successor = finding("R1", "src/b.rs", "g2");
        let old_id = old["id"].as_str().unwrap().to_owned();
        let new_id = successor["id"].as_str().unwrap().to_owned();
        let stored = vec![upsert(&[], &old, T0).unwrap()];

        let written = supersede(&stored, &old_id, &successor, T1).unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(written[0]["status"], "superseded");
        assert_eq!(written[0]["supersededBy"], new_id);
        assert_eq!(written[0]["resolvedGeneration"], "g2");
        assert_eq!(written[1]["id"], new_id);
        assert_eq!(written[1]["supersedes"], json!([old_id.clone()]));
        assert_eq!(written[1]["status"], "open");

        assert_eq!(
            supersede(&stored, "audit:rule:none", &successor, T1).unwrap_err(),
            StoreError::Unknown("audit:rule:none".into())
        );
        assert!(matches!(
            supersede(&stored, &old_id, &old, T1),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn upsert_preserves_first_seen_and_links_on_reemit() {
        let first = finding("R1", "src/a.rs", "g1");
        let stored = vec![upsert(&[], &first, T0).unwrap()];
        let mut again = finding("R1", "src/a.rs", "g2");
        again["lastSeenAt"] = json!("");
        let merged = upsert(&stored, &again, T1).unwrap();
        assert_eq!(merged["firstSeenGeneration"], "g1");
        assert_eq!(merged["firstSeenAt"], T0);
        assert_eq!(merged["lastSeenGeneration"], "g2");
        assert_eq!(merged["lastSeenAt"], T1);
        assert!(merged["supersededBy"].is_null());
        assert_eq!(merged["supersedes"], json!([]));
    }

    #[test]
    fn fold_keeps_the_last_snapshot_in_first_seen_order() {
        let a = finding("R1", "src/a.rs", "g1");
        let b = finding("R2", "src/b.rs", "g1");
        let a_id = a["id"].as_str().unwrap().to_owned();
        let mut a2 = a.clone();
        a2["title"] = json!("renamed");
        let folded = fold(&[a.clone(), b.clone(), a2]);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0]["id"], a_id);
        assert_eq!(folded[0]["title"], "renamed");
        assert_eq!(folded[1]["id"], b["id"]);
        assert_eq!(active(&folded, Some("repo-1")).len(), 2);
        assert!(active(&folded, Some("other")).is_empty());
    }

    #[test]
    fn utc_formatting_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_now().len(), 20);
    }

    #[test]
    fn file_store_appends_snapshots_and_folds_them_on_load() {
        let repo = temp_repo("lifecycle");
        let store = FindingStore::new(&repo);
        assert!(store.load().unwrap().is_empty());

        let record = finding("R1", "src/a.rs", "g1");
        let id = record["id"].as_str().unwrap().to_owned();
        store.upsert(&record, Some(T0)).unwrap();
        store
            .set_status(&id, "resolved", Some("g2"), Some(T1))
            .unwrap();
        let successor = finding("R1", "src/b.rs", "g3");
        let new_id = successor["id"].as_str().unwrap().to_owned();
        store.supersede(&id, &successor, Some(T1)).unwrap();

        let raw = fs::read_to_string(store.path()).unwrap();
        assert_eq!(raw.lines().count(), 4, "append-only: one line per write");
        let current = store.load().unwrap();
        assert_eq!(current.len(), 2);
        assert_eq!(store.get(&id).unwrap().unwrap()["status"], "superseded");
        assert_eq!(store.get(&new_id).unwrap().unwrap()["status"], "open");
        let open = store.active(None).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["id"], new_id);

        assert!(store
            .set_status("audit:rule:none", "open", None, None)
            .is_err());
        fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn corrupt_store_lines_are_reported_with_their_position() {
        let repo = temp_repo("corrupt");
        let store = FindingStore::new(&repo);
        fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        fs::write(store.path(), "{not json}\n").unwrap();
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("corrupt JSONL"), "{error}");
        assert!(error.contains(":1:"), "{error}");
        fs::remove_dir_all(repo).unwrap();
    }
}
