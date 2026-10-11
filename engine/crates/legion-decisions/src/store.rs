use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;

use crate::{
    error::DecisionError,
    model::{DecisionRecord, DecisionStatus},
};

const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS decision_records (
  row_id INTEGER PRIMARY KEY,
  id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  linked_graph_generation TEXT NOT NULL,
  rationale TEXT NOT NULL,
  alternatives_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  implementation_refs_json TEXT NOT NULL,
  supersedes_json TEXT NOT NULL,
  superseded_by TEXT,
  current_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  source_path TEXT,
  provenance_json TEXT NOT NULL,
  UNIQUE(id, source_hash)
);
CREATE INDEX IF NOT EXISTS decision_records_match
  ON decision_records(repository_id, scope_id, current_status, linked_graph_generation);
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertDisposition {
    Inserted,
    AlreadyPresent,
}

pub struct DecisionStore {
    connection: Connection,
}

impl DecisionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DecisionError> {
        let connection = Connection::open(path)?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, DecisionError> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn initialize(&self) -> Result<(), DecisionError> {
        self.connection.execute_batch(CREATE_SCHEMA)?;
        Ok(())
    }

    pub fn insert(&mut self, record: &DecisionRecord) -> Result<InsertDisposition, DecisionError> {
        let mut record = record.clone();
        record.validate()?;
        record.ensure_source_hash()?;
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO decision_records
             (id,source_hash,repository_id,scope_id,task_id,linked_graph_generation,rationale,
              alternatives_json,evidence_json,implementation_refs_json,supersedes_json,
              superseded_by,current_status,created_at,source_path,provenance_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                record.id,
                record.source_hash,
                record.repository_id,
                record.scope_id,
                record.task_id,
                record.linked_graph_generation,
                record.rationale,
                json(&record.alternatives)?,
                json(&record.evidence)?,
                json(&record.implementation_refs)?,
                json(&record.supersedes)?,
                record.superseded_by,
                status(&record.current_status),
                record.created_at,
                record.source_path,
                json(&record.provenance)?
            ],
        )?;
        transaction.commit()?;
        Ok(if changed == 1 {
            InsertDisposition::Inserted
        } else {
            InsertDisposition::AlreadyPresent
        })
    }

    pub fn append(&mut self, record: &DecisionRecord) -> Result<InsertDisposition, DecisionError> {
        self.insert(record)
    }

    /// Make `record` the newest retained row for its stable id.
    ///
    /// `insert` deduplicates on `(id, source_hash)`, so returning to a status
    /// that was recorded earlier would leave an older row as the newest one.
    /// After insertion the matching row is therefore moved to the end of the
    /// retention order, which is what `get` reports as the current state.
    pub fn set_current(
        &mut self,
        record: &DecisionRecord,
    ) -> Result<InsertDisposition, DecisionError> {
        let disposition = self.insert(record)?;
        let mut record = record.clone();
        record.ensure_source_hash()?;
        self.connection.execute(
            "UPDATE decision_records
             SET row_id = (SELECT COALESCE(MAX(row_id), 0) + 1 FROM decision_records)
             WHERE id = ?1 AND source_hash = ?2",
            params![record.id, record.source_hash],
        )?;
        Ok(disposition)
    }

    /// Set the current status of stable id `id` by appending a new state row.
    /// Returns the newly current record, or `None` when the id is unknown.
    pub fn set_status(
        &mut self,
        id: &str,
        status: DecisionStatus,
    ) -> Result<Option<DecisionRecord>, DecisionError> {
        let Some(mut record) = self.get(id)? else {
            return Ok(None);
        };
        record.current_status = status;
        record.source_hash = record.compute_source_hash()?;
        self.set_current(&record)?;
        self.get(id)
    }

    pub fn all(&self) -> Result<Vec<DecisionRecord>, DecisionError> {
        let mut statement = self.connection.prepare("SELECT id,source_hash,repository_id,scope_id,task_id,linked_graph_generation,rationale,alternatives_json,evidence_json,implementation_refs_json,supersedes_json,superseded_by,current_status,created_at,source_path,provenance_json FROM decision_records ORDER BY row_id")?;
        let rows = statement.query_map([], row_to_record)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(DecisionError::from)
    }

    pub fn get(&self, id: &str) -> Result<Option<DecisionRecord>, DecisionError> {
        let mut statement = self.connection.prepare("SELECT id,source_hash,repository_id,scope_id,task_id,linked_graph_generation,rationale,alternatives_json,evidence_json,implementation_refs_json,supersedes_json,superseded_by,current_status,created_at,source_path,provenance_json FROM decision_records WHERE id = ?1 ORDER BY row_id DESC LIMIT 1")?;
        statement
            .query_row([id], row_to_record)
            .optional()
            .map_err(DecisionError::from)
    }

    pub fn by_id(&self, id: &str) -> Result<Vec<DecisionRecord>, DecisionError> {
        let mut statement = self.connection.prepare("SELECT id,source_hash,repository_id,scope_id,task_id,linked_graph_generation,rationale,alternatives_json,evidence_json,implementation_refs_json,supersedes_json,superseded_by,current_status,created_at,source_path,provenance_json FROM decision_records WHERE id = ?1 ORDER BY source_hash")?;
        let rows = statement.query_map([id], row_to_record)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(DecisionError::from)
    }

    pub fn active(
        &self,
        repository_id: Option<&str>,
    ) -> Result<Vec<DecisionRecord>, DecisionError> {
        let records = self.all()?;
        Ok(records
            .into_iter()
            .filter(|record| {
                record.current_status.is_active()
                    && repository_id
                        .map(|id| id == record.repository_id)
                        .unwrap_or(true)
            })
            .collect())
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, DecisionError> {
    Ok(serde_json::to_string(value)?)
}

fn status(value: &DecisionStatus) -> &'static str {
    match value {
        DecisionStatus::Proposed => "proposed",
        DecisionStatus::Accepted => "accepted",
        DecisionStatus::Implemented => "implemented",
        DecisionStatus::Superseded => "superseded",
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(
    value: String,
    _column: &str,
) -> Result<T, rusqlite::Error> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(DecisionError::Json(error)),
        )
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> Result<DecisionRecord, rusqlite::Error> {
    let current_status: String = row.get(12)?;
    let current_status = match current_status.as_str() {
        "proposed" => DecisionStatus::Proposed,
        "accepted" => DecisionStatus::Accepted,
        "implemented" => DecisionStatus::Implemented,
        "superseded" => DecisionStatus::Superseded,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown status {other}"),
                )),
            ))
        }
    };
    Ok(DecisionRecord {
        schema_version: 1,
        id: row.get(0)?,
        source_hash: row.get(1)?,
        repository_id: row.get(2)?,
        scope_id: row.get(3)?,
        task_id: row.get(4)?,
        linked_graph_generation: row.get(5)?,
        rationale: row.get(6)?,
        alternatives: parse_json(row.get(7)?, "alternatives")?,
        evidence: parse_json(row.get(8)?, "evidence")?,
        implementation_refs: parse_json(row.get(9)?, "implementationRefs")?,
        supersedes: parse_json(row.get(10)?, "supersedes")?,
        superseded_by: row.get(11)?,
        current_status,
        created_at: row.get(13)?,
        source_path: row.get(14)?,
        provenance: parse_json(row.get(15)?, "provenance")?,
    })
}

pub(crate) fn value_to_record(
    value: Value,
    source_path: Option<String>,
) -> Result<DecisionRecord, DecisionError> {
    let mut record: DecisionRecord = serde_json::from_value(value)?;
    if record.source_path.is_none() {
        record.source_path = source_path;
    }
    record.validate()?;
    record.ensure_source_hash()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::DecisionStore;
    use crate::model::{DecisionRecord, DecisionStatus};

    fn draft() -> DecisionRecord {
        DecisionRecord::new(
            "repo-a",
            "workspace",
            "T-1",
            "use sqlite",
            DecisionStatus::Proposed,
        )
    }

    #[test]
    fn set_status_moves_current_state_forward_and_back() {
        let mut store = DecisionStore::in_memory().unwrap();
        let proposed = draft();
        let id = proposed.id.clone();
        store.set_current(&proposed).unwrap();

        let accepted = store
            .set_status(&id, DecisionStatus::Accepted)
            .unwrap()
            .expect("record exists");
        assert_eq!(accepted.current_status, DecisionStatus::Accepted);

        let back = store
            .set_status(&id, DecisionStatus::Proposed)
            .unwrap()
            .expect("record exists");
        assert_eq!(back.current_status, DecisionStatus::Proposed);

        let again = store
            .set_status(&id, DecisionStatus::Accepted)
            .unwrap()
            .expect("record exists");
        assert_eq!(again.current_status, DecisionStatus::Accepted);
        assert_eq!(
            store.get(&id).unwrap().unwrap().current_status,
            DecisionStatus::Accepted
        );
        assert_eq!(store.by_id(&id).unwrap().len(), 2);
    }

    #[test]
    fn set_status_on_unknown_id_is_none_and_writes_nothing() {
        let mut store = DecisionStore::in_memory().unwrap();
        let result = store
            .set_status("architect:decision:missing", DecisionStatus::Accepted)
            .unwrap();
        assert!(result.is_none());
        assert!(store.all().unwrap().is_empty());
    }
}
