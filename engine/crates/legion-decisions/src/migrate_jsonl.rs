use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{
    error::DecisionError,
    model::DecisionRecord,
    store::{value_to_record, DecisionStore, InsertDisposition},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MigrationDiagnostic {
    pub source: String,
    pub line: usize,
    pub message: String,
    pub raw: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MigrationDisposition {
    pub source: String,
    pub line: usize,
    pub id: String,
    pub source_hash: String,
    pub disposition: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub inserted: Vec<MigrationDisposition>,
    pub already_present: Vec<MigrationDisposition>,
    pub malformed: Vec<MigrationDiagnostic>,
}

impl MigrationReport {
    pub fn accepted(&self) -> usize {
        self.inserted.len() + self.already_present.len()
    }
    pub fn malformed_count(&self) -> usize {
        self.malformed.len()
    }
}

pub fn migrate_jsonl(
    store: &mut DecisionStore,
    path: impl AsRef<Path>,
) -> Result<MigrationReport, DecisionError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| DecisionError::Io {
        path: path.display().to_string(),
        source,
    })?;
    migrate_reader(store, BufReader::new(file), path.display().to_string())
}

pub fn migrate_reader<R: BufRead>(
    store: &mut DecisionStore,
    reader: R,
    source: impl Into<String>,
) -> Result<MigrationReport, DecisionError> {
    let source = source.into();
    let mut report = MigrationReport::default();
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let raw = match line {
            Ok(value) => value,
            Err(error) => {
                report.malformed.push(MigrationDiagnostic {
                    source: source.clone(),
                    line: line_number,
                    message: error.to_string(),
                    raw: String::new(),
                });
                continue;
            }
        };
        if raw.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(error) => {
                report.malformed.push(MigrationDiagnostic {
                    source: source.clone(),
                    line: line_number,
                    message: error.to_string(),
                    raw,
                });
                continue;
            }
        };
        let mut record: DecisionRecord = match value_to_record(value, Some(source.clone())) {
            Ok(record) => record,
            Err(error) => {
                report.malformed.push(MigrationDiagnostic {
                    source: source.clone(),
                    line: line_number,
                    message: error.to_string(),
                    raw,
                });
                continue;
            }
        };
        record
            .provenance
            .entry("sourceLine".into())
            .or_insert_with(|| line_number.to_string());
        let disposition = store.insert(&record)?;
        let item = MigrationDisposition {
            source: source.clone(),
            line: line_number,
            id: record.id.clone(),
            source_hash: record.source_hash.clone(),
            disposition: match disposition {
                InsertDisposition::Inserted => "inserted",
                InsertDisposition::AlreadyPresent => "already_present",
            }
            .into(),
        };
        match disposition {
            InsertDisposition::Inserted => report.inserted.push(item),
            InsertDisposition::AlreadyPresent => report.already_present.push(item),
        }
    }
    Ok(report)
}
