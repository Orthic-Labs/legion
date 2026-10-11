//! Native implementations of `legacy.data.internal-suite` and
//! `legacy.infrastructure.internal-suite`.
//!
//! Both suites are candidate generators, like the framework suite: their
//! candidates are retained in details and never promoted to ProviderResult
//! findings. Coverage follows the same convention -- the result is Partial
//! whenever a denominator file is unreadable, the denominator is empty, no
//! file in it is one the suite inspects, or the suite itself failed; it is
//! never Complete on zero inspected files.

use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
};

use legion_contracts::{ProviderResult, ProviderStatus};
use serde_json::Value;

use super::common::{denominator, result, source_files, ProviderInput};
use crate::error::AuditError;
use crate::native_providers::p11d_quality::{data_suite, infrastructure_suite};

type Suite = fn(&Path, &[String]) -> Value;

fn execute_candidate_suite(
    input: &ProviderInput<'_>,
    label: &str,
    suite: Suite,
    inspects: fn(&str) -> bool,
) -> Result<ProviderResult, AuditError> {
    let selected = denominator(input)?;
    let (files, mut gaps) = source_files(input, &selected);
    let inspected: Vec<String> = files
        .iter()
        .map(|(entry, _)| entry.path.clone())
        .filter(|path| inspects(path))
        .collect();
    if selected.entries.is_empty() {
        gaps.push(format!("{label}-denominator-zero"));
    } else if inspected.is_empty() {
        gaps.push(format!("{label}-no-inspectable-files"));
    }
    let analysis = match catch_unwind(AssertUnwindSafe(|| suite(input.root, &inspected))) {
        Ok(value) => value,
        Err(_) => {
            gaps.push(format!("{label}-suite-failed"));
            Value::Null
        }
    };
    if let Some(items) = analysis.get("coverageGaps").and_then(Value::as_array) {
        gaps.extend(items.iter().filter_map(|item| {
            item.get("kind")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        }));
    }
    let candidates = analysis
        .get("candidates")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let has_candidates = candidates.as_array().is_some_and(|rows| !rows.is_empty());
    let complete = gaps.is_empty() && files.len() == selected.entries.len();
    let mut details = BTreeMap::new();
    details.insert("analysis".to_owned(), analysis);
    details.insert("candidates".to_owned(), candidates);
    details.insert(
        "inspectedFiles".to_owned(),
        Value::from(inspected.len() as u64),
    );
    let status_label = if !complete {
        "unproven"
    } else if has_candidates {
        "candidates"
    } else {
        "pass"
    };
    details.insert("status".to_owned(), Value::String(status_label.to_owned()));
    result(
        input,
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        &selected,
        files.len(),
        Vec::new(),
        gaps.clone(),
        gaps,
        details,
    )
}

pub fn execute_data(input: &ProviderInput<'_>) -> Result<ProviderResult, AuditError> {
    execute_candidate_suite(
        input,
        "data",
        data_suite::run_data_suite,
        data_suite::inspects,
    )
}

pub fn execute_infrastructure(input: &ProviderInput<'_>) -> Result<ProviderResult, AuditError> {
    // Every rule decides applicability from the path and text itself, so each
    // selected file is inspected.
    execute_candidate_suite(
        input,
        "infrastructure",
        infrastructure_suite::run_infrastructure_suite,
        |_| true,
    )
}
