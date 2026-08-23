//! Deterministic validation surfaces for legacy dispatch artifacts.
//!
//! Validators intentionally return data instead of printing or performing effects.  Each
//! validator applies the same ordered phases: shape, identity, references, ordering,
//! ownership, then semantic bounds.

pub mod dispatch;
pub mod goalroute;
pub mod minimize;
pub mod tasklist;

use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub source: String,
    pub line: u32,
    pub field: String,
    pub reason: String,
    pub code: String,
    pub level: DiagnosticLevel,
}

impl Diagnostic {
    pub fn error(
        source: impl Into<String>,
        line: u32,
        field: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            line,
            field: field.into(),
            reason: reason.into(),
            code: code.into(),
            level: DiagnosticLevel::Error,
        }
    }
}

impl Ord for Diagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.source,
            self.line,
            &self.field,
            &self.code,
            &self.reason,
        )
            .cmp(&(
                &other.source,
                other.line,
                &other.field,
                &other.code,
                &other.reason,
            ))
    }
}

impl PartialOrd for Diagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn from_diagnostics(mut diagnostics: Vec<Diagnostic>) -> Self {
        diagnostics.sort();
        diagnostics.dedup();
        Self { diagnostics }
    }
    pub fn is_valid(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|item| item.level == DiagnosticLevel::Error)
    }
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|item| item.level == DiagnosticLevel::Error)
    }
}

pub(crate) fn require_non_empty(
    value: &str,
    source: &str,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if value.trim().is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            field,
            "INVALID_INPUT_OR_SCHEMA",
            "must be non-empty",
        ));
    }
}

pub(crate) fn require_unique(
    values: &[String],
    source: &str,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            errors.push(Diagnostic::error(
                source,
                0,
                field,
                "IDENTITY_NOT_UNIQUE",
                format!("duplicate identity: {value}"),
            ));
        }
    }
}
