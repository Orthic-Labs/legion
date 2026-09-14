//! Stable contracts for legacy-check providers.
//!
//! A legacy check is a project-owned tool boundary.  This module only models
//! its request, command shape, output, and terminal errors; it never resolves
//! or launches a project executable.

use std::{collections::BTreeMap, path::PathBuf};

use legion_contracts::{Coverage, FindingRef, ProviderStatus};
use serde_json::Value;

use crate::{inventory::InventoryDenominator, plan::AuditProvider};

/// Every legacy-check record in the frozen registry uses this request kind.
pub const REQUEST_KIND: &str = "legion-named-check";
pub const CONTRACT_SCHEMA_VERSION: u32 = 1;

/// A command is argv-only.  `Named` is resolved by the host's registered
/// project-tool surface; it is intentionally not a shell command string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandShape {
    /// A native Rust adapter owns this check's algorithm.
    Native { operation: &'static str },
    /// One fixed executable and argument vector.
    Fixed {
        executable: &'static str,
        args: &'static [&'static str],
    },
    /// A host resolves one of these project tools, preserving alternatives
    /// from the registry without selecting a tool in Legion.
    Named {
        tool: &'static str,
        args: &'static [&'static str],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyCheckSpec {
    pub provider_id: &'static str,
    pub check: &'static str,
    pub phase: &'static str,
    pub role: &'static str,
    pub tool: &'static str,
    pub selector: &'static str,
    pub command: CommandShape,
}

/// Complete frozen input passed to a check.  Values are copied at dispatch so
/// later host mutation cannot change the request that was authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCheckInput {
    pub provider_id: String,
    pub check: String,
    pub root: PathBuf,
    pub inventory_generation: String,
    pub inventory_digest: String,
    pub denominator: InventoryDenominator,
    pub binding: Option<Value>,
    pub projection: Option<Value>,
    pub artifacts: Value,
}

/// Typed process request handed to an external-project-tool implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCheckProcessRequest {
    pub schema_version: u32,
    pub kind: &'static str,
    pub provider_id: String,
    pub check: String,
    pub cwd: PathBuf,
    pub binding: Option<Value>,
    pub denominator: InventoryDenominator,
    pub projection: Option<Value>,
    pub artifacts: Value,
    pub command: CommandShape,
}

/// A host may preserve arbitrary check-specific output in `details` while the
/// common fields remain typed for report aggregation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCheckOutput {
    pub status: ProviderStatus,
    pub complete: bool,
    pub coverage: Option<Coverage>,
    pub findings: Vec<FindingRef>,
    pub candidates: Vec<Value>,
    pub coverage_gaps: Vec<String>,
    pub degradation: Vec<String>,
    pub details: BTreeMap<String, Value>,
}

impl Default for LegacyCheckOutput {
    fn default() -> Self {
        Self {
            status: ProviderStatus::Partial,
            complete: false,
            coverage: None,
            findings: Vec::new(),
            candidates: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::new(),
        }
    }
}

/// Terminal process states are retained separately from provider findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyCheckProcessState {
    Completed,
    Failed,
    MissingExecutable,
    Unauthorized,
    Timeout,
    Cancelled,
    OutputLimited,
    CleanupUnconfirmed,
}

impl LegacyCheckProcessState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::MissingExecutable => "missing_executable",
            Self::Unauthorized => "unauthorized_effect",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::OutputLimited => "output_limited",
            Self::CleanupUnconfirmed => "cleanup_unconfirmed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCheckError {
    pub provider_id: String,
    pub check: String,
    pub state: LegacyCheckProcessState,
    pub message: String,
}

impl std::fmt::Display for LegacyCheckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "legacy check {} ({}) {}: {}",
            self.provider_id,
            self.check,
            self.state.as_str(),
            self.message
        )
    }
}

impl std::error::Error for LegacyCheckError {}

/// Host result envelope.  Keeping process metadata alongside parsed output
/// prevents an unsuccessful tool from being mistaken for an empty pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCheckExecution {
    pub state: LegacyCheckProcessState,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub receipt_id: Option<String>,
    pub output: Option<LegacyCheckOutput>,
    pub error: Option<LegacyCheckError>,
}

impl LegacyCheckExecution {
    pub fn failed(
        provider_id: impl Into<String>,
        check: impl Into<String>,
        state: LegacyCheckProcessState,
        message: impl Into<String>,
    ) -> Self {
        let provider_id = provider_id.into();
        let check = check.into();
        Self {
            state,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            receipt_id: None,
            output: None,
            error: Some(LegacyCheckError {
                provider_id,
                check,
                state,
                message: message.into(),
            }),
        }
    }
}

/// Minimal validation shared by every dispatcher implementation.
pub fn validate_provider(
    provider: &AuditProvider,
    spec: &LegacyCheckSpec,
) -> Result<(), LegacyCheckError> {
    let invalid = |message: String| LegacyCheckError {
        provider_id: provider.id.clone(),
        check: spec.check.to_owned(),
        state: LegacyCheckProcessState::Failed,
        message,
    };
    if provider.id != spec.provider_id {
        return Err(invalid(format!(
            "provider id does not match contract {}",
            spec.provider_id
        )));
    }
    let runner = provider
        .configuration
        .get("runner")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("provider runner is missing".into()))?;
    if runner.get("kind").and_then(Value::as_str) != Some("legacy-check") {
        return Err(invalid("provider runner kind is not legacy-check".into()));
    }
    if runner.get("check").and_then(Value::as_str) != Some(spec.check) {
        return Err(invalid(format!("runner check is not {}", spec.check)));
    }
    Ok(())
}
