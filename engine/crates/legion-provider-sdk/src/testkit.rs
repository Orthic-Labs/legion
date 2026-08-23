use std::time::Instant;

use crate::{
    context::ProviderContext,
    error::{ProviderError, ProviderErrorKind},
    result::{normalize_result, ProviderResult},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceCase {
    MissingTool,
    Timeout,
    MalformedOutput,
    EmptySuccess,
    Cancellation,
}

pub fn expected_error(case: ConformanceCase) -> Option<ProviderErrorKind> {
    match case {
        ConformanceCase::MissingTool => Some(ProviderErrorKind::MissingTool),
        ConformanceCase::Timeout => Some(ProviderErrorKind::Timeout),
        ConformanceCase::MalformedOutput => Some(ProviderErrorKind::MalformedOutput),
        ConformanceCase::EmptySuccess => None,
        ConformanceCase::Cancellation => Some(ProviderErrorKind::Cancelled),
    }
}

pub fn missing_tool(tool: impl Into<String>) -> ProviderError {
    ProviderError::missing_tool(tool)
}
pub fn timeout() -> ProviderError {
    ProviderError::timeout()
}
pub fn malformed_output(message: impl Into<String>) -> ProviderError {
    ProviderError::malformed(message)
}

pub fn cancellation(context: &ProviderContext) -> Result<(), ProviderError> {
    if context.is_cancelled() {
        Err(ProviderError::cancelled())
    } else {
        Ok(())
    }
}

pub fn timeout_at(context: &ProviderContext, now: Instant) -> Result<(), ProviderError> {
    context.ensure_available(now)
}

/// Normalize an explicitly empty provider result. Empty findings do not add
/// coverage and therefore cannot turn an unproven result into a complete one.
pub fn empty_success(result: ProviderResult) -> Result<ProviderResult, ProviderError> {
    normalize_result(result)
}

pub fn assert_case(case: ConformanceCase, error: &ProviderError) -> Result<(), ProviderError> {
    match expected_error(case) {
        Some(kind) if kind == error.kind => Ok(()),
        Some(kind) => Err(ProviderError::new(
            ProviderErrorKind::InvalidResult,
            format!("expected {kind}, got {}", error.kind),
        )),
        None => Err(ProviderError::new(
            ProviderErrorKind::InvalidResult,
            "case does not expect an error",
        )),
    }
}
