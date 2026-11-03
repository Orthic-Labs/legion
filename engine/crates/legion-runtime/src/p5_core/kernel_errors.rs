//! Ported from src/packages/kernel/lib/errors.mjs (packet P5d).
//!
//! Faithful port of `EXIT_CODES` and `KernelError`. JS attaches an
//! `exitCode` derived from `category` at construction time; this port does
//! the same via `exit_code_for_category`.

use legion_catalog::json;

/// Port of the `EXIT_CODES` category -> process exit code map.
pub fn exit_code_for_category(category: &str) -> i32 {
    match category {
        "usage" => 2,
        "precondition" => 3,
        "authority" => 4,
        "policy" => 5,
        "integrity" => 6,
        "context" => 7,
        "execution" => 8,
        "external" => 9,
        "resource" => 10,
        "conflict" => 11,
        "cancelled" => 130,
        "internal" => 70,
        _ => 70,
    }
}

/// Options accepted by [`KernelError::new`], mirroring the JS `options` bag.
#[derive(Debug, Clone, Default)]
pub struct KernelErrorOptions {
    pub category: Option<String>,
    pub layer: Option<String>,
    pub retryable: Option<bool>,
    pub state_preserved: Option<bool>,
    pub remediation: Option<String>,
    pub details: Option<json::Value>,
    pub cause: Option<String>,
}

/// Port of `class KernelError extends Error`.
#[derive(Debug, Clone)]
pub struct KernelError {
    pub code: String,
    pub message: String,
    pub category: String,
    pub layer: String,
    pub retryable: bool,
    pub state_preserved: bool,
    pub exit_code: i32,
    pub remediation: Option<String>,
    pub details: Option<json::Value>,
    pub cause: Option<String>,
}

impl KernelError {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        options: KernelErrorOptions,
    ) -> Self {
        let category = options.category.unwrap_or_else(|| "internal".to_string());
        let exit_code = exit_code_for_category(&category);
        KernelError {
            code: code.into(),
            message: message.into(),
            category,
            layer: options.layer.unwrap_or_else(|| "kernel".to_string()),
            retryable: options.retryable.unwrap_or(false),
            state_preserved: options.state_preserved.unwrap_or(true),
            exit_code,
            remediation: options.remediation,
            details: options.details,
            cause: options.cause,
        }
    }

    /// Convenience constructor matching the common `(code, message, category)` call shape.
    pub fn simple(
        code: impl Into<String>,
        message: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self::new(
            code,
            message,
            KernelErrorOptions {
                category: Some(category.into()),
                ..Default::default()
            },
        )
    }

    /// Port of `toJSON()`.
    pub fn to_json(&self) -> json::Value {
        json::json!({
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "responsibleLayer": self.layer,
            "retryable": self.retryable,
            "statePreserved": self.state_preserved,
            "exitCode": self.exit_code,
            "remediation": self.remediation,
            "details": self.details,
        })
    }
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for KernelError {}
