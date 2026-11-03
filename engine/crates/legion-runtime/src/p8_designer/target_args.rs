//! Port of `skills/designer/engine/scripts/lib/target-args.mjs`.
//!
//! Same inputs/outputs and error semantics as the JS source: parses a
//! `--target <path>` / `-t <path>` / `--target=<path>` argument out of an
//! argv-style slice, optionally requiring a value in `strict` mode.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetArgError {
    pub message: String,
    pub code: &'static str,
}

impl fmt::Display for TargetArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TargetArgError {}

/// Mirrors `parseTargetPath(args, { strict })`.
pub fn parse_target_path(args: &[String], strict: bool) -> Result<Option<String>, TargetArgError> {
    let mut target_path: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--target" || arg == "-t" {
            let next = args.get(i + 1);
            if let Some(next) = next {
                if !next.starts_with('-') {
                    target_path = Some(next.clone());
                    i += 2;
                    continue;
                }
            }
            if strict {
                return Err(TargetArgError {
                    message: "--target requires a path value.".to_string(),
                    code: "TARGET_VALUE_MISSING",
                });
            }
            i += 1;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--target=") {
            if !value.is_empty() {
                target_path = Some(value.to_string());
                i += 1;
                continue;
            }
            if strict {
                return Err(TargetArgError {
                    message: "--target requires a path value.".to_string(),
                    code: "TARGET_VALUE_MISSING",
                });
            }
        }
        i += 1;
    }
    Ok(target_path)
}

/// Mirrors `parseTargetOptions(args, options)`: `None` when no target was
/// given (JS returns `{}`), `Some(path)` otherwise (JS returns
/// `{ targetPath }`).
pub fn parse_target_options(
    args: &[String],
    strict: bool,
) -> Result<Option<String>, TargetArgError> {
    parse_target_path(args, strict)
}
