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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_long_flag_with_space() {
        let args = v(&["--target", "foo/bar.html"]);
        assert_eq!(
            parse_target_path(&args, false).unwrap(),
            Some("foo/bar.html".to_string())
        );
    }

    #[test]
    fn parses_short_flag() {
        let args = v(&["-t", "foo.html"]);
        assert_eq!(
            parse_target_path(&args, false).unwrap(),
            Some("foo.html".to_string())
        );
    }

    #[test]
    fn parses_equals_form() {
        let args = v(&["--target=foo.html"]);
        assert_eq!(
            parse_target_path(&args, false).unwrap(),
            Some("foo.html".to_string())
        );
    }

    #[test]
    fn missing_value_non_strict_returns_none() {
        let args = v(&["--target"]);
        assert_eq!(parse_target_path(&args, false).unwrap(), None);
    }

    #[test]
    fn missing_value_strict_errors() {
        let args = v(&["--target"]);
        let err = parse_target_path(&args, true).unwrap_err();
        assert_eq!(err.code, "TARGET_VALUE_MISSING");
    }

    #[test]
    fn value_that_looks_like_flag_is_rejected_as_missing() {
        let args = v(&["--target", "--other"]);
        assert_eq!(parse_target_path(&args, false).unwrap(), None);
    }

    #[test]
    fn no_target_present() {
        let args = v(&["--other", "val"]);
        assert_eq!(parse_target_path(&args, false).unwrap(), None);
    }

    #[test]
    fn last_occurrence_wins() {
        let args = v(&["--target", "a.html", "--target", "b.html"]);
        assert_eq!(
            parse_target_path(&args, false).unwrap(),
            Some("b.html".to_string())
        );
    }

    #[test]
    fn options_wrapper_matches_path_parse() {
        let args = v(&["-t", "x.html"]);
        assert_eq!(
            parse_target_options(&args, false).unwrap(),
            Some("x.html".to_string())
        );
        let none_args = v(&[]);
        assert_eq!(parse_target_options(&none_args, false).unwrap(), None);
    }
}
