//! Port of `FORBIDDEN_STORAGE_PARTS` and `storage_errors()` from
//! `validate-dispatch.py` (lines ~27-149).

use super::route_scan::label_value;
use crate::wf_port::w2_045::path_utils::{
    clean_path_value, in_platform_temp_dir, normalized_path, resolve_declared_path,
};
use std::collections::BTreeSet;
use std::path::Path;

/// Port of `FORBIDDEN_STORAGE_PARTS`.
pub const FORBIDDEN_STORAGE_PARTS: &[&str] = &[
    "temp",
    "tmp",
    ".tmp",
    "temporary",
    "cache",
    ".cache",
    "review-run",
    "review-runs",
    ".review-runs",
    ".council-runs",
    "scratch",
];

fn forbidden_parts(normalized: &str) -> bool {
    let parts: BTreeSet<&str> = normalized.split('/').collect();
    parts.iter().any(|p| FORBIDDEN_STORAGE_PARTS.contains(p))
        || parts.iter().any(|p| p.starts_with(".validator-"))
}

/// Port of `storage_errors()`.
pub fn storage_errors(
    text: &str,
    artifact: &Path,
    write_receipt: Option<&Path>,
    verify_receipt: Option<&Path>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let declared_artifact =
        clean_path_value(&label_value(text, "**Validated artifact path:**").unwrap_or_default());
    let declared_receipt =
        clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
    let actual_artifact = artifact.to_path_buf();
    let receipt_arg = write_receipt.or(verify_receipt);

    if !artifact.is_absolute() {
        errors.push("validator requires absolute dispatch file path".to_string());
    }
    if declared_artifact.is_empty() {
        errors.push("declared dispatch artifact path is required".to_string());
    } else if resolve_declared_path(&declared_artifact, &actual_artifact) != actual_artifact {
        errors.push("declared dispatch artifact path does not match validated file".to_string());
    }

    let artifact_normalized = normalized_path(&actual_artifact.to_string_lossy(), None);
    if forbidden_parts(&artifact_normalized) || in_platform_temp_dir(&actual_artifact) {
        errors.push("canonical dispatch cannot use temporary/cache/review-run storage".to_string());
    }
    let suffix_is_md = actual_artifact
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase() == "md")
        .unwrap_or(false);
    if !suffix_is_md {
        errors.push("canonical dispatch must be Markdown".to_string());
    }

    let Some(receipt_arg) = receipt_arg else {
        errors.push("validation must write or verify sidecar receipt".to_string());
        return errors;
    };
    if !receipt_arg.is_absolute() {
        errors.push("validator requires absolute receipt path".to_string());
    }
    if declared_receipt.is_empty() {
        errors.push("declared receipt path is required".to_string());
    } else if resolve_declared_path(&declared_receipt, &actual_artifact) != receipt_arg {
        errors.push("declared receipt path does not match validator receipt argument".to_string());
    }
    let receipt_parent = receipt_arg.parent().unwrap_or_else(|| Path::new(""));
    let artifact_parent = actual_artifact.parent().unwrap_or_else(|| Path::new(""));
    if normalized_path(&receipt_parent.to_string_lossy(), None)
        != normalized_path(&artifact_parent.to_string_lossy(), None)
    {
        errors.push("dispatch receipt must be adjacent to canonical artifact".to_string());
    }
    let stem = actual_artifact
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let expected_receipt = format!("{stem}.receipt.json");
    let receipt_name = receipt_arg
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if receipt_name != expected_receipt {
        errors.push(format!("dispatch receipt must be named {expected_receipt}"));
    }
    let receipt_normalized = normalized_path(&receipt_arg.to_string_lossy(), None);
    if forbidden_parts(&receipt_normalized) || in_platform_temp_dir(&receipt_arg) {
        errors.push("dispatch receipt cannot use temporary/cache/review-run storage".to_string());
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_artifact_path_flagged() {
        let text = "- **Validated artifact path:** dispatch.md\n- **Receipt path:** dispatch.receipt.json\n";
        let errors = storage_errors(text, Path::new("dispatch.md"), None, None);
        assert!(errors.iter().any(|e| e.contains("absolute dispatch file path")));
    }

    #[test]
    fn missing_receipt_arg_is_required() {
        let artifact = Path::new("/repo/dispatch.md");
        let text = "- **Validated artifact path:** /repo/dispatch.md\n- **Receipt path:** /repo/dispatch.receipt.json\n";
        let errors = storage_errors(text, artifact, None, None);
        assert!(errors.iter().any(|e| e.contains("write or verify sidecar receipt")));
    }

    #[test]
    fn temp_storage_is_rejected() {
        let artifact = Path::new("/repo/.tmp/dispatch.md");
        let text = "- **Validated artifact path:** /repo/.tmp/dispatch.md\n- **Receipt path:** /repo/.tmp/dispatch.receipt.json\n";
        let errors = storage_errors(text, artifact, None, None);
        assert!(errors
            .iter()
            .any(|e| e.contains("temporary/cache/review-run storage")));
    }
}
