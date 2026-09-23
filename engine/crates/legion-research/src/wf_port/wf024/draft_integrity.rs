//! Port of `src/lib/research-core/draft_integrity.py`.
//!
//! Detects any sourced-draft edit that bypasses the authenticated patch
//! path, by comparing the sha256 of `run_dir/draft.md` against the hash
//! recorded on the manifest's last authorized draft artifact.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Python truthiness for an arbitrary JSON value (used for `if patched:`,
/// mirroring `domain_verify`'s `truthy`: `None`, `false`, `0`, `""`, `[]`,
/// and `{}` are all falsy).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn sha256_hex(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Faithful port of `check(run_dir, manifest_doc)`.
pub fn check(run_dir: &Path, manifest_doc: &Value) -> Value {
    let draft = run_dir.join("draft.md");
    if !draft.is_file() {
        return json!({"ok": false, "reason": "draft.md is missing"});
    }

    let artifacts = manifest_doc
        .get("artifacts")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let patched = artifacts.get("patched-draft");
    let sourced = artifacts.get("sourced-draft");
    let patch_exists = run_dir.join("applied.patch").is_file();

    let (expected, authority) = if patch_exists {
        match patched.and_then(|p| p.get("sha256")).and_then(Value::as_str) {
            None => {
                return json!({
                    "ok": false,
                    "reason": "applied.patch exists without a hash-bound patched-draft artifact",
                });
            }
            Some(sha) if sha.is_empty() => {
                return json!({
                    "ok": false,
                    "reason": "applied.patch exists without a hash-bound patched-draft artifact",
                });
            }
            Some(sha) => (sha.to_string(), "patched-draft"),
        }
    } else {
        if patched.map(truthy).unwrap_or(false) {
            return json!({
                "ok": false,
                "reason": "patched-draft artifact exists without applied.patch",
            });
        }
        match sourced.and_then(|s| s.get("sha256")).and_then(Value::as_str) {
            None => {
                return json!({
                    "ok": false,
                    "reason": "sourced-draft artifact is missing its hash",
                });
            }
            Some(sha) if sha.is_empty() => {
                return json!({
                    "ok": false,
                    "reason": "sourced-draft artifact is missing its hash",
                });
            }
            Some(sha) => (sha.to_string(), "sourced-draft"),
        }
    };

    let actual = match sha256_hex(&draft) {
        Ok(hash) => hash,
        Err(_) => {
            return json!({"ok": false, "reason": "draft.md is missing"});
        }
    };

    let ok = actual == expected;
    json!({
        "ok": ok,
        "reason": if ok { "ok" } else { "draft hash differs from the last authorized draft artifact" },
        "authority": authority,
        "expected_sha256": expected,
        "actual_sha256": actual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf024_draft_integrity_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_draft(dir: &Path, contents: &str) -> String {
        let path = dir.join("draft.md");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(contents.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[test]
    fn missing_draft_fails() {
        let dir = temp_dir("missing");
        let result = check(&dir, &json!({}));
        assert_eq!(result, json!({"ok": false, "reason": "draft.md is missing"}));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sourced_draft_matches() {
        let dir = temp_dir("sourced_match");
        let hash = write_draft(&dir, "hello world");
        let manifest = json!({"artifacts": {"sourced-draft": {"sha256": hash}}});
        let result = check(&dir, &manifest);
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["authority"], json!("sourced-draft"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sourced_draft_hash_mismatch() {
        let dir = temp_dir("sourced_mismatch");
        write_draft(&dir, "hello world");
        let manifest = json!({"artifacts": {"sourced-draft": {"sha256": "deadbeef"}}});
        let result = check(&dir, &manifest);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["reason"],
            json!("draft hash differs from the last authorized draft artifact")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patched_draft_without_patch_file_fails() {
        let dir = temp_dir("patched_no_patch");
        write_draft(&dir, "hello world");
        let manifest = json!({"artifacts": {"patched-draft": {"sha256": "abc"}}});
        let result = check(&dir, &manifest);
        assert_eq!(
            result,
            json!({"ok": false, "reason": "patched-draft artifact exists without applied.patch"})
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn applied_patch_without_hash_fails() {
        let dir = temp_dir("patch_no_hash");
        write_draft(&dir, "hello world");
        fs::write(dir.join("applied.patch"), "diff").unwrap();
        let manifest = json!({"artifacts": {}});
        let result = check(&dir, &manifest);
        assert_eq!(
            result,
            json!({
                "ok": false,
                "reason": "applied.patch exists without a hash-bound patched-draft artifact"
            })
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn applied_patch_with_matching_hash_ok() {
        let dir = temp_dir("patch_match");
        let hash = write_draft(&dir, "patched content");
        fs::write(dir.join("applied.patch"), "diff").unwrap();
        let manifest = json!({"artifacts": {"patched-draft": {"sha256": hash}}});
        let result = check(&dir, &manifest);
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["authority"], json!("patched-draft"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_sourced_draft_hash_fails() {
        let dir = temp_dir("no_sourced_hash");
        write_draft(&dir, "hello world");
        let manifest = json!({"artifacts": {}});
        let result = check(&dir, &manifest);
        assert_eq!(
            result,
            json!({"ok": false, "reason": "sourced-draft artifact is missing its hash"})
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
