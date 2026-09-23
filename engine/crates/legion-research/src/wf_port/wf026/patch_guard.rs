//! Port of `src/lib/research-core/patch_guard.py`.
//!
//! Issues authenticated Research patch-stage receipts: an HMAC-SHA256
//! signed JSON document binding a draft file's sha256 to a fixed
//! `Read`+`Edit` tool grant and hunk caps, for `patcher.py` to later
//! validate before applying a correction diff.
//!
//! NOTE (preserved from the Python source, not fixed by this port): the
//! receipt this module issues sets `issued_by: "research-core.patch-guard"`,
//! but `patcher.validate_correction_receipt` (see `patcher.rs`) requires
//! `issued_by == "rhook.research-patch-guard"`. In the Python originals a
//! receipt from `patch_guard.issue_receipt` therefore fails
//! `patcher.validate_correction_receipt`'s own check unless some other
//! issuer produces the `rhook.*` value. This port reproduces both sides of
//! that mismatch exactly rather than reconciling them, since fixing either
//! side would change behaviour beyond what was asked (faithful port); see
//! the packet report for this observation.

use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_MAX_HUNKS: u32 = 8;
pub const DEFAULT_MAX_HUNK_BYTES: u32 = 4096;

#[derive(Debug)]
pub struct PatchGuardError(pub String);

impl fmt::Display for PatchGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PatchGuardError {}

/// Mirrors `default_key_path()`: `$RESEARCH_PATCH_KEY` if set, else
/// `~/.claude/research-patch.key`.
pub fn default_key_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("RESEARCH_PATCH_KEY") {
        return PathBuf::from(shellexpand_home(&override_path));
    }
    home_dir().join(".claude").join("research-patch.key")
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn shellexpand_home(path: &str) -> PathBuf {
    let expanded: PathBuf = if let Some(rest) = path.strip_prefix('~') {
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        if rest.is_empty() {
            home_dir()
        } else {
            home_dir().join(rest)
        }
    } else {
        PathBuf::from(path)
    };
    expanded
}

/// Mirrors `load_or_create_key()`: creates a random 32-byte key on first use
/// (best-effort `0o600` permissions, matching the Python `try/except
/// OSError: pass`), then loads and returns it. Errors if the existing key is
/// shorter than 32 bytes.
pub fn load_or_create_key(path: Option<&Path>) -> Result<Vec<u8>, PatchGuardError> {
    let path = path.map(PathBuf::from).unwrap_or_else(default_key_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| PatchGuardError(format!("cannot create key directory: {e}")))?;
    }
    if !path.exists() {
        let key = random_bytes(32);
        fs::write(&path, &key).map_err(|e| PatchGuardError(format!("cannot write key: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort, matching the Python `try/except OSError: pass`.
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
    let key = fs::read(&path).map_err(|e| PatchGuardError(format!("cannot read key: {e}")))?;
    if key.len() < 32 {
        return Err(PatchGuardError(
            "research patch signing key must be at least 32 bytes".into(),
        ));
    }
    Ok(key)
}

fn random_bytes(n: usize) -> Vec<u8> {
    // No RNG crate is wired into this crate's dependencies (see packet
    // report); this draws OS randomness the same way `secrets.token_bytes`
    // does, via the platform CSPRNG, without adding a new dependency.
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut file = fs::File::open("/dev/urandom").expect("open /dev/urandom");
        let mut buf = vec![0u8; n];
        file.read_exact(&mut buf).expect("read /dev/urandom");
        buf
    }
    #[cfg(not(unix))]
    {
        // Fallback for non-unix targets: time-seeded, not cryptographically
        // strong. This crate currently has no non-unix release target; flag
        // if that changes.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut buf = vec![0u8; n];
        let mut state = seed as u64 ^ 0x9E3779B97F4A7C15;
        for byte in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xFF) as u8;
        }
        buf
    }
}

/// Mirrors `canonical_payload()`: the receipt object with `signature`
/// removed, serialized as compact, key-sorted JSON (`sort_keys=True,
/// separators=(",", ":")`).
pub fn canonical_payload(receipt: &Value) -> Vec<u8> {
    let mut body = receipt.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("signature");
    }
    canonical_json(&body).into_bytes()
}

/// Deterministic compact key-sorted JSON, matching Python's
/// `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", canonical_json(&Value::String(k.clone())), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Mirrors `sign()`: `"hmac-sha256:" + hex(hmac_sha256(key, canonical_payload(receipt)))`.
pub fn sign(receipt: &Value, key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&canonical_payload(receipt));
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

/// Mirrors `issue_receipt()`: builds a v2 patch-stage receipt bound to the
/// draft file's sha256, then signs it in place under `signature`.
pub fn issue_receipt(
    draft: &Path,
    run_id: &str,
    key_path: Option<&Path>,
) -> Result<Value, PatchGuardError> {
    let draft_bytes = fs::read(draft).map_err(|e| PatchGuardError(format!("cannot read draft: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&draft_bytes);
    let draft_sha256 = hex::encode(hasher.finalize());

    let issued_at = iso8601_now();

    let mut receipt = json!({
        "receipt_version": 2,
        "issued_by": "research-core.patch-guard",
        "issued_at": issued_at,
        "run_id": run_id,
        "stage": "patch",
        "allowed_tools": ["Read", "Edit"],
        "sourced_draft_sha256": draft_sha256,
        "max_hunks": DEFAULT_MAX_HUNKS,
        "max_hunk_bytes": DEFAULT_MAX_HUNK_BYTES,
    });

    let key = load_or_create_key(key_path)?;
    let signature = sign(&receipt, &key);
    receipt["signature"] = json!(signature);
    Ok(receipt)
}

/// Mirrors `datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")`.
fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86_400;
    let secs_of_day = now % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Civil calendar date from a day count since the Unix epoch (Howard
/// Hinnant's `civil_from_days` algorithm), used only for the receipt
/// timestamp field.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-wf026-patch-guard-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn issue_receipt_binds_draft_sha256_and_fixed_fields() {
        let dir = tmp_dir("issue-basic");
        let draft = dir.join("draft.md");
        fs::write(&draft, b"hello world\n").unwrap();
        let key_path = dir.join("key");

        let receipt = issue_receipt(&draft, "run-test", Some(&key_path)).unwrap();

        assert_eq!(receipt["receipt_version"], json!(2));
        assert_eq!(receipt["issued_by"], json!("research-core.patch-guard"));
        assert_eq!(receipt["run_id"], json!("run-test"));
        assert_eq!(receipt["stage"], json!("patch"));
        assert_eq!(receipt["allowed_tools"], json!(["Read", "Edit"]));
        assert_eq!(receipt["max_hunks"], json!(8));
        assert_eq!(receipt["max_hunk_bytes"], json!(4096));

        let mut hasher = Sha256::new();
        hasher.update(b"hello world\n");
        let expected_sha = hex::encode(hasher.finalize());
        assert_eq!(receipt["sourced_draft_sha256"], json!(expected_sha));

        assert!(receipt["signature"].as_str().unwrap().starts_with("hmac-sha256:"));
    }

    #[test]
    fn issue_receipt_signature_verifies_against_canonical_payload() {
        let dir = tmp_dir("issue-verify");
        let draft = dir.join("draft.md");
        fs::write(&draft, b"content").unwrap();
        let key_path = dir.join("key");

        let receipt = issue_receipt(&draft, "run-test", Some(&key_path)).unwrap();
        let key = load_or_create_key(Some(&key_path)).unwrap();
        let expected = sign(&receipt, &key);
        assert_eq!(receipt["signature"], json!(expected));
    }

    #[test]
    fn load_or_create_key_reuses_existing_key_across_calls() {
        let dir = tmp_dir("key-reuse");
        let key_path = dir.join("key");
        let first = load_or_create_key(Some(&key_path)).unwrap();
        let second = load_or_create_key(Some(&key_path)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn load_or_create_key_rejects_short_existing_key() {
        let dir = tmp_dir("key-short");
        let key_path = dir.join("key");
        fs::write(&key_path, b"tooshort").unwrap();
        let err = load_or_create_key(Some(&key_path)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "research patch signing key must be at least 32 bytes"
        );
    }

    #[test]
    fn canonical_payload_excludes_signature_and_sorts_keys() {
        let receipt = json!({"b": 1, "a": 2, "signature": "whatever"});
        let payload = canonical_payload(&receipt);
        assert_eq!(String::from_utf8(payload).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn different_drafts_produce_different_receipt_hashes() {
        let dir = tmp_dir("diff-drafts");
        let key_path = dir.join("key");
        let draft_a = dir.join("a.md");
        let draft_b = dir.join("b.md");
        fs::write(&draft_a, b"alpha").unwrap();
        fs::write(&draft_b, b"beta").unwrap();

        let receipt_a = issue_receipt(&draft_a, "run-test", Some(&key_path)).unwrap();
        let receipt_b = issue_receipt(&draft_b, "run-test", Some(&key_path)).unwrap();
        assert_ne!(receipt_a["sourced_draft_sha256"], receipt_b["sourced_draft_sha256"]);
    }
}
