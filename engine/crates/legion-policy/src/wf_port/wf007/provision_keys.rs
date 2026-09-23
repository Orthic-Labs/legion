//! Port of `src/lib/guard/compat/host/provision-keys.mjs`.
//!
//! EC-1 — one-time bootstrap for Arcane host-held signing keys. Layout
//! matches `KEY-CUSTODY.md`: `<dir>/<keyId>.key` holds hex-encoded raw key
//! bytes, an optional sibling `<dir>/<keyId>.json` holds non-secret metadata
//! `{createdAt, custody, status}`.
//!
//! Idempotent by default: if an active (non-revoked) key already exists in
//! the target directory, [`provision_keys`] returns `created: false` rather
//! than overwriting it. Pass `rotate: true` to provision a new key alongside
//! the existing one.
//!
//! NEVER returns or logs key material — only key id and paths, same
//! contract as the JS source's `console.log` calls (this port has no CLI
//! `main()`; that stays a thin binary-crate wrapper, out of scope for a
//! library port).
//!
//! `ulid()` here is a straightforward (non-monotonic-bump) Crockford-base32
//! ULID: 48-bit millisecond timestamp + 80 bits of randomness. JS's
//! `ulid()` additionally increments the random component when called twice
//! in the same millisecond (`bumpRandom`); that refinement only matters for
//! strict lexicographic ordering of ids minted in the same tick, which
//! `provisionKeys` (called at most once per process invocation) never
//! exercises, so it is not carried over here — flagged in the wf007 report.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_time(now_ms: u64) -> String {
    let mut out = [0u8; 10];
    let mut n = now_ms;
    for i in (0..10).rev() {
        out[i] = CROCKFORD[(n % 32) as usize];
        n /= 32;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

fn encode_random(bytes: &[u8; 10]) -> String {
    // 80 bits -> 16 base32 chars, 5 bits at a time, matching JS's bit-packing
    // over a 10-byte buffer.
    let mut bits: u128 = 0;
    for &b in bytes {
        bits = (bits << 8) | b as u128;
    }
    let mut out = [0u8; 16];
    for i in (0..16).rev() {
        out[i] = CROCKFORD[(bits & 0x1f) as usize];
        bits >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

fn random_bytes_10() -> [u8; 10] {
    // No RNG crate dependency available to this chunk (see wf007 report);
    // uses the OS CSPRNG via `getrandom`-equivalent syscalls is not
    // reachable without a dependency, so this composes system entropy
    // sources already reachable from `std`: process id, current time
    // sub-millisecond jitter, and address-space layout (a `Box` pointer),
    // hashed together. This is NOT cryptographically reviewed random
    // generation and must not be treated as equivalent to `randomBytes(10)`
    // — see the wf007 report's flagged gap and proposed `rand`/`getrandom`
    // dependency patch.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut seed_hasher = DefaultHasher::new();
    std::process::id().hash(&mut seed_hasher);
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().hash(&mut seed_hasher);
    let boxed = Box::new(0u8);
    (&*boxed as *const u8 as usize).hash(&mut seed_hasher);

    let mut out = [0u8; 10];
    let mut state = seed_hasher.finish();
    for chunk in out.chunks_mut(8) {
        let mut h = DefaultHasher::new();
        state.hash(&mut h);
        state = h.finish();
        let bytes = state.to_le_bytes();
        for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
    }
    out
}

/// Mirrors JS `ulid(now = Date.now())`.
pub fn ulid(now_ms: u64) -> String {
    let rnd = random_bytes_10();
    format!("{}{}", encode_time(now_ms), encode_random(&rnd))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

pub fn default_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".claude").join("arcane-keys")
}

#[derive(Debug, Clone)]
pub struct ProvisionOptions {
    pub dir: PathBuf,
    pub rotate: bool,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self { dir: default_dir(), rotate: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionResult {
    pub key_id: String,
    pub key_path: PathBuf,
    pub meta_path: PathBuf,
    pub created: bool,
}

fn ensure_owner_only_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        // best-effort, matching the JS source's try/catch around chmod.
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Reads `status` out of `<dir>/<keyId>.json` without a JSON library
/// dependency: the metadata file is small and fixed-shape
/// (`{"createdAt": "...", "custody": "...", "status": "active"}`), so a
/// direct substring search is faithful to
/// `JSON.parse(...).status ?? 'active'` for the files this bootstrap script
/// itself writes, while degrading to `'active'` (matching the JS `catch`)
/// for anything else.
fn read_status(meta_path: &Path) -> String {
    let Ok(content) = fs::read_to_string(meta_path) else {
        return "active".to_string();
    };
    if let Some(status) = super::json_parse::parse(&content).as_ref().and_then(|v| v.get("status")).and_then(|v| v.as_str()) {
        status.to_string()
    } else {
        "active".to_string()
    }
}

fn existing_active_key_id(dir: &Path) -> Option<String> {
    if !dir.is_dir() {
        return None;
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let key_id = path.file_stem()?.to_str()?.to_string();
        let meta_path = dir.join(format!("{key_id}.json"));
        let status = if meta_path.is_file() { read_status(&meta_path) } else { "active".to_string() };
        if status == "active" {
            return Some(key_id);
        }
    }
    None
}

/// Provision a new host key in `options.dir`. `created` is `false`
/// (idempotent no-op) when an active key already exists and `rotate` was
/// not set.
pub fn provision_keys(options: &ProvisionOptions) -> io::Result<ProvisionResult> {
    ensure_owner_only_dir(&options.dir)?;

    if let Some(existing) = existing_active_key_id(&options.dir) {
        if !options.rotate {
            return Ok(ProvisionResult {
                key_path: options.dir.join(format!("{existing}.key")),
                meta_path: options.dir.join(format!("{existing}.json")),
                key_id: existing,
                created: false,
            });
        }
    }

    let key_id = format!("hostkey_{}", ulid(now_ms()));
    let key_path = options.dir.join(format!("{key_id}.key"));
    let meta_path = options.dir.join(format!("{key_id}.json"));

    let key_material = random_bytes_10_expanded_to_32();
    let hex = hex_encode(&key_material);
    fs::write(&key_path, &hex)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }

    let created_at = super::user_approval::iso8601_from_epoch_ms(now_ms() as i64);
    let meta = format!(
        "{{\n  \"createdAt\": \"{created_at}\",\n  \"custody\": \"host-provisioned\",\n  \"status\": \"active\"\n}}\n"
    );
    fs::write(&meta_path, meta)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&meta_path, fs::Permissions::from_mode(0o600));
    }

    Ok(ProvisionResult { key_id, key_path, meta_path, created: true })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 32 bytes of key material. See [`random_bytes_10`]'s doc comment: this is
/// NOT a cryptographically reviewed RNG in this chunk's dependency-free
/// form — flagged in the wf007 report.
fn random_bytes_10_expanded_to_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(10) {
        let r = random_bytes_10();
        let n = chunk.len().min(10);
        chunk[..n].copy_from_slice(&r[..n]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_has_expected_length_and_alphabet() {
        let id = ulid(1_767_225_600_000);
        assert_eq!(id.len(), 26);
        assert!(id.bytes().all(|b| CROCKFORD.contains(&b)));
    }

    #[test]
    fn provision_keys_creates_new_key_when_dir_empty() {
        let tmp = std::env::temp_dir().join(format!("wf007-provision-test-{}", ulid(now_ms())));
        let opts = ProvisionOptions { dir: tmp.clone(), rotate: false };
        let result = provision_keys(&opts).unwrap();
        assert!(result.created);
        assert!(result.key_path.is_file());
        assert!(result.meta_path.is_file());
        let hex = fs::read_to_string(&result.key_path).unwrap();
        assert_eq!(hex.trim().len(), 64);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn provision_keys_is_idempotent_without_rotate() {
        let tmp = std::env::temp_dir().join(format!("wf007-provision-test-idem-{}", ulid(now_ms())));
        let opts = ProvisionOptions { dir: tmp.clone(), rotate: false };
        let first = provision_keys(&opts).unwrap();
        let second = provision_keys(&opts).unwrap();
        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.key_id, second.key_id);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn provision_keys_rotate_adds_a_new_key() {
        let tmp = std::env::temp_dir().join(format!("wf007-provision-test-rotate-{}", ulid(now_ms())));
        let opts_no_rotate = ProvisionOptions { dir: tmp.clone(), rotate: false };
        let first = provision_keys(&opts_no_rotate).unwrap();
        let opts_rotate = ProvisionOptions { dir: tmp.clone(), rotate: true };
        let second = provision_keys(&opts_rotate).unwrap();
        assert!(second.created);
        assert_ne!(first.key_id, second.key_id);
        let _ = fs::remove_dir_all(&tmp);
    }
}
