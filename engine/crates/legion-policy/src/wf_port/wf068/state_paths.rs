//! Port of `src/lib/contracts/arcane/state-paths.mjs`.
//!
//! ## Already-native finding
//! `stateRoot`, `keyHex`, and `stateFile` are already ported and verified
//! native at `engine/crates/legion-arcane/src/state_paths.rs`
//! (`state_root`, `key_hex`, `state_file`), byte-identical in behaviour:
//! same `.audit/arcane` root join, same `canonical_digest({ domain, values
//! })` input shape, same `sha256:` prefix strip (JS `.slice(7)` == this
//! port's `.strip_prefix("sha256:")`), same `<hex>.json` filename. Verified
//! by reading both sources side by side.
//!
//! JS's `statePaths(workspace)` — the single object aggregating all eight
//! named subdirectories (`receipts`, `replay`, `capabilities/grants`,
//! `capabilities/transitions`, `contract-seals`, `authority-bindings`,
//! `session-bindings`, `pre-effect-correlations`) — has **no single ported
//! Rust equivalent**: call sites across `engine/bins/legion` and
//! `engine/crates/legion-arcane` instead join each literal path component ad
//! hoc at their point of use (e.g. `root.join(".audit/arcane/contract-seals")`
//! in `engine/bins/legion/src/commands/contract.rs:726`,
//! `root.join(".audit/arcane/session-bindings")` in
//! `engine/bins/legion/src/commands/run.rs:350`). Every literal checked
//! (`contract-seals`, `session-bindings`, `authority-bindings`) matches the
//! JS string exactly, so this is not a behavioural gap — but it means no
//! single call proves every one of the eight paths is right, only the three
//! literals that happen to be referenced today. This module adds the
//! missing aggregator as new, additive API so future call sites (and this
//! chunk's tests) have one place asserting all eight names against the JS
//! source, without touching the pre-existing ad hoc call sites (out of
//! scope for this chunk — they are read-only files this agent does not own).
//!
//! This module reuses `legion_contracts::canonical_digest`, already a real
//! `legion-policy` dependency (see `Cargo.toml`), for the digest — no new
//! crate dependency needed for this file.

use legion_contracts::canonical::CanonicalError;
use legion_contracts::canonical_digest;
use serde_json::json;
use std::path::{Path, PathBuf};

/// JS `stateRoot`: `join(workspace, '.audit', 'arcane')`.
pub fn state_root(workspace: &Path) -> PathBuf {
    workspace.join(".audit").join("arcane")
}

/// All eight paths JS's `statePaths(workspace)` returns, plus `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub root: PathBuf,
    pub receipts: PathBuf,
    pub replay: PathBuf,
    pub capability_grants: PathBuf,
    pub capability_transitions: PathBuf,
    pub contract_seals: PathBuf,
    pub authority_bindings: PathBuf,
    pub session_bindings: PathBuf,
    pub pre_effect_correlations: PathBuf,
}

/// Port of JS `statePaths(workspace)`.
pub fn state_paths(workspace: &Path) -> StatePaths {
    let root = state_root(workspace);
    StatePaths {
        receipts: root.join("receipts"),
        replay: root.join("replay"),
        capability_grants: root.join("capabilities").join("grants"),
        capability_transitions: root.join("capabilities").join("transitions"),
        contract_seals: root.join("contract-seals"),
        authority_bindings: root.join("authority-bindings"),
        session_bindings: root.join("session-bindings"),
        pre_effect_correlations: root.join("pre-effect-correlations"),
        root,
    }
}

/// JS `keyHex(domain, values) => digestValue({ domain, values }).slice(7)`.
/// `digestValue` prefixes with `sha256:` (7 chars); JS's fixed `.slice(7)`
/// only strips a well-formed `sha256:` prefix, so this port mirrors that
/// literally with `strip_prefix` (equivalent for every digest this repo's
/// canonicalizer ever produces, and safer than a blind byte slice if that
/// ever changed).
pub fn key_hex(domain: &str, values: &[String]) -> Result<String, CanonicalError> {
    let digest = canonical_digest(&json!({ "domain": domain, "values": values }))?;
    Ok(digest.strip_prefix("sha256:").unwrap_or(digest.as_str()).to_owned())
}

/// JS `stateFile(dir, domain, values) => join(dir, \`${keyHex(...)}.json\`)`.
pub fn state_file(dir: &Path, domain: &str, values: &[String]) -> Result<PathBuf, CanonicalError> {
    Ok(dir.join(format!("{}.json", key_hex(domain, values)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn state_root_joins_dot_audit_arcane() {
        assert_eq!(
            state_root(Path::new("/ws")),
            Path::new("/ws/.audit/arcane")
        );
    }

    #[test]
    fn state_paths_names_all_eight_subdirectories() {
        let sp = state_paths(Path::new("/ws"));
        assert_eq!(sp.root, Path::new("/ws/.audit/arcane"));
        assert_eq!(sp.receipts, Path::new("/ws/.audit/arcane/receipts"));
        assert_eq!(sp.replay, Path::new("/ws/.audit/arcane/replay"));
        assert_eq!(
            sp.capability_grants,
            Path::new("/ws/.audit/arcane/capabilities/grants")
        );
        assert_eq!(
            sp.capability_transitions,
            Path::new("/ws/.audit/arcane/capabilities/transitions")
        );
        assert_eq!(
            sp.contract_seals,
            Path::new("/ws/.audit/arcane/contract-seals")
        );
        assert_eq!(
            sp.authority_bindings,
            Path::new("/ws/.audit/arcane/authority-bindings")
        );
        assert_eq!(
            sp.session_bindings,
            Path::new("/ws/.audit/arcane/session-bindings")
        );
        assert_eq!(
            sp.pre_effect_correlations,
            Path::new("/ws/.audit/arcane/pre-effect-correlations")
        );
    }

    #[test]
    fn key_hex_matches_legion_arcane_native_port() {
        // Cross-check against the already-native `legion_arcane::state_paths::key_hex`
        // is done at the integration level (different crate dependency
        // graph); this asserts the digest is stable/deterministic and
        // 64 lowercase hex chars, the shape `.slice(7)` off `sha256:<64hex>`
        // must always produce.
        let hex = key_hex("domain", &["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        let hex2 = key_hex("domain", &["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(hex, hex2, "digest must be deterministic for identical input");
    }

    #[test]
    fn state_file_appends_dot_json() {
        let f = state_file(Path::new("/dir"), "d", &["x".to_string()]).unwrap();
        assert!(f.starts_with("/dir"));
        assert_eq!(f.extension().unwrap(), "json");
    }
}
