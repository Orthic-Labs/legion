//! Faithful port of `src/lib/guard/compat/effects/preeffect-correlation.mjs`
//! (EC-5 item 5 — pre-effect -> post-effect correlation pointer store).
//!
//! Filename is `sha256hex(toolUseId)`, never the raw id. `reserve` is
//! get-first then exclusive-create; on a concurrent create it reads back the
//! winner instead of overwriting or minting a second id. Every method
//! degrades to `None` on I/O failure rather than propagating an error —
//! this store is routing-grade, not evidence-grade (see file header in the
//! JS source for why a corrupt/forged correlation record cannot fabricate a
//! receipt).

use std::fs;
use std::path::{Path, PathBuf};

use super::canonical::sha256_hex;

/// Minimal `req_<26 base32-crockford>` id generator, matching the shape
/// `contracts/arcane/ids.mjs`'s `mintId('request')` produces
/// (`^req_[0-9A-HJKMNP-TV-Z]{26}$`). Uses a process-local counter plus
/// system randomness via `std::collections::hash_map::RandomState` so no
/// new dependency is required.
pub fn mint_request_id() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut out = String::with_capacity(30);
    out.push_str("req_");
    let seed_a = RandomState::new();
    let seed_b = RandomState::new();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    for i in 0..26u128 {
        let mut h = seed_a.build_hasher();
        (now, i).hash(&mut h);
        let mut h2 = seed_b.build_hasher();
        h.finish().hash(&mut h2);
        let idx = (h2.finish() % ALPHABET.len() as u64) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn key_file_name(tool_use_id: &str) -> String {
    format!("{}.json", sha256_hex(tool_use_id.as_bytes()))
}

fn finalized_file_name(tool_use_id: &str) -> String {
    format!("{}.finalized.json", sha256_hex(tool_use_id.as_bytes()))
}

/// Very small hand-rolled record: `{requestId, capabilityId, requestedEffect,
/// authorizedEffect}` serialized as flat `key=value` lines, avoiding a JSON
/// dependency in this scoped port. `requestedEffect`/`authorizedEffect` are
/// carried as opaque canonical-JSON-ish strings the caller supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRecord {
    pub request_id: String,
    pub capability_id: String,
    pub requested_effect: String,
    pub authorized_effect: String,
}

fn write_kv(path: &Path, pairs: &[(&str, &str)]) -> std::io::Result<()> {
    let mut content = String::new();
    for (k, v) in pairs {
        content.push_str(k);
        content.push('=');
        content.push_str(v);
        content.push('\n');
    }
    // Exclusive create, matching JS `flag: 'wx'`.
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(content.as_bytes())
}

fn read_kv(path: &Path) -> Option<Vec<(String, String)>> {
    let content = fs::read_to_string(path).ok()?;
    Some(
        content
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

pub struct PreEffectCorrelationStore {
    root: PathBuf,
}

impl PreEffectCorrelationStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, tool_use_id: &str) -> PathBuf {
        self.root.join(key_file_name(tool_use_id))
    }
    fn finalized_path_for(&self, tool_use_id: &str) -> PathBuf {
        self.root.join(finalized_file_name(tool_use_id))
    }

    fn read_reservation(&self, tool_use_id: &str) -> Option<Reservation> {
        let kv = read_kv(&self.path_for(tool_use_id))?;
        let request_id = kv.into_iter().find(|(k, _)| k == "requestId").map(|(_, v)| v)?;
        Some(Reservation { request_id })
    }

    pub fn get_request_id(&self, tool_use_id: &str) -> Option<String> {
        if tool_use_id.is_empty() {
            return None;
        }
        self.read_reservation(tool_use_id).map(|r| r.request_id)
    }

    /// Reserve a tool-use id before authorization; repeat delivery never
    /// mints again. Returns `(request_id, created)`.
    pub fn reserve(&self, tool_use_id: &str) -> Option<(String, bool)> {
        if tool_use_id.is_empty() {
            return None;
        }
        if let Some(existing) = self.get_request_id(tool_use_id) {
            return Some((existing, false));
        }
        let request_id = mint_request_id();
        let path = self.path_for(tool_use_id);
        if fs::create_dir_all(&self.root).is_err() {
            return None;
        }
        match write_kv(&path, &[("requestId", &request_id)]) {
            Ok(()) => Some((request_id, true)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.get_request_id(tool_use_id).map(|winner| (winner, false))
            }
            Err(_) => None,
        }
    }

    /// Compatibility projection of `reserve()`.
    pub fn ensure_request_id(&self, tool_use_id: &str) -> Option<String> {
        self.reserve(tool_use_id).map(|(id, _)| id)
    }

    pub fn finalize(
        &self,
        tool_use_id: &str,
        request_id: &str,
        capability_id: &str,
        requested_effect: &str,
        authorized_effect: &str,
    ) -> Option<FinalizedRecord> {
        if tool_use_id.is_empty() || request_id.is_empty() || capability_id.is_empty() || requested_effect.is_empty() || authorized_effect.is_empty() {
            return None;
        }
        let reservation = self.read_reservation(tool_use_id)?;
        if reservation.request_id != request_id {
            return None;
        }
        let record = FinalizedRecord {
            request_id: request_id.to_string(),
            capability_id: capability_id.to_string(),
            requested_effect: requested_effect.to_string(),
            authorized_effect: authorized_effect.to_string(),
        };
        let path = self.finalized_path_for(tool_use_id);
        if fs::create_dir_all(&self.root).is_err() {
            return None;
        }
        let pairs = [
            ("requestId", record.request_id.as_str()),
            ("capabilityId", record.capability_id.as_str()),
            ("requestedEffect", record.requested_effect.as_str()),
            ("authorizedEffect", record.authorized_effect.as_str()),
        ];
        match write_kv(&path, &pairs) {
            Ok(()) => Some(record),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let winner = self.get_finalized(tool_use_id)?;
                if winner == record {
                    Some(winner)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn get_finalized(&self, tool_use_id: &str) -> Option<FinalizedRecord> {
        if tool_use_id.is_empty() {
            return None;
        }
        let kv = read_kv(&self.finalized_path_for(tool_use_id))?;
        let get = |k: &str| kv.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        let record = FinalizedRecord {
            request_id: get("requestId")?,
            capability_id: get("capabilityId")?,
            requested_effect: get("requestedEffect")?,
            authorized_effect: get("authorizedEffect")?,
        };
        let reservation = self.read_reservation(tool_use_id)?;
        if reservation.request_id == record.request_id {
            Some(record)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wf006-correlation-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn reserve_mints_once_and_is_idempotent() {
        let root = temp_root("reserve");
        let store = PreEffectCorrelationStore::new(root.clone());
        let (id1, created1) = store.reserve("tool-use-1").unwrap();
        assert!(created1);
        let (id2, created2) = store.reserve("tool-use-1").unwrap();
        assert!(!created2);
        assert_eq!(id1, id2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn get_request_id_is_none_before_reserve() {
        let root = temp_root("get-before");
        let store = PreEffectCorrelationStore::new(root.clone());
        assert_eq!(store.get_request_id("never-reserved"), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn finalize_requires_matching_reservation() {
        let root = temp_root("finalize");
        let store = PreEffectCorrelationStore::new(root.clone());
        let (request_id, _) = store.reserve("tool-use-2").unwrap();
        let bad = store.finalize("tool-use-2", "wrong-request-id", "cap-1", "req-effect", "auth-effect");
        assert!(bad.is_none());
        let good = store.finalize("tool-use-2", &request_id, "cap-1", "req-effect", "auth-effect");
        assert!(good.is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn get_finalized_round_trips() {
        let root = temp_root("get-finalized");
        let store = PreEffectCorrelationStore::new(root.clone());
        let (request_id, _) = store.reserve("tool-use-3").unwrap();
        store.finalize("tool-use-3", &request_id, "cap-9", "req-eff", "auth-eff").unwrap();
        let got = store.get_finalized("tool-use-3").unwrap();
        assert_eq!(got.capability_id, "cap-9");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_tool_use_id_is_always_none() {
        let root = temp_root("empty");
        let store = PreEffectCorrelationStore::new(root.clone());
        assert_eq!(store.reserve(""), None);
        assert_eq!(store.get_request_id(""), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_request_id_matches_shape() {
        let id = mint_request_id();
        assert!(id.starts_with("req_"));
        assert_eq!(id.len(), 4 + 26);
    }
}
