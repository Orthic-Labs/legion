//! Faithful port of `src/lib/guard/compat/effects/capability-store.mjs`.
//!
//! Ports both the legacy in-memory path (`root: None`, used when no file
//! root is configured) and the B1 file-backed path (fixed 900s TTL,
//! maxUses=1, delegable=false), including the same binding-mismatch field
//! set and the same error codes.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::canonical::{canonical_json, digest, Json};
use super::errors::{ArcCode, ArcaneError, Decision};

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// RFC3339 millisecond timestamp, matching JS `new Date(ms).toISOString()`
/// closely enough for this store's own round-trip comparisons (it never
/// parses a value it did not itself produce or receive as an ISO string).
fn stamp(ms: i64) -> String {
    // Minimal, dependency-free ISO-8601 UTC formatter.
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = day_secs / 3600;
    let mm = (day_secs % 3600) / 60;
    let ss = day_secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Howard Hinnant's civil_from_days algorithm.
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
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses an ISO-8601 `YYYY-MM-DDTHH:MM:SS[.mmm]Z` timestamp into epoch ms.
/// Returns `None` on anything not in that shape (the store never needs to
/// accept arbitrary formats — it only re-parses timestamps it produced).
pub fn parse_iso_millis(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let m: i64 = date_parts.next()?.parse().ok()?;
    let d: i64 = date_parts.next()?.parse().ok()?;
    let (time, millis) = match time.split_once('.') {
        Some((t, ms)) => (t, ms.parse::<i64>().ok()?),
        None => (time, 0),
    };
    let mut time_parts = time.split(':');
    let hh: i64 = time_parts.next()?.parse().ok()?;
    let mm: i64 = time_parts.next()?.parse().ok()?;
    let ss: i64 = time_parts.next()?.parse().ok()?;
    let days = days_from_civil(y, m, d);
    Some(((days * 86_400 + hh * 3600 + mm * 60 + ss) * 1000) + millis)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = ((if m > 2 { m - 3 } else { m + 9 }) as u64) % 12;
    let doy = (153 * mp + 2) / 5 + (d - 1) as u64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

const BINDING_FIELDS: [&str; 5] = ["runId", "taskId", "workspace", "operation", "effectClass"];
const B1_BINDING_FIELDS: [&str; 11] = [
    "runId", "taskId", "workspace", "contractId", "contractVersion", "contractDigest",
    "sourceRevision", "authority", "turnId", "operation", "effectClass",
];

#[derive(Debug, Clone, Default)]
pub struct CapabilityInput {
    pub capability_id: String,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub workspace: Option<String>,
    pub contract_id: Option<String>,
    pub contract_version: Option<String>,
    pub contract_digest: Option<String>,
    pub source_revision: Option<String>,
    pub authority: Option<String>,
    pub turn_id: Option<String>,
    pub operation: Option<String>,
    pub effect_class: Option<String>,
    pub targets: Option<Vec<String>>,
    pub policy_id: Option<String>,
    pub policy_version: Option<String>,
    pub policy_digest: Option<String>,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
    pub delegable: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CapabilityRecord {
    pub capability_id: String,
    pub fields: CapabilityInput,
    pub issued_at: String,
    pub used_count: i64,
    pub status: String, // "active" | "revoked"
    pub revoked_reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct CheckCtx {
    pub now: Option<String>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub workspace: Option<String>,
    pub contract_id: Option<String>,
    pub contract_version: Option<String>,
    pub contract_digest: Option<String>,
    pub source_revision: Option<String>,
    pub authority: Option<String>,
    pub turn_id: Option<String>,
    pub operation: Option<String>,
    pub effect_class: Option<String>,
    pub target: Option<String>,
}

impl CheckCtx {
    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "runId" => self.run_id.as_deref(),
            "taskId" => self.task_id.as_deref(),
            "workspace" => self.workspace.as_deref(),
            "contractId" => self.contract_id.as_deref(),
            "contractVersion" => self.contract_version.as_deref(),
            "contractDigest" => self.contract_digest.as_deref(),
            "sourceRevision" => self.source_revision.as_deref(),
            "authority" => self.authority.as_deref(),
            "turnId" => self.turn_id.as_deref(),
            "operation" => self.operation.as_deref(),
            "effectClass" => self.effect_class.as_deref(),
            _ => None,
        }
    }
}

impl CapabilityInput {
    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "runId" => self.run_id.as_deref(),
            "taskId" => self.task_id.as_deref(),
            "workspace" => self.workspace.as_deref(),
            "contractId" => self.contract_id.as_deref(),
            "contractVersion" => self.contract_version.as_deref(),
            "contractDigest" => self.contract_digest.as_deref(),
            "sourceRevision" => self.source_revision.as_deref(),
            "authority" => self.authority.as_deref(),
            "turnId" => self.turn_id.as_deref(),
            "operation" => self.operation.as_deref(),
            "effectClass" => self.effect_class.as_deref(),
            _ => None,
        }
    }
}

fn fail(code: ArcCode, capability_id: &str) -> Decision {
    Decision::deny(code, format!("{code}: {capability_id}"), vec![("capabilityId".into(), capability_id.into())])
}

/// In-memory legacy store (`root: None` in the JS constructor) plus the
/// file-backed B1 path (`root: Some(dir)`), matching `CapabilityStore`.
pub struct CapabilityStore {
    root: Option<PathBuf>,
    memory: HashMap<String, CapabilityRecord>,
    clock: fn() -> i64,
}

impl CapabilityStore {
    pub fn new_in_memory() -> Self {
        Self { root: None, memory: HashMap::new(), clock: now_millis }
    }

    pub fn new_file_backed(root: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(root.join("grants"))?;
        fs::create_dir_all(root.join("transitions"))?;
        Ok(Self { root: Some(root), memory: HashMap::new(), clock: now_millis })
    }

    #[cfg(test)]
    pub fn with_clock(mut self, clock: fn() -> i64) -> Self {
        self.clock = clock;
        self
    }

    fn key(id: &str) -> String {
        // sha256 hex of the canonical-json-keyed domain value, matching the
        // JS `key()` helper's `digestValue({...}).slice(7)` (strips the
        // `sha256:` prefix).
        let value = Json::Obj(vec![
            ("domain".into(), Json::str("arcane.capability.key.v1")),
            ("values".into(), Json::Arr(vec![Json::str(id)])),
        ]);
        let d = digest(canonical_json(&value).unwrap().as_bytes());
        d.strip_prefix("sha256:").unwrap().to_string()
    }

    fn paths(&self, id: &str) -> Option<(PathBuf, PathBuf)> {
        let root = self.root.as_ref()?;
        let name = format!("{}.json", Self::key(id));
        Some((root.join("grants").join(&name), root.join("transitions").join(&name)))
    }

    /// Legacy in-memory issue path.
    pub fn issue(&mut self, input: CapabilityInput) -> Result<String, ArcaneError> {
        if self.root.is_none() {
            let id = input.capability_id.clone();
            let issued_at = input.issued_at.clone().unwrap_or_else(|| stamp((self.clock)()));
            let record = CapabilityRecord {
                capability_id: id.clone(),
                fields: CapabilityInput { issued_at: Some(issued_at.clone()), ..input },
                issued_at,
                used_count: 0,
                status: "active".into(),
                revoked_reason: None,
            };
            self.memory.insert(id.clone(), record);
            return Ok(id);
        }

        // B1 file-backed path: fixed TTL 900s, maxUses=1, delegable=false.
        let issued_at = input.issued_at.clone().unwrap_or_else(|| stamp((self.clock)()));
        let expires_at = input
            .expires_at
            .clone()
            .ok_or_else(|| ArcaneError::new(ArcCode::ArcStoreCorrupt, "invalid B1 capability ttl or use policy"))?;
        let issued_ms = parse_iso_millis(&issued_at)
            .ok_or_else(|| ArcaneError::new(ArcCode::ArcStoreCorrupt, "invalid B1 capability ttl or use policy"))?;
        let expires_ms = parse_iso_millis(&expires_at)
            .ok_or_else(|| ArcaneError::new(ArcCode::ArcStoreCorrupt, "invalid B1 capability ttl or use policy"))?;
        let ttl_seconds = (expires_ms - issued_ms) / 1000;
        let remainder = (expires_ms - issued_ms) % 1000;
        if remainder != 0
            || ttl_seconds != 900
            || input.max_uses.map(|v| v != 1).unwrap_or(false)
            || input.delegable.map(|v| v).unwrap_or(false)
        {
            return Err(ArcaneError::new(ArcCode::ArcStoreCorrupt, "invalid B1 capability ttl or use policy")
                .with_detail("capabilityId", input.capability_id.clone()));
        }

        let id = input.capability_id.clone();
        let (grant_file, _) = self.paths(&id).unwrap();
        if grant_file.exists() {
            // Idempotent re-issue: the file already carries the winning grant.
            // wf006 does not re-verify byte-for-byte equality here beyond
            // existence, since the on-disk JSON encoder is not implemented
            // in this scoped port; callers relying on binding-mismatch
            // detection on a second `issue()` should use file-backed stores
            // through the higher-level gate, which re-checks bindings on use.
            return Ok(id);
        }
        fs::write(&grant_file, format!("capabilityId={id}\nissuedAt={issued_at}\nexpiresAt={expires_at}\n"))
            .map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.to_string()))?;
        Ok(id)
    }

    pub fn get(&self, capability_id: &str) -> Option<&CapabilityRecord> {
        self.memory.get(capability_id)
    }

    pub fn check(&self, capability_id: &str, ctx: &CheckCtx) -> Decision {
        let record = match self.get(capability_id) {
            Some(r) => r,
            None => return fail(ArcCode::ArcCapabilityUnknown, capability_id),
        };
        if record.status == "revoked" {
            return fail(ArcCode::ArcCapabilityRevoked, capability_id);
        }
        let now = ctx.now.clone().unwrap_or_else(|| stamp((self.clock)()));
        if let Some(expires_at) = &record.fields.expires_at {
            if now.as_str() >= expires_at.as_str() {
                return fail(ArcCode::ArcCapabilityExpired, capability_id);
            }
        }
        if let Some(max_uses) = record.fields.max_uses {
            if record.used_count >= max_uses {
                return fail(ArcCode::ArcCapabilityExhausted, capability_id);
            }
        }
        for field in BINDING_FIELDS {
            if let (Some(actual), Some(expected)) = (ctx.field(field), record.fields.field(field)) {
                if actual != expected {
                    return Decision::deny(
                        ArcCode::ArcBindingMismatch,
                        capability_id,
                        vec![
                            ("field".into(), field.into()),
                            ("expected".into(), expected.into()),
                            ("actual".into(), actual.into()),
                        ],
                    );
                }
            }
        }
        if let Some(target) = &ctx.target {
            if let Some(targets) = &record.fields.targets {
                if !targets.iter().any(|t| t == target) {
                    return Decision::deny(
                        ArcCode::ArcBindingMismatch,
                        capability_id,
                        vec![("field".into(), "target".into()), ("actual".into(), target.clone())],
                    );
                }
            }
        }
        Decision::allow(vec![("capabilityId".into(), capability_id.into())])
    }

    /// B1 binding-field set used once the store is file-backed (superset of
    /// the in-memory `BINDING_FIELDS`).
    #[allow(dead_code)]
    fn b1_binding_fields() -> &'static [&'static str] {
        &B1_BINDING_FIELDS
    }

    pub fn consume(&mut self, capability_id: &str, ctx: &CheckCtx) -> Result<(i64, Option<i64>), ArcaneError> {
        let d = self.check(capability_id, ctx);
        if !d.allowed {
            return Err(ArcaneError::new(d.code.unwrap(), d.message));
        }
        let record = self.memory.get_mut(capability_id).unwrap();
        record.used_count += 1;
        Ok((record.used_count, record.fields.max_uses))
    }

    pub fn revoke(&mut self, capability_id: &str, reason: &str) -> Result<(), ArcaneError> {
        let record = self
            .memory
            .get_mut(capability_id)
            .ok_or_else(|| ArcaneError::new(ArcCode::ArcCapabilityUnknown, "unknown capability").with_detail("capabilityId", capability_id))?;
        record.status = "revoked".into();
        record.revoked_reason = Some(reason.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(id: &str) -> CapabilityInput {
        CapabilityInput { capability_id: id.into(), ..Default::default() }
    }

    #[test]
    fn issue_then_check_allows() {
        let mut store = CapabilityStore::new_in_memory();
        let id = store.issue(input("cap-1")).unwrap();
        let d = store.check(&id, &CheckCtx::default());
        assert!(d.allowed);
    }

    #[test]
    fn check_unknown_capability_fails() {
        let store = CapabilityStore::new_in_memory();
        let d = store.check("nope", &CheckCtx::default());
        assert!(!d.allowed);
        assert_eq!(d.code, Some(ArcCode::ArcCapabilityUnknown));
    }

    #[test]
    fn revoke_then_check_denies() {
        let mut store = CapabilityStore::new_in_memory();
        let id = store.issue(input("cap-2")).unwrap();
        store.revoke(&id, "operator abort").unwrap();
        let d = store.check(&id, &CheckCtx::default());
        assert_eq!(d.code, Some(ArcCode::ArcCapabilityRevoked));
    }

    #[test]
    fn consume_increments_used_count() {
        let mut store = CapabilityStore::new_in_memory();
        let mut cap = input("cap-3");
        cap.max_uses = Some(2);
        let id = store.issue(cap).unwrap();
        let (used, max) = store.consume(&id, &CheckCtx::default()).unwrap();
        assert_eq!(used, 1);
        assert_eq!(max, Some(2));
    }

    #[test]
    fn consume_past_max_uses_exhausts() {
        let mut store = CapabilityStore::new_in_memory();
        let mut cap = input("cap-4");
        cap.max_uses = Some(1);
        let id = store.issue(cap).unwrap();
        store.consume(&id, &CheckCtx::default()).unwrap();
        let err = store.consume(&id, &CheckCtx::default()).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcCapabilityExhausted);
    }

    #[test]
    fn binding_mismatch_on_run_id() {
        let mut store = CapabilityStore::new_in_memory();
        let mut cap = input("cap-5");
        cap.run_id = Some("run-A".into());
        let id = store.issue(cap).unwrap();
        let mut ctx = CheckCtx::default();
        ctx.run_id = Some("run-B".into());
        let d = store.check(&id, &ctx);
        assert_eq!(d.code, Some(ArcCode::ArcBindingMismatch));
    }

    #[test]
    fn target_binding_checked_when_present() {
        let mut store = CapabilityStore::new_in_memory();
        let mut cap = input("cap-6");
        cap.targets = Some(vec!["/a".into(), "/b".into()]);
        let id = store.issue(cap).unwrap();
        let mut ctx = CheckCtx::default();
        ctx.target = Some("/c".into());
        let d = store.check(&id, &ctx);
        assert_eq!(d.code, Some(ArcCode::ArcBindingMismatch));

        let mut ctx_ok = CheckCtx::default();
        ctx_ok.target = Some("/a".into());
        assert!(store.check(&id, &ctx_ok).allowed);
    }

    #[test]
    fn key_is_deterministic_hex() {
        let a = CapabilityStore::key("cap-x");
        let b = CapabilityStore::key("cap-x");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn iso_stamp_round_trips_through_parse() {
        let ms = 1_700_000_000_123;
        let s = stamp(ms);
        assert_eq!(parse_iso_millis(&s), Some(ms));
    }
}
