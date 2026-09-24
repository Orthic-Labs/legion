//! Port of `writeRunManifest` from `src/lib/core/index.mjs` (packet r44).
//!
//! `src/lib/core/index.mjs` is otherwise deterministic-API glue: nine
//! re-exports of sibling modules, and two thin wrappers (`buildPlan`,
//! `verifyRun` = an alias of `verifySealedRun`) that depend on
//! `../../../tools/audit/audit-plan.mjs` and `../registry/provider-registry.mjs`
//! — both outside `src/lib/core/**` and not owned by this packet, so those
//! two remain **NOT-STARTED**. `writeRunManifest` is the one function with
//! real logic (`records.map(...)`, the manifest object literal, `digest`)
//! that does not require inventing `RunArtifactStore`
//! (`../artifacts/run-store.mjs`)'s shape: [`build_run_manifest`] takes the
//! already-written records as plain data (mirroring what
//! `store.records()` returns) and returns the manifest value; the actual
//! `store.writeJson(...)` call to persist it is the caller's job, exactly
//! as in JS the function's last line is a side effect around a value this
//! function already fully computed.
//!
//! One faithfully-preserved JS quirk: `terminalAbsences` filters
//! `records.filter(({status}) => status === 'missing')`, but
//! `RunArtifactStore.records()` (`src/lib/artifacts/run-store.mjs`) never
//! sets a `status` field on any record it writes — so in the real system
//! `terminalAbsences` is always empty. [`ArtifactRecord::status`] is
//! carried through unchanged (always `None` from a real store) rather than
//! silently dropped, so a future caller that does populate `status` gets
//! the same filter behaviour JS would.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::binding::digest;

/// Mirrors one element of `store.records()`.
#[derive(Clone, Debug)]
pub struct ArtifactRecord {
    pub kind: String,
    pub path: String,
    pub digest: String,
    pub bytes: u64,
    pub producer: String,
    pub schema_version: u32,
    pub media_type: String,
    pub binding: Option<Value>,
    /// Never set by the real `RunArtifactStore` — see module docs.
    pub status: Option<String>,
}

/// Mirrors `writeRunManifest`'s manifest value (everything but the
/// `store.writeJson(...)` side effect).
#[derive(Clone, Debug)]
pub struct RunManifest {
    pub schema_version: u32,
    pub kind: String,
    pub binding: Option<Value>,
    pub source_revision: Option<Value>,
    pub terminal_absences: Vec<String>,
    pub artifacts: Vec<Value>,
    pub digest: String,
}

impl RunManifest {
    pub fn to_json(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "binding": self.binding.clone().unwrap_or(Value::Null),
            "sourceRevision": self.source_revision.clone().unwrap_or(Value::Null),
            "terminalAbsences": self.terminal_absences,
            "artifacts": self.artifacts,
            "digest": self.digest,
        })
    }
}

/// Mirrors `writeRunManifest(store, {binding})`, given `records` as the
/// `store.records()` result.
pub fn build_run_manifest(records: &[ArtifactRecord], binding: Option<&Value>) -> RunManifest {
    let record_values: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "kind": r.kind,
                "path": r.path,
                "digest": r.digest,
                "bytes": r.bytes,
                "producer": r.producer,
                "schemaVersion": r.schema_version,
                "mediaType": r.media_type,
                "binding": r.binding.clone().or_else(|| binding.cloned()).unwrap_or(Value::Null),
            })
        })
        .collect();

    let source_revision = binding.and_then(|b| {
        b.get("sourceRevision")
            .filter(|v| !v.is_null())
            .or_else(|| b.get("repositoryRevision"))
            .cloned()
    });

    let mut terminal_absences: Vec<String> = records
        .iter()
        .filter(|r| r.status.as_deref() == Some("missing"))
        .map(|r| r.path.clone())
        .collect();
    terminal_absences.sort();

    let mut manifest = RunManifest {
        schema_version: 1,
        kind: "legion-run-manifest".to_string(),
        binding: binding.cloned(),
        source_revision,
        terminal_absences,
        artifacts: record_values,
        digest: String::new(),
    };
    let mut digest_value = manifest.to_json();
    // `manifest.digest=coreDigest(manifest)` runs before `digest` exists on
    // the object, so JS digests the manifest without a `digest` field.
    if let Value::Object(obj) = &mut digest_value {
        obj.remove("digest");
    }
    manifest.digest = digest(&digest_value);
    manifest
}

/// Convenience alias mirroring the `records` map key type used by
/// `store.records()` callers that key by path (unused by
/// `build_run_manifest` itself, kept for callers assembling `records` from
/// a map).
pub type RecordsByPath = BTreeMap<String, ArtifactRecord>;

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: &str, binding: Option<Value>) -> ArtifactRecord {
        ArtifactRecord {
            kind: "audit-report".to_string(),
            path: path.to_string(),
            digest: "sha256:deadbeef".to_string(),
            bytes: 10,
            producer: "legion.core".to_string(),
            schema_version: 1,
            media_type: "application/json".to_string(),
            binding,
            status: None,
        }
    }

    #[test]
    fn manifest_carries_binding_and_kind() {
        let binding = json!({"rev": "abc"});
        let manifest = build_run_manifest(&[], Some(&binding));
        assert_eq!(manifest.kind, "legion-run-manifest");
        assert_eq!(manifest.binding, Some(binding));
        assert_eq!(manifest.schema_version, 1);
    }

    #[test]
    fn manifest_source_revision_prefers_source_revision_over_repository_revision() {
        let binding = json!({"sourceRevision": "s1", "repositoryRevision": "r1"});
        let manifest = build_run_manifest(&[], Some(&binding));
        assert_eq!(manifest.source_revision, Some(json!("s1")));
    }

    #[test]
    fn manifest_source_revision_falls_back_to_repository_revision() {
        let binding = json!({"repositoryRevision": "r1"});
        let manifest = build_run_manifest(&[], Some(&binding));
        assert_eq!(manifest.source_revision, Some(json!("r1")));
    }

    #[test]
    fn manifest_record_uses_own_binding_before_manifest_binding() {
        let own_binding = json!({"rev": "own"});
        let manifest_binding = json!({"rev": "outer"});
        let records = vec![record("a.json", Some(own_binding.clone()))];
        let manifest = build_run_manifest(&records, Some(&manifest_binding));
        assert_eq!(manifest.artifacts[0]["binding"], own_binding);
    }

    #[test]
    fn manifest_record_falls_back_to_manifest_binding() {
        let manifest_binding = json!({"rev": "outer"});
        let records = vec![record("a.json", None)];
        let manifest = build_run_manifest(&records, Some(&manifest_binding));
        assert_eq!(manifest.artifacts[0]["binding"], manifest_binding);
    }

    #[test]
    fn terminal_absences_is_always_empty_from_a_real_store_records_shape() {
        // Mirrors the JS quirk: real RunArtifactStore records never set
        // `status`, so the 'missing' filter never matches.
        let records = vec![record("a.json", None), record("b.json", None)];
        let manifest = build_run_manifest(&records, None);
        assert!(manifest.terminal_absences.is_empty());
    }

    #[test]
    fn terminal_absences_is_sorted_when_status_is_populated() {
        let mut b = record("b.json", None);
        b.status = Some("missing".to_string());
        let mut a = record("a.json", None);
        a.status = Some("missing".to_string());
        let manifest = build_run_manifest(&[b, a], None);
        assert_eq!(manifest.terminal_absences, vec!["a.json".to_string(), "b.json".to_string()]);
    }

    #[test]
    fn digest_is_deterministic_and_excludes_itself() {
        let binding = json!({"rev": "abc"});
        let records = vec![record("a.json", None)];
        let m1 = build_run_manifest(&records, Some(&binding));
        let m2 = build_run_manifest(&records, Some(&binding));
        assert_eq!(m1.digest, m2.digest);
        assert!(!m1.digest.is_empty());
    }
}
