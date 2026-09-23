//! Port of `src/lib/core/run-manifest.mjs` — see the chunk-level doc
//! comment in [`super`] for the full disposition note.

use serde_json::{json, Value};

use crate::l3_inventory::binding::{digest as binding_digest, same_binding};

/// One artifact record as `writeCanonicalManifest`/`validateRunManifest`
/// consume it (`store.records()` / the `files` argument). JS treats these
/// as loosely-typed `{path, status, digest, ...}` records; this is kept as
/// `Value` so unknown/extra fields round-trip exactly the way JS's
/// `artifacts` array does.
pub type ArtifactRecord = Value;

/// The `writeCanonicalManifest` return value (`manifest.json`'s `value`
/// field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunManifest {
    pub schema_version: u32,
    pub kind: String,
    pub binding: Value,
    pub source_revision: Value,
    pub terminal_absences: Vec<String>,
    pub artifacts: Vec<ArtifactRecord>,
    pub digest: String,
}

impl RunManifest {
    pub fn to_value(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "binding": self.binding,
            "sourceRevision": self.source_revision,
            "terminalAbsences": self.terminal_absences,
            "artifacts": self.artifacts,
            "digest": self.digest,
        })
    }
}

/// The envelope `writeCanonicalManifest` passes to `store.writeJson(...)`,
/// alongside `value` (the [`RunManifest`]). Persisting this is outside this
/// chunk's scope (see the chunk-level doc comment on `run-manifest.mjs`'s
/// disposition) — an integrator with a `Store` abstraction writes this
/// envelope's fields plus `to_value()` to `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalManifestArtifact {
    pub path: &'static str,
    pub kind: &'static str,
    pub producer: &'static str,
    pub producer_version: &'static str,
    pub schema_version: u32,
    pub media_type: &'static str,
    pub binding: Value,
    /// JS passes `denominatorDigest: null` unconditionally.
    pub denominator_digest: Value,
    pub value: RunManifest,
}

/// Port of `writeCanonicalManifest(store, binding)` minus the
/// `store.writeJson` I/O call itself (see [`CanonicalManifestArtifact`]).
/// `records` stands in for `store.records()`.
pub fn build_canonical_manifest(records: Vec<ArtifactRecord>, binding: Value) -> CanonicalManifestArtifact {
    let source_revision = binding
        .get("sourceRevision")
        .filter(|value| !value.is_null())
        .cloned()
        .or_else(|| binding.get("repositoryRevision").filter(|value| !value.is_null()).cloned())
        .unwrap_or(Value::Null);

    let mut terminal_absences: Vec<String> = records
        .iter()
        .filter(|record| record.get("status").and_then(Value::as_str) == Some("missing"))
        .filter_map(|record| record.get("path").and_then(Value::as_str).map(str::to_string))
        .collect();
    terminal_absences.sort();

    let digest_input = json!({
        "binding": binding.clone(),
        "sourceRevision": source_revision.clone(),
        "terminalAbsences": terminal_absences.clone(),
        "artifacts": records.clone(),
    });
    let digest = binding_digest(&digest_input);

    let value = RunManifest {
        schema_version: 1,
        kind: "legion-run-manifest".to_string(),
        binding: binding.clone(),
        source_revision,
        terminal_absences,
        artifacts: records,
        digest,
    };

    CanonicalManifestArtifact {
        path: "run-manifest.json",
        kind: "run-manifest",
        producer: "legion.core",
        producer_version: "1.0.0",
        schema_version: 1,
        media_type: "application/json",
        binding,
        denominator_digest: Value::Null,
        value,
    }
}

/// Port of `validateRunManifest(manifest, files, expectedBinding)`. Returns
/// the sorted list of issue strings, empty when the manifest is fully
/// consistent with `files` (mirrors JS's mixed-order `[...issues, ...orphans,
/// ...driftedOrMissing].sort()`, which the final `.sort()` makes a plain
/// lexicographic sort regardless of push order — replicated identically
/// here).
pub fn validate_run_manifest(manifest: &Value, files: &[ArtifactRecord], expected_binding: Option<&Value>) -> Vec<String> {
    let binding = manifest.get("binding");
    let expected = expected_binding.unwrap_or_else(|| manifest.get("binding").unwrap_or(&Value::Null));

    let mut issues: Vec<String> = Vec::new();

    let binding_ok = match binding {
        Some(value) if !value.is_null() => same_binding(value, expected),
        _ => false,
    };
    if !binding_ok {
        issues.push("binding:mismatch".to_string());
    }

    let source_revision_missing = manifest
        .get("sourceRevision")
        .map(|value| value.is_null() || matches!(value, Value::String(s) if s.is_empty()))
        .unwrap_or(true);
    if source_revision_missing {
        issues.push("source-revision:missing".to_string());
    }

    let declared: Vec<(String, Value)> = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let path = item.get("path")?.as_str()?.to_string();
            Some((path, item.get("digest").cloned().unwrap_or(Value::Null)))
        })
        .collect();
    let actual: Vec<(String, Value)> = files
        .iter()
        .filter_map(|item| {
            let path = item.get("path")?.as_str()?.to_string();
            Some((path, item.get("digest").cloned().unwrap_or(Value::Null)))
        })
        .collect();

    let declared_paths: std::collections::BTreeMap<&str, &Value> =
        declared.iter().map(|(path, digest)| (path.as_str(), digest)).collect();
    let actual_paths: std::collections::BTreeMap<&str, &Value> =
        actual.iter().map(|(path, digest)| (path.as_str(), digest)).collect();

    let mut absent: Vec<&str> = declared_paths
        .keys()
        .filter(|path| !actual_paths.contains_key(*path))
        .copied()
        .collect();
    absent.sort();

    let mut declared_terminal_absences: Vec<String> = manifest
        .get("terminalAbsences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    declared_terminal_absences.sort();

    let absent_owned: Vec<String> = absent.iter().map(|s| s.to_string()).collect();
    if absent_owned != declared_terminal_absences {
        issues.push("terminal-absences:mismatch".to_string());
    }

    for path in actual_paths.keys() {
        if !declared_paths.contains_key(*path) {
            issues.push(format!("orphan:{path}"));
        }
    }
    for (path, declared_digest) in &declared_paths {
        let missing_or_drifted = match actual_paths.get(path) {
            None => true,
            Some(actual_digest) => actual_digest != declared_digest,
        };
        if missing_or_drifted {
            issues.push(format!("missing-or-drifted:{path}"));
        }
    }

    issues.sort();
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_canonical_manifest_sorts_terminal_absences_and_carries_source_revision() {
        let binding = json!({"repositoryRevision": "rev-1", "sourceRevision": "rev-1"});
        let records = vec![
            json!({"path": "b.txt", "status": "missing", "digest": "sha256:1"}),
            json!({"path": "a.txt", "status": "missing", "digest": "sha256:2"}),
            json!({"path": "c.txt", "status": "present", "digest": "sha256:3"}),
        ];
        let artifact = build_canonical_manifest(records, binding);
        assert_eq!(artifact.value.terminal_absences, vec!["a.txt", "b.txt"]);
        assert_eq!(artifact.value.source_revision, json!("rev-1"));
        assert_eq!(artifact.value.kind, "legion-run-manifest");
        assert_eq!(artifact.path, "run-manifest.json");
        assert!(artifact.value.digest.starts_with("sha256:"));
    }

    #[test]
    fn build_canonical_manifest_falls_back_to_repository_revision() {
        let binding = json!({"repositoryRevision": "rev-9"});
        let artifact = build_canonical_manifest(vec![], binding);
        assert_eq!(artifact.value.source_revision, json!("rev-9"));
    }

    #[test]
    fn validate_run_manifest_passes_when_everything_matches() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "sourceRevision": "rev-1",
            "terminalAbsences": [],
            "artifacts": [{"path": "a.txt", "digest": "sha256:1"}],
        });
        let files = vec![json!({"path": "a.txt", "digest": "sha256:1"})];
        let issues = validate_run_manifest(&manifest, &files, None);
        assert!(issues.is_empty(), "expected no issues, got {issues:?}");
    }

    #[test]
    fn validate_run_manifest_reports_binding_mismatch() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "sourceRevision": "rev-1",
            "terminalAbsences": [],
            "artifacts": [],
        });
        let expected = json!({"repositoryRevision": "rev-2"});
        let issues = validate_run_manifest(&manifest, &[], Some(&expected));
        assert!(issues.contains(&"binding:mismatch".to_string()));
    }

    #[test]
    fn validate_run_manifest_reports_missing_source_revision() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "terminalAbsences": [],
            "artifacts": [],
        });
        let issues = validate_run_manifest(&manifest, &[], None);
        assert!(issues.contains(&"source-revision:missing".to_string()));
    }

    #[test]
    fn validate_run_manifest_reports_orphans_and_drift() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "sourceRevision": "rev-1",
            "terminalAbsences": [],
            "artifacts": [{"path": "a.txt", "digest": "sha256:1"}],
        });
        let files = vec![
            json!({"path": "a.txt", "digest": "sha256:DRIFTED"}),
            json!({"path": "orphan.txt", "digest": "sha256:2"}),
        ];
        let issues = validate_run_manifest(&manifest, &files, None);
        assert!(issues.contains(&"orphan:orphan.txt".to_string()));
        assert!(issues.contains(&"missing-or-drifted:a.txt".to_string()));
    }

    #[test]
    fn validate_run_manifest_reports_terminal_absences_mismatch() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "sourceRevision": "rev-1",
            "terminalAbsences": [],
            "artifacts": [{"path": "gone.txt", "digest": "sha256:1"}],
        });
        let issues = validate_run_manifest(&manifest, &[], None);
        assert!(issues.contains(&"terminal-absences:mismatch".to_string()));
    }

    #[test]
    fn validate_run_manifest_matches_declared_terminal_absences() {
        let manifest = json!({
            "binding": {"repositoryRevision": "rev-1"},
            "sourceRevision": "rev-1",
            "terminalAbsences": ["gone.txt"],
            "artifacts": [{"path": "gone.txt", "digest": "sha256:1"}],
        });
        let issues = validate_run_manifest(&manifest, &[], None);
        assert!(!issues.contains(&"terminal-absences:mismatch".to_string()), "{issues:?}");
        assert!(issues.contains(&"missing-or-drifted:gone.txt".to_string()));
    }
}
