use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
};

use crate::{AuditProvider, InventoryDenominator, InventoryEntry, InventoryEnvelope};

/// This capability is never deserialized. Only the self-sourcing adapter may
/// admit observed source bytes; JSON inputs keep the tool-artifact contract.
#[derive(Clone, Debug, PartialEq)]
struct SourceBinding {
    repository_revision: String,
    inventory_digest: String,
    denominator_digest: String,
}

#[derive(Clone, Debug)]
pub(super) struct SourceObservation {
    path: String,
    observed_digest: String,
}

impl SourceObservation {
    pub(super) fn from_bytes(path: &str, bytes: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            observed_digest: bytes_digest(bytes),
        }
    }
}

#[derive(Debug)]
struct SourceRecord {
    binding: SourceBinding,
    path: String,
    frozen_digest: Option<String>,
    observed_digest: String,
}

#[derive(Debug)]
pub(super) struct NativeSourceEvidence<'a> {
    root: &'a Path,
    selected: BTreeMap<&'a str, &'a InventoryEntry>,
    binding: SourceBinding,
    binding_valid: bool,
    records: BTreeMap<String, SourceRecord>,
}

pub(super) fn source_reference(path: &str) -> String {
    format!("native-source:{}", bytes_digest(path.as_bytes()))
}

fn bytes_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0', ':'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

/// Refuse symlink components, including links inside the root. Canonical root
/// containment is checked before & after reading the same bounded bytes.
fn contained_source_bytes(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    if !canonical_relative_path(relative) {
        return Err("native-source-path-invalid".into());
    }
    let root = root
        .canonicalize()
        .map_err(|_| "native-source-root-unavailable")?;
    let verify = || -> Result<PathBuf, String> {
        let mut path = root.clone();
        for component in relative.split('/') {
            path.push(component);
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|_| "native-source-unreadable")?;
            if metadata.file_type().is_symlink() {
                return Err("native-source-symlink".into());
            }
        }
        let canonical = path
            .canonicalize()
            .map_err(|_| "native-source-unreadable")?;
        if !canonical.starts_with(&root) {
            return Err("native-source-outside-root".into());
        }
        let metadata = std::fs::metadata(&canonical).map_err(|_| "native-source-unreadable")?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err("native-source-not-bounded-file".into());
        }
        Ok(canonical)
    };
    let path = verify()?;
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|_| "native-source-unreadable")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native-source-unreadable")?;
    if bytes.len() > 1024 * 1024 || verify()? != path {
        return Err("native-source-path-changed".into());
    }
    Ok(bytes)
}

impl<'a> NativeSourceEvidence<'a> {
    pub(super) fn new(
        root: &'a Path,
        inventory: &'a InventoryEnvelope,
        denominator: &'a InventoryDenominator,
        provider: &AuditProvider,
        observations: &BTreeMap<String, SourceObservation>,
    ) -> Self {
        // Inventory generation is the frozen repository content revision. It
        // deliberately does not pretend to be a Git commit or a tool receipt.
        let binding = SourceBinding {
            repository_revision: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            denominator_digest: denominator.digest.clone(),
        };
        let entries = inventory
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let selected = denominator
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let binding_valid = inventory.validate().is_ok()
            && provider
                .configuration
                .get("denominatorDigest")
                .and_then(Value::as_str)
                == Some(denominator.digest.as_str())
            && provider
                .configuration
                .get("denominatorCount")
                .and_then(Value::as_u64)
                == Some(denominator.entries.len() as u64)
            && selected.len() == denominator.entries.len()
            && selected
                .iter()
                .all(|(path, entry)| entries.get(path) == Some(entry));
        let records = observations
            .iter()
            .map(|(path, observation)| {
                let frozen_digest = selected
                    .get(path.as_str())
                    .and_then(|entry| entry.digest.clone());
                (
                    source_reference(path),
                    SourceRecord {
                        binding: binding.clone(),
                        path: observation.path.clone(),
                        frozen_digest,
                        observed_digest: observation.observed_digest.clone(),
                    },
                )
            })
            .collect();
        Self {
            root,
            selected,
            binding,
            binding_valid,
            records,
        }
    }

    pub(super) fn validate_observation(&self, row: &Map<String, Value>) -> Vec<String> {
        let validate = || -> Result<(), String> {
            if !self.binding_valid {
                return Err("native-source-binding-mismatch".into());
            }
            let path = row
                .get("path")
                .and_then(Value::as_str)
                .ok_or("native-source-observation-path-missing")?;
            if !canonical_relative_path(path) {
                return Err("native-source-path-invalid".into());
            }
            let refs = row
                .get("evidenceRefs")
                .and_then(Value::as_array)
                .filter(|refs| refs.len() == 1)
                .ok_or("native-source-reference-invalid")?;
            let reference = refs[0].as_str().ok_or("native-source-reference-invalid")?;
            let record = self
                .records
                .get(reference)
                .ok_or("native-source-reference-missing")?;
            if record.binding != self.binding {
                return Err("native-source-binding-mismatch".into());
            }
            if record.path != path || reference != source_reference(path) {
                return Err("native-source-observation-mismatch".into());
            }
            let entry = self
                .selected
                .get(path)
                .ok_or("native-source-outside-denominator")?;
            let frozen = entry
                .digest
                .as_deref()
                .ok_or("native-source-frozen-digest-missing")?;
            if !digest(Some(&Value::String(frozen.into())))
                || record.frozen_digest.as_deref() != Some(frozen)
                || record.observed_digest != frozen
            {
                return Err("native-source-digest-mismatch".into());
            }
            let bytes = contained_source_bytes(self.root, path)?;
            if bytes_digest(&bytes) != frozen {
                return Err("native-source-bytes-changed".into());
            }
            // Framework source observations cover whole files. A supplied
            // line must still identify a real line in those exact bytes.
            if let Some(line) = row.get("line") {
                let line = line
                    .as_u64()
                    .filter(|line| *line > 0)
                    .ok_or("native-source-span-invalid")?;
                let text = std::str::from_utf8(&bytes).map_err(|_| "native-source-span-invalid")?;
                if line > text.lines().count() as u64 {
                    return Err("native-source-span-invalid".into());
                }
            }
            Ok(())
        };
        validate().err().into_iter().collect()
    }

    pub(super) fn summary(&self) -> Value {
        serde_json::json!({
            "kind": "native-frozen-source",
            "claim": "source-bytes-observed",
            "repositoryRevision": self.binding.repository_revision,
            "inventoryDigest": self.binding.inventory_digest,
            "denominatorDigest": self.binding.denominator_digest,
            "bindingValid": self.binding_valid,
            "records": self.records.iter().map(|(reference, record)| serde_json::json!({
                "reference": reference, "path": record.path,
                "frozenDigest": record.frozen_digest, "observedDigest": record.observed_digest,
            })).collect::<Vec<_>>(),
        })
    }
}

fn digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn same_binding(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    let Some(actual) = actual.and_then(Value::as_object) else {
        return false;
    };
    let Some(expected) = expected.and_then(Value::as_object) else {
        return false;
    };
    actual.get("repositoryRevision") == expected.get("repositoryRevision")
        && actual.get("digest") == expected.get("digest")
}

fn expired(value: &str, now: Option<&str>) -> bool {
    // Node uses Date.parse.  This accepts the canonical UTC forms used by
    // evidence receipts while remaining dependency-free in the audit crate.
    fn parse(raw: &str) -> Option<i64> {
        let normalized = raw.strip_suffix('Z').unwrap_or(raw);
        let parts = normalized.split(['-', 'T', ':', '.']).collect::<Vec<_>>();
        if parts.len() < 6 {
            return None;
        }
        let nums = parts[..6]
            .iter()
            .map(|item| item.parse::<i64>().ok())
            .collect::<Option<Vec<_>>>()?;
        // Howard Hinnant's civil-date conversion.
        let (year, month) = (nums[0], nums[1]);
        let adjusted = year - i64::from(month <= 2);
        let era = (if adjusted >= 0 {
            adjusted
        } else {
            adjusted - 399
        }) / 400;
        let year_of_era = adjusted - era * 400;
        let month_prime = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * month_prime + 2) / 5 + nums[2] - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        Some((era * 146097 + day_of_era - 719468) * 86400 + nums[3] * 3600 + nums[4] * 60 + nums[5])
    }
    let Some(expiry) = parse(value) else {
        return true;
    };
    let Some(current) = now.and_then(parse) else {
        return true;
    };
    expiry <= current
}

/// Port of `validateEvidenceRefs` from `evidence-authority.mjs`.
/// Checks supplied bytes & receipt metadata, not the authenticity of caller JSON.
pub fn validate_refs(refs: Option<&Value>, authority: &Value) -> Vec<String> {
    let Some(refs) = refs.and_then(Value::as_array) else {
        return vec!["evidence-refs-empty".into()];
    };
    if refs.is_empty() {
        return vec!["evidence-refs-empty".into()];
    }
    let index = authority.get("evidenceIndex").and_then(Value::as_object);
    let root = authority.get("root").and_then(Value::as_str);
    let binding = authority.get("binding");
    let now = authority.get("now").and_then(Value::as_str);
    let mut errors = Vec::new();
    for item in refs {
        let reference = item
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| item.to_string());
        let Some(record) = index
            .and_then(|items| items.get(&reference))
            .and_then(Value::as_object)
        else {
            errors.push(format!("evidence-ref-missing:{reference}"));
            continue;
        };
        if !digest(record.get("digest")) {
            errors.push(format!("evidence-digest-invalid:{reference}"));
        }
        if !same_binding(record.get("binding"), binding) {
            errors.push(format!("evidence-binding-mismatch:{reference}"));
        }
        if let Some(expires) = record.get("expiresAt").and_then(Value::as_str) {
            if expired(expires, now) {
                errors.push(format!("evidence-expired:{reference}"));
            }
        }
        let path = record.get("path").and_then(Value::as_str);
        if root.is_none() || path.is_none() {
            errors.push(format!("evidence-path-missing:{reference}"));
        } else {
            let path = Path::new(root.unwrap()).join(path.unwrap());
            match std::fs::read(path) {
                Ok(bytes) => {
                    let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
                    if Some(actual.as_str()) != record.get("digest").and_then(Value::as_str) {
                        errors.push(format!("evidence-bytes-mismatch:{reference}"));
                    }
                }
                Err(_) => errors.push(format!("evidence-bytes-missing:{reference}")),
            }
        }
        if record
            .get("storageReceipt")
            .and_then(Value::as_object)
            .and_then(|o| o.get("immutable"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            errors.push(format!("evidence-storage-unproven:{reference}"));
        }
        if record
            .get("toolReceipt")
            .and_then(Value::as_object)
            .and_then(|o| o.get("complete"))
            .and_then(Value::as_bool)
            != Some(true)
            || !digest(
                record
                    .get("toolReceipt")
                    .and_then(Value::as_object)
                    .and_then(|o| o.get("tool"))
                    .and_then(Value::as_object)
                    .and_then(|o| o.get("executableDigest")),
            )
        {
            errors.push(format!("evidence-tool-unproven:{reference}"));
        }
    }
    errors
}

/// Backend/compatibility have no native runtime evidence capability. Neither
/// receipt-shaped JSON nor a successful protocol comparison can mint one.
pub(super) fn limit_runtime_evidence(analysis: &mut super::common::Analysis) {
    analysis.status = "unproven".into();
    analysis.complete = false;
    analysis
        .extras
        .insert("certificationClaim".into(), Value::Bool(false));
    let gap = super::common::gap("runtime-evidence-trust-unavailable");
    if !analysis.coverage_gaps.contains(&gap) {
        analysis.coverage_gaps.push(gap);
    }
}

pub fn authority(
    plan: Option<&Value>,
    artifacts: Option<&Value>,
    root: Option<&Value>,
    now: Option<&str>,
) -> Value {
    let mut object = Map::new();
    if let Some(root) = root.and_then(Value::as_str).or_else(|| {
        artifacts
            .and_then(|value| value.get("root"))
            .and_then(Value::as_str)
    }) {
        object.insert("root".into(), Value::String(root.into()));
    }
    if let Some(index) = artifacts.and_then(|value| value.get("evidenceIndex")) {
        object.insert("evidenceIndex".into(), index.clone());
    }
    if let Some(binding) = plan.and_then(|value| value.get("binding")) {
        object.insert("binding".into(), binding.clone());
    }
    if let Some(now) = now {
        object.insert("now".into(), Value::String(now.into()));
    }
    Value::Object(object)
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::{AuditPlan, FilesystemInventorySource, InventorySource};
    use legion_contracts::ProviderSpec;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn file_only_provider_accuracy_native_source_rejects_binding_scope_and_path_escape() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "legion-native-source-safety-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let body = "model User {\n  id Int @id\n}\n";
        std::fs::write(root.join("schema.prisma"), body).unwrap();
        std::fs::write(root.join("outside.prisma"), body).unwrap();
        let inventory = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("source-safety")
            .unwrap();
        let registry: Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../src/registry/providers.json",
            ))
            .unwrap(),
        )
        .unwrap();
        let mut spec: ProviderSpec = serde_json::from_value(
            registry["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["id"] == "framework.data")
                .unwrap()
                .clone(),
        )
        .unwrap();
        spec.selector = json!({"op":"paths", "paths":["schema.prisma"]});
        let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
            .unwrap()
            .freeze(Some(b"native-source-safety-fixture-key"))
            .unwrap();
        let provider = plan.provider("framework.data").unwrap();
        let denominator = inventory
            .denominator_entries(&provider.configuration["selector"])
            .unwrap();
        // An overbroad producer cannot admit an observation outside selection.
        let facts = super::super::producer::scan(&root, &inventory.entries);
        let mut source =
            NativeSourceEvidence::new(&root, &inventory, &denominator, provider, &facts.sources);
        let reference = source_reference("schema.prisma");
        let valid = json!({"path":"schema.prisma", "evidenceRefs":[reference]});
        let valid = valid.as_object().unwrap();
        assert!(source.validate_observation(valid).is_empty());
        for field in ["revision", "inventory", "denominator"] {
            let record = source.records.get_mut(&reference).unwrap();
            match field {
                "revision" => record.binding.repository_revision = "wrong-revision".into(),
                "inventory" => record.binding.inventory_digest = "wrong-inventory".into(),
                _ => record.binding.denominator_digest = "wrong-denominator".into(),
            }
            assert_eq!(
                source.validate_observation(valid),
                ["native-source-binding-mismatch"]
            );
            source.records.get_mut(&reference).unwrap().binding = source.binding.clone();
        }
        let outside =
            json!({"path":"outside.prisma", "evidenceRefs":[source_reference("outside.prisma")]});
        assert_eq!(
            source.validate_observation(outside.as_object().unwrap()),
            ["native-source-outside-denominator"]
        );
        let wrong_ref =
            json!({"path":"schema.prisma", "evidenceRefs":[source_reference("outside.prisma")]});
        assert_eq!(
            source.validate_observation(wrong_ref.as_object().unwrap()),
            ["native-source-observation-mismatch"]
        );
        for path in [
            "../schema.prisma".to_owned(),
            root.join("schema.prisma").to_string_lossy().into_owned(),
            "dir/../schema.prisma".into(),
            "dir\\schema.prisma".into(),
        ] {
            let escaped = json!({"path":path, "evidenceRefs":[reference]});
            assert_eq!(
                source.validate_observation(escaped.as_object().unwrap()),
                ["native-source-path-invalid"]
            );
        }
        let invalid_span = json!({"path":"schema.prisma", "line":100, "evidenceRefs":[reference]});
        assert_eq!(
            source.validate_observation(invalid_span.as_object().unwrap()),
            ["native-source-span-invalid"]
        );
        std::fs::write(root.join("schema.prisma"), "model Changed {}\n").unwrap();
        assert_eq!(
            source.validate_observation(valid),
            ["native-source-bytes-changed"]
        );
        std::fs::write(root.join("schema.prisma"), body).unwrap();
        let record = source.records.get_mut(&reference).unwrap();
        record.observed_digest = bytes_digest(b"different observed bytes");
        assert_eq!(
            source.validate_observation(valid),
            ["native-source-digest-mismatch"]
        );
        source.records.get_mut(&reference).unwrap().observed_digest = bytes_digest(body.as_bytes());
        #[cfg(unix)]
        {
            let outside_file = root.with_extension("outside-source");
            std::fs::write(&outside_file, body).unwrap();
            std::fs::remove_file(root.join("schema.prisma")).unwrap();
            std::os::unix::fs::symlink(&outside_file, root.join("schema.prisma")).unwrap();
            assert_eq!(
                source.validate_observation(valid),
                ["native-source-symlink"]
            );
            std::fs::remove_file(outside_file).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
