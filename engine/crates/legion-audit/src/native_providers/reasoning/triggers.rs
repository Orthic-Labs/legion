//! Deterministic trigger evaluation for the five conditional lenses
//! (`a11y`, `data-safety`, `resilience`, `platform-parity`,
//! `release-readiness`), per `skills/audit/references/{lens-routing,
//! manual}.md`: "Conditional lenses activate on deterministic triggers, not
//! judgment ... Record the trigger evidence (the grep hit or file) when a
//! conditional lens runs; when it does NOT run, its absence from
//! `lenses_ran` must be provably not-applicable (trigger checked, zero
//! hits)."
//!
//! This module supplies the trigger *evidence* (the actual local check over
//! the frozen inventory), closing the gap `lens_plan.rs` left open: that
//! module only carries the trigger *description* in the packet; whether the
//! trigger fired was previously assumed already decided upstream by the
//! provider's presence in the `FrozenPlan`. This module is the deterministic
//! check a plan-freeze caller runs to make that inclusion decision, and it
//! folds the same evidence into the packet for host-side transparency.
//!
//! Dependency-free by design (no new crate): path/extension heuristics plus
//! a small bounded raw-byte scan for the two triggers (`platform-parity`,
//! `resilience`) that need a content signature rather than a path shape.

use std::{io::Read, path::Path};

use rightkit_evidence_contracts::canonical_digest;
use serde_json::{json, Value};

use crate::error::AuditError;
use crate::snapshot::{FrozenSnapshot, SnapshotAdmission, SnapshotSide};

/// One evaluated trigger: whether it fired, and the human-readable evidence
/// (grep hit or file path) recorded regardless of outcome, so a
/// not-applicable result is provably checked rather than silently skipped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerEvaluation {
    pub lens: &'static str,
    pub fired: bool,
    /// Evidence: matched paths (fired) or the description of what was
    /// checked and found empty (not fired).
    pub reason: String,
    /// The specific paths that fired the trigger, if any. Empty when not
    /// fired.
    pub evidence_paths: Vec<String>,
    /// Content-based trigger checks that could not rule applicability out.
    /// These paths remain required work, never checked-zero exclusions.
    pub unavailable_paths: Vec<String>,
}

impl TriggerEvaluation {
    pub fn required_paths(&self) -> Vec<String> {
        self.evidence_paths
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Unknown applicability keeps one deterministic review surface available;
    /// every unavailable path remains a gap, without forcing exhaustive review.
    pub fn applicable_paths(&self) -> Vec<String> {
        let witnesses = self.required_paths();
        if !witnesses.is_empty() {
            return witnesses;
        }
        self.unavailable_paths
            .iter()
            .min()
            .cloned()
            .into_iter()
            .collect()
    }

    /// Frozen before coverage selection; bound to the full applicable inventory.
    pub fn snapshot(&self, inventory_digest: &str, paths: &[String]) -> Result<Value, AuditError> {
        self.snapshot_with_source_sides(inventory_digest, paths, &std::collections::BTreeMap::new())
    }

    pub fn snapshot_with_source_sides(
        &self,
        inventory_digest: &str,
        paths: &[String],
        source_sides: &std::collections::BTreeMap<String, String>,
    ) -> Result<Value, AuditError> {
        let checked: std::collections::BTreeSet<&str> = paths.iter().map(String::as_str).collect();
        let checked_digest =
            canonical_digest(&checked).map_err(|error| AuditError::Invalid(error.to_string()))?;
        let mut value = json!({
            "schemaVersion": 1,
            "lens": self.lens,
            "fired": self.fired,
            "reason": self.reason,
            "evidencePaths": self.evidence_paths,
            "unavailablePaths": self.unavailable_paths,
            "mandatoryWitnessPaths": self.required_paths(),
            "checkedPathsDigest": checked_digest,
            "sourceSides": source_sides,
            "inventoryDigest": inventory_digest,
            "applicability": if self.fired { "triggered" } else if self.unavailable_paths.is_empty() { "not-applicable" } else { "unavailable" },
        });
        let digest =
            canonical_digest(&value).map_err(|error| AuditError::Invalid(error.to_string()))?;
        value["digest"] = json!(digest);
        Ok(value)
    }
}

/// Bound on how many bytes of any one file are scanned for a content-based
/// trigger signature (`cfg(target_os`, sidecar/child-process spawn sites).
/// Kept small: triggers only need to know a signature is present anywhere
/// in the file, not to read the whole file.
const CONTENT_SCAN_CAP_BYTES: usize = 64 * 1024;

/// One planning operation admits the sealed reader before scanning, then
/// revalidates it before publishing results. Each consumed file still hashes
/// against its sealed digest; admission never occurs inside the file loop.
pub(crate) struct TriggerSource<'a> {
    root: &'a Path,
    snapshot: Option<(SnapshotAdmission, SnapshotSide)>,
}

impl<'a> TriggerSource<'a> {
    pub(crate) fn new(root: &'a Path) -> Result<Self, AuditError> {
        let snapshot = crate::inventory::frozen_snapshot(root)?
            .map(|(snapshot, side)| {
                FrozenSnapshot::operation_admission(&snapshot).map(|admission| (admission, side))
            })
            .transpose()?;
        Ok(Self { root, snapshot })
    }

    pub(crate) fn source_sides(&self) -> std::collections::BTreeMap<String, String> {
        let mut sides = std::collections::BTreeMap::new();
        if let Some((snapshot, SnapshotSide::Selected)) = &self.snapshot {
            let snapshot = snapshot.snapshot();
            for path in &snapshot.manifest.scope.changed_paths {
                if !snapshot.manifest.files.contains_key(path)
                    && snapshot.manifest.base_files.contains_key(path)
                {
                    sides.insert(path.clone(), "base".into());
                }
            }
        }
        sides
    }

    pub(crate) fn revalidate(&self) -> Result<(), AuditError> {
        if let Some((admission, side)) = &self.snapshot {
            let snapshot = admission.snapshot();
            let expected_root = match side {
                SnapshotSide::Selected => &snapshot.manifest.execution_root,
                SnapshotSide::Base => &snapshot.manifest.baseline_root,
            };
            let current_root = self.root.canonicalize().map_err(|error| {
                AuditError::SourceDrift(format!("Audit trigger root changed: {error}"))
            })?;
            if &current_root != expected_root {
                return Err(AuditError::SourceDrift("Audit trigger root changed".into()));
            }
            return admission.revalidate();
        }
        if crate::inventory::frozen_snapshot(self.root)?.is_none() {
            Ok(())
        } else {
            Err(AuditError::SourceDrift(
                "Audit trigger source admission changed during planning".into(),
            ))
        }
    }

    pub(crate) fn evaluate(&self, lens: &str, paths: &[String]) -> Option<TriggerEvaluation> {
        evaluate_with_head(lens, paths, &|path| self.read_head(path))
    }

    fn read_head(&self, path: &str) -> Result<(String, bool), ()> {
        if let Some((snapshot, root_side)) = &self.snapshot {
            let snapshot = snapshot.snapshot();
            let side = if *root_side == SnapshotSide::Base
                || !snapshot.manifest.files.contains_key(path)
                    && snapshot.manifest.scope.changed_paths.contains(path)
                    && snapshot.manifest.base_files.contains_key(path)
            {
                SnapshotSide::Base
            } else {
                SnapshotSide::Selected
            };
            // Preserve the raw-byte cap: oversized sealed files remain
            // applicability-unknown rather than reading unbound live bytes.
            let bytes = snapshot
                .read(path, side, CONTENT_SCAN_CAP_BYTES)
                .map_err(|_| ())?;
            return Ok((String::from_utf8_lossy(&bytes).into_owned(), false));
        }
        read_live_head(self.root, path)
    }
}

fn read_live_head(root: &Path, path: &str) -> Result<(String, bool), ()> {
    let canonical_root = root.canonicalize().map_err(|_| ())?;
    let canonical_path = root.join(path).canonicalize().map_err(|_| ())?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(());
    }
    let file = std::fs::File::open(canonical_path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take((CONTENT_SCAN_CAP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let truncated = bytes.len() > CONTENT_SCAN_CAP_BYTES;
    bytes.truncate(CONTENT_SCAN_CAP_BYTES);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

fn has_extension(path: &str, extensions: &[&str]) -> bool {
    extensions
        .iter()
        .any(|extension| path.to_ascii_lowercase().ends_with(extension))
}

fn contains_any(path_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path_lower.contains(needle))
}

/// `a11y`: fires on any UI target file present in the denominator
/// (JSX/TSX/HTML/templates/Vue/Svelte), per `lens-routing.md` line 272.
fn evaluate_a11y(paths: &[String]) -> TriggerEvaluation {
    let extensions = [".jsx", ".tsx", ".html", ".htm", ".vue", ".svelte"];
    let hits: Vec<String> = paths
        .iter()
        .filter(|path| has_extension(path, &extensions))
        .cloned()
        .collect();
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "a11y",
        fired,
        reason: if fired {
            format!("UI target present: {} matching file(s)", hits.len())
        } else {
            "checked JSX/TSX/HTML/Vue/Svelte extensions across the denominator; zero hits".into()
        },
        evidence_paths: hits,
        unavailable_paths: Vec::new(),
    }
}

/// `data-safety`: fires on migration/SQL/ORM/storage/telemetry surfaces in
/// scope, per `manual.md` line 273.
fn evaluate_data_safety(paths: &[String]) -> TriggerEvaluation {
    let needles = [
        "migration",
        "migrations",
        ".sql",
        "/schema",
        "schema.rs",
        "schema.ts",
        "schema.py",
        "localstorage",
        "asyncstorage",
        "sqlite",
        "keychain",
        "keystore",
        "telemetry",
        "analytics",
    ];
    let hits: Vec<String> = paths
        .iter()
        .filter(|path| contains_any(&path.to_ascii_lowercase(), &needles))
        .cloned()
        .collect();
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "data-safety",
        fired,
        reason: if fired {
            format!(
                "migration/SQL/storage/telemetry surface present: {} matching file(s)",
                hits.len()
            )
        } else {
            "checked migration/SQL/storage/telemetry path signatures; zero hits".into()
        },
        evidence_paths: hits,
        unavailable_paths: Vec::new(),
    }
}

/// `resilience`: fires on sidecar/child-process/server/queue code, per
/// `manual.md` line 274. Path signature first (cheap), then a bounded
/// content scan on plausible source files for a spawn/Command site — the
/// path alone under-fires ("server.rs" is common but a raw spawn call
/// inside an unrelated file would be missed by path alone).
fn evaluate_resilience(
    paths: &[String],
    read_head: &impl Fn(&str) -> Result<(String, bool), ()>,
) -> TriggerEvaluation {
    let path_needles = [
        "sidecar",
        "child_process",
        "daemon",
        "worker",
        "queue",
        "/server",
    ];
    let mut hits: Vec<String> = paths
        .iter()
        .filter(|path| contains_any(&path.to_ascii_lowercase(), &path_needles))
        .cloned()
        .collect();
    let content_extensions = [".rs", ".ts", ".tsx", ".js", ".py"];
    let content_needles = [
        "Command::new(",
        "spawn_sidecar",
        "child_process.spawn",
        "subprocess.Popen",
    ];
    let mut unavailable = Vec::new();
    for path in paths {
        if hits.contains(path) || !has_extension(path, &content_extensions) {
            continue;
        }
        match read_head(path) {
            Ok((content, truncated)) => {
                if content_needles
                    .iter()
                    .any(|needle| content.contains(needle))
                {
                    hits.push(path.clone());
                } else if truncated {
                    unavailable.push(path.clone());
                }
            }
            Err(()) => unavailable.push(path.clone()),
        }
    }
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "resilience",
        fired,
        reason: if fired {
            format!(
                "sidecar/child-process/server/queue code present: {} matching file(s)",
                hits.len()
            )
        } else {
            "checked sidecar/child-process/server/queue path and spawn-site signatures; zero confirmed hits; unavailable content checks remain explicit"
                .into()
        },
        evidence_paths: hits,
        unavailable_paths: unavailable,
    }
}

/// `platform-parity`: fires on `cfg(target_os` (Rust) or `usePlatform`
/// (TS/JS) content signatures, per `manual.md` line 275.
fn evaluate_platform_parity(
    paths: &[String],
    read_head: &impl Fn(&str) -> Result<(String, bool), ()>,
) -> TriggerEvaluation {
    let mut hits = Vec::new();
    let mut unavailable = Vec::new();
    for path in paths {
        let is_rust = has_extension(path, &[".rs"]);
        let is_ts = has_extension(path, &[".ts", ".tsx", ".js", ".jsx"]);
        if !is_rust && !is_ts {
            continue;
        }
        match read_head(path) {
            Ok((content, truncated)) => {
                let matched = (is_rust && content.contains("cfg(target_os"))
                    || (is_ts && content.contains("usePlatform"));
                if matched {
                    hits.push(path.clone());
                } else if truncated {
                    unavailable.push(path.clone());
                }
            }
            Err(()) => unavailable.push(path.clone()),
        }
    }
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "platform-parity",
        fired,
        reason: if fired {
            format!(
                "cfg(target_os or usePlatform present: {} matching file(s)",
                hits.len()
            )
        } else {
            "checked cfg(target_os / usePlatform content signature across .rs/.ts/.tsx/.js/.jsx; zero confirmed hits; unavailable content checks remain explicit".into()
        },
        evidence_paths: hits,
        unavailable_paths: unavailable,
    }
}

/// `release-readiness`: fires on publish/signing/updater scripts or
/// `tauri.conf.json` bundle config, per `manual.md` line 276.
fn evaluate_release_readiness(paths: &[String]) -> TriggerEvaluation {
    let needles = [
        "tauri.conf",
        "release",
        "sign",
        "notariz",
        "installer",
        "updater",
        "entitlements",
    ];
    let hits: Vec<String> = paths
        .iter()
        .filter(|path| contains_any(&path.to_ascii_lowercase(), &needles))
        .cloned()
        .collect();
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "release-readiness",
        fired,
        reason: if fired {
            format!(
                "publish/signing/updater/bundle-config surface present: {} matching file(s)",
                hits.len()
            )
        } else {
            "checked publish/signing/updater/tauri.conf.json path signatures; zero hits".into()
        },
        evidence_paths: hits,
        unavailable_paths: Vec::new(),
    }
}

/// Evaluates the deterministic trigger for one of the five conditional
/// lenses against the frozen denominator's paths, reading bounded file
/// content under `root` only where a path signature alone is insufficient
/// (`resilience`, `platform-parity`). Returns `None` for any lens that is
/// not conditional (those are `Applicability::Always` and never gated by a
/// trigger).
pub fn evaluate_trigger(root: &Path, lens: &str, paths: &[String]) -> Option<TriggerEvaluation> {
    if !matches!(lens, "resilience" | "platform-parity") {
        return evaluate_with_head(lens, paths, &|_| Err(()));
    }
    let source = TriggerSource::new(root);
    if let Ok(source) = source {
        let evaluation = source.evaluate(lens, paths);
        if source.revalidate().is_ok() {
            return evaluation;
        }
    }
    // This compatibility API cannot return admission errors. Failed content
    // checks remain explicit unknown applicability, never checked-zero.
    evaluate_with_head(lens, paths, &|_| Err(()))
}

pub(crate) fn evaluate_with_head(
    lens: &str,
    paths: &[String],
    read_head: &impl Fn(&str) -> Result<(String, bool), ()>,
) -> Option<TriggerEvaluation> {
    match lens {
        "a11y" => Some(evaluate_a11y(paths)),
        "data-safety" => Some(evaluate_data_safety(paths)),
        "resilience" => Some(evaluate_resilience(paths, read_head)),
        "platform-parity" => Some(evaluate_platform_parity(paths, read_head)),
        "release-readiness" => Some(evaluate_release_readiness(paths)),
        _ => None,
    }
}

/// Evaluates every conditional lens's trigger at once (the plan-freeze use
/// case: decide, for each conditional lens, whether it belongs in the run).
pub fn evaluate_all_conditional_triggers(root: &Path, paths: &[String]) -> Vec<TriggerEvaluation> {
    let lenses = [
        "a11y",
        "data-safety",
        "resilience",
        "platform-parity",
        "release-readiness",
    ];
    if let Ok(source) = TriggerSource::new(root) {
        let evaluations = lenses
            .iter()
            .filter_map(|lens| source.evaluate(lens, paths))
            .collect();
        if source.revalidate().is_ok() {
            return evaluations;
        }
    }
    lenses
        .iter()
        .filter_map(|lens| evaluate_with_head(lens, paths, &|_| Err(())))
        .collect()
}
