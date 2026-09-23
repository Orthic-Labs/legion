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

use std::path::Path;

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
}

/// Bound on how many bytes of any one file are scanned for a content-based
/// trigger signature (`cfg(target_os`, sidecar/child-process spawn sites).
/// Kept small: triggers only need to know a signature is present anywhere
/// in the file, not to read the whole file.
const CONTENT_SCAN_CAP_BYTES: usize = 64 * 1024;

fn read_head(root: &Path, path: &str) -> Option<String> {
    let full = root.join(path);
    let bytes = std::fs::read(full).ok()?;
    let capped = &bytes[..bytes.len().min(CONTENT_SCAN_CAP_BYTES)];
    Some(String::from_utf8_lossy(capped).into_owned())
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
    }
}

/// `data-safety`: fires on migration/SQL/ORM/storage/telemetry surfaces in
/// scope, per `manual.md` line 273.
fn evaluate_data_safety(paths: &[String]) -> TriggerEvaluation {
    let needles = [
        "migration", "migrations", ".sql", "/schema", "schema.rs", "schema.ts", "schema.py",
        "localstorage", "asyncstorage", "sqlite", "keychain", "keystore", "telemetry",
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
    }
}

/// `resilience`: fires on sidecar/child-process/server/queue code, per
/// `manual.md` line 274. Path signature first (cheap), then a bounded
/// content scan on plausible source files for a spawn/Command site — the
/// path alone under-fires ("server.rs" is common but a raw spawn call
/// inside an unrelated file would be missed by path alone).
fn evaluate_resilience(root: &Path, paths: &[String]) -> TriggerEvaluation {
    let path_needles = ["sidecar", "child_process", "daemon", "worker", "queue", "/server"];
    let mut hits: Vec<String> = paths
        .iter()
        .filter(|path| contains_any(&path.to_ascii_lowercase(), &path_needles))
        .cloned()
        .collect();
    let content_extensions = [".rs", ".ts", ".tsx", ".js", ".py"];
    let content_needles = ["Command::new(", "spawn_sidecar", "child_process.spawn", "subprocess.Popen"];
    for path in paths {
        if hits.contains(path) || !has_extension(path, &content_extensions) {
            continue;
        }
        if let Some(content) = read_head(root, path) {
            if content_needles.iter().any(|needle| content.contains(needle)) {
                hits.push(path.clone());
            }
        }
    }
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "resilience",
        fired,
        reason: if fired {
            format!("sidecar/child-process/server/queue code present: {} matching file(s)", hits.len())
        } else {
            "checked sidecar/child-process/server/queue path and spawn-site signatures; zero hits".into()
        },
        evidence_paths: hits,
    }
}

/// `platform-parity`: fires on `cfg(target_os` (Rust) or `usePlatform`
/// (TS/JS) content signatures, per `manual.md` line 275.
fn evaluate_platform_parity(root: &Path, paths: &[String]) -> TriggerEvaluation {
    let mut hits = Vec::new();
    for path in paths {
        let is_rust = has_extension(path, &[".rs"]);
        let is_ts = has_extension(path, &[".ts", ".tsx", ".js", ".jsx"]);
        if !is_rust && !is_ts {
            continue;
        }
        if let Some(content) = read_head(root, path) {
            let matched = (is_rust && content.contains("cfg(target_os"))
                || (is_ts && content.contains("usePlatform"));
            if matched {
                hits.push(path.clone());
            }
        }
    }
    let fired = !hits.is_empty();
    TriggerEvaluation {
        lens: "platform-parity",
        fired,
        reason: if fired {
            format!("cfg(target_os or usePlatform present: {} matching file(s)", hits.len())
        } else {
            "checked cfg(target_os / usePlatform content signature across .rs/.ts/.tsx/.js/.jsx; zero hits".into()
        },
        evidence_paths: hits,
    }
}

/// `release-readiness`: fires on publish/signing/updater scripts or
/// `tauri.conf.json` bundle config, per `manual.md` line 276.
fn evaluate_release_readiness(paths: &[String]) -> TriggerEvaluation {
    let needles = [
        "tauri.conf", "release", "sign", "notariz", "installer", "updater", "entitlements",
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
    }
}

/// Evaluates the deterministic trigger for one of the five conditional
/// lenses against the frozen denominator's paths, reading bounded file
/// content under `root` only where a path signature alone is insufficient
/// (`resilience`, `platform-parity`). Returns `None` for any lens that is
/// not conditional (those are `Applicability::Always` and never gated by a
/// trigger).
pub fn evaluate_trigger(root: &Path, lens: &str, paths: &[String]) -> Option<TriggerEvaluation> {
    match lens {
        "a11y" => Some(evaluate_a11y(paths)),
        "data-safety" => Some(evaluate_data_safety(paths)),
        "resilience" => Some(evaluate_resilience(root, paths)),
        "platform-parity" => Some(evaluate_platform_parity(root, paths)),
        "release-readiness" => Some(evaluate_release_readiness(paths)),
        _ => None,
    }
}

/// Evaluates every conditional lens's trigger at once (the plan-freeze use
/// case: decide, for each conditional lens, whether it belongs in the run).
pub fn evaluate_all_conditional_triggers(root: &Path, paths: &[String]) -> Vec<TriggerEvaluation> {
    ["a11y", "data-safety", "resilience", "platform-parity", "release-readiness"]
        .iter()
        .filter_map(|lens| evaluate_trigger(root, lens, paths))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Dependency-free scratch directory (no `tempfile` crate): a unique
    /// subdirectory under `std::env::temp_dir()`, cleaned up on drop.
    struct ScratchDir(PathBuf);
    impl ScratchDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "legion-audit-triggers-test-{}-{}-{id}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write(root: &Path, rel: &str, content: &str) {
        let full = root.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    #[test]
    fn a11y_fires_on_jsx_and_not_otherwise() {
        let paths = vec!["src/App.jsx".to_string()];
        let evaluation = evaluate_trigger(Path::new("."), "a11y", &paths).unwrap();
        assert!(evaluation.fired);
        assert_eq!(evaluation.evidence_paths, vec!["src/App.jsx".to_string()]);

        let empty: Vec<String> = vec!["src/lib.rs".to_string()];
        let evaluation = evaluate_trigger(Path::new("."), "a11y", &empty).unwrap();
        assert!(!evaluation.fired);
        assert!(evaluation.reason.contains("zero hits"));
    }

    #[test]
    fn platform_parity_needs_content_signature_not_just_extension() {
        let dir = ScratchDir::new();
        write(dir.path(), "src/os.rs", "fn plain() {}\n");
        write(dir.path(), "src/os2.rs", "#[cfg(target_os = \"macos\")]\nfn mac() {}\n");
        let paths = vec!["src/os.rs".to_string(), "src/os2.rs".to_string()];
        let evaluation = evaluate_trigger(dir.path(), "platform-parity", &paths).unwrap();
        assert!(evaluation.fired);
        assert_eq!(evaluation.evidence_paths, vec!["src/os2.rs".to_string()]);
    }

    #[test]
    fn resilience_fires_on_spawn_site_content() {
        let dir = ScratchDir::new();
        write(dir.path(), "src/run.rs", "std::process::Command::new(\"x\");\n");
        let paths = vec!["src/run.rs".to_string()];
        let evaluation = evaluate_trigger(dir.path(), "resilience", &paths).unwrap();
        assert!(evaluation.fired);
    }

    #[test]
    fn non_conditional_lens_has_no_trigger() {
        assert!(evaluate_trigger(Path::new("."), "correctness", &[]).is_none());
    }

    #[test]
    fn evaluate_all_covers_exactly_the_five_conditional_lenses() {
        let dir = ScratchDir::new();
        let evaluations = evaluate_all_conditional_triggers(dir.path(), &[]);
        let lenses: Vec<&str> = evaluations.iter().map(|evaluation| evaluation.lens).collect();
        assert_eq!(
            lenses,
            vec!["a11y", "data-safety", "resilience", "platform-parity", "release-readiness"]
        );
        assert!(evaluations.iter().all(|evaluation| !evaluation.fired));
    }
}
