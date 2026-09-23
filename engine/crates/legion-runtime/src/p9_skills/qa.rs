//! Packet P9-skill-scripts: Rust port of `skills/qa/scripts/{qa,qa-shot,qa-functional}.mjs`.
//!
//! All three files are an identical 7-line dispatcher differing only in which engine script
//! they delegate to under `src/lib/qa-engine/`. That dispatcher (resolve the engine script path
//! relative to the repo root, spawn `node` on it with the passed-through args, forward its exit
//! status) is the only logic that lives inside `skills/qa/**`; it is ported below verbatim as
//! `resolve_engine_script_path` (pure path logic) plus `EngineDispatch` (the argv/exit-status
//! contract). The engine scripts themselves (`src/lib/qa-engine/qa.mjs`, `qa-shot.mjs`,
//! `qa-functional.mjs`) live outside `skills/**` and are out of this packet's scope — see the
//! packet report.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QaVerb {
    Qa,
    QaShot,
    QaFunctional,
}

impl QaVerb {
    /// The engine script each dispatcher script forwards to, relative to the repo root
    /// (`resolve(dirname(fileURLToPath(import.meta.url)), "../../..")` from
    /// `skills/qa/scripts/<name>.mjs`, i.e. the repo root, then `src/lib/qa-engine/<name>.mjs`).
    pub fn engine_relative_path(self) -> &'static str {
        match self {
            QaVerb::Qa => "src/lib/qa-engine/qa.mjs",
            QaVerb::QaShot => "src/lib/qa-engine/qa-shot.mjs",
            QaVerb::QaFunctional => "src/lib/qa-engine/qa-functional.mjs",
        }
    }
}

/// The command a caller should spawn to reproduce `spawnSync(process.execPath, [enginePath,
/// ...args], { stdio: "inherit", shell: false })`, given the repo root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDispatch {
    pub program: String,
    pub args: Vec<String>,
}

pub fn build_dispatch(verb: QaVerb, repo_root: &str, extra_args: &[String]) -> EngineDispatch {
    let engine_path = format!("{}/{}", repo_root.trim_end_matches('/'), verb.engine_relative_path());
    let mut args = vec![engine_path];
    args.extend(extra_args.iter().cloned());
    EngineDispatch {
        program: "node".to_string(),
        args,
    }
}

/// Mirrors `process.exit(result.status ?? 1)`: an engine process that exits without a status
/// (e.g. killed by a signal) is reported as exit code 1.
pub fn resolve_exit_code(child_status: Option<i32>) -> i32 {
    child_status.unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_verb_resolves_to_its_engine_script() {
        assert_eq!(QaVerb::Qa.engine_relative_path(), "src/lib/qa-engine/qa.mjs");
        assert_eq!(QaVerb::QaShot.engine_relative_path(), "src/lib/qa-engine/qa-shot.mjs");
        assert_eq!(
            QaVerb::QaFunctional.engine_relative_path(),
            "src/lib/qa-engine/qa-functional.mjs"
        );
    }

    #[test]
    fn build_dispatch_forwards_args_after_engine_path() {
        let dispatch = build_dispatch(
            QaVerb::QaShot,
            "/repo",
            &["--url".to_string(), "http://localhost".to_string()],
        );
        assert_eq!(dispatch.program, "node");
        assert_eq!(
            dispatch.args,
            vec![
                "/repo/src/lib/qa-engine/qa-shot.mjs".to_string(),
                "--url".to_string(),
                "http://localhost".to_string(),
            ]
        );
    }

    #[test]
    fn missing_status_defaults_to_exit_one() {
        assert_eq!(resolve_exit_code(None), 1);
        assert_eq!(resolve_exit_code(Some(0)), 0);
        assert_eq!(resolve_exit_code(Some(2)), 2);
    }
}
