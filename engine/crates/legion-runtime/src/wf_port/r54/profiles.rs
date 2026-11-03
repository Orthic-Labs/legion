//! Port of `qa.mjs`'s zombie-profile guard: `PROFILE_PREFIXES` and `sweepStaleProfiles`
//! (lines 149-196).

pub const PROFILE_PREFIXES: [&str; 2] = ["qa-browser-profile-", "qa-cdp-profile-"];

/// One entry of the `.cache` directory listing `sweepStaleProfiles` walks.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub mtime_ms: f64,
}

/// Abstracts `readdirSync`/`statSync`/`rmSync` on `.cache` so the sweep is testable without disk
/// I/O. `remove` is only called for entries this function decides to delete.
pub trait ProfileDir {
    #[allow(clippy::result_unit_err)]
    fn list(&self) -> Result<Vec<DirEntry>, ()>;
    fn remove(&mut self, name: &str);
}

/// Port of `sweepStaleProfiles({ olderThanMs, now })` (qa.mjs lines 178-196). `active` mirrors
/// the in-process `_profiles` set: entries the current run still owns are never swept, matching
/// `if (_profiles.has(target)) continue;`. Returns the count removed (0 on a missing `.cache`,
/// matching the JS `catch { return 0; }`).
pub fn sweep_stale_profiles(
    dir: &mut dyn ProfileDir,
    older_than_ms: f64,
    now: f64,
    active: &[String],
) -> u32 {
    let entries = match dir.list() {
        Ok(e) => e,
        Err(()) => return 0,
    };
    let mut removed = 0u32;
    for entry in entries {
        if !entry.is_dir || entry.is_symlink {
            continue;
        }
        if !PROFILE_PREFIXES.iter().any(|p| entry.name.starts_with(p)) {
            continue;
        }
        if active.iter().any(|a| a == &entry.name) {
            continue;
        }
        if now - entry.mtime_ms < older_than_ms {
            continue;
        }
        dir.remove(&entry.name);
        removed += 1;
    }
    removed
}

/// Default cutoff used by the implicit sweep at every `wireCleanup()` startup (qa.mjs line 178:
/// `olderThanMs = 60 * 60_000`).
pub const STARTUP_OLDER_THAN_MS: f64 = 60.0 * 60_000.0;

/// Cutoff used by the explicit `--sweep` CLI path (qa.mjs line 735: `5 * 60_000`).
pub const EXPLICIT_SWEEP_OLDER_THAN_MS: f64 = 5.0 * 60_000.0;
