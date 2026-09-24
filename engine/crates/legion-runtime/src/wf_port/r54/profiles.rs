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
    fn list(&self) -> Result<Vec<DirEntry>, ()>;
    fn remove(&mut self, name: &str);
}

/// Port of `sweepStaleProfiles({ olderThanMs, now })` (qa.mjs lines 178-196). `active` mirrors
/// the in-process `_profiles` set: entries the current run still owns are never swept, matching
/// `if (_profiles.has(target)) continue;`. Returns the count removed (0 on a missing `.cache`,
/// matching the JS `catch { return 0; }`).
pub fn sweep_stale_profiles(dir: &mut dyn ProfileDir, older_than_ms: f64, now: f64, active: &[String]) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDir {
        entries: Vec<DirEntry>,
        removed: Vec<String>,
        fail_list: bool,
    }
    impl ProfileDir for FakeDir {
        fn list(&self) -> Result<Vec<DirEntry>, ()> {
            if self.fail_list { Err(()) } else { Ok(self.entries.clone()) }
        }
        fn remove(&mut self, name: &str) {
            self.removed.push(name.to_string());
        }
    }

    fn entry(name: &str, mtime_ms: f64) -> DirEntry {
        DirEntry { name: name.to_string(), is_dir: true, is_symlink: false, mtime_ms }
    }

    #[test]
    fn missing_cache_dir_returns_zero() {
        let mut dir = FakeDir { entries: vec![], removed: vec![], fail_list: true };
        assert_eq!(sweep_stale_profiles(&mut dir, 60_000.0, 1_000_000.0, &[]), 0);
    }

    #[test]
    fn sweeps_old_profile_directories() {
        let mut dir = FakeDir { entries: vec![entry("qa-browser-profile-1", 0.0)], removed: vec![], fail_list: false };
        let removed = sweep_stale_profiles(&mut dir, 60_000.0, 1_000_000.0, &[]);
        assert_eq!(removed, 1);
        assert_eq!(dir.removed, vec!["qa-browser-profile-1".to_string()]);
    }

    #[test]
    fn leaves_fresh_profiles_alone() {
        let mut dir = FakeDir { entries: vec![entry("qa-cdp-profile-2", 999_000.0)], removed: vec![], fail_list: false };
        let removed = sweep_stale_profiles(&mut dir, 60_000.0, 1_000_000.0, &[]);
        assert_eq!(removed, 0);
        assert!(dir.removed.is_empty());
    }

    #[test]
    fn skips_active_profiles_even_if_old() {
        let mut dir = FakeDir { entries: vec![entry("qa-cdp-profile-3", 0.0)], removed: vec![], fail_list: false };
        let removed = sweep_stale_profiles(&mut dir, 60_000.0, 1_000_000.0, &["qa-cdp-profile-3".to_string()]);
        assert_eq!(removed, 0);
    }

    #[test]
    fn ignores_non_matching_and_non_directory_entries() {
        let mut dir = FakeDir {
            entries: vec![
                entry("unrelated-dir", 0.0),
                DirEntry { name: "qa-browser-profile-file".into(), is_dir: false, is_symlink: false, mtime_ms: 0.0 },
                DirEntry { name: "qa-browser-profile-link".into(), is_dir: true, is_symlink: true, mtime_ms: 0.0 },
            ],
            removed: vec![],
            fail_list: false,
        };
        let removed = sweep_stale_profiles(&mut dir, 60_000.0, 1_000_000.0, &[]);
        assert_eq!(removed, 0);
    }

    #[test]
    fn cutoff_constants_match_js() {
        assert_eq!(STARTUP_OLDER_THAN_MS, 3_600_000.0);
        assert_eq!(EXPLICIT_SWEEP_OLDER_THAN_MS, 300_000.0);
    }
}
