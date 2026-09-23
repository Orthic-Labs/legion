//! Faithful Rust port of `src/lib/gauntlet/lib/order.mjs`.
//!
//! Test-order independence, diff-scoped. Reuses the same seeded
//! xorshift32/Fisher-Yates approach as the JS implementation so a recorded
//! seed reproduces a run. Runs `test_command` `runs` times with a
//! different shuffled test order (communicated via `GAUNTLET_TEST_ORDER`)
//! and requires every run to pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::diff::DiffFile;

pub struct Xorshift32 {
    state: u32,
}

impl Xorshift32 {
    pub fn new(seed: u32) -> Self {
        Xorshift32 {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Returns a float in [0, 1), matching `rng()` in order.mjs.
    pub fn next_f64(&mut self) -> f64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        self.state = state;
        (state as f64) / 4_294_967_296.0 // 0x1_0000_0000
    }
}

pub fn fisher_yates<T>(arr: &mut Vec<T>, rng: &mut Xorshift32) {
    let len = arr.len();
    if len == 0 {
        return;
    }
    for i in (1..len).rev() {
        let j = (rng.next_f64() * ((i + 1) as f64)).floor() as usize;
        arr.swap(i, j);
    }
}

/// `findTests(cwd, files)` — default test discovery: all `*.test.(mjs|js|ts)`
/// files under the diff's changed directories.
fn find_tests(cwd: &Path, files: &[DiffFile]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    for f in files {
        let abs = cwd.join(&f.path);
        if let Some(parent) = abs.parent() {
            roots.insert(parent.to_path_buf());
        }
    }
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    for root in &roots {
        walk(root, &mut found);
    }
    found
        .into_iter()
        .filter_map(|p| p.strip_prefix(cwd).ok().map(|r| r.to_string_lossy().into_owned()))
        .collect()
}

fn walk(dir: &Path, found: &mut std::collections::BTreeSet<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.as_ref() == "node_modules" || name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else if is_test_file(&name_str) {
            found.insert(path);
        }
    }
}

/// Matches `/\.test\.(mjs|js|ts)$/`.
fn is_test_file(name: &str) -> bool {
    for ext in [".test.mjs", ".test.js", ".test.ts"] {
        if name.ends_with(ext) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OrderRunResult {
    pub run: usize,
    pub seed: u32,
    pub status: Option<i32>,
    pub order: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OrderLayer {
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
    pub ok: bool,
    pub results: Vec<OrderRunResult>,
}

pub struct RunOrderOptions<'a> {
    pub cwd: &'a Path,
    pub files: &'a [DiffFile],
    pub test_command: &'a str,
    pub runs: usize,
    pub seed: Option<u32>,
}

/// Mirrors `runOrder({ cwd, files, testCommand, runs, seed })`.
pub fn run_order(opts: RunOrderOptions<'_>) -> OrderLayer {
    let tests = find_tests(opts.cwd, opts.files);
    let mut rng = Xorshift32::new(opts.seed.unwrap_or(0xC0FFEE));
    let mut results = Vec::with_capacity(opts.runs);
    for i in 0..opts.runs {
        let mut order = tests.clone();
        fisher_yates(&mut order, &mut rng);
        let output = Command::new("sh")
            .arg("-c")
            .arg(opts.test_command)
            .current_dir(opts.cwd)
            .env("GAUNTLET_TEST_ORDER", order.join(","))
            .output();
        let status = output.as_ref().ok().and_then(|o| o.status.code());
        let seed_after = (rng.next_f64() * 4_294_967_296.0) as u32;
        results.push(OrderRunResult {
            run: i + 1,
            seed: seed_after,
            status,
            order,
        });
    }
    let failed = results.iter().filter(|r| r.status != Some(0)).count();
    OrderLayer {
        passed: results.len() - failed,
        failed,
        total: results.len(),
        ok: failed == 0,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xorshift32_is_deterministic_for_seed() {
        let mut a = Xorshift32::new(0xC0FFEE);
        let mut b = Xorshift32::new(0xC0FFEE);
        for _ in 0..5 {
            assert_eq!(a.next_f64(), b.next_f64());
        }
    }

    #[test]
    fn fisher_yates_is_a_permutation() {
        let mut rng = Xorshift32::new(42);
        let mut v: Vec<i32> = (0..10).collect();
        fisher_yates(&mut v, &mut rng);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..10).collect::<Vec<_>>());
    }
}
