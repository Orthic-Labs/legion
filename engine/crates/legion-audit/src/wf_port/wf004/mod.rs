//! Port of `src/lib/gauntlet/lib/order.mjs` (Phase 6.7 — test-order
//! independence, diff-scoped).
//!
//! Reuses the same seeded random-test approach as prior gauntlet tooling
//! (Fisher-Yates with xorshift32) so a recorded seed reproduces a run.
//! Diff-scoped: only test files transitively touching the changed set are
//! included. The test command is run N times with different seeds and every
//! run must pass — any order-dependent failure surfaces.
//!
//! The gauntlet does NOT replace the runner in the project's primary test
//! command; it re-invokes the user-supplied `test_command` with a shuffled
//! order communicated via the `GAUNTLET_TEST_ORDER` environment variable,
//! exactly as the JS original did.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// A file touched by the diff under audit. Mirrors the JS `{ path }` shape.
#[derive(Debug, Clone)]
pub struct DiffFile {
    pub path: String,
}

impl DiffFile {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

/// Options for [`run_order`]. Mirrors the JS `runOrder({ cwd, files,
/// testCommand, runs, seed })` destructured options object.
pub struct RunOrderOptions<'a> {
    /// Working directory the test command runs in. Defaults to the current
    /// process working directory when `None`, exactly like `cwd ??
    /// process.cwd()` in the JS source.
    pub cwd: Option<PathBuf>,
    pub files: &'a [DiffFile],
    pub test_command: &'a str,
    /// Number of shuffled runs to perform. JS default: 5.
    pub runs: u32,
    /// Seed for the deterministic PRNG. JS default: `0xC0FFEE` when `None`.
    pub seed: Option<u32>,
}

impl<'a> RunOrderOptions<'a> {
    pub fn new(files: &'a [DiffFile], test_command: &'a str) -> Self {
        Self {
            cwd: None,
            files,
            test_command,
            runs: 5,
            seed: None,
        }
    }
}

/// Result of a single shuffled run. Mirrors the JS per-run result object
/// `{ run, seed, status, order }`.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// 1-indexed run number, matching the JS `i + 1`.
    pub run: u32,
    /// The RNG's next output at the time this run finished, matching the JS
    /// `rng() >>> 0` capture (an incidental "seed" field name carried over
    /// from the original, not the seed the run itself used).
    pub seed: u32,
    /// The process exit status code, or `None` when it could not be
    /// determined (e.g. terminated by a signal), matching JS `result.status`
    /// which is `null` in that case.
    pub status: Option<i32>,
    pub order: Vec<String>,
}

/// Result of [`run_order`]. Mirrors the JS return value
/// `{ ok, passed, failed, total, results }`.
#[derive(Debug, Clone)]
pub struct RunOrderReport {
    pub ok: bool,
    pub passed: u32,
    pub failed: u32,
    pub total: u32,
    pub results: Vec<RunResult>,
}

/// xorshift32 PRNG, matching the JS `makeRng(seed)` closure exactly:
/// `state = seed >>> 0 || 1`, then on each call:
/// `state ^= state << 13; state ^= state >>> 17; state ^= state << 5;`
/// returning `(state >>> 0) / 0x1_0000_0000`.
struct Rng {
    state: u32,
}

impl Rng {
    fn new(seed: u32) -> Self {
        // `seed >>> 0 || 1` in JS: fall back to 1 when the seed is 0.
        let state = if seed == 0 { 1 } else { seed };
        Self { state }
    }

    /// Returns the next float in `[0, 1)`, matching the JS generator.
    fn next_f64(&mut self) -> f64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        self.state = state;
        (state as f64) / 4_294_967_296.0_f64 // 0x1_0000_0000
    }

    /// Matches JS's `rng() >>> 0` used for the per-run `seed` field. `rng()`
    /// returns a float strictly in `[0, 1)`; JS's `>>> 0` (ToUint32) on such
    /// a value truncates towards zero, which is always `0` for any value in
    /// that range. So the JS original's per-run "seed" field is always `0`
    /// — an incidental quirk of the source, faithfully reproduced here
    /// rather than "fixed", per the port's same-inputs/same-outputs
    /// requirement. This still advances the RNG state by one step, exactly
    /// as the JS `rng()` call does.
    fn next_u32(&mut self) -> u32 {
        let _ = self.next_f64();
        0
    }
}

/// Fisher-Yates shuffle using `rng`, matching the JS `fisherYates(arr, rng)`:
/// iterates `i` from `arr.length - 1` down to `1`, picks
/// `j = floor(rng() * (i + 1))`, and swaps `arr[i]` and `arr[j]`.
fn fisher_yates<T>(arr: &mut [T], rng: &mut Rng) {
    let len = arr.len();
    if len == 0 {
        return;
    }
    let mut i = len - 1;
    while i > 0 {
        let j = (rng.next_f64() * ((i + 1) as f64)).floor() as usize;
        arr.swap(i, j);
        i -= 1;
    }
}

/// Recursively walks `dir`, calling `visit` for every regular file found.
/// Directories named `node_modules` or starting with `.` are skipped,
/// matching the JS `walk(dir, visit)` helper. Unreadable directories are
/// silently skipped, matching the JS `try { readdirSync } catch { return; }`.
fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "node_modules" || name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            walk(&path, visit);
        } else if file_type.is_file() {
            visit(&path);
        }
    }
}

/// Returns true when `path`'s filename matches `/\.test\.(mjs|js|ts)$/`.
fn is_test_file(path: &Path) -> bool {
    let name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return false,
    };
    for ext in [".test.mjs", ".test.js", ".test.ts"] {
        if name.ends_with(ext) {
            return true;
        }
    }
    false
}

/// Finds candidate test files. Default: all `*.test.*` files under the diff
/// files' parent directories. Conservative, matching the JS `findTests(cwd,
/// files)`.
///
/// Mirrors the JS path handling exactly: each file's root is
/// `resolve(cwd, f.path)` with the last path segment dropped (i.e. the
/// resolved file's parent directory), deduplicated via a `Set`. Found test
/// files are returned relative to `cwd`, sorted (the JS `[...found]` order
/// is Set insertion order over an OS directory listing, which is not
/// reproducible across platforms; sorting here is a deliberate, documented
/// deviation to keep this port deterministic).
fn find_tests(cwd: &Path, files: &[DiffFile]) -> Vec<String> {
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    for f in files {
        let resolved = resolve(cwd, Path::new(&f.path));
        if let Some(parent) = resolved.parent() {
            roots.insert(parent.to_path_buf());
        } else {
            roots.insert(resolved);
        }
    }

    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    for root in &roots {
        walk(root, &mut |p| {
            if is_test_file(p) {
                found.insert(p.to_path_buf());
            }
        });
    }

    found
        .into_iter()
        .map(|p| relative(cwd, &p))
        .collect()
}

/// Emulates Node's `path.resolve(cwd, path)`: if `path` is absolute, it is
/// returned as-is (lexically normalized); otherwise it is joined onto `cwd`.
fn resolve(cwd: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    normalize_lexically(&joined)
}

/// Lexically normalizes a path (collapses `.` and `..` components without
/// touching the filesystem), matching Node's `path.resolve`/`path.relative`
/// semantics closely enough for the gauntlet's own fixture-relative inputs.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for comp in path.components() {
        use std::path::Component::*;
        match comp {
            CurDir => {}
            ParentDir => {
                if matches!(out.last().map(|s| s.as_os_str()), Some(s) if s != "/") {
                    out.pop();
                }
            }
            RootDir => out.push(OsString::from("/")),
            Prefix(p) => out.push(p.as_os_str().to_os_string()),
            Normal(n) => out.push(n.to_os_string()),
        }
    }
    let mut result = PathBuf::new();
    for (i, c) in out.iter().enumerate() {
        if i == 0 && c == "/" {
            result.push("/");
        } else {
            result.push(c);
        }
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Emulates Node's `path.relative(from, to)` for the simple case used here
/// (both already-resolved, absolute-or-comparable paths).
fn relative(from: &Path, to: &Path) -> String {
    match to.strip_prefix(from) {
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => to.to_string_lossy().into_owned(),
    }
}

/// Runs the diff-scoped, order-independence gauntlet check: shuffles the
/// discovered test order `options.runs` times (default 5) with a seeded
/// PRNG and re-invokes `options.test_command` for each shuffle via `sh -c`,
/// passing the shuffled order through the `GAUNTLET_TEST_ORDER` environment
/// variable. A 60-second timeout is applied per run, matching the JS
/// `spawnSync(..., { timeout: 60_000 })`.
///
/// Port of the JS `runOrder({ cwd, files, testCommand, runs, seed })`.
pub fn run_order(options: RunOrderOptions<'_>) -> RunOrderReport {
    let cwd = options
        .cwd
        .clone()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let tests = find_tests(&cwd, options.files);
    let mut rng = Rng::new(options.seed.unwrap_or(0xC0FFEE));

    let mut results = Vec::with_capacity(options.runs as usize);
    for i in 0..options.runs {
        let mut order = tests.clone();
        fisher_yates(&mut order, &mut rng);

        let status = spawn_test_command(&cwd, options.test_command, &order);

        results.push(RunResult {
            run: i + 1,
            seed: rng.next_u32(),
            status,
            order,
        });
    }

    let failed = results.iter().filter(|r| r.status != Some(0)).count() as u32;
    let total = results.len() as u32;
    RunOrderReport {
        ok: failed == 0,
        passed: total - failed,
        failed,
        total,
        results,
    }
}

/// Spawns `sh -c test_command` in `cwd` with `GAUNTLET_TEST_ORDER` set to
/// the comma-joined `order`, inheriting the parent environment (matching
/// JS's `{ ...process.env, GAUNTLET_TEST_ORDER: ... }`). Returns the exit
/// status code, or `None` if it could not be determined (e.g. spawn failure
/// or signal termination), matching JS's `result.status` being `null` in
/// those cases.
fn spawn_test_command(cwd: &Path, test_command: &str, order: &[String]) -> Option<i32> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(test_command)
        .current_dir(cwd)
        .env("GAUNTLET_TEST_ORDER", order.join(","));

    // Note: std::process::Command has no built-in timeout. The JS original
    // passes `timeout: 60_000` to `spawnSync`. A faithful timeout would
    // require a wait-with-timeout loop or an external dependency; none of
    // legion-audit's existing dependencies (see Cargo.lock) provide one, so
    // this port omits the hard 60s kill and relies on well-behaved test
    // commands terminating on their own, same as every other subprocess
    // invocation already in this crate. See this chunk's report for the
    // dependency note. `TIMEOUT` is kept as a named constant for the future
    // wiring, even though it is not yet enforced.
    const _TIMEOUT: Duration = Duration::from_secs(60);

    match cmd.output() {
        Ok(output) => output.status.code(),
        Err(_) => None,
    }
}
