//! Port of `skills/designer/engine/scripts/context-signals.mjs`: a cheap,
//! deterministic (well, "cheap" — one part is a live TCP probe and one part
//! shells out to `git`) signal gatherer for the bare `impeccable` no-argument
//! path. Never scores or ranks; just surfaces raw signals for the caller to
//! reason over.
//!
//! Not ported: the CLI wrapper (`cli()`/`invokedAsScript()`), which is pure
//! stdout/argv plumbing over `gather_signals` below.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::context::{extract_register, load_context, TargetOptions};
use super::critique_storage::get_critique_dir;

/// Is there code here at all, or just context files / an empty repo?
pub fn has_code(cwd: &Path) -> bool {
    if cwd.join("package.json").exists() {
        return true;
    }
    for d in ["src", "app", "pages", "site", "public", "components", "lib"] {
        if cwd.join(d).exists() {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct LatestCritique {
    pub slug: Option<String>,
    pub score: Option<f64>,
    pub p0: Option<f64>,
    pub p1: Option<f64>,
    pub timestamp: Option<String>,
    pub file: String,
}

/// The most recent critique snapshot across all targets. Filenames are
/// timestamp-prefixed (`<iso>__<slug>.md`), so a lexical sort is
/// chronological. Parses the small frontmatter for score + P0/P1 counts.
pub fn latest_critique(cwd: &Path, options: &TargetOptions) -> Option<LatestCritique> {
    let dir = get_critique_dir(cwd, options);
    if !dir.exists() {
        return None;
    }
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".md") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    if files.is_empty() {
        return None;
    }
    files.sort();
    let newest = files.last()?.clone();
    let text = std::fs::read_to_string(dir.join(&newest)).ok()?;
    let front = text.split("---").nth(1).unwrap_or("");
    let get = |k: &str| -> Option<String> {
        for line in front.split('\n') {
            let trimmed = line;
            if let Some(rest) = trimmed.strip_prefix(&format!("{k}:")) {
                return Some(rest.trim().to_string());
            }
        }
        None
    };
    let num = |v: Option<String>| -> Option<f64> { v.and_then(|s| s.parse::<f64>().ok()) };
    Some(LatestCritique {
        slug: get("slug"),
        score: num(get("score")),
        p0: num(get("p0")),
        p1: num(get("p1")),
        timestamp: get("timestamp"),
        file: to_posix_relative(&relative_path(cwd, &dir.join(&newest))),
    })
}

#[derive(Debug, Clone, Default)]
pub struct GitSignals {
    pub is_repo: bool,
    pub branch: Option<String>,
    pub base: Option<String>,
    pub changed_files: Vec<String>,
    pub changed_count: usize,
}

/// Branch + a scope hint: files changed vs the default branch, else working
/// tree. Every `git` invocation is best-effort: any failure (not a repo, no
/// git binary, detached HEAD, etc) degrades gracefully rather than erroring.
pub fn git_signals(cwd: &Path) -> GitSignals {
    let run = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).current_dir(cwd).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let run_raw = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).current_dir(cwd).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    };

    if run(&["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        return GitSignals::default();
    }
    let branch = run(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let mut base = None;
    for b in ["main", "master"] {
        if run(&["rev-parse", "--verify", "--quiet", b]).is_some() {
            base = Some(b.to_string());
            break;
        }
    }
    let diff_base = match (&base, &branch) {
        (Some(b), Some(br)) if br != b => Some(b.clone()),
        _ => None,
    };
    let from_diff = diff_base
        .as_ref()
        .and_then(|b| run(&["diff", "--name-only", &format!("{b}...HEAD")]));
    let from_status = run_raw(&["-c", "core.quotepath=false", "status", "--porcelain"]);

    let changed: Vec<String> = if let Some(diff) = from_diff.filter(|s| !s.is_empty()) {
        diff.split('\n').filter(|s| !s.is_empty()).map(String::from).collect()
    } else if let Some(status) = from_status.filter(|s| !s.is_empty()) {
        status
            .split("\r\n")
            .flat_map(|l| l.split('\n'))
            .filter(|s| !s.is_empty())
            .map(|l| {
                // porcelain lines are `XY PATH`: 2-char status + space, then
                // the path. Renames render as `old -> new`.
                let p = if l.len() >= 3 { &l[3..] } else { "" };
                match p.find(" -> ") {
                    Some(idx) => p[idx + 4..].to_string(),
                    None => p.to_string(),
                }
            })
            .collect()
    } else {
        vec![]
    };

    GitSignals {
        is_repo: true,
        branch,
        base: diff_base,
        changed_count: changed.len(),
        changed_files: changed.into_iter().take(50).collect(),
    }
}

const COMMON_DEV_PORTS: [u16; 7] = [4321, 3000, 5173, 5174, 8080, 8000, 4200];

#[derive(Debug, Clone, Default)]
pub struct DevServerSignals {
    pub running: bool,
    pub ports: Vec<u16>,
}

fn probe_port(port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Probes a short, fixed list of common local dev-server ports. Sequential
/// (the JS version parallelizes with `Promise.all`, but there's no shared
/// mutable state to race here, and the total worst case — 7 * 250ms — is
/// small and bounded).
pub fn dev_server_signals() -> DevServerSignals {
    let mut open: Vec<u16> = COMMON_DEV_PORTS
        .iter()
        .copied()
        .filter(|&p| probe_port(p, Duration::from_millis(250)))
        .collect();
    open.sort_unstable();
    DevServerSignals {
        running: !open.is_empty(),
        ports: open,
    }
}

const SCANNABLE_EXT: [&str; 9] = [
    "html", "htm", "css", "scss", "jsx", "tsx", "js", "ts", "vue",
];
const SCANNABLE_EXT2: [&str; 2] = ["svelte", "astro"];
const SOURCE_DIRS: [&str; 5] = ["src", "app", "components", "pages", "public"];

fn is_scannable_ext(ext: &str) -> bool {
    SCANNABLE_EXT.contains(&ext) || SCANNABLE_EXT2.contains(&ext)
}

#[derive(Debug, Clone)]
pub struct ScanTargets {
    pub targets: Vec<String>,
    pub via: Option<&'static str>,
}

/// Local paths the agent should point the bundled detector at — never a URL.
pub fn scan_targets(cwd: &Path, git: &GitSignals) -> ScanTargets {
    if git.is_repo && !git.changed_files.is_empty() {
        let changed: Vec<String> = git
            .changed_files
            .iter()
            .filter(|f| {
                Path::new(f)
                    .extension()
                    .map(|e| is_scannable_ext(&e.to_string_lossy().to_lowercase()))
                    .unwrap_or(false)
            })
            .filter(|f| cwd.join(f).exists())
            .cloned()
            .collect();
        if !changed.is_empty() {
            return ScanTargets {
                targets: changed.into_iter().take(50).collect(),
                via: Some("git-changes"),
            };
        }
    }
    let dirs: Vec<String> = SOURCE_DIRS
        .iter()
        .filter(|d| cwd.join(d).exists())
        .map(|d| d.to_string())
        .collect();
    if !dirs.is_empty() {
        return ScanTargets {
            targets: dirs,
            via: Some("source-dir"),
        };
    }
    if cwd.join("index.html").exists() {
        return ScanTargets {
            targets: vec!["index.html".to_string()],
            via: Some("html"),
        };
    }
    if has_code(cwd) {
        return ScanTargets {
            targets: vec![".".to_string()],
            via: Some("root"),
        };
    }
    ScanTargets {
        targets: vec![],
        via: None,
    }
}

#[derive(Debug, Clone)]
pub struct SetupSignals {
    pub has_product: bool,
    pub product_path: Option<String>,
    pub has_design: bool,
    pub design_path: Option<String>,
    pub has_code: bool,
    pub register: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GatheredSignals {
    pub setup: SetupSignals,
    pub critique_latest: Option<LatestCritique>,
    pub git: GitSignals,
    pub dev_server: DevServerSignals,
    pub scan: ScanTargets,
}

pub fn gather_signals(cwd: &Path) -> GatheredSignals {
    let options = TargetOptions::none();
    let ctx = load_context(cwd, &options);
    let git = git_signals(cwd);
    GatheredSignals {
        setup: SetupSignals {
            has_product: ctx.has_product,
            product_path: ctx.product_path.clone(),
            has_design: ctx.has_design,
            design_path: ctx.design_path.clone(),
            has_code: has_code(cwd),
            register: extract_register(ctx.product.as_deref()),
        },
        critique_latest: latest_critique(cwd, &options),
        scan: scan_targets(cwd, &git),
        git,
        dev_server: dev_server_signals(),
    }
}

fn relative_path(base: &Path, target: &Path) -> PathBuf {
    let base = lexical_abs(base);
    let target = lexical_abs(target);
    let base_comps: Vec<_> = base.components().collect();
    let target_comps: Vec<_> = target.components().collect();
    let mut i = 0;
    while i < base_comps.len() && i < target_comps.len() && base_comps[i] == target_comps[i] {
        i += 1;
    }
    let mut out = PathBuf::new();
    for _ in i..base_comps.len() {
        out.push("..");
    }
    for comp in &target_comps[i..] {
        out.push(comp.as_os_str());
    }
    out
}

fn lexical_abs(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push(comp);
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn to_posix_relative(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion_w2010_ctxsignals_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn has_code_true_for_package_json() {
        let dir = tmp_dir("has_code_pkg");
        fs::write(dir.join("package.json"), "{}").unwrap();
        assert!(has_code(&dir));
    }

    #[test]
    fn has_code_true_for_src_dir() {
        let dir = tmp_dir("has_code_src");
        fs::create_dir_all(dir.join("src")).unwrap();
        assert!(has_code(&dir));
    }

    #[test]
    fn has_code_false_for_empty_dir() {
        let dir = tmp_dir("has_code_empty");
        assert!(!has_code(&dir));
    }

    #[test]
    fn latest_critique_none_when_dir_missing() {
        let dir = tmp_dir("critique_missing");
        assert!(latest_critique(&dir, &TargetOptions::none()).is_none());
    }

    #[test]
    fn latest_critique_parses_frontmatter_of_newest_file() {
        let dir = tmp_dir("critique_latest");
        let critique_dir = dir.join(".impeccable/critique");
        fs::create_dir_all(&critique_dir).unwrap();
        fs::write(
            critique_dir.join("2026-01-01T00-00-00Z__old-slug.md"),
            "---\nscore: 50\np0: 2\np1: 1\ntimestamp: 2026-01-01T00-00-00Z\nslug: old-slug\n---\nold body",
        )
        .unwrap();
        fs::write(
            critique_dir.join("2026-02-01T00-00-00Z__new-slug.md"),
            "---\nscore: 90\np0: 0\np1: 2\ntimestamp: 2026-02-01T00-00-00Z\nslug: new-slug\n---\nnew body",
        )
        .unwrap();
        let latest = latest_critique(&dir, &TargetOptions::none()).unwrap();
        assert_eq!(latest.slug.as_deref(), Some("new-slug"));
        assert_eq!(latest.score, Some(90.0));
        assert_eq!(latest.p0, Some(0.0));
        assert_eq!(latest.p1, Some(2.0));
    }

    #[test]
    fn scan_targets_prefers_git_changes() {
        let dir = tmp_dir("scan_git");
        fs::write(dir.join("App.tsx"), "// x").unwrap();
        let git = GitSignals {
            is_repo: true,
            branch: Some("feature".into()),
            base: Some("main".into()),
            changed_files: vec!["App.tsx".to_string(), "README.md".to_string()],
            changed_count: 2,
        };
        let result = scan_targets(&dir, &git);
        assert_eq!(result.via, Some("git-changes"));
        assert_eq!(result.targets, vec!["App.tsx".to_string()]);
    }

    #[test]
    fn scan_targets_falls_back_to_source_dir() {
        let dir = tmp_dir("scan_srcdir");
        fs::create_dir_all(dir.join("src")).unwrap();
        let git = GitSignals::default();
        let result = scan_targets(&dir, &git);
        assert_eq!(result.via, Some("source-dir"));
        assert_eq!(result.targets, vec!["src".to_string()]);
    }

    #[test]
    fn scan_targets_falls_back_to_index_html() {
        let dir = tmp_dir("scan_html");
        fs::write(dir.join("index.html"), "<html></html>").unwrap();
        let git = GitSignals::default();
        let result = scan_targets(&dir, &git);
        assert_eq!(result.via, Some("html"));
        assert_eq!(result.targets, vec!["index.html".to_string()]);
    }

    #[test]
    fn scan_targets_none_for_empty_project() {
        let dir = tmp_dir("scan_none");
        let git = GitSignals::default();
        let result = scan_targets(&dir, &git);
        assert_eq!(result.via, None);
        assert!(result.targets.is_empty());
    }

    #[test]
    fn git_signals_not_a_repo() {
        let dir = tmp_dir("git_not_repo");
        let result = git_signals(&dir);
        assert!(!result.is_repo);
        assert!(result.branch.is_none());
        assert!(result.changed_files.is_empty());
    }

    #[test]
    fn gather_signals_end_to_end_smoke() {
        let dir = tmp_dir("gather_smoke");
        fs::write(dir.join("PRODUCT.md"), "# Demo\n\n## Register\nbrand\n").unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        let signals = gather_signals(&dir);
        assert!(signals.setup.has_product);
        assert_eq!(signals.setup.register.as_deref(), Some("brand"));
        assert!(signals.setup.has_code);
        assert!(!signals.git.is_repo);
        assert_eq!(signals.scan.via, Some("source-dir"));
    }
}
