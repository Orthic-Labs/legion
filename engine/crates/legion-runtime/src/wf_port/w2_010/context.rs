//! Port of `skills/designer/engine/scripts/context.mjs`'s deterministic
//! context-resolution core: PRODUCT.md/DESIGN.md discovery, monorepo
//! workspace-root detection, and the `## Register` extractor.
//!
//! Faithfully ported:
//!   - `resolveContextDir` / `loadContext` / `resolveProjectRoot`
//!   - `resolveTargetSelection` / `discoverTargetCandidates` and the whole
//!     workspace-pattern-matching machinery it depends on
//!   - `extractRegister`
//!
//! Deliberately NOT ported (documented gap, see `w2_010.md`):
//!   - The CLI entry point (`cli()`, arg parsing/printing, process exit codes)
//!     — that's I/O plumbing over this module's data, not algorithm.
//!   - The skill self-update check (`computeUpdateDirective` and friends):
//!     it polls an external network host (`designer.style`) for a newer
//!     skill version and caches the result under the user's home directory.
//!     That's a product/network concern orthogonal to context resolution,
//!     and Membrane/Blueprint-style external calls are explicitly out of
//!     scope for this port.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

const PRODUCT_NAMES: [&str; 3] = ["PRODUCT.md", "Product.md", "product.md"];
const DESIGN_NAMES: [&str; 3] = ["DESIGN.md", "Design.md", "design.md"];
const FALLBACK_DIRS: [&str; 2] = [".agents/context", "docs"];
const MONOREPO_MARKER_FILES: [&str; 4] =
    ["pnpm-workspace.yaml", "turbo.json", "nx.json", "lerna.json"];
const MONOREPO_FALLBACK_PROJECT_DIRS: [&str; 2] = ["apps", "packages"];

fn is_ignored_workspace_discovery_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "node_modules"
                | ".git"
                | "dist"
                | "build"
                | ".next"
                | ".nuxt"
                | ".svelte-kit"
                | ".turbo"
                | ".cache"
                | "coverage"
        )
}

/// Options mirroring the JS `{ targetPath }` bag threaded through the
/// original functions.
#[derive(Debug, Default, Clone)]
pub struct TargetOptions {
    pub target_path: Option<String>,
}

impl TargetOptions {
    pub fn none() -> Self {
        Self::default()
    }
    pub fn with(target_path: impl Into<String>) -> Self {
        Self {
            target_path: Some(target_path.into()),
        }
    }
    fn has_target(&self) -> bool {
        self.target_path
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct ProjectResolution {
    pub target_dir: PathBuf,
    pub project_root: PathBuf,
    pub repo_root: PathBuf,
    pub is_monorepo: bool,
}

#[derive(Debug, Clone)]
pub struct ContextResolution {
    pub context_dir: PathBuf,
    pub product_path: Option<PathBuf>,
    pub design_path: Option<PathBuf>,
    pub project_root: PathBuf,
    pub repo_root: PathBuf,
    pub is_monorepo: bool,
    pub target_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LoadedContext {
    pub has_product: bool,
    pub product: Option<String>,
    /// project-root-relative, POSIX-separated, like the JS `path.relative` result.
    pub product_path: Option<String>,
    pub has_design: bool,
    pub design: Option<String>,
    pub design_path: Option<String>,
    pub context_dir: PathBuf,
    pub product_context_dir: Option<PathBuf>,
    pub design_context_dir: Option<PathBuf>,
    pub project_root: PathBuf,
    pub repo_root: PathBuf,
    pub is_monorepo: bool,
}

#[derive(Debug, Clone)]
pub struct TargetCandidate {
    pub name: String,
    pub path: String,
    pub target_example: String,
    pub product_status: &'static str,
    pub product_path: Option<String>,
    pub design_status: &'static str,
    pub design_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TargetSelection {
    pub target_path: Option<String>,
    pub project_root: PathBuf,
    pub repo_root: PathBuf,
    pub target_candidates: Vec<TargetCandidate>,
}

// ─── public entry points ────────────────────────────────────────────────

pub fn resolve_context_dir(cwd: &Path, options: &TargetOptions) -> PathBuf {
    resolve_context(cwd, options).context_dir
}

pub fn load_context(cwd: &Path, options: &TargetOptions) -> LoadedContext {
    let resolved = resolve_context(cwd, options);
    let abs_cwd = absolute(cwd);
    let product = resolved.product_path.as_deref().and_then(safe_read);
    let design = resolved.design_path.as_deref().and_then(safe_read);
    LoadedContext {
        has_product: product.is_some(),
        product,
        product_path: resolved
            .product_path
            .as_deref()
            .map(|p| to_posix_relative(&path_relative(&abs_cwd, p))),
        has_design: design.is_some(),
        design,
        design_path: resolved
            .design_path
            .as_deref()
            .map(|p| to_posix_relative(&path_relative(&abs_cwd, p))),
        context_dir: resolved.context_dir,
        product_context_dir: resolved
            .product_path
            .as_deref()
            .and_then(|p| p.parent().map(Path::to_path_buf)),
        design_context_dir: resolved
            .design_path
            .as_deref()
            .and_then(|p| p.parent().map(Path::to_path_buf)),
        project_root: resolved.project_root,
        repo_root: resolved.repo_root,
        is_monorepo: resolved.is_monorepo,
    }
}

pub fn resolve_project_root(cwd: &Path, options: &TargetOptions) -> PathBuf {
    resolve_project(cwd, options).project_root
}

pub fn resolve_target_selection(cwd: &Path, options: &TargetOptions) -> Option<TargetSelection> {
    if options.has_target() {
        return None;
    }
    let project = resolve_project(cwd, &TargetOptions::none());
    if !project.is_monorepo || project.project_root != project.repo_root {
        return None;
    }
    let target_candidates = discover_target_candidates(&project.repo_root);
    if target_candidates.is_empty() {
        return None;
    }
    Some(TargetSelection {
        target_path: None,
        project_root: project.project_root,
        repo_root: project.repo_root,
        target_candidates,
    })
}

/// Pull the register (`brand` or `product`) out of PRODUCT.md by looking for
/// a `## Register` section and reading the first non-empty line that follows
/// it. Returns `None` when the file is legacy / register-less.
pub fn extract_register(product: Option<&str>) -> Option<String> {
    let product = product?;
    let header = Regex::new(r"(?i)^##\s+Register\b").unwrap();
    let lines: Vec<&str> = product.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        if header.is_match(line.trim()) {
            for next in &lines[i + 1..] {
                let next = next.trim();
                if next.is_empty() {
                    continue;
                }
                let word = next.to_lowercase();
                if word == "brand" || word == "product" {
                    return Some(word);
                }
                return None;
            }
        }
    }
    None
}

// ─── internal: context/project resolution ──────────────────────────────

fn resolve_context(cwd: &Path, options: &TargetOptions) -> ContextResolution {
    let abs_cwd = absolute(cwd);
    let project = resolve_project(&abs_cwd, options);
    let project_context_dir = resolve_local_context_dir(&project.project_root);
    let root_context_dir = if project.is_monorepo && project.repo_root != project.project_root {
        resolve_local_context_dir(&project.repo_root)
    } else {
        None
    };

    let mut product_path = project_context_dir
        .as_deref()
        .and_then(|d| first_existing(d, &PRODUCT_NAMES))
        .or_else(|| {
            root_context_dir
                .as_deref()
                .and_then(|d| first_existing(d, &PRODUCT_NAMES))
        });
    let mut design_path = project_context_dir
        .as_deref()
        .and_then(|d| first_existing(d, &DESIGN_NAMES))
        .or_else(|| {
            root_context_dir
                .as_deref()
                .and_then(|d| first_existing(d, &DESIGN_NAMES))
        });

    let mut env_context_dir = None;
    if product_path.is_none() && design_path.is_none() {
        env_context_dir = resolve_env_context_dir(&abs_cwd);
        if let Some(dir) = &env_context_dir {
            product_path = first_existing(dir, &PRODUCT_NAMES);
            design_path = first_existing(dir, &DESIGN_NAMES);
        }
    }

    let context_dir = product_path
        .as_deref()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .or_else(|| {
            design_path
                .as_deref()
                .and_then(|p| p.parent().map(Path::to_path_buf))
        })
        .or(env_context_dir)
        .unwrap_or_else(|| project.project_root.clone());

    ContextResolution {
        context_dir,
        product_path,
        design_path,
        project_root: project.project_root,
        repo_root: project.repo_root,
        is_monorepo: project.is_monorepo,
        target_dir: project.target_dir,
    }
}

fn resolve_project(cwd: &Path, options: &TargetOptions) -> ProjectResolution {
    let abs_cwd = absolute(cwd);
    let target_dir = resolve_target_dir(&abs_cwd, options);
    let mut repo_root = find_monorepo_root(&target_dir);
    if repo_root.is_none() && target_dir != abs_cwd {
        if let Some(cwd_repo_root) = find_monorepo_root(&abs_cwd) {
            if is_path_inside(&target_dir, &cwd_repo_root) {
                repo_root = Some(cwd_repo_root);
            }
        }
    }
    match repo_root {
        None => ProjectResolution {
            target_dir,
            project_root: abs_cwd.clone(),
            repo_root: abs_cwd,
            is_monorepo: false,
        },
        Some(repo_root) => {
            let project_root =
                resolve_workspace_project_root(&repo_root, &target_dir).unwrap_or_else(|| repo_root.clone());
            ProjectResolution {
                target_dir,
                project_root,
                repo_root,
                is_monorepo: true,
            }
        }
    }
}

fn resolve_local_context_dir(root: &Path) -> Option<PathBuf> {
    let mut names = PRODUCT_NAMES.to_vec();
    names.extend_from_slice(&DESIGN_NAMES);
    if first_existing(root, &names).is_some() {
        return Some(root.to_path_buf());
    }
    for rel in FALLBACK_DIRS {
        let candidate = root.join(rel);
        if first_existing(&candidate, &names).is_some() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_env_context_dir(cwd: &Path) -> Option<PathBuf> {
    let env_dir = std::env::var("IMPECCABLE_CONTEXT_DIR").ok()?;
    let trimmed = env_dir.trim();
    if trimmed.is_empty() {
        return None;
    }
    let p = Path::new(trimmed);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    })
}

fn resolve_target_dir(cwd: &Path, options: &TargetOptions) -> PathBuf {
    let target_path = match &options.target_path {
        Some(t) if !t.trim().is_empty() => t,
        _ => return cwd.to_path_buf(),
    };
    let p = Path::new(target_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    match fs::metadata(&abs) {
        Ok(meta) if meta.is_dir() => abs,
        Ok(_) => abs.parent().map(Path::to_path_buf).unwrap_or(abs),
        Err(_) => {
            if abs.extension().is_some() {
                abs.parent().map(Path::to_path_buf).unwrap_or(abs)
            } else {
                abs
            }
        }
    }
}

fn find_monorepo_root(start_dir: &Path) -> Option<PathBuf> {
    let home_dir = dirs_home();
    let mut dir = absolute(start_dir);
    loop {
        if Some(&dir) == home_dir.as_ref() {
            return None;
        }
        if is_monorepo_root(&dir) {
            return Some(dir);
        }
        if has_git_boundary(&dir) {
            return None;
        }
        let parent = dir.parent()?.to_path_buf();
        if parent == dir {
            return None;
        }
        dir = parent;
    }
}

fn is_monorepo_root(dir: &Path) -> bool {
    if read_workspace_patterns(dir)
        .iter()
        .any(|p| !normalize_workspace_pattern(p).starts_with('!'))
    {
        return true;
    }
    if !MONOREPO_MARKER_FILES
        .iter()
        .any(|f| dir.join(f).exists())
    {
        return false;
    }
    has_fallback_workspace_children(dir)
}

fn has_git_boundary(dir: &Path) -> bool {
    dir.join(".git").exists()
}

fn has_fallback_workspace_children(dir: &Path) -> bool {
    for name in MONOREPO_FALLBACK_PROJECT_DIRS {
        let base = dir.join(name);
        let entries = match fs::read_dir(&base) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if entry.path().is_dir() && !is_ignored_workspace_discovery_dir(&file_name) {
                return true;
            }
        }
    }
    false
}

fn discover_target_candidates(repo_root: &Path) -> Vec<TargetCandidate> {
    use std::collections::BTreeMap;
    let mut roots: BTreeMap<String, PathBuf> = BTreeMap::new();
    let patterns = read_workspace_patterns(repo_root);
    for pattern in &patterns {
        for root in discover_roots_for_pattern(repo_root, pattern) {
            let rel = to_posix_relative(&path_relative(repo_root, &root));
            roots.insert(rel, root);
        }
    }
    if MONOREPO_MARKER_FILES.iter().any(|f| repo_root.join(f).exists()) {
        for name in MONOREPO_FALLBACK_PROJECT_DIRS {
            let base = repo_root.join(name);
            let entries = match fs::read_dir(&base) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy().to_string();
                if !entry.path().is_dir() || is_ignored_workspace_discovery_dir(&file_name) {
                    continue;
                }
                let root = base.join(&file_name);
                let rel = to_posix_relative(&path_relative(repo_root, &root));
                roots.insert(rel, root);
            }
        }
    }

    let mut out: Vec<(String, PathBuf)> = roots.into_iter().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter()
        .filter(|(rel, _)| {
            let segs: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
            !rel.is_empty()
                && !rel.starts_with("..")
                && !is_excluded_by_workspace_pattern(&segs, &patterns)
        })
        .map(|(rel, root)| {
            let target_example = find_target_example(repo_root, &root);
            let summary = resolve_candidate_context_summary(repo_root, &root, &target_example);
            TargetCandidate {
                name: root
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                path: rel,
                target_example,
                product_status: summary.0,
                product_path: summary.1,
                design_status: summary.2,
                design_path: summary.3,
            }
        })
        .collect()
}

type CandidateSummary = (&'static str, Option<String>, &'static str, Option<String>);

fn resolve_candidate_context_summary(
    repo_root: &Path,
    project_root: &Path,
    target_path: &str,
) -> CandidateSummary {
    let options = TargetOptions::with(target_path.to_string());
    let ctx = resolve_context(repo_root, &options);
    (
        context_source_status(ctx.product_path.as_deref(), repo_root, project_root),
        context_source_path(ctx.product_path.as_deref(), repo_root),
        context_source_status(ctx.design_path.as_deref(), repo_root, project_root),
        context_source_path(ctx.design_path.as_deref(), repo_root),
    )
}

fn context_source_status(
    file_path: Option<&Path>,
    repo_root: &Path,
    project_root: &Path,
) -> &'static str {
    let file_path = match file_path {
        Some(p) => absolute(p),
        None => return "missing",
    };
    let abs_project_root = absolute(project_root);
    let abs_repo_root = absolute(repo_root);
    if is_path_inside_or_equal(&file_path, &abs_project_root) {
        return if file_path.parent() == Some(abs_project_root.as_path()) {
            "child"
        } else {
            "fallback"
        };
    }
    if abs_project_root != abs_repo_root && is_path_inside_or_equal(&file_path, &abs_repo_root) {
        return "inherited";
    }
    "fallback"
}

fn context_source_path(file_path: Option<&Path>, repo_root: &Path) -> Option<String> {
    let file_path = file_path?;
    let rel = path_relative(repo_root, file_path);
    if !rel.as_os_str().is_empty() && !rel.starts_with("..") && rel.is_relative() {
        Some(to_posix_relative(&rel))
    } else {
        Some(file_path.to_string_lossy().to_string())
    }
}

fn discover_roots_for_pattern(repo_root: &Path, raw_pattern: &str) -> Vec<PathBuf> {
    let pattern = normalize_workspace_pattern(raw_pattern);
    if pattern.is_empty() || pattern.starts_with('!') {
        return vec![];
    }
    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return vec![];
    }
    let first_glob_index = segments.iter().position(|s| s.contains('*'));
    let literal_prefix = match first_glob_index {
        None => &segments[..],
        Some(i) => &segments[..i],
    };
    let base = literal_prefix
        .iter()
        .fold(repo_root.to_path_buf(), |acc, s| acc.join(s));
    if !base.exists() {
        return vec![];
    }
    if segments.contains(&"**") {
        let mut package_roots = vec![];
        walk_dirs(&base, &mut |dir: &Path| {
            if dir != base && is_candidate_project_root(dir) {
                package_roots.push(dir.to_path_buf());
            }
        });
        if !package_roots.is_empty() {
            return package_roots;
        }
        return direct_child_dirs(&base);
    }
    expand_simple_pattern(repo_root, &segments, 0, repo_root)
}

fn expand_simple_pattern(
    repo_root: &Path,
    pattern_segments: &[&str],
    index: usize,
    current: &Path,
) -> Vec<PathBuf> {
    if index >= pattern_segments.len() {
        return if current.exists() {
            vec![current.to_path_buf()]
        } else {
            vec![]
        };
    }
    let segment = pattern_segments[index];
    if !segment.contains('*') {
        return expand_simple_pattern(repo_root, pattern_segments, index + 1, &current.join(segment));
    }
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    let mut roots = vec![];
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if !entry.path().is_dir() || is_ignored_workspace_discovery_dir(&name) {
            continue;
        }
        if !segment_matches(segment, &name) {
            continue;
        }
        roots.extend(expand_simple_pattern(
            repo_root,
            pattern_segments,
            index + 1,
            &current.join(&*name),
        ));
    }
    roots
}

fn direct_child_dirs(dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                e.path().is_dir() && !is_ignored_workspace_discovery_dir(&name.to_string_lossy())
            })
            .map(|e| e.path())
            .collect(),
        Err(_) => vec![],
    }
}

fn walk_dirs(root: &Path, visit: &mut dyn FnMut(&Path)) {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if !entry.path().is_dir() || is_ignored_workspace_discovery_dir(&name) {
            continue;
        }
        let dir = entry.path();
        visit(&dir);
        walk_dirs(&dir, visit);
    }
}

fn is_candidate_project_root(dir: &Path) -> bool {
    let mut names = PRODUCT_NAMES.to_vec();
    names.extend_from_slice(&DESIGN_NAMES);
    dir.join("package.json").exists()
        || first_existing(dir, &names).is_some()
        || dir.join("src").exists()
        || dir.join("app").exists()
        || dir.join("pages").exists()
        || dir.join("public").exists()
}

fn find_target_example(repo_root: &Path, project_root: &Path) -> String {
    const EXAMPLES: [&str; 9] = [
        "src/App.jsx",
        "src/App.tsx",
        "src/main.jsx",
        "src/main.tsx",
        "src/index.jsx",
        "src/index.ts",
        "app/page.tsx",
        "pages/index.tsx",
        "public/index.html",
    ];
    for rel in EXAMPLES {
        let abs = project_root.join(rel);
        if abs.exists() {
            return to_posix_relative(&path_relative(repo_root, &abs));
        }
    }
    to_posix_relative(&path_relative(repo_root, project_root))
}

fn resolve_workspace_project_root(repo_root: &Path, target_dir: &Path) -> Option<PathBuf> {
    let rel = path_relative(repo_root, target_dir);
    if rel.as_os_str().is_empty() || rel.starts_with("..") || rel.is_absolute() {
        return Some(repo_root.to_path_buf());
    }
    let rel_segments: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let rel_seg_refs: Vec<&str> = rel_segments.iter().map(String::as_str).collect();
    let patterns = read_workspace_patterns(repo_root);
    let excluded = is_excluded_by_workspace_pattern(&rel_seg_refs, &patterns);
    if !excluded {
        for pattern in &patterns {
            if let Some(root) = project_root_from_workspace_pattern(repo_root, &rel_seg_refs, pattern) {
                return Some(root);
            }
        }
    }
    if excluded {
        return Some(repo_root.to_path_buf());
    }
    if rel_segments.len() >= 2 && MONOREPO_FALLBACK_PROJECT_DIRS.contains(&rel_segments[0].as_str()) {
        return Some(repo_root.join(&rel_segments[0]).join(&rel_segments[1]));
    }
    if let Some(nearest) = nearest_project_like_root(repo_root, target_dir) {
        return Some(nearest);
    }
    Some(repo_root.to_path_buf())
}

fn is_excluded_by_workspace_pattern(rel_segments: &[&str], patterns: &[String]) -> bool {
    patterns.iter().any(|raw_pattern| {
        let pattern = normalize_workspace_pattern(raw_pattern);
        if !pattern.starts_with('!') {
            return false;
        }
        workspace_pattern_matches_rel(&pattern[1..], rel_segments)
    })
}

fn nearest_project_like_root(repo_root: &Path, target_dir: &Path) -> Option<PathBuf> {
    let mut names = PRODUCT_NAMES.to_vec();
    names.extend_from_slice(&DESIGN_NAMES);
    let mut dir = absolute(target_dir);
    let stop = absolute(repo_root);
    while dir != stop {
        if first_existing(&dir, &names).is_some() || dir.join("package.json").exists() {
            return Some(dir);
        }
        let parent = dir.parent()?.to_path_buf();
        if parent == dir {
            break;
        }
        dir = parent;
    }
    None
}

fn nearest_package_root_between(repo_root: &Path, target_dir: &Path, stop_dir: &Path) -> Option<PathBuf> {
    let mut dir = absolute(target_dir);
    let stop = absolute(stop_dir);
    let root = absolute(repo_root);
    while dir != stop && is_path_inside_or_equal(&dir, &root) {
        if dir.join("package.json").exists() {
            return Some(dir);
        }
        let parent = dir.parent()?.to_path_buf();
        if parent == dir {
            break;
        }
        dir = parent;
    }
    None
}

fn is_path_inside_or_equal(candidate: &Path, root: &Path) -> bool {
    absolute(candidate) == absolute(root) || is_path_inside(candidate, root)
}

fn is_path_inside(candidate: &Path, root: &Path) -> bool {
    let rel = path_relative(root, candidate);
    !rel.as_os_str().is_empty() && !rel.starts_with("..") && rel.is_relative()
}

fn workspace_pattern_matches_rel(pattern: &str, rel_segments: &[&str]) -> bool {
    let normalized = normalize_workspace_pattern(pattern);
    let pattern_segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if pattern_segments.is_empty() {
        return false;
    }
    if pattern_segments.contains(&"**") {
        let first_glob_index = pattern_segments.iter().position(|s| s.contains('*'));
        let literal_prefix: &[&str] = match first_glob_index {
            None => &pattern_segments[..],
            Some(i) => &pattern_segments[..i],
        };
        if rel_segments.len() < literal_prefix.len() + 1 {
            return false;
        }
        for (i, seg) in literal_prefix.iter().enumerate() {
            if !segment_matches(seg, rel_segments[i]) {
                return false;
            }
        }
        return true;
    }
    if rel_segments.len() < pattern_segments.len() {
        return false;
    }
    for (i, seg) in pattern_segments.iter().enumerate() {
        if !segment_matches(seg, rel_segments[i]) {
            return false;
        }
    }
    true
}

fn read_workspace_patterns(repo_root: &Path) -> Vec<String> {
    let mut out = read_package_workspaces(repo_root);
    out.extend(read_pnpm_workspaces(repo_root));
    out.extend(read_lerna_workspaces(repo_root));
    out
}

fn read_package_workspaces(repo_root: &Path) -> Vec<String> {
    let pkg = read_json(&repo_root.join("package.json"));
    let pkg = match pkg {
        Some(v) => v,
        None => return vec![],
    };
    if let Some(arr) = pkg.get("workspaces").and_then(|w| w.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    if let Some(arr) = pkg
        .get("workspaces")
        .and_then(|w| w.get("packages"))
        .and_then(|p| p.as_array())
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    vec![]
}

fn read_lerna_workspaces(repo_root: &Path) -> Vec<String> {
    let lerna = match read_json(&repo_root.join("lerna.json")) {
        Some(v) => v,
        None => return vec![],
    };
    lerna
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn read_pnpm_workspaces(repo_root: &Path) -> Vec<String> {
    let body = match fs::read_to_string(repo_root.join("pnpm-workspace.yaml")) {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let mut patterns = vec![];
    let mut in_packages = false;
    let flow_re = Regex::new(r"^packages:\s*\[(.*)\]\s*$").unwrap();
    let packages_header_re = Regex::new(r"^packages:\s*$").unwrap();
    let key_re = Regex::new(r"^[A-Za-z0-9_-]+:\s*").unwrap();
    let item_re = Regex::new(r"^-\s*(.+)$").unwrap();
    for line in body.split("\r\n").flat_map(|l| l.split('\n')) {
        let trimmed = strip_yaml_inline_comment(line).trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(caps) = flow_re.captures(&trimmed) {
            patterns.extend(parse_yaml_flow_list(&caps[1]));
            in_packages = false;
            continue;
        }
        if packages_header_re.is_match(&trimmed) {
            in_packages = true;
            continue;
        }
        if in_packages && key_re.is_match(&trimmed) {
            break;
        }
        if in_packages {
            if let Some(caps) = item_re.captures(&trimmed) {
                let value = unquote_yaml_value(&caps[1]);
                if !value.is_empty() {
                    patterns.push(value);
                }
            }
        }
    }
    patterns
}

fn strip_yaml_inline_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let chars: Vec<char> = line.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if (ch == '"' || ch == '\'') && (i == 0 || chars[i - 1] != '\\') {
            quote = if quote == Some(ch) { None } else { Some(quote.unwrap_or(ch)) };
            continue;
        }
        if ch == '#' && quote.is_none() {
            // find byte offset of char index i
            let byte_idx: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
            return &line[..byte_idx];
        }
    }
    line
}

fn parse_yaml_flow_list(body: &str) -> Vec<String> {
    let mut items = vec![];
    let mut quote: Option<char> = None;
    let mut current = String::new();
    let chars: Vec<char> = body.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if (ch == '"' || ch == '\'') && (i == 0 || chars[i - 1] != '\\') {
            quote = if quote == Some(ch) { None } else { Some(quote.unwrap_or(ch)) };
            current.push(ch);
            continue;
        }
        if ch == ',' && quote.is_none() {
            let value = unquote_yaml_value(&current);
            if !value.is_empty() {
                items.push(value);
            }
            current.clear();
            continue;
        }
        current.push(ch);
    }
    let value = unquote_yaml_value(&current);
    if !value.is_empty() {
        items.push(value);
    }
    items
}

fn unquote_yaml_value(value: &str) -> String {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn read_json(file_path: &Path) -> Option<serde_json::Value> {
    let text = fs::read_to_string(file_path).ok()?;
    serde_json::from_str(&text).ok()
}

fn project_root_from_workspace_pattern(
    repo_root: &Path,
    rel_segments: &[&str],
    raw_pattern: &str,
) -> Option<PathBuf> {
    let pattern = normalize_workspace_pattern(raw_pattern);
    if pattern.is_empty() || pattern.starts_with('!') {
        return None;
    }
    let pattern_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    if pattern_segments.is_empty() {
        return None;
    }
    if pattern_segments.contains(&"**") {
        return project_root_from_double_star_pattern(repo_root, rel_segments, &pattern_segments);
    }
    if rel_segments.len() < pattern_segments.len() {
        return None;
    }
    for (i, seg) in pattern_segments.iter().enumerate() {
        if !segment_matches(seg, rel_segments[i]) {
            return None;
        }
    }
    let mut p = repo_root.to_path_buf();
    for seg in &rel_segments[..pattern_segments.len()] {
        p = p.join(seg);
    }
    Some(p)
}

fn project_root_from_double_star_pattern(
    repo_root: &Path,
    rel_segments: &[&str],
    pattern_segments: &[&str],
) -> Option<PathBuf> {
    let first_glob_index = pattern_segments.iter().position(|s| s.contains('*'));
    let literal_prefix: &[&str] = match first_glob_index {
        None => pattern_segments,
        Some(i) => &pattern_segments[..i],
    };
    if rel_segments.len() < literal_prefix.len() + 1 {
        return None;
    }
    for (i, seg) in literal_prefix.iter().enumerate() {
        if !segment_matches(seg, rel_segments[i]) {
            return None;
        }
    }
    let mut prefix_dir = repo_root.to_path_buf();
    for seg in literal_prefix {
        prefix_dir = prefix_dir.join(seg);
    }
    let mut target_dir = repo_root.to_path_buf();
    for seg in rel_segments {
        target_dir = target_dir.join(seg);
    }
    if let Some(package_root) = nearest_package_root_between(repo_root, &target_dir, &prefix_dir) {
        return Some(package_root);
    }
    let mut p = repo_root.to_path_buf();
    for seg in &rel_segments[..literal_prefix.len() + 1] {
        p = p.join(seg);
    }
    Some(p)
}

fn normalize_workspace_pattern(pattern: &str) -> String {
    let trimmed = pattern.trim();
    let trimmed = trimmed.trim_start_matches('\'').trim_start_matches('"');
    let trimmed = trimmed.trim_end_matches('\'').trim_end_matches('"');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    trimmed.trim_end_matches('/').to_string()
}

fn segment_matches(pattern_segment: &str, rel_segment: &str) -> bool {
    if pattern_segment == "*" {
        return true;
    }
    if !pattern_segment.contains('*') {
        return pattern_segment == rel_segment;
    }
    let escaped = regex::escape(pattern_segment).replace(r"\*", "[^/]*");
    let re = Regex::new(&format!("^{}$", escaped)).unwrap();
    re.is_match(rel_segment)
}

fn first_existing(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let abs = dir.join(name);
        if abs.exists() {
            return Some(abs);
        }
    }
    None
}

fn safe_read(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        normalize_lexically(p)
    } else {
        let cwd = std::env::current_dir().unwrap_or_default();
        normalize_lexically(&cwd.join(p))
    }
}

/// Lexical (no filesystem access) normalization: collapses `.` and resolves
/// `..` against preceding components, mirroring Node's `path.resolve`.
fn normalize_lexically(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
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

/// `path.relative(base, target)` equivalent for two lexically-absolute paths.
fn path_relative(base: &Path, target: &Path) -> PathBuf {
    let base = normalize_lexically(&absolute(base));
    let target = normalize_lexically(&absolute(target));
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
            "legion_w2010_ctx_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extract_register_reads_first_non_empty_line() {
        let product = "# Title\n\n## Register\n\nbrand\n\nmore text";
        assert_eq!(extract_register(Some(product)), Some("brand".to_string()));
    }

    #[test]
    fn extract_register_returns_none_when_absent() {
        assert_eq!(extract_register(Some("# Title\nno register here")), None);
        assert_eq!(extract_register(None), None);
    }

    #[test]
    fn extract_register_returns_none_for_unrecognized_value() {
        let product = "## Register\nweird-value";
        assert_eq!(extract_register(Some(product)), None);
    }

    #[test]
    fn load_context_finds_product_md_in_project_root() {
        let root = tmp_dir("simple");
        fs::write(root.join("PRODUCT.md"), "# Hello\n## Register\nproduct\n").unwrap();
        let ctx = load_context(&root, &TargetOptions::none());
        assert!(ctx.has_product);
        assert_eq!(ctx.product_path.as_deref(), Some("PRODUCT.md"));
        assert!(!ctx.is_monorepo);
        assert_eq!(extract_register(ctx.product.as_deref()), Some("product".to_string()));
    }

    #[test]
    fn load_context_falls_back_to_agents_context_dir() {
        let root = tmp_dir("fallback");
        fs::create_dir_all(root.join(".agents/context")).unwrap();
        fs::write(root.join(".agents/context/PRODUCT.md"), "# Hello").unwrap();
        let ctx = load_context(&root, &TargetOptions::none());
        assert!(ctx.has_product);
        assert_eq!(ctx.product_path.as_deref(), Some(".agents/context/PRODUCT.md"));
    }

    #[test]
    fn load_context_reports_missing_product() {
        let root = tmp_dir("missing");
        let ctx = load_context(&root, &TargetOptions::none());
        assert!(!ctx.has_product);
        assert_eq!(ctx.product_path, None);
    }

    #[test]
    fn monorepo_detection_via_pnpm_workspace() {
        let root = tmp_dir("pnpm_mono");
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("apps/web/src")).unwrap();
        fs::write(root.join("apps/web/PRODUCT.md"), "# Web app").unwrap();

        let child = root.join("apps/web");
        let ctx = load_context(&child, &TargetOptions::none());
        assert!(ctx.is_monorepo);
        assert_eq!(ctx.project_root, child);
        assert_eq!(ctx.repo_root, root);
        assert!(ctx.has_product);
    }

    #[test]
    fn discover_target_candidates_lists_workspace_apps() {
        let root = tmp_dir("candidates");
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("apps/web")).unwrap();
        fs::create_dir_all(root.join("apps/api")).unwrap();
        fs::write(root.join("apps/web/PRODUCT.md"), "# Web").unwrap();

        let selection = resolve_target_selection(&root, &TargetOptions::none());
        let selection = selection.expect("expected a target selection");
        let names: Vec<_> = selection
            .target_candidates
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert!(names.contains(&"web".to_string()));
        assert!(names.contains(&"api".to_string()));
        let web = selection
            .target_candidates
            .iter()
            .find(|c| c.name == "web")
            .unwrap();
        assert_eq!(web.product_status, "child");
    }

    #[test]
    fn negated_workspace_pattern_excludes_candidate() {
        let root = tmp_dir("excluded");
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/internal'\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("packages/internal")).unwrap();
        fs::create_dir_all(root.join("packages/public")).unwrap();

        let selection = resolve_target_selection(&root, &TargetOptions::none());
        let selection = selection.expect("expected a target selection");
        let names: Vec<_> = selection
            .target_candidates
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert!(names.contains(&"public".to_string()));
        assert!(!names.contains(&"internal".to_string()));
    }

    #[test]
    fn resolve_target_selection_none_without_workspace_children() {
        let root = tmp_dir("no_children");
        let selection = resolve_target_selection(&root, &TargetOptions::none());
        assert!(selection.is_none());
    }
}
