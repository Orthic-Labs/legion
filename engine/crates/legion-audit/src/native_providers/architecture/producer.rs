//! Self-sourcing input producer for the architecture-family providers.
//!
//! The analyzers in this directory are pure: they judge an input and refuse to
//! claim success over an empty one. Nothing used to build that input, so an
//! ordinary `legion audit <root>` reported every one of them unavailable. This
//! module derives the input natively from the frozen denominator: it reads the
//! files the denominator names (bounded), builds a module/import graph, a
//! manifest list, a docs index with the code paths it cites, a test map,
//! requirement-ID references and framework markers, and shapes each into the
//! JSON the matching analyzer expects.
//!
//! Boundaries kept deliberately:
//! - Host-injected input never reaches this module; the adapter consults it
//!   only when no input was supplied.
//! - Every denominator path is either read (`filesRead`) or becomes a
//!   `producer-skipped:<path>:<reason>` coverage gap (size, byte, file-count
//!   caps, unreadable, or content drift against the inventory digest).
//! - Static derivation cannot mint evidence receipts. Providers whose
//!   analyzers require bound evidence (framework routes/models/components,
//!   verified requirements) therefore report the analyzer's own evidence gaps,
//!   and `compatibility.core` stays unavailable with a specific reason.

use super::common::{gap, Analysis};
use crate::InventoryEntry;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FILES: usize = 50_000;
const MAX_EDGES: usize = 50_000;
const MAX_CLAIMS: usize = 5_000;
const MAX_ITEMS: usize = 2_000;
const MAX_LISTED_GAPS: usize = 50;
/// Findings emitted per noisy provider; the remainder becomes a named gap.
const MAX_FINDINGS: usize = 200;
/// Source files with fewer non-blank lines are re-export shells, not code.
const MIN_SOURCE_LINES: usize = 15;
/// Frozen-history or generated trees: documents under them are never audited
/// for stale citations.
const DOC_SKIP_SEGMENTS: &[&str] = &[
    "provenance",
    "audits",
    "archive",
    "node_modules",
    "dist",
    "target",
];

macro_rules! lazy_re {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            CELL.get_or_init(|| Regex::new($pattern).expect("producer regex"))
        }
    };
}

lazy_re!(
    rust_mod_re,
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*;"
);
lazy_re!(
    rust_use_re,
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use[ \t]+([^;]+);"
);
lazy_re!(
    js_import_re,
    r#"(?m)\b(?:import|export)\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#
);
lazy_re!(
    js_call_re,
    r#"\b(?:require|import)\(\s*['"]([^'"]+)['"]\s*\)"#
);
lazy_re!(py_import_re, r"(?m)^[ \t]*import[ \t]+([^\n#;]+)");
lazy_re!(
    py_from_re,
    r"(?m)^[ \t]*from[ \t]+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?[ \t]+import[ \t]+([^\n#;]+)"
);
lazy_re!(md_link_re, r#"\]\(([^)\s]+)(?:\s+"[^"]*")?\)"#);
lazy_re!(md_span_re, r"`([^`\n]+)`");
lazy_re!(req_id_re, r"\b(?:REQ|FR|NFR|SR|US)-[0-9]{1,5}\b");
lazy_re!(
    fake_assert_re,
    r"assert!\(\s*true\s*\)|assert_eq!\(\s*true\s*,\s*true\s*\)|expect\(\s*true\s*\)\s*\.\s*to(?:Be|Equal|StrictEqual)\(\s*true\s*\)|\bassert\s+True\b|assertTrue\(\s*True\s*\)|assert\.ok\(\s*true\s*\)"
);
lazy_re!(
    test_decl_re,
    r#"#\[(?:tokio::)?test\b|\b(?:it|test)\s*\(\s*['"`]|\bdef\s+test_|\bfunc\s+Test[A-Z_]"#
);
lazy_re!(
    assertion_re,
    r"\bassert|\bexpect\s*\(|\.should\b|\.unwrap\(|\.expect\(|\bpanic!|\bt\.(?:Error|Fatal|Fail)|\bverify"
);
lazy_re!(word_re, r"[A-Za-z_][A-Za-z0-9_]*");
lazy_re!(
    route_js_re,
    r#"\b(?:app|router|server|fastify|api)\.(get|post|put|patch|delete|all)\(\s*['"`](/[^'"`]*)['"`]"#
);
lazy_re!(
    route_nest_re,
    r#"@(Get|Post|Put|Patch|Delete)\(\s*(?:['"]([^'"]*)['"])?\s*\)"#
);
lazy_re!(
    route_py_re,
    r#"@\w+\.(get|post|put|patch|delete|route)\(\s*['"]([^'"]+)['"]"#
);
lazy_re!(
    route_django_re,
    r#"\b(?:re_path|path)\(\s*r?['"]([^'"]*)['"]"#
);
lazy_re!(route_axum_re, r#"\.route\(\s*"([^"]+)""#);
lazy_re!(
    route_attr_re,
    r#"#\[(get|post|put|patch|delete)\(\s*"([^"]+)""#
);
lazy_re!(
    route_go_re,
    r#"\.(Get|Post|Put|Patch|Delete|Handle|HandleFunc|GET|POST|PUT|PATCH|DELETE)\(\s*"(/[^"]*)""#
);
lazy_re!(cargo_name_re, r#"(?m)^[ \t]*name[ \t]*=[ \t]*"([^"]+)""#);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lang {
    Rust,
    Js,
    Python,
    Go,
    Other,
}

const JS_EXTS: &[&str] = &[
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte",
];
const IGNORED_ROOTS: &[&str] = &[
    "dist",
    "build",
    "target",
    "node_modules",
    ".git",
    "out",
    "tmp",
    "coverage",
    ".next",
    ".cache",
];
const PLACEHOLDER_ROOTS: &[&str] = &["path", "your", "my", "foo", "bar", "xxx", "some", "example"];
const NON_SOURCE_DIRS: &[&str] = &[
    "fixtures",
    "fixture",
    "examples",
    "example",
    "scripts",
    "docs",
    "benches",
    "tests",
    "migrations",
    "vendor",
    "third_party",
    "generated",
    "__mocks__",
    "mocks",
    "stories",
];

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(head, _)| head).unwrap_or("")
}
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
fn file_stem(name: &str) -> &str {
    name.rsplit_once('.').map(|(head, _)| head).unwrap_or(name)
}
fn extension(path: &str) -> String {
    let name = file_name(path);
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}
fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_owned()
    } else {
        format!("{base}/{name}")
    }
}
fn normalize(path: &str) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            other => out.push(other),
        }
    }
    Some(out.join("/"))
}
fn short_hash(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes())[..6])
}
fn line_of(text: &str, offset: usize) -> usize {
    1 + text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

fn lang_of(path: &str) -> Lang {
    match extension(path).as_str() {
        "rs" => Lang::Rust,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "vue" | "svelte" => Lang::Js,
        "py" => Lang::Python,
        "go" => Lang::Go,
        _ => Lang::Other,
    }
}

fn is_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod"
    ) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

fn retain(path: &str) -> bool {
    lang_of(path) != Lang::Other || extension(path) == "md" || is_manifest_name(file_name(path))
}

fn is_test_path(path: &str) -> bool {
    let name = file_name(path);
    name.contains(".test.")
        || name.contains(".spec.")
        || name.starts_with("test_")
        || ["_test.rs", "_test.py", "_test.go", "_spec.rb", "_spec.py"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        || path
            .split('/')
            .any(|part| matches!(part, "tests" | "test" | "__tests__" | "e2e"))
}

/// The stem a test file is named after (`foo.test.ts`, `test_foo.py`,
/// `foo_test.go` all name `foo`).
fn test_subject(path: &str) -> String {
    let mut stem = file_stem(file_name(path)).to_owned();
    for suffix in [".test", ".spec", "_test", "_spec"] {
        if let Some(head) = stem.strip_suffix(suffix) {
            stem = head.to_owned();
        }
    }
    if let Some(tail) = stem.strip_prefix("test_") {
        stem = tail.to_owned();
    }
    stem
}

#[derive(Clone, Debug)]
struct Edge {
    kind: &'static str,
    structural: bool,
}

#[derive(Debug, Default)]
struct EdgeSet {
    map: BTreeMap<(String, String), Edge>,
    capped: bool,
}

impl EdgeSet {
    fn add(&mut self, from: &str, to: &str, kind: &'static str, structural: bool) {
        if from == to {
            return;
        }
        let key = (from.to_owned(), to.to_owned());
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= MAX_EDGES {
            self.capped = true;
            return;
        }
        self.map.insert(key, Edge { kind, structural });
    }
}

#[derive(Debug, Default)]
struct ModTree {
    by_path: BTreeMap<Vec<String>, String>,
}

/// Facts derived once per denominator and shared by every provider.
#[derive(Debug, Default)]
pub struct Facts {
    pub files_read: u64,
    gaps: Vec<String>,
    edges: EdgeSet,
    cycles: Vec<Value>,
    manifests: Vec<Value>,
    doc_index: Vec<Value>,
    claims: Vec<Value>,
    claim_meta: BTreeMap<String, Value>,
    requirements: Vec<Value>,
    test_obs: Vec<Value>,
    test_map: Vec<Value>,
    source_count: usize,
    test_file_count: usize,
    frontend: Vec<Value>,
    backend: Vec<Value>,
    data_models: Vec<Value>,
}

/// Shared scan results keyed by root and denominator digest.
#[derive(Clone, Debug, Default)]
pub struct ProducerCache {
    inner: Arc<Mutex<BTreeMap<String, Arc<Facts>>>>,
}

impl ProducerCache {
    pub fn facts(&self, root: &Path, digest: &str, entries: &[InventoryEntry]) -> Arc<Facts> {
        let key = format!("{}\n{digest}", root.display());
        if let Ok(guard) = self.inner.lock() {
            if let Some(found) = guard.get(&key) {
                return found.clone();
            }
        }
        let facts = Arc::new(scan(root, entries));
        if let Ok(mut guard) = self.inner.lock() {
            if guard.len() >= 4 {
                guard.clear();
            }
            guard.insert(key, facts.clone());
        }
        facts
    }
}

pub enum Production {
    Input(Value),
    Unavailable(String),
}

struct Ctx<'a> {
    entries: &'a [InventoryEntry],
    all: HashSet<String>,
    dirs: HashSet<String>,
    texts: BTreeMap<String, String>,
    manifest_dirs: Vec<String>,
}

impl Ctx<'_> {
    fn package_dir(&self, path: &str) -> &str {
        self.manifest_dirs
            .iter()
            .find(|dir| dir.is_empty() || path.starts_with(&format!("{dir}/")))
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// Reads one denominator file within the caps. `Ok(None)` means the file was
/// examined but has no analyzable text (symlink or non-UTF-8).
fn load(
    root: &Path,
    entry: &InventoryEntry,
    budget: &mut u64,
) -> Result<Option<String>, &'static str> {
    let full = root.join(&entry.path);
    let meta = std::fs::symlink_metadata(&full).map_err(|_| "unreadable")?;
    if meta.file_type().is_symlink() {
        return Ok(None);
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err("oversize");
    }
    if meta.len() > *budget {
        return Err("byte-budget");
    }
    let bytes = std::fs::read(&full).map_err(|_| "unreadable")?;
    *budget = budget.saturating_sub(bytes.len() as u64);
    if let Some(expected) = &entry.digest {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if &actual != expected {
            return Err("drift");
        }
    }
    Ok(String::from_utf8(bytes).ok())
}

pub fn scan(root: &Path, entries: &[InventoryEntry]) -> Facts {
    let mut facts = Facts::default();
    let mut texts = BTreeMap::new();
    let mut skipped: Vec<(String, &'static str)> = Vec::new();
    let mut budget = MAX_TOTAL_BYTES;
    for (index, entry) in entries.iter().enumerate() {
        if index >= MAX_FILES {
            skipped.push((entry.path.clone(), "file-cap"));
            continue;
        }
        match load(root, entry, &mut budget) {
            Ok(text) => {
                facts.files_read += 1;
                if let Some(text) = text {
                    if retain(&entry.path) {
                        texts.insert(entry.path.clone(), text);
                    }
                }
            }
            Err(reason) => skipped.push((entry.path.clone(), reason)),
        }
    }
    let all: HashSet<String> = entries.iter().map(|entry| entry.path.clone()).collect();
    let mut dirs = HashSet::new();
    for path in &all {
        let mut dir = parent(path);
        while !dir.is_empty() {
            if !dirs.insert(dir.to_owned()) {
                break;
            }
            dir = parent(dir);
        }
    }
    let mut manifest_dirs: Vec<String> = entries
        .iter()
        .filter(|entry| is_manifest_name(file_name(&entry.path)))
        .map(|entry| parent(&entry.path).to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    manifest_dirs.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    let ctx = Ctx {
        entries,
        all,
        dirs,
        texts,
        manifest_dirs,
    };
    build_manifests(&ctx, &mut facts);
    build_graph(&ctx, &mut facts);
    build_docs(&ctx, &mut facts);
    build_requirements(&ctx, &mut facts);
    build_tests(&ctx, &mut facts);
    build_frameworks(&ctx, &mut facts);
    for (path, reason) in skipped.iter().take(MAX_LISTED_GAPS) {
        facts.gaps.push(format!("producer-skipped:{path}:{reason}"));
    }
    if skipped.len() > MAX_LISTED_GAPS {
        facts.gaps.push(format!(
            "producer-skipped:+{}-more",
            skipped.len() - MAX_LISTED_GAPS
        ));
    }
    if facts.edges.capped {
        facts.gaps.push(format!("producer-edge-cap:{MAX_EDGES}"));
    }
    facts
}

fn build_manifests(ctx: &Ctx, facts: &mut Facts) {
    for entry in ctx.entries {
        let name = file_name(&entry.path);
        if !is_manifest_name(name) {
            continue;
        }
        let text = ctx.texts.get(&entry.path).map(String::as_str).unwrap_or("");
        let package = match name {
            "package.json" => serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|value| value.get("name").and_then(Value::as_str).map(str::to_owned)),
            "Cargo.toml" => cargo_package_name(text),
            "pyproject.toml" => cargo_package_name(text),
            _ => None,
        };
        facts.manifests.push(json!({
            "path": entry.path,
            "kind": name,
            "name": package,
            "dependencies": entry.dependencies,
        }));
    }
}

fn cargo_package_name(text: &str) -> Option<String> {
    let start = text.find("[package]").or_else(|| text.find("[project]"))?;
    let section = &text[start + 1..];
    let end = section.find("\n[").unwrap_or(section.len());
    cargo_name_re()
        .captures(&section[..end])
        .map(|captures| captures[1].to_owned())
}

// ---------------------------------------------------------------------------
// Module / import graph
// ---------------------------------------------------------------------------

fn expand_use(spec: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = spec.chars().collect();
    let mut pos = 0;
    use_tree(&chars, &mut pos, Vec::new(), 0)
}

fn use_tree(
    chars: &[char],
    pos: &mut usize,
    prefix: Vec<String>,
    depth: usize,
) -> Vec<Vec<String>> {
    let mut path = prefix;
    let mut out = Vec::new();
    loop {
        if *pos >= chars.len() {
            out.push(path);
            return out;
        }
        match chars[*pos] {
            '{' => {
                *pos += 1;
                if depth < 16 {
                    loop {
                        out.extend(use_tree(chars, pos, path.clone(), depth + 1));
                        if *pos < chars.len() && chars[*pos] == ',' {
                            *pos += 1;
                            continue;
                        }
                        break;
                    }
                }
                if *pos < chars.len() && chars[*pos] == '}' {
                    *pos += 1;
                }
                return out;
            }
            ',' | '}' => {
                out.push(path);
                return out;
            }
            ':' => {
                *pos += 1;
            }
            _ => {
                let start = *pos;
                while *pos < chars.len() && !matches!(chars[*pos], ':' | ',' | '{' | '}') {
                    *pos += 1;
                }
                let segment: String = chars[start..*pos].iter().collect();
                if let Some(first) = segment.split_whitespace().next() {
                    path.push(first.to_owned());
                }
            }
        }
    }
}

fn rust_use_target(
    segs: &[String],
    tree: Option<usize>,
    module: &[String],
    trees: &[ModTree],
    crate_names: &HashMap<String, usize>,
) -> Option<(usize, Vec<String>)> {
    let first = segs.first()?;
    let (t, mut cur, rest, explicit): (usize, Vec<String>, &[String], bool) = match first.as_str() {
        "crate" => (tree?, Vec::new(), &segs[1..], true),
        "self" => (tree?, module.to_vec(), &segs[1..], true),
        "super" => {
            let mut cur = module.to_vec();
            let mut index = 0;
            while index < segs.len() && segs[index] == "super" {
                cur.pop()?;
                index += 1;
            }
            (tree?, cur, &segs[index..], true)
        }
        name => match crate_names.get(name) {
            Some(found) => (*found, Vec::new(), &segs[1..], true),
            None => (tree?, module.to_vec(), segs, false),
        },
    };
    let mut progressed = false;
    for segment in rest {
        let mut candidate = cur.clone();
        candidate.push(segment.clone());
        if trees[t].by_path.contains_key(&candidate) {
            cur = candidate;
            progressed = true;
        } else {
            break;
        }
    }
    if !explicit && !progressed {
        return None;
    }
    if trees[t].by_path.contains_key(&cur) {
        Some((t, cur))
    } else {
        None
    }
}

fn build_rust_tree(root_file: &str, ctx: &Ctx, edges: &mut EdgeSet) -> ModTree {
    let mut tree = ModTree::default();
    let mut work: Vec<(String, Vec<String>)> = vec![(root_file.to_owned(), Vec::new())];
    let mut seen = HashSet::new();
    while let Some((file, module)) = work.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        tree.by_path.insert(module.clone(), file.clone());
        let Some(text) = ctx.texts.get(&file) else {
            continue;
        };
        let stem = file_stem(file_name(&file)).to_owned();
        let base = if matches!(stem.as_str(), "mod" | "lib" | "main") {
            parent(&file).to_owned()
        } else {
            join(parent(&file), &stem)
        };
        for captures in rust_mod_re().captures_iter(text) {
            let name = captures[1].to_owned();
            let flat = join(&base, &format!("{name}.rs"));
            let nested = join(&base, &format!("{name}/mod.rs"));
            let child = if ctx.all.contains(&flat) {
                Some(flat)
            } else if ctx.all.contains(&nested) {
                Some(nested)
            } else {
                None
            };
            if let Some(child) = child {
                edges.add(&file, &child, "mod", true);
                let mut child_module = module.clone();
                child_module.push(name);
                work.push((child, child_module));
            }
        }
    }
    tree
}

fn is_prefix(short: &[String], long: &[String]) -> bool {
    short.len() <= long.len() && long[..short.len()] == *short
}

fn build_graph(ctx: &Ctx, facts: &mut Facts) {
    let mut edges = EdgeSet::default();
    // Rust: module trees per crate root, then `use` resolution.
    let mut trees: Vec<ModTree> = Vec::new();
    let mut crate_names: HashMap<String, usize> = HashMap::new();
    for entry in ctx.entries {
        if file_name(&entry.path) != "Cargo.toml" {
            continue;
        }
        let dir = parent(&entry.path);
        let name = ctx
            .texts
            .get(&entry.path)
            .and_then(|text| cargo_package_name(text))
            .map(|name| name.replace('-', "_"));
        for (root_name, is_lib) in [("lib.rs", true), ("main.rs", false)] {
            let root_file = join(dir, &format!("src/{root_name}"));
            if !ctx.texts.contains_key(&root_file) {
                continue;
            }
            let tree = build_rust_tree(&root_file, ctx, &mut edges);
            trees.push(tree);
            if is_lib {
                if let Some(name) = &name {
                    crate_names.insert(name.clone(), trees.len() - 1);
                }
            }
        }
    }
    let mut file_module: HashMap<String, (usize, Vec<String>)> = HashMap::new();
    for (index, tree) in trees.iter().enumerate() {
        for (module, file) in &tree.by_path {
            file_module
                .entry(file.clone())
                .or_insert((index, module.clone()));
        }
    }
    let rust_files: Vec<&String> = ctx
        .texts
        .keys()
        .filter(|path| lang_of(path) == Lang::Rust)
        .collect();
    for file in rust_files {
        let text = &ctx.texts[file];
        let (tree, module) = match file_module.get(file) {
            Some((tree, module)) => (Some(*tree), module.clone()),
            None => (None, Vec::new()),
        };
        for captures in rust_use_re().captures_iter(text) {
            for segs in expand_use(&captures[1]) {
                if let Some((target_tree, target_module)) =
                    rust_use_target(&segs, tree, &module, &trees, &crate_names)
                {
                    let target = trees[target_tree].by_path[&target_module].clone();
                    let structural = tree == Some(target_tree)
                        && (is_prefix(&module, &target_module)
                            || is_prefix(&target_module, &module));
                    edges.add(file, &target, "use", structural);
                }
            }
        }
    }
    // JavaScript / TypeScript.
    for (file, text) in &ctx.texts {
        match lang_of(file) {
            Lang::Js => {
                let specs: Vec<String> = js_import_re()
                    .captures_iter(text)
                    .chain(js_call_re().captures_iter(text))
                    .map(|captures| captures[1].to_owned())
                    .collect();
                for spec in specs {
                    if let Some(target) = js_resolve(file, &spec, ctx) {
                        edges.add(file, &target, "import", false);
                    }
                }
            }
            Lang::Python => {
                for target in py_targets(file, text, ctx) {
                    edges.add(file, &target, "import", false);
                }
            }
            _ => {}
        }
    }
    facts.edges = edges;
    facts.cycles = find_cycles(&facts.edges);
}

fn js_resolve(from: &str, spec: &str, ctx: &Ctx) -> Option<String> {
    if !spec.starts_with('.') {
        return None;
    }
    let spec = spec.split(['?', '#']).next().unwrap_or(spec);
    let base = normalize(&join(parent(from), spec))?;
    let mut candidates = vec![base.clone()];
    for ext in JS_EXTS {
        candidates.push(format!("{base}{ext}"));
    }
    for js in [".js", ".jsx", ".mjs", ".cjs"] {
        if let Some(stem) = base.strip_suffix(js) {
            for ts in [".ts", ".tsx", ".mts", ".cts"] {
                candidates.push(format!("{stem}{ts}"));
            }
        }
    }
    for ext in JS_EXTS {
        candidates.push(format!("{base}/index{ext}"));
    }
    candidates
        .into_iter()
        .find(|candidate| ctx.all.contains(candidate) && lang_of(candidate) == Lang::Js)
}

fn py_candidates(base_dir: &str, module: &str, name: Option<&str>) -> Vec<String> {
    let module_path = module.replace('.', "/");
    let package = if module_path.is_empty() {
        base_dir.to_owned()
    } else {
        join(base_dir, &module_path)
    };
    let mut out = Vec::new();
    if !module_path.is_empty() {
        out.push(format!("{package}.py"));
        out.push(join(&package, "__init__.py"));
    }
    if let Some(name) = name {
        out.push(join(&package, &format!("{name}.py")));
        out.push(join(&package, &format!("{name}/__init__.py")));
    }
    out
}

fn py_targets(file: &str, text: &str, ctx: &Ctx) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let mut dir = parent(file).to_owned();
    loop {
        roots.push(dir.clone());
        roots.push(join(&dir, "src"));
        if dir.is_empty() {
            break;
        }
        dir = parent(&dir).to_owned();
    }
    let mut found = Vec::new();
    let mut resolve = |dots: usize, module: &str, name: Option<&str>| {
        let bases: Vec<String> = if dots > 0 {
            let mut base = parent(file).to_owned();
            for _ in 1..dots {
                base = parent(&base).to_owned();
            }
            vec![base]
        } else {
            roots.clone()
        };
        for base in bases {
            if let Some(hit) = py_candidates(&base, module, name)
                .into_iter()
                .find(|candidate| ctx.all.contains(candidate))
            {
                found.push(hit);
                return;
            }
        }
    };
    for captures in py_import_re().captures_iter(text) {
        for part in captures[1].split(',') {
            if let Some(module) = part.split_whitespace().next() {
                resolve(0, module, None);
            }
        }
    }
    for captures in py_from_re().captures_iter(text) {
        let dots = captures[1].len();
        let module = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let names = captures[3].replace(['(', ')'], " ");
        let mut any = false;
        for part in names.split(',') {
            if let Some(name) = part.split_whitespace().next() {
                if name != "*" {
                    resolve(dots, module, Some(name));
                    any = true;
                }
            }
        }
        if !any || !module.is_empty() {
            resolve(dots, module, None);
        }
    }
    found.sort();
    found.dedup();
    found
}

fn tarjan(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adj.len();
    let mut index = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut out = Vec::new();
    let mut counter = 0usize;
    for root in 0..n {
        if index[root] != usize::MAX {
            continue;
        }
        index[root] = counter;
        low[root] = counter;
        counter += 1;
        stack.push(root);
        on_stack[root] = true;
        let mut call: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some(&(v, i)) = call.last() {
            if i < adj[v].len() {
                if let Some(top) = call.last_mut() {
                    top.1 += 1;
                }
                let w = adj[v][i];
                if index[w] == usize::MAX {
                    index[w] = counter;
                    low[w] = counter;
                    counter += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    call.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                call.pop();
                if low[v] == index[v] {
                    let mut component = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        component.push(w);
                        if w == v {
                            break;
                        }
                    }
                    out.push(component);
                }
                if let Some(&(parent_node, _)) = call.last() {
                    low[parent_node] = low[parent_node].min(low[v]);
                }
            }
        }
    }
    out
}

fn find_cycles(edges: &EdgeSet) -> Vec<Value> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for ((from, to), edge) in &edges.map {
        if !edge.structural {
            names.insert(from);
            names.insert(to);
        }
    }
    let names: Vec<&str> = names.into_iter().collect();
    let index: HashMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
    for ((from, to), edge) in &edges.map {
        if !edge.structural {
            adj[index[from.as_str()]].push(index[to.as_str()]);
        }
    }
    let mut findings = Vec::new();
    let mut components: Vec<Vec<usize>> = tarjan(&adj)
        .into_iter()
        .filter(|component| component.len() > 1)
        .collect();
    for component in &mut components {
        component.sort_by_key(|node| names[*node]);
    }
    components.sort_by_key(|component| names[component[0]]);
    for component in components {
        let members: Vec<&str> = component.iter().map(|node| names[*node]).collect();
        let member_set: HashSet<usize> = component.iter().copied().collect();
        let start = component[0];
        // Shortest cycle through the first member, by BFS inside the component.
        let mut parent_of: HashMap<usize, usize> = HashMap::new();
        let mut queue = VecDeque::from([start]);
        let mut seen: HashSet<usize> = HashSet::from([start]);
        let mut closing = None;
        'bfs: while let Some(node) = queue.pop_front() {
            for next in &adj[node] {
                if *next == start {
                    closing = Some(node);
                    break 'bfs;
                }
                if member_set.contains(next) && seen.insert(*next) {
                    parent_of.insert(*next, node);
                    queue.push_back(*next);
                }
            }
        }
        let mut cycle_path = vec![names[start].to_owned()];
        if let Some(last) = closing {
            let mut back = vec![last];
            let mut cursor = last;
            while let Some(prev) = parent_of.get(&cursor) {
                back.push(*prev);
                cursor = *prev;
            }
            back.reverse();
            for node in back.into_iter().skip(1) {
                cycle_path.push(names[node].to_owned());
            }
            cycle_path.push(names[start].to_owned());
        } else {
            cycle_path.extend(members.iter().skip(1).map(|m| (*m).to_owned()));
            cycle_path.push(names[start].to_owned());
        }
        let mut consumers: Vec<String> = members.iter().map(|m| (*m).to_owned()).collect();
        for ((from, to), edge) in &edges.map {
            if !edge.structural
                && index
                    .get(to.as_str())
                    .is_some_and(|i| member_set.contains(i))
                && !index
                    .get(from.as_str())
                    .is_some_and(|i| member_set.contains(i))
            {
                consumers.push(from.clone());
            }
        }
        consumers.sort();
        consumers.dedup();
        consumers.truncate(25);
        let candidate = json!({
            "id": format!("architecture.core:cycle:{}", short_hash(&members.join("\n"))),
            "severity": "warning",
            "kind": "import-cycle",
            "path": members[0],
            "title": format!("import cycle across {} files", members.len()),
            "dependencyPath": cycle_path,
            "scenario": format!(
                "a change to {} must be understood together with every file in its import cycle",
                members[0]
            ),
            "affectedConsumers": consumers,
        });
        if let Ok(finding) = super::core::architecture_finding(&candidate) {
            findings.push(finding);
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Docs index
// ---------------------------------------------------------------------------

fn code_span_path(span: &str) -> Option<String> {
    let span = span.trim();
    if span.is_empty() || span.len() > 200 {
        return None;
    }
    if span.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '<' | '>'
                    | '*'
                    | '{'
                    | '}'
                    | '$'
                    | '('
                    | ')'
                    | '='
                    | ','
                    | ';'
                    | '|'
                    | '"'
                    | '\''
                    | '@'
                    | '#'
                    | '?'
                    | '['
                    | ']'
                    | '\\'
                    | ':'
            )
    }) {
        return None;
    }
    let span = span.strip_prefix("./").unwrap_or(span);
    if span.starts_with('/') || span.starts_with('~') || span.starts_with('-') {
        return None;
    }
    if span.split('/').any(|part| part == "..") || !span.contains('/') {
        return None;
    }
    let trimmed = span.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    let has_extension = last.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty()
            && (1..=6).contains(&ext.len())
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
    });
    if !(span.ends_with('/') || has_extension) {
        return None;
    }
    let first = trimmed.split('/').next().unwrap_or("");
    if IGNORED_ROOTS.contains(&first) || PLACEHOLDER_ROOTS.contains(&first) {
        return None;
    }
    Some(trimmed.to_owned())
}

fn build_docs(ctx: &Ctx, facts: &mut Facts) {
    // Every suffix of every file and directory path, so a doc may cite
    // `module/file.rs` without spelling the full repository path.
    let mut known: HashSet<String> = HashSet::new();
    for path in ctx.all.iter().chain(ctx.dirs.iter()) {
        let mut rest = path.as_str();
        known.insert(rest.to_owned());
        while let Some((_, tail)) = rest.split_once('/') {
            known.insert(tail.to_owned());
            rest = tail;
        }
    }
    let exists_exact =
        |rel: &str| rel.is_empty() || ctx.all.contains(rel) || ctx.dirs.contains(rel);
    let mut seen_claims: HashSet<String> = HashSet::new();
    for (doc, text) in &ctx.texts {
        if extension(doc) != "md" {
            continue;
        }
        if doc
            .split('/')
            .any(|segment| DOC_SKIP_SEGMENTS.contains(&segment))
        {
            continue;
        }
        let lower = file_name(doc).to_ascii_lowercase();
        if lower.starts_with("changelog")
            || lower.starts_with("changes")
            || lower.starts_with("history")
        {
            continue;
        }
        let mut headings: Vec<String> = Vec::new();
        let mut cites: BTreeSet<String> = BTreeSet::new();
        let mut in_fence = false;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            if trimmed.starts_with('#') {
                let title = trimmed.trim_start_matches('#');
                if title.starts_with(' ') && headings.len() < 50 {
                    headings.push(title.trim().to_owned());
                }
            }
            let mut found: Vec<(String, bool)> = Vec::new();
            for captures in md_link_re().captures_iter(line) {
                let raw = &captures[1];
                if raw.contains("://")
                    || raw.starts_with('#')
                    || raw.starts_with("mailto:")
                    || raw.starts_with("tel:")
                    || raw.contains(['<', '*', '{'])
                {
                    continue;
                }
                let target = raw.split(['#', '?']).next().unwrap_or("");
                if target.is_empty() || !(target.contains('/') || target.contains('.')) {
                    continue;
                }
                let joined = match target.strip_prefix('/') {
                    Some(rooted) => rooted.to_owned(),
                    None => join(parent(doc), target),
                };
                let Some(normalized) = normalize(&joined) else {
                    continue;
                };
                let first = normalized.split('/').next().unwrap_or("");
                if IGNORED_ROOTS.contains(&first) {
                    continue;
                }
                found.push((normalized, true));
            }
            for captures in md_span_re().captures_iter(line) {
                if let Some(candidate) = code_span_path(&captures[1]) {
                    found.push((candidate, false));
                }
            }
            for (cited, exact_only) in found {
                let claim = format!("{doc} cites {cited}");
                if !seen_claims.insert(claim.clone()) {
                    continue;
                }
                let present = if exact_only {
                    exists_exact(&cited)
                } else {
                    exists_exact(&cited)
                        || exists_exact(&join(parent(doc), &cited))
                        || known.contains(&cited)
                };
                // Existing-path claims are detail only and bounded; a missing
                // path is always kept so the overflow count stays honest.
                if present && facts.claims.len() >= MAX_CLAIMS {
                    continue;
                }
                cites.insert(cited.clone());
                facts.claims.push(json!({
                    "claim": claim,
                    "authority": doc,
                    "status": if present { "unproven" } else { "contradicted" },
                    "evidence": [],
                }));
                if !present {
                    facts.claim_meta.insert(
                        claim.clone(),
                        json!({
                            "id": format!("docs.contract:{}", short_hash(&claim)),
                            "severity": "warning",
                            "kind": "missing-cited-path",
                            "path": doc,
                            "line": index + 1,
                            "cited": cited,
                        }),
                    );
                }
            }
        }
        facts.doc_index.push(json!({
            "path": doc,
            "headings": headings,
            "cites": cites.into_iter().take(100).collect::<Vec<_>>(),
        }));
    }
}

// ---------------------------------------------------------------------------
// Requirement references
// ---------------------------------------------------------------------------

fn build_requirements(ctx: &Ctx, facts: &mut Facts) {
    #[derive(Default)]
    struct Requirement {
        declared: Option<(String, usize)>,
        code: BTreeSet<String>,
        tests: BTreeSet<String>,
    }
    let mut found: BTreeMap<String, Requirement> = BTreeMap::new();
    for (path, text) in &ctx.texts {
        let is_doc = extension(path) == "md";
        if !is_doc && lang_of(path) == Lang::Other {
            continue;
        }
        for hit in req_id_re().find_iter(text) {
            let entry = found.entry(hit.as_str().to_owned()).or_default();
            if is_doc {
                if entry.declared.is_none() {
                    entry.declared = Some((path.clone(), line_of(text, hit.start())));
                }
            } else if is_test_path(path) {
                entry.tests.insert(path.clone());
            } else {
                entry.code.insert(path.clone());
            }
        }
    }
    for (id, requirement) in found {
        let Some((doc, line)) = requirement.declared else {
            continue;
        };
        let (status, severity) = if !requirement.code.is_empty() {
            ("implemented-unverified", "info")
        } else if !requirement.tests.is_empty() {
            ("unproven", "warning")
        } else {
            ("missing", "warning")
        };
        facts.requirements.push(json!({
            "id": id,
            "authority": doc,
            "owner": "unassigned",
            "status": status,
            "evidence": [],
            "path": doc,
            "line": line,
            "severity": severity,
            "covered": status == "implemented-unverified" && !requirement.tests.is_empty(),
            "codeRefs": requirement.code.iter().take(10).collect::<Vec<_>>(),
            "testRefs": requirement.tests.iter().take(10).collect::<Vec<_>>(),
        }));
    }
}

// ---------------------------------------------------------------------------
// Test map and test quality
// ---------------------------------------------------------------------------

fn is_source_candidate(path: &str, text: &str) -> bool {
    let lang = lang_of(path);
    if !matches!(lang, Lang::Rust | Lang::Js | Lang::Python | Lang::Go) {
        return false;
    }
    if is_test_path(path) || path.ends_with(".d.ts") {
        return false;
    }
    let name = file_name(path);
    if is_generated_name(name) {
        return false;
    }
    if matches!(
        name,
        "build.rs" | "__init__.py" | "conftest.py" | "setup.py"
    ) || name.contains(".config.")
        || name.starts_with("index.")
    {
        return false;
    }
    if path.split('/').any(|part| NON_SOURCE_DIRS.contains(&part)) {
        return false;
    }
    let code_lines = text.lines().filter(|line| !line.trim().is_empty()).count();
    // mod.rs/lib.rs/main.rs are usually re-export shells: only real code counts.
    let shell = matches!(name, "mod.rs" | "lib.rs" | "main.rs");
    code_lines >= if shell { MIN_SOURCE_LINES } else { 5 }
}

fn is_generated_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains(".generated.")
        || lower.contains("_generated.")
        || lower.contains(".gen.")
        || lower.contains(".min.")
        || lower.ends_with(".pb.go")
        || lower.ends_with("_pb2.py")
        || lower.ends_with("_pb2_grpc.py")
}

fn build_tests(ctx: &Ctx, facts: &mut Facts) {
    let mut importers: HashMap<&str, Vec<&str>> = HashMap::new();
    for ((from, to), _) in &facts.edges.map {
        importers
            .entry(to.as_str())
            .or_default()
            .push(from.as_str());
    }
    // Per package: names a test file refers to, and test stems.
    let mut words: HashMap<String, HashSet<String>> = HashMap::new();
    let mut subjects: HashMap<String, HashSet<String>> = HashMap::new();
    let mut test_files: Vec<&String> = Vec::new();
    for (path, text) in &ctx.texts {
        if !is_test_path(path) || lang_of(path) == Lang::Other {
            continue;
        }
        test_files.push(path);
        let package = ctx.package_dir(path).to_owned();
        subjects
            .entry(package.clone())
            .or_default()
            .insert(test_subject(path));
        let bucket = words.entry(package).or_default();
        for word in word_re().find_iter(text) {
            bucket.insert(word.as_str().to_owned());
        }
    }
    facts.test_file_count = test_files.len();
    let empty = HashSet::new();
    for (path, text) in &ctx.texts {
        if !is_source_candidate(path, text) {
            continue;
        }
        facts.source_count += 1;
        let package = ctx.package_dir(path);
        let stem = file_stem(file_name(path));
        let inline = lang_of(path) == Lang::Rust
            && (text.contains("#[cfg(test)]") || text.contains("#[test]"));
        let mut tests: BTreeSet<String> = importers
            .get(path.as_str())
            .into_iter()
            .flatten()
            .filter(|from| is_test_path(from))
            .map(|from| (*from).to_owned())
            .collect();
        let named = subjects.get(package).unwrap_or(&empty).contains(stem);
        let referenced = lang_of(path) == Lang::Rust
            && words.get(package).unwrap_or(&empty).contains(stem)
            && !test_files.is_empty();
        if named || referenced {
            for test in &test_files {
                if ctx.package_dir(test) == package && (test_subject(test) == stem || referenced) {
                    tests.insert((*test).clone());
                }
            }
        }
        if facts.test_map.len() < MAX_ITEMS * 2 {
            facts.test_map.push(json!({
                "source": path,
                "tests": tests.iter().take(10).collect::<Vec<_>>(),
                "inlineTests": inline,
            }));
        }
        if !inline && tests.is_empty() && !named && !referenced && facts.test_obs.len() < MAX_ITEMS
        {
            facts.test_obs.push(json!({
                "id": format!("test-quality.core:missing:{}", short_hash(path)),
                "severity": "warning",
                "kind": "missing",
                "path": path,
                "evidencePath": path,
                "contract": "every source file has a corresponding test",
                "subjective": false,
            }));
        }
    }
    for path in test_files {
        let text = &ctx.texts[path];
        let declared = test_decl_re().is_match(text);
        let kind = if fake_assert_re().is_match(text) {
            Some(("fake", "test asserts a constant truth"))
        } else if declared && !assertion_re().is_match(text) {
            Some(("weak", "test declares cases but asserts nothing"))
        } else {
            None
        };
        if let Some((kind, contract)) = kind {
            if facts.test_obs.len() < MAX_ITEMS {
                facts.test_obs.push(json!({
                    "id": format!("test-quality.core:{kind}:{}", short_hash(path)),
                    "severity": "warning",
                    "kind": kind,
                    "path": path,
                    "evidencePath": path,
                    "contract": contract,
                    "subjective": false,
                }));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Framework markers
// ---------------------------------------------------------------------------

fn manifest_framework_dependencies(ctx: &Ctx) -> Vec<(String, String, Vec<String>)> {
    // (package dir, manifest name, lowercase dependency names)
    let mut out = Vec::new();
    for entry in ctx.entries {
        let name = file_name(&entry.path);
        if !is_manifest_name(name) {
            continue;
        }
        let mut dependencies: Vec<String> = entry
            .dependencies
            .iter()
            .map(|dep| dep.to_ascii_lowercase())
            .collect();
        if name.starts_with("requirements") {
            if let Some(text) = ctx.texts.get(&entry.path) {
                for line in text.lines() {
                    let token: String = line
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                        .collect();
                    if !token.is_empty() {
                        dependencies.push(token.to_ascii_lowercase());
                    }
                }
            }
        }
        out.push((
            parent(&entry.path).to_owned(),
            name.to_owned(),
            dependencies,
        ));
    }
    out
}

fn under(dir: &str, path: &str) -> bool {
    dir.is_empty() || path.starts_with(&format!("{dir}/"))
}

fn build_frameworks(ctx: &Ctx, facts: &mut Facts) {
    let manifests = manifest_framework_dependencies(ctx);
    let mut frontend: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut backend: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (dir, name, deps) in &manifests {
        let has = |wanted: &[&str]| deps.iter().any(|dep| wanted.contains(&dep.as_str()));
        if name == "package.json" {
            let components = |exts: &[&str], suffix: Option<&str>| -> BTreeSet<String> {
                ctx.texts
                    .keys()
                    .filter(|path| {
                        under(dir, path)
                            && !is_test_path(path)
                            && exts.iter().any(|ext| path.ends_with(ext))
                            && suffix.is_none_or(|s| path.ends_with(s))
                    })
                    .take(MAX_ITEMS)
                    .cloned()
                    .collect()
            };
            for (framework, wanted, exts, suffix) in [
                ("react", vec!["react"], vec![".tsx", ".jsx"], None),
                ("next", vec!["next"], vec![".tsx", ".jsx"], None),
                (
                    "remix",
                    vec!["@remix-run/react"],
                    vec![".tsx", ".jsx"],
                    None,
                ),
                ("vue", vec!["vue"], vec![".vue"], None),
                ("nuxt", vec!["nuxt"], vec![".vue"], None),
                ("svelte", vec!["svelte"], vec![".svelte"], None),
                ("astro", vec!["astro"], vec![".astro"], None),
                (
                    "angular",
                    vec!["@angular/core"],
                    vec![".ts"],
                    Some(".component.ts"),
                ),
            ] {
                if has(&wanted) {
                    frontend
                        .entry(framework)
                        .or_default()
                        .extend(components(&exts, suffix));
                }
            }
            for (framework, wanted) in [
                ("express", vec!["express"]),
                ("fastify", vec!["fastify"]),
                ("nest", vec!["@nestjs/core"]),
            ] {
                if has(&wanted) {
                    backend.entry(framework).or_default().insert(dir.clone());
                }
            }
        } else if name == "pyproject.toml" || name.starts_with("requirements") {
            for (framework, wanted) in [
                ("django", "django"),
                ("fastapi", "fastapi"),
                ("flask", "flask"),
            ] {
                if deps.iter().any(|dep| dep == wanted) {
                    backend.entry(framework).or_default().insert(dir.clone());
                }
            }
        } else if name == "Cargo.toml" {
            if has(&["axum", "actix-web", "rocket", "warp", "poem"]) {
                backend.entry("rust-web").or_default().insert(dir.clone());
            }
        } else if name == "go.mod"
            && deps.iter().any(|dep| {
                [
                    "go-chi/chi",
                    "gorilla/mux",
                    "gin-gonic/gin",
                    "labstack/echo",
                    "julienschmidt/httprouter",
                ]
                .iter()
                .any(|wanted| dep.contains(wanted))
            })
        {
            backend.entry("go-router").or_default().insert(dir.clone());
        }
    }
    for (name, components) in frontend {
        facts.frontend.push(json!({
            "name": name,
            "components": components.iter().map(|path| json!({"path": path})).collect::<Vec<_>>(),
        }));
    }
    for (name, dirs) in backend {
        let mut routes: Vec<Value> = Vec::new();
        'files: for (path, text) in &ctx.texts {
            if !dirs.iter().any(|dir| under(dir, path)) || is_test_path(path) {
                continue;
            }
            let mut push = |method: &str, route: &str, offset: usize| -> bool {
                if routes.len() >= MAX_ITEMS {
                    return false;
                }
                let route = if route.is_empty() { "/" } else { route };
                routes.push(json!({
                    "method": method.to_ascii_uppercase(),
                    "path": route,
                    "file": path,
                    "line": line_of(text, offset),
                    "auth": "unknown",
                }));
                true
            };
            let lang = lang_of(path);
            let mut ok = true;
            match (name, lang) {
                ("express" | "fastify", Lang::Js) => {
                    for c in route_js_re().captures_iter(text) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("nest", Lang::Js) => {
                    for c in route_nest_re().captures_iter(text) {
                        let route = c.get(2).map_or("", |m| m.as_str());
                        ok &= push(&c[1], route, c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("fastapi" | "flask", Lang::Python) => {
                    for c in route_py_re().captures_iter(text) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("django", Lang::Python) if file_name(path) == "urls.py" => {
                    for c in route_django_re().captures_iter(text) {
                        ok &= push("any", &c[1], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("rust-web", Lang::Rust) => {
                    for c in route_axum_re().captures_iter(text) {
                        ok &= push("any", &c[1], c.get(0).map_or(0, |m| m.start()));
                    }
                    for c in route_attr_re().captures_iter(text) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("go-router", Lang::Go) => {
                    for c in route_go_re().captures_iter(text) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                _ => {}
            }
            if !ok {
                break 'files;
            }
        }
        facts.backend.push(json!({"name": name, "routes": routes}));
    }
    for path in ctx
        .texts
        .keys()
        .chain(ctx.all.iter())
        .collect::<BTreeSet<_>>()
    {
        let name = file_name(path);
        let ext = extension(path);
        let is_model = ext == "prisma"
            || (ext == "sql" && (path.contains("migrat") || path.contains("schema")))
            || name == "models.py"
            || name == "schema.rs"
            || name.ends_with(".entity.ts")
            || name.ends_with(".model.ts")
            || name.ends_with(".model.js");
        if is_model && facts.data_models.len() < MAX_ITEMS {
            facts.data_models.push(json!({"path": path, "kind": name}));
        }
    }
}

// ---------------------------------------------------------------------------
// Per-provider shaping
// ---------------------------------------------------------------------------

fn producer_note(facts: &Facts) -> Value {
    json!({"kind": "self-sourced", "filesRead": facts.files_read})
}

/// Builds the analyzer input for `provider`, or names why it cannot be derived.
pub fn produce(facts: &Facts, provider: &str) -> Production {
    let producer = producer_note(facts);
    match provider {
        "architecture.core" => {
            if facts.edges.map.is_empty() {
                return Production::Unavailable(
                    "architecture-graph-empty:no-internal-import-edges-resolved".into(),
                );
            }
            let edges: Vec<Value> = facts
                .edges
                .map
                .iter()
                .map(|((from, to), edge)| json!({"from": from, "to": to, "kind": edge.kind}))
                .collect();
            Production::Input(json!({
                "projection": {
                    "auditFacts": {"dependencyEdges": edges},
                    "manifests": facts.manifests,
                },
                "producer": producer,
            }))
        }
        "compatibility.core" => Production::Unavailable(
            "compatibility-observations-not-derivable:requires-bound-producer-consumer-evidence"
                .into(),
        ),
        "docs.contract" => {
            if facts.claims.is_empty() {
                return Production::Unavailable("no-document-path-citations-found".into());
            }
            Production::Input(json!({
                "artifacts": {"docClaims": facts.claims},
                "docIndex": facts.doc_index,
                "producer": producer,
            }))
        }
        "requirements.traceability" => {
            if facts.requirements.is_empty() {
                return Production::Unavailable("no-requirement-ids-declared-in-docs".into());
            }
            Production::Input(json!({
                "artifacts": {"requirements": facts.requirements},
                "producer": producer,
            }))
        }
        "test-quality.core" => {
            if facts.source_count == 0 && facts.test_file_count == 0 {
                return Production::Unavailable("no-source-or-test-files-found".into());
            }
            Production::Input(json!({
                "artifacts": {"testQuality": facts.test_obs},
                "testMap": facts.test_map,
                "producer": producer,
            }))
        }
        "framework.backend" => {
            if facts.backend.is_empty() {
                return Production::Unavailable("no-backend-framework-detected".into());
            }
            Production::Input(json!({
                "artifacts": {"backendFrameworks": facts.backend},
                "producer": producer,
            }))
        }
        "framework.frontend" => {
            if facts.frontend.is_empty() {
                return Production::Unavailable("no-frontend-framework-detected".into());
            }
            Production::Input(json!({
                "artifacts": {"frontendFrameworks": facts.frontend},
                "producer": producer,
            }))
        }
        "framework.data" => {
            if facts.data_models.is_empty() {
                return Production::Unavailable("no-data-model-files-detected".into());
            }
            Production::Input(json!({
                "artifacts": {"dataModels": facts.data_models},
                "producer": producer,
            }))
        }
        other => Production::Unavailable(format!("no-producer-for:{other}")),
    }
}

/// Adjusts an analyzer result produced from self-sourced input: attaches the
/// producer's locations to findings, folds in producer coverage gaps, and
/// reports `examined` as files actually read.
pub fn reconcile(facts: &Facts, provider: &str, analysis: &mut Analysis) {
    match provider {
        "architecture.core" => analysis.findings = facts.cycles.clone(),
        "docs.contract" => {
            for finding in &mut analysis.findings {
                let meta = finding
                    .get("claim")
                    .and_then(Value::as_str)
                    .and_then(|claim| facts.claim_meta.get(claim));
                if let (Some(Value::Object(meta)), Some(object)) = (meta, finding.as_object_mut()) {
                    for (key, value) in meta {
                        object.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        "requirements.traceability" => {
            analysis
                .findings
                .retain(|finding| finding.get("covered") != Some(&Value::Bool(true)));
            for finding in &mut analysis.findings {
                if let Some(object) = finding.as_object_mut() {
                    if let Some(id) = object.get("id").and_then(Value::as_str).map(str::to_owned) {
                        object.insert("requirement".into(), Value::String(id.clone()));
                        object.insert(
                            "id".into(),
                            Value::String(format!("requirements.traceability:{id}")),
                        );
                    }
                }
            }
        }
        "test-quality.core" => {
            if facts.test_obs.is_empty() {
                // The producer's denominator is the files it classified: a
                // clean scan is a measured zero, not an empty denominator.
                analysis.coverage_gaps.retain(|g| {
                    g.get("kind").and_then(Value::as_str) != Some("test-quality-denominator-zero")
                });
                if analysis.coverage_gaps.is_empty() {
                    analysis.status = "pass".into();
                    analysis.complete = true;
                }
            }
        }
        _ => {}
    }
    if matches!(provider, "docs.contract" | "test-quality.core")
        && analysis.findings.len() > MAX_FINDINGS
    {
        let remainder = analysis.findings.len() - MAX_FINDINGS;
        analysis.findings.truncate(MAX_FINDINGS);
        analysis
            .coverage_gaps
            .push(gap(&format!("{provider}:findings-overflow:{remainder}")));
        analysis.complete = false;
        if analysis.status == "pass" || analysis.status == "measured" {
            analysis.status = "unproven".into();
        }
    }
    for kind in &facts.gaps {
        analysis.coverage_gaps.push(gap(kind));
    }
    if !facts.gaps.is_empty() {
        analysis.complete = false;
        if analysis.status == "pass" || analysis.status == "measured" {
            analysis.status = "unproven".into();
        }
    }
    if !analysis.findings.is_empty() && analysis.status != "unproven" {
        analysis.status = "fail".into();
        analysis.complete = false;
    }
    if let Some(object) = analysis.denominator.as_object_mut() {
        object.insert("examined".into(), Value::from(facts.files_read));
    }
}
