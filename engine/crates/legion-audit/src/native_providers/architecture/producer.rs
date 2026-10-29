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
//! - Native frontend/data evidence proves selected source bytes were observed;
//!   it is not an immutable-storage, tool-execution or verification receipt.
//!   Backend auth, verified requirements & compatibility keep their own gaps.

use super::{
    common::{gap, Analysis},
    evidence::{source_reference, SourceObservation},
};
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

// Literal source facts only: no mounted path composition or runtime auth claim.
// Lexical filtering rejects unsupported multiline strings before anchored matching.
// Computed/array routes remain absent facts, never invented route values.
lazy_re!(
    route_spring_re,
    r#"(?m)^[ \t]*@(Get|Post|Put|Patch|Delete)Mapping\([ \t]*(?:(?:value|path)[ \t]*=[ \t]*)?"([^"\r\n]+)"[ \t]*\)"#
);
lazy_re!(
    route_ktor_re,
    r#"(?m)^[ \t]*(get|post|put|patch|delete)\([ \t]*"([^"\r\n]+)"[ \t]*\)"#
);
lazy_re!(
    route_aspnet_re,
    r#"(?m)^[ \t]*(?:app|group)\.Map(Get|Post|Put|Patch|Delete)\([ \t]*"([^"\r\n]+)"[ \t]*,"#
);
lazy_re!(
    route_rails_re,
    r#"(?m)^[ \t]*(get|post|put|patch|delete)[ \t]+['"]([^'"\r\n]+)['"]"#
);
lazy_re!(
    route_laravel_re,
    r#"(?m)^[ \t]*Route::(get|post|put|patch|delete)\([ \t]*['"]([^'"\r\n]+)['"][ \t]*,"#
);
lazy_re!(
    aspnet_sdk_re,
    r#"(?s)^\s*(?:<\?xml[^?]*\?>\s*)?<Project\b[^>]*\bSdk[ \t]*=[ \t]*['"]Microsoft\.NET\.Sdk\.Web['"]"#
);

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

fn is_backend_manifest_name(name: &str) -> bool {
    is_manifest_name(name)
        || matches!(
            name,
            "pom.xml" | "build.gradle" | "build.gradle.kts" | "Gemfile" | "composer.json"
        )
        || name.ends_with(".csproj")
}

fn retain(path: &str) -> bool {
    lang_of(path) != Lang::Other
        || extension(path) == "md"
        || is_backend_manifest_name(file_name(path))
        || matches!(
            extension(path).as_str(),
            "java" | "kt" | "cs" | "rb" | "php"
        )
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
    pub(super) sources: BTreeMap<String, SourceObservation>,
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
    /// Inventory files with an extension only frontend frameworks use.
    frontend_source_files: usize,
    /// Inventory files in a server-capable language. Broad on purpose: a
    /// framework the producer does not detect must keep its gap.
    backend_source_files: usize,
    /// Inventory paths that could hold a data model. Broader than the models
    /// `build_frameworks` recognises, so an unrecognised model keeps its gap.
    data_hint_files: usize,
}

/// Extensions only frontend frameworks use. Plain `.js` is deliberately absent.
const FRONTEND_SOURCE_EXTENSIONS: &[&str] = &["jsx", "tsx", "vue", "svelte", "astro", "hbs"];

/// Server-capable source extensions.
const BACKEND_SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "py", "go", "java", "kt", "scala",
    "rb", "php", "cs", "fs", "vb",
];

fn is_data_hint(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["model", "schema", "migrat", "entity"]
        .iter()
        .any(|hint| lower.contains(*hint))
        || matches!(
            extension(path).as_str(),
            "prisma" | "sql" | "graphql" | "gql"
        )
}

impl Facts {
    /// Typed reason the framework provider has nothing to analyse, or `None`
    /// when it applies. Absence needs an empty detection AND no inventory file
    /// that could carry the framework; any such file keeps the provider's gap.
    pub fn framework_absence(&self, provider: &str) -> Option<&'static str> {
        match provider {
            "framework.frontend" => (self.frontend.is_empty() && self.frontend_source_files == 0)
                .then_some("no-frontend-files-in-inventory"),
            "framework.backend" => (self.backend.is_empty() && self.backend_source_files == 0)
                .then_some("no-backend-files-in-inventory"),
            "framework.data" => (self.data_models.is_empty() && self.data_hint_files == 0)
                .then_some("no-data-files-in-inventory"),
            _ => None,
        }
    }
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

/// Reads one denominator file within the caps. An absent text means the file was
/// examined but has no analyzable text (symlink or non-UTF-8).
fn load(
    root: &Path,
    entry: &InventoryEntry,
    budget: &mut u64,
) -> Result<(Option<String>, Option<SourceObservation>), &'static str> {
    let full = root.join(&entry.path);
    let meta = std::fs::symlink_metadata(&full).map_err(|_| "unreadable")?;
    if meta.file_type().is_symlink() {
        return Ok((None, None));
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
    let observation = SourceObservation::from_bytes(&entry.path, &bytes);
    Ok((String::from_utf8(bytes).ok(), Some(observation)))
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
            Ok((text, observation)) => {
                facts.files_read += 1;
                if let Some(observation) = observation {
                    facts.sources.insert(entry.path.clone(), observation);
                }
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
    for path in &ctx.all {
        let ext = extension(path);
        if FRONTEND_SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            facts.frontend_source_files += 1;
        }
        if BACKEND_SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            facts.backend_source_files += 1;
        }
        if is_data_hint(path) {
            facts.data_hint_files += 1;
        }
    }
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

fn xml_without_comments(text: &str) -> String {
    static COMMENT: OnceLock<Regex> = OnceLock::new();
    COMMENT
        .get_or_init(|| Regex::new(r"(?s)<!--.*?-->").expect("XML comment regex"))
        .replace_all(text, "")
        .into_owned()
}

// Literal readers retain route argument strings, but reject lexical forms
// requiring a language parser before matching any route. Newlines inside an
// ordinary quoted Ruby/PHP string are legal: their contents are never code.
fn backend_lexical(text: &str, name: &str) -> (String, bool) {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let mut quote = None;
    let mut unsupported = name == "laravel" && !text.trim_start().starts_with("<?php");
    while i < bytes.len() {
        if let Some(delimiter) = quote {
            if bytes[i] == b'\\' {
                if bytes.get(i + 1) == Some(&b'\n') {
                    unsupported = true;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
            if matches!(bytes[i], b'\n' | b'\r') {
                unsupported = true;
            }
            if (name == "rails" && bytes[i..].starts_with(b"#{"))
                || (name == "laravel" && bytes[i..].starts_with(b"{$"))
            {
                unsupported = true;
            }
            if bytes[i] == delimiter {
                quote = None;
            }
            i += 1;
        } else if (!matches!(name, "rails") && bytes[i..].starts_with(b"//"))
            || (matches!(name, "rails" | "laravel") && bytes[i] == b'#')
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
        } else if name != "rails" && bytes[i..].starts_with(b"/*") {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                if bytes[i..].starts_with(b"/*") {
                    unsupported = true;
                }
                if !matches!(bytes[i], b'\n' | b'\r') {
                    out[i] = b' ';
                }
                i += 1;
            }
            if i + 1 < bytes.len() {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
            } else {
                unsupported = true;
            }
        } else {
            if bytes[i..].starts_with(b"\"\"\"")
                || bytes[i..].starts_with(b"<<")
                || bytes[i] == b'`'
                || (name == "aspnet" && bytes[i..].starts_with(b"@\""))
                || (name == "rails" && matches!(bytes[i], b'%' | b'/'))
                || (name == "rails" && bytes[i..].starts_with(b"=begin"))
                || (name == "laravel" && bytes[i..].starts_with(b"?>"))
            {
                unsupported = true;
            }
            if matches!(bytes[i], b'\'' | b'"') {
                quote = Some(bytes[i]);
            }
            i += 1;
        }
    }
    (
        String::from_utf8(out).expect("only ASCII comment bytes replaced"),
        unsupported || quote.is_some(),
    )
}

fn manifest_framework_dependencies(ctx: &Ctx) -> Vec<(String, String, Vec<String>)> {
    // (package dir, manifest name, lowercase dependency names)
    let mut out = Vec::new();
    for entry in ctx.entries {
        let name = file_name(&entry.path);
        if !is_backend_manifest_name(name) {
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
        if let Some(text) = ctx.texts.get(&entry.path) {
            if name == "composer.json" {
                if let Ok(value) = serde_json::from_str::<Value>(text) {
                    if value
                        .get("require")
                        .and_then(Value::as_object)
                        .is_some_and(|items| items.contains_key("laravel/framework"))
                    {
                        dependencies.push("laravel/framework".into());
                    }
                }
            } else if matches!(name, "build.gradle" | "build.gradle.kts") {
                // Inventory's shallow coordinate parser omits versioned literals.
                // Keep original frozen inventory intact; read this named manifest.
                static COORDINATE: OnceLock<Regex> = OnceLock::new();
                let (lexical, unsupported) = backend_lexical(text, "gradle");
                if !unsupported {
                    for capture in COORDINATE.get_or_init(|| Regex::new(
                        r#"(?m)^[ \t]*(?:implementation|api|compile|compileOnly|runtimeOnly)[ \t]*\(?[ \t]*["']([^"':\s]+):([^"':\s]+)(?::[^"'\s]+)?["']"#
                    ).expect("Gradle dependency regex")).captures_iter(&lexical) {
                        dependencies.push(format!("{}:{}", &capture[1], &capture[2]).to_ascii_lowercase());
                    }
                }
            } else if name.ends_with(".csproj")
                && aspnet_sdk_re().is_match(&xml_without_comments(text))
            {
                dependencies.push("microsoft.net.sdk.web".into());
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
        } else if matches!(
            name.as_str(),
            "pom.xml" | "build.gradle" | "build.gradle.kts"
        ) {
            if deps.iter().any(|dep| {
                dep.starts_with("org.springframework:")
                    || dep.starts_with("org.springframework.boot:")
                    || dep == "org.springframework.boot"
            }) {
                backend.entry("spring").or_default().insert(dir.clone());
            }
            if deps
                .iter()
                .any(|dep| dep.starts_with("io.ktor:") || dep == "io.ktor.plugin")
            {
                backend.entry("ktor").or_default().insert(dir.clone());
            }
        } else if name.ends_with(".csproj") && has(&["microsoft.net.sdk.web"]) {
            backend.entry("aspnet").or_default().insert(dir.clone());
        } else if name == "Gemfile" && has(&["rails"]) {
            backend.entry("rails").or_default().insert(dir.clone());
        } else if name == "composer.json" && has(&["laravel/framework"]) {
            backend.entry("laravel").or_default().insert(dir.clone());
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
        if components.len() > MAX_ITEMS {
            facts.gaps.push(format!(
                "producer-frontend-component-cap:{name}:{MAX_ITEMS}"
            ));
        }
        facts.frontend.push(json!({
            "name": name,
            "components": components.iter().take(MAX_ITEMS).map(|path| json!({
                "path": path, "evidenceRefs": [source_reference(path)],
            })).collect::<Vec<_>>(),
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
            let bounded_reader_source = match name {
                "spring" => matches!(extension(path).as_str(), "java" | "kt"),
                "ktor" => extension(path) == "kt",
                "aspnet" => extension(path) == "cs",
                "rails" => path.ends_with("config/routes.rb"),
                "laravel" => {
                    extension(path) == "php" && path.split('/').any(|part| part == "routes")
                }
                _ => false,
            };
            let (lexical, unsupported) = if bounded_reader_source {
                backend_lexical(text, name)
            } else {
                (String::new(), false)
            };
            if unsupported {
                facts
                    .gaps
                    .push(format!("producer-backend-source-syntax-unsupported:{path}"));
                continue;
            }
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
                ("spring", _) if matches!(extension(path).as_str(), "java" | "kt") => {
                    for c in route_spring_re().captures_iter(&lexical) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("ktor", _) if extension(path) == "kt" => {
                    for c in route_ktor_re().captures_iter(&lexical) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("aspnet", _) if extension(path) == "cs" => {
                    for c in route_aspnet_re().captures_iter(&lexical) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("rails", _) if path.ends_with("config/routes.rb") => {
                    for c in route_rails_re().captures_iter(&lexical) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                ("laravel", _)
                    if extension(path) == "php" && path.split('/').any(|part| part == "routes") =>
                {
                    for c in route_laravel_re().captures_iter(&lexical) {
                        ok &= push(&c[1], &c[2], c.get(0).map_or(0, |m| m.start()));
                    }
                }
                _ => {}
            }
            if !ok {
                facts
                    .gaps
                    .push(format!("producer-backend-route-cap:{name}:{MAX_ITEMS}"));
                break 'files;
            }
        }
        facts.backend.push(json!({"name": name, "routes": routes}));
    }
    let mut model_overflow = false;
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
        if is_model {
            if facts.data_models.len() < MAX_ITEMS {
                facts.data_models.push(json!({
                    "path": path, "kind": name, "evidenceRefs": [source_reference(path)],
                }));
            } else {
                model_overflow = true;
            }
        }
    }
    if model_overflow {
        facts
            .gaps
            .push(format!("producer-data-model-cap:{MAX_ITEMS}"));
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

/// Folds signed, verified runtime observations (issue #63) into the analysis
/// of `provider`. This is the only path by which `compatibility.core` and
/// `framework.backend` can learn of runtime probe results; `produce` keeps its
/// default (observations unavailable) when none were verified. Satisfies only
/// the plan-named probes against the bound subject and never claims general
/// authentication or compatibility correctness. Call regardless of whether
/// the input was self-sourced.
pub fn apply_observations(
    provider: &str,
    analysis: &mut Analysis,
    verdicts: &[crate::artifact_evidence::ObservationVerdict],
) {
    match provider {
        "compatibility.core" => super::compatibility::apply_observations(analysis, verdicts),
        "framework.backend" => super::framework::apply_backend_observations(analysis, verdicts),
        _ => {}
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
    let mut producer_incomplete = false;
    for kind in &facts.gaps {
        if (kind.starts_with("producer-frontend-component-cap:")
            && provider != "framework.frontend")
            || (kind.starts_with("producer-data-model-cap:") && provider != "framework.data")
            || ((kind.starts_with("producer-backend-route-cap:")
                || kind.starts_with("producer-backend-source-syntax-unsupported:"))
                && provider != "framework.backend")
        {
            continue;
        }
        analysis.coverage_gaps.push(gap(kind));
        producer_incomplete = true;
    }
    if producer_incomplete {
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

/// Self-sourced producers for the assurance-extension providers: structure
/// facts (`architecture.structure`), nginx configuration facts
/// (`framework.nginx`) and the PostgreSQL facts merged into `framework.data`.
///
/// Every denominator file is either read (bounded, digest-verified) or named
/// in a `file-skipped:<reason>:<path>` gap. None of these producers connects to a
/// service, runs a binary or reads a discovered credential; runtime and
/// executed-database evidence only ever arrives as authenticated imports, so
/// source-only results stay `unproven`.
pub mod assurance {
    use super::{extension, file_name, parent};
    use crate::native_providers::{
        architecture::{
            common::{gap, string_gap, Analysis},
            nginx::{self, ConfigOrigin, NginxContext, NginxFileInput, NginxPolicy},
            postgres::{self, PostgresAnalysis, PostgresContext, PostgresSourceFile},
            structure::{self, StructureConfig, StructureFileInput},
        },
        code::producer::{read_frozen, MAX_FILE_BYTES, MAX_TOTAL_BYTES},
    };
    use crate::InventoryEntry;
    use serde_json::{json, Value};
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::Path,
    };

    /// Repository declaration of infrastructure facts the source cannot
    /// prove: `{"postgres": {...}, "nginx": {"default"|"roots": {...}}}`.
    /// Declared facts only bind version/phase context; they never replace
    /// authenticated evidence (`contractCompatVerified` and `tableRows` are
    /// refused) and never override template/rendered origin.
    pub const INFRASTRUCTURE_DECLARATION_PATH: &str = ".legion/infrastructure.json";

    /// Frozen repository declarations for the architecture providers.
    #[derive(Clone, Debug, Default)]
    pub struct DeclaredContext {
        pub infrastructure: Option<Value>,
        pub infrastructure_declared: bool,
        /// Declaration read/parse defects and refused fields; always gaps.
        pub gaps: BTreeSet<String>,
        pub runtime: crate::runtime_obligations::RuntimeDeclarations,
    }

    /// Read `.legion/infrastructure.json`, `.legion/journeys.json`,
    /// `.legion/rust-targets.json` and Cargo manifests from the frozen
    /// inventory (digest-verified). An unreadable declared file is a gap.
    pub fn load_declared_context(
        root: Option<&Path>,
        inventory: &crate::inventory::InventoryEnvelope,
    ) -> DeclaredContext {
        let wanted: Vec<&InventoryEntry> = inventory
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.path.as_str(),
                    INFRASTRUCTURE_DECLARATION_PATH
                        | crate::runtime_obligations::JOURNEY_DECLARATION_PATH
                        | crate::runtime_obligations::RUST_MATRIX_DECLARATION_PATH
                ) || file_name(&entry.path) == "Cargo.toml"
            })
            .collect();
        let read = read_frozen(root, wanted, MAX_FILE_BYTES, MAX_TOTAL_BYTES);
        let mut out = DeclaredContext {
            runtime: crate::runtime_obligations::RuntimeDeclarations::from_inventory(
                inventory,
                |path| read.files.get(path).cloned(),
            ),
            ..DeclaredContext::default()
        };
        if inventory
            .entries
            .iter()
            .any(|entry| entry.path == INFRASTRUCTURE_DECLARATION_PATH)
        {
            out.infrastructure_declared = true;
            match read
                .files
                .get(INFRASTRUCTURE_DECLARATION_PATH)
                .map(|bytes| serde_json::from_slice::<Value>(bytes))
            {
                Some(Ok(value)) if value.is_object() => out.infrastructure = Some(value),
                Some(_) => {
                    out.gaps.insert(format!(
                        "infrastructure-declaration-invalid:{INFRASTRUCTURE_DECLARATION_PATH}"
                    ));
                }
                None => {
                    out.gaps.insert(format!(
                        "infrastructure-declaration-unreadable:{INFRASTRUCTURE_DECLARATION_PATH}"
                    ));
                }
            }
        }
        out
    }

    /// Fields that only authenticated evidence may supply.
    const EVIDENCE_ONLY_POSTGRES: &[&str] = &["contractCompatVerified", "tableRows"];

    /// PostgresContext from the declaration. Unknown stays unset (a gap in the
    /// analyzer); refused fields and malformed values become gaps.
    pub fn postgres_context(declared: &DeclaredContext) -> (PostgresContext, BTreeSet<String>) {
        let mut context = PostgresContext::default();
        let mut gaps = BTreeSet::new();
        let Some(section) = declared
            .infrastructure
            .as_ref()
            .and_then(|value| value.get("postgres"))
        else {
            return (context, gaps);
        };
        let Some(object) = section.as_object() else {
            gaps.insert("infrastructure-declaration-invalid:postgres".into());
            return (context, gaps);
        };
        for field in EVIDENCE_ONLY_POSTGRES {
            if object.contains_key(*field) {
                gaps.insert(format!(
                    "infrastructure-declaration-refused:postgres.{field}:requires-authenticated-evidence"
                ));
            }
        }
        if let Some(value) = object.get("serverMajor") {
            match value.as_u64().and_then(|n| u32::try_from(n).ok()) {
                Some(major) if major > 0 => context.server_major = Some(major),
                _ => {
                    gaps.insert("infrastructure-declaration-invalid:postgres.serverMajor".into());
                }
            }
        }
        if let Some(value) = object.get("searchPath") {
            match value.as_array().map(|items| {
                items
                    .iter()
                    .map(|i| i.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            }) {
                Some(Some(path)) => context.search_path = Some(path),
                _ => {
                    gaps.insert("infrastructure-declaration-invalid:postgres.searchPath".into());
                }
            }
        }
        if let Some(value) = object.get("baselineTables") {
            match value.as_array().map(|items| {
                items
                    .iter()
                    .map(|i| i.as_str().map(str::to_owned))
                    .collect::<Option<BTreeSet<_>>>()
            }) {
                Some(Some(tables)) => context.baseline_tables = tables,
                _ => {
                    gaps.insert(
                        "infrastructure-declaration-invalid:postgres.baselineTables".into(),
                    );
                }
            }
        }
        if let Some(value) = object.get("phases") {
            match value.as_object() {
                Some(phases) => {
                    for (path, phase) in phases {
                        match phase.as_str() {
                            Some("expand") => {
                                context
                                    .phases
                                    .insert(path.clone(), postgres::MigrationPhase::Expand);
                            }
                            Some("contract") => {
                                context
                                    .phases
                                    .insert(path.clone(), postgres::MigrationPhase::Contract);
                            }
                            _ => {
                                gaps.insert(format!(
                                    "infrastructure-declaration-invalid:postgres.phases:{path}"
                                ));
                            }
                        }
                    }
                }
                None => {
                    gaps.insert("infrastructure-declaration-invalid:postgres.phases".into());
                }
            }
        }
        if let Some(value) = object.get("transactionWrapped") {
            match value.as_object() {
                Some(map) => {
                    for (path, wrapped) in map {
                        match wrapped.as_bool() {
                            Some(flag) => {
                                context.transaction_wrapped.insert(path.clone(), flag);
                            }
                            None => {
                                gaps.insert(format!(
                                    "infrastructure-declaration-invalid:postgres.transactionWrapped:{path}"
                                ));
                            }
                        }
                    }
                }
                None => {
                    gaps.insert(
                        "infrastructure-declaration-invalid:postgres.transactionWrapped".into(),
                    );
                }
            }
        }
        if let Some(value) = object.get("lockTimeoutDeclared") {
            match value.as_bool() {
                Some(flag) => context.lock_timeout_declared = flag,
                None => {
                    gaps.insert(
                        "infrastructure-declaration-invalid:postgres.lockTimeoutDeclared".into(),
                    );
                }
            }
        }
        (context, gaps)
    }

    fn valid_semver(version: &str) -> bool {
        let parts: Vec<&str> = version.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Declared nginx binding for the configuration root `dir` (`""` = repository
    /// root): `nginx.roots[dir]`, else `nginx.default`. Origin is not
    /// declarable. `None` leaves the analyzer's unbound-context gaps in force.
    pub fn nginx_context_for_root(
        declared: &DeclaredContext,
        dir: &str,
        origin: ConfigOrigin,
    ) -> (NginxContext, BTreeSet<String>) {
        let mut context = NginxContext {
            origin,
            ..NginxContext::default()
        };
        let mut gaps = BTreeSet::new();
        let Some(nginx) = declared
            .infrastructure
            .as_ref()
            .and_then(|value| value.get("nginx"))
        else {
            return (context, gaps);
        };
        let key = if dir.is_empty() { "." } else { dir };
        let Some(section) = nginx
            .get("roots")
            .and_then(|roots| roots.get(key))
            .or_else(|| nginx.get("default"))
        else {
            return (context, gaps);
        };
        let Some(object) = section.as_object() else {
            gaps.insert(format!("infrastructure-declaration-invalid:nginx.{key}"));
            return (context, gaps);
        };
        if object.contains_key("origin") {
            gaps.insert(format!(
                "infrastructure-declaration-refused:nginx.{key}.origin:derived-from-files"
            ));
        }
        if let Some(value) = object.get("mainFile") {
            match value
                .as_str()
                .filter(|v| !v.is_empty() && !v.starts_with('/') && !v.contains(".."))
            {
                Some(main) => context.main_file = main.to_owned(),
                None => {
                    gaps.insert(format!(
                        "infrastructure-declaration-invalid:nginx.{key}.mainFile"
                    ));
                }
            }
        }
        if let Some(value) = object.get("confPrefix") {
            match value
                .as_str()
                .filter(|v| v.starts_with('/') && !v.contains(".."))
            {
                Some(prefix) => context.conf_prefix = prefix.to_owned(),
                None => {
                    gaps.insert(format!(
                        "infrastructure-declaration-invalid:nginx.{key}.confPrefix"
                    ));
                }
            }
        }
        if let Some(value) = object.get("version") {
            match value.as_str().filter(|v| valid_semver(v)) {
                Some(version) => context.version = Some(version.to_owned()),
                None => {
                    gaps.insert(format!(
                        "infrastructure-declaration-invalid:nginx.{key}.version"
                    ));
                }
            }
        }
        if let Some(value) = object.get("modules") {
            match value.as_array().map(|items| {
                items
                    .iter()
                    .map(|i| i.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            }) {
                Some(Some(modules)) => context.modules = Some(modules),
                _ => {
                    gaps.insert(format!(
                        "infrastructure-declaration-invalid:nginx.{key}.modules"
                    ));
                }
            }
        }
        (context, gaps)
    }

    /// Attach the stack's runtime-obligation gaps and detail to `analysis`.
    /// Absence of declared journeys is an explicit gap, never silence.
    pub fn attach_runtime_obligations(
        analysis: &mut Analysis,
        declared: &DeclaredContext,
        stack: crate::runtime_obligations::Stack,
    ) {
        if !declared.runtime.stacks.contains(&stack) {
            return;
        }
        let gaps = declared.runtime.gaps_for_stack(stack);
        let known: BTreeSet<String> = analysis.coverage_gaps.iter().map(string_gap).collect();
        for item in &gaps {
            if !known.contains(item) {
                analysis.coverage_gaps.push(gap(item));
            }
        }
        analysis.extras.insert(
            "runtimeObligations".into(),
            json!({
                "stack": stack.label(),
                "gaps": gaps,
                "report": declared.runtime.provider_report(),
            }),
        );
        if !analysis.coverage_gaps.is_empty() {
            analysis.complete = false;
            if analysis.status == "pass" || analysis.status == "measured" {
                analysis.status = "unproven".into();
            }
        }
    }

    /// Frozen Blueprint artifact for structure analysis. The plan carries it
    /// in the provider configuration: `blueprintArtifact` (a `legion-graph/1`
    /// document) and `blueprintResolverDigest`.
    #[derive(Clone, Debug)]
    pub struct BlueprintInput {
        pub artifact: Value,
        pub resolver_config_digest: String,
    }

    /// The plan-carried Blueprint input, when both pieces are frozen.
    pub fn blueprint_from_configuration(
        configuration: &BTreeMap<String, Value>,
    ) -> Option<BlueprintInput> {
        let artifact = configuration.get("blueprintArtifact")?.clone();
        let resolver = configuration
            .get("blueprintResolverDigest")
            .and_then(Value::as_str)
            .filter(|digest| !digest.is_empty())?;
        Some(BlueprintInput {
            artifact,
            resolver_config_digest: resolver.to_owned(),
        })
    }

    pub const STRUCTURE_PROVIDER_ID: &str = "architecture.structure";
    pub const NGINX_PROVIDER_ID: &str = "framework.nginx";

    /// Facts larger than this stay in the analyzer; the result carries a
    /// summary and a named gap instead of an unbounded JSON blob.
    const MAX_FACTS_JSON_BYTES: usize = 8 * 1024 * 1024;
    const MAX_POSTGRES_FILES: usize = 2_000;
    const TEMPLATE_SUFFIXES: &[&str] = &[".template", ".tpl", ".tmpl", ".j2", ".erb", ".envsubst"];

    /// Structure facts over the frozen denominator. Facts are native evidence,
    /// never a verdict: with no Blueprint graph the analyzer names
    /// `blueprint-unavailable` and the result is `unproven`.
    pub fn produce_structure(root: Option<&Path>, entries: &[InventoryEntry]) -> Analysis {
        produce_structure_with(root, entries, None)
    }

    /// `produce_structure` with the plan-carried Blueprint graph. The graph is
    /// passed to the analyzer only when it validates against the exact frozen
    /// bytes read (`bound-to-frozen-covered-bytes`); a rejected or absent graph
    /// is an explicit gap and the lexical floor remains.
    pub fn produce_structure_with(
        root: Option<&Path>,
        entries: &[InventoryEntry],
        blueprint: Option<&BlueprintInput>,
    ) -> Analysis {
        let read = read_frozen(root, entries.iter(), MAX_FILE_BYTES, MAX_TOTAL_BYTES);
        let mut gaps: BTreeSet<String> = read
            .skips
            .iter()
            .map(|skip| format!("file-skipped:{skip}"))
            .collect();
        let mut inputs = Vec::new();
        for (path, bytes) in &read.files {
            match std::str::from_utf8(bytes) {
                Ok(text) => inputs.push(StructureFileInput {
                    path: path.clone(),
                    text: text.to_owned(),
                }),
                Err(_) => {
                    gaps.insert(format!("file-skipped:non-utf8:{path}"));
                }
            }
        }
        let graph = blueprint.and_then(|blueprint| {
            let context = crate::graph_context::build_graph_context(
                &read.files,
                Some(&blueprint.artifact),
                &blueprint.resolver_config_digest,
            );
            if context.freshness == "bound-to-frozen-covered-bytes" {
                Some(context)
            } else {
                gaps.insert(format!("graph-context-rejected:{}", context.freshness));
                None
            }
        });
        let facts =
            structure::analyze_structure(&inputs, graph.as_ref(), &StructureConfig::default());
        gaps.extend(facts.gaps.iter().cloned());
        if facts.partial {
            gaps.insert("structure-partial".into());
        }
        let value = serde_json::to_value(&facts).unwrap_or(Value::Null);
        let facts_value = if value.to_string().len() <= MAX_FACTS_JSON_BYTES {
            value
        } else {
            gaps.insert("structure-facts-truncated-in-result".into());
            json!({"truncated": true})
        };
        let complete = gaps.is_empty();
        let mut analysis = Analysis::new(
            if complete { "measured" } else { "unproven" },
            complete,
            json!({
                "kind": "structure-files",
                "expected": entries.len(),
                "examined": read.files.len(),
            }),
        );
        analysis.include_findings = false;
        analysis.coverage_gaps = gaps.iter().map(|item| gap(item)).collect();
        analysis.extras.insert(
            "structureSummary".into(),
            json!({
                "files": facts.files.len(),
                "duplicates": facts.duplicates.len(),
                "unusedCandidates": facts.unused_candidates.len(),
                "suggestions": facts.suggestions.len(),
                "exclusions": facts.exclusions.len(),
                "provesDeadCode": facts.proves_dead_code,
            }),
        );
        analysis.extras.insert("structureFacts".into(), facts_value);
        analysis
    }

    /// Nginx configuration facts and policy candidates. Configuration is
    /// grouped by the directory holding an `nginx.conf` (its configuration
    /// root); files outside every root are named gaps. Source configuration
    /// never binds the deployed effective configuration, so the analyzer's
    /// `effective-config-unbound` gap keeps the result `unproven` until a
    /// rendered/`nginx -T` input is analyzed.
    pub fn produce_nginx(
        root: Option<&Path>,
        entries: &[InventoryEntry],
        input: &Value,
    ) -> Analysis {
        produce_nginx_with(root, entries, input, &DeclaredContext::default())
    }

    /// `produce_nginx` with repository-declared per-root context
    /// (`nginx.roots[<dir>]` / `nginx.default`). Undeclared fields stay unbound.
    pub fn produce_nginx_with(
        root: Option<&Path>,
        entries: &[InventoryEntry],
        input: &Value,
        declared: &DeclaredContext,
    ) -> Analysis {
        let read = read_frozen(root, entries.iter(), MAX_FILE_BYTES, MAX_TOTAL_BYTES);
        let mut gaps: BTreeSet<String> = read
            .skips
            .iter()
            .map(|skip| format!("file-skipped:{skip}"))
            .collect();
        let mut texts: BTreeMap<String, String> = BTreeMap::new();
        for (path, bytes) in &read.files {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    texts.insert(path.clone(), text.to_owned());
                }
                Err(_) => {
                    gaps.insert(format!("file-skipped:non-utf8:{path}"));
                }
            }
        }
        let policy = match input.get("nginxPolicy") {
            None | Some(Value::Null) => NginxPolicy::default(),
            Some(value) => match serde_json::from_value::<NginxPolicy>(value.clone()) {
                Ok(policy) => policy,
                Err(_) => {
                    gaps.insert("input-invalid:nginxPolicy".into());
                    NginxPolicy::default()
                }
            },
        };
        let mut roots: BTreeSet<String> = texts
            .keys()
            .filter(|path| file_name(path) == "nginx.conf")
            .map(|path| parent(path).to_owned())
            .collect();
        if roots.is_empty() {
            // No main file: analyze everything as one root so the analyzer
            // names `main-config-missing` instead of the files vanishing.
            roots.insert(String::new());
        }
        let mut groups: BTreeMap<String, Vec<NginxFileInput>> = BTreeMap::new();
        let mut template_roots: BTreeSet<String> = BTreeSet::new();
        for (path, text) in &texts {
            let owner = roots
                .iter()
                .filter(|dir| dir.is_empty() || path.starts_with(&format!("{dir}/")))
                .max_by_key(|dir| dir.len())
                .cloned();
            let Some(owner) = owner else {
                gaps.insert(format!("nginx-config-unrooted:{path}"));
                continue;
            };
            let relative = if owner.is_empty() {
                path.clone()
            } else {
                path[owner.len() + 1..].to_owned()
            };
            let lower = path.to_ascii_lowercase();
            if TEMPLATE_SUFFIXES
                .iter()
                .any(|suffix| lower.ends_with(suffix))
                || text.contains("{{")
                || text.contains("${")
            {
                template_roots.insert(owner.clone());
            }
            groups.entry(owner).or_default().push(NginxFileInput {
                path: relative,
                text: text.clone(),
            });
        }
        let multiple = roots.len() > 1;
        let mut findings: Vec<Value> = Vec::new();
        let mut rows: Vec<Value> = Vec::new();
        for (dir, inputs) in &groups {
            let (context, context_gaps) = nginx_context_for_root(
                declared,
                dir,
                if template_roots.contains(dir) {
                    ConfigOrigin::Template
                } else {
                    ConfigOrigin::Source
                },
            );
            gaps.extend(context_gaps);
            let analysis = nginx::analyze_nginx(inputs, &context, &policy, &[]);
            let label = if dir.is_empty() { "." } else { dir.as_str() };
            for finding in &analysis.findings {
                let mut finding = finding.clone();
                if let Some(object) = finding.as_object_mut() {
                    if !dir.is_empty() {
                        if let Some(path) = object.get("path").and_then(Value::as_str) {
                            let original = path.to_owned();
                            object.insert("path".into(), json!(format!("{dir}/{original}")));
                            object.insert("configPath".into(), json!(original));
                        }
                    }
                    if multiple {
                        if let Some(id) = object.get("id").and_then(Value::as_str) {
                            let scoped = format!("{label}:{id}");
                            object.insert("id".into(), json!(scoped));
                        }
                    }
                }
                findings.push(finding);
            }
            for item in &analysis.coverage_gaps {
                gaps.insert(string_gap(item));
            }
            rows.push(json!({
                "root": label,
                "files": inputs.len(),
                "status": analysis.status,
                "delivery": analysis.extras.get("delivery").cloned().unwrap_or(Value::Null),
                "nginxFacts": analysis.extras.get("nginxFacts").cloned().unwrap_or(Value::Null),
                "nginxGaps": analysis.extras.get("nginxGaps").cloned().unwrap_or(Value::Null),
                "runtimeAssertions": analysis
                    .extras
                    .get("runtimeAssertions")
                    .cloned()
                    .unwrap_or(Value::Null),
            }));
        }
        let complete = gaps.is_empty() && findings.is_empty();
        let status = if !gaps.is_empty() {
            "unproven"
        } else if !findings.is_empty() {
            "fail"
        } else {
            "pass"
        };
        let mut analysis = Analysis::new(
            status,
            complete,
            json!({
                "kind": "nginx-config",
                "expected": entries.len(),
                "examined": texts.len(),
                "roots": groups.len(),
            }),
        );
        analysis.findings = findings;
        analysis.coverage_gaps = gaps.iter().map(|item| gap(item)).collect();
        analysis.extras.insert(
            "nginxContextSource".into(),
            json!(if declared.infrastructure.is_some() {
                "repository-declaration"
            } else {
                "default-unbound"
            }),
        );
        analysis
            .extras
            .insert("nginxRoots".into(), Value::Array(rows));
        for item in &declared.gaps {
            analysis.coverage_gaps.push(gap(item));
        }
        attach_runtime_obligations(
            &mut analysis,
            declared,
            crate::runtime_obligations::Stack::Nginx,
        );
        if !analysis.coverage_gaps.is_empty() && analysis.complete {
            analysis.complete = false;
            analysis.status = "unproven".into();
        }
        analysis
    }

    fn is_postgres_candidate(path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        let name = file_name(&lower);
        let ext = extension(&lower);
        matches!(ext.as_str(), "sql" | "yml" | "yaml" | "toml")
            || name.starts_with("dockerfile")
            || name.starts_with("docker-compose")
            || name.contains("tool-versions")
            || name.ends_with(".env.example")
            || ((lower.contains("migrat") || lower.contains("alembic"))
                && matches!(ext.as_str(), "py" | "js" | "ts" | "mjs" | "cjs" | "rb"))
    }

    /// PostgreSQL migration/config facts over the frozen denominator. `None`
    /// when no candidate file could be read. Read failures count as gaps only
    /// when PostgreSQL is detected, so an unrelated unreadable YAML never
    /// makes a non-PostgreSQL repository incomplete.
    pub fn analyze_postgres_denominator(
        root: Option<&Path>,
        entries: &[InventoryEntry],
    ) -> Option<PostgresAnalysis> {
        analyze_postgres_denominator_with(root, entries, &DeclaredContext::default())
    }

    /// `analyze_postgres_denominator` with the repository-declared context
    /// (`postgres` section of `.legion/infrastructure.json`). Refused or
    /// malformed declarations become gaps; unknown stays unset.
    pub fn analyze_postgres_denominator_with(
        root: Option<&Path>,
        entries: &[InventoryEntry],
        declared: &DeclaredContext,
    ) -> Option<PostgresAnalysis> {
        let mut candidates: Vec<&InventoryEntry> = entries
            .iter()
            .filter(|entry| is_postgres_candidate(&entry.path))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let capped = candidates.len().saturating_sub(MAX_POSTGRES_FILES);
        candidates.truncate(MAX_POSTGRES_FILES);
        let read = read_frozen(
            root,
            candidates.iter().copied(),
            MAX_FILE_BYTES,
            MAX_TOTAL_BYTES,
        );
        let mut skipped: Vec<String> = read
            .skips
            .iter()
            .map(|skip| format!("postgres-source-skipped:{skip}"))
            .collect();
        if capped > 0 {
            skipped.push(format!("postgres-source-cap:+{capped}"));
        }
        let files: Vec<PostgresSourceFile> = read
            .files
            .iter()
            .filter_map(|(path, bytes)| {
                std::str::from_utf8(bytes)
                    .ok()
                    .map(|text| PostgresSourceFile {
                        path: path.clone(),
                        text: text.to_owned(),
                    })
            })
            .collect();
        if files.is_empty() {
            return None;
        }
        let (context, context_gaps) = postgres_context(declared);
        let mut analysis = postgres::analyze_postgres(&files, &context);
        if analysis.applicable {
            analysis.gaps.extend(skipped);
            analysis.gaps.extend(context_gaps);
            analysis.gaps.extend(declared.gaps.iter().cloned());
            analysis.gaps.extend(
                declared
                    .runtime
                    .gaps_for_stack(crate::runtime_obligations::Stack::Postgres),
            );
        }
        Some(analysis)
    }

    /// Folds PostgreSQL findings, gaps and facts into the `framework.data`
    /// analysis. A repository where PostgreSQL is not detected keeps its
    /// analysis unchanged apart from a typed `postgres` fact.
    pub fn merge_postgres(analysis: &mut Analysis, postgres: PostgresAnalysis) {
        if !postgres.applicable {
            analysis
                .extras
                .insert("postgres".into(), json!({"applicable": false}));
            return;
        }
        let converted = postgres.into_analysis();
        if let Some(facts) = converted.extras.get("postgres") {
            analysis.extras.insert("postgres".into(), facts.clone());
        }
        let known: BTreeSet<String> = analysis.coverage_gaps.iter().map(string_gap).collect();
        for item in &converted.coverage_gaps {
            if !known.contains(&string_gap(item)) {
                analysis.coverage_gaps.push(item.clone());
            }
        }
        if !converted.findings.is_empty() {
            analysis.findings.extend(converted.findings);
            analysis.include_findings = true;
        }
        if !analysis.coverage_gaps.is_empty() {
            analysis.complete = false;
            if analysis.status == "pass" || analysis.status == "measured" {
                analysis.status = "unproven".into();
            }
        }
        if !analysis.findings.is_empty() && analysis.status != "unproven" {
            analysis.status = "fail".into();
            analysis.complete = false;
        }
    }
}
