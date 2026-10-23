//! Native structural facts for decomposition, dead-code-candidate and
//! minimize review (packet A09). Pure facts only: this module never emits a
//! defect, severity or release outcome. Thresholds only prioritise human
//! investigation, mirroring `native_decomposition` in `legacy_checks`
//! (size is a review trigger, never proof decomposition is needed) and the
//! ponytail/minimize false-positive discipline (DI/test/security seams and
//! legitimate barrels are preserved, mechanical `partNN`/`include!` splits
//! aggregate back to one logical module).
//!
//! Parser honesty: `legion-audit` has no tree-sitter/grammar dependency, so
//! every language here is measured with the crate's existing lexical support
//! and records `grammar = "lexical-<lang>/1"`. Root approves any missing
//! grammar dependency before that label can change. Unbalanced or otherwise
//! unsupported syntax yields `ParseStatus::Partial` with `metrics: None` —
//! never zero complexity, never clean. No second cross-language symbol graph
//! is built: callers/entrypoints come from the canonical
//! [`crate::graph_context::GraphContext`] (Blueprint) when supplied, else
//! from bounded lexical facts, and no-callers is never deletion proof
//! (`certifies_dead` is always `false`, as in `BlastRadiusContext`).

use crate::graph_context::GraphContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const STRUCTURE_FACTS_VERSION: u32 = 1;
pub const METRIC_SUITE_VERSION: &str = "structure-metrics/1";
pub const TOKEN_NORMALIZER_VERSION: &str = "token-normalize/1";
/// Mirrors the decomposition workspace default review trigger (LOC).
pub const DEFAULT_REVIEW_LOC_THRESHOLD: u64 = 400;
pub const DEFAULT_DUPLICATE_MIN_TOKENS: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructureLanguage {
    Rust,
    TypeScript,
    JavaScript,
    Swift,
    Kotlin,
}

impl StructureLanguage {
    pub fn from_path(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Self::Rust,
            "ts" | "tsx" | "mts" | "cts" => Self::TypeScript,
            "js" | "jsx" | "mjs" | "cjs" => Self::JavaScript,
            "swift" => Self::Swift,
            "kt" | "kts" => Self::Kotlin,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::JavaScript => "javascript",
            Self::Swift => "swift",
            Self::Kotlin => "kotlin",
        }
    }
    /// Existing parser support in this crate is lexical; recorded verbatim so
    /// cross-language metrics always carry grammar/version context.
    pub fn grammar(self) -> &'static str {
        match self {
            Self::Rust => "lexical-rust/1",
            Self::TypeScript => "lexical-typescript/1",
            Self::JavaScript => "lexical-javascript/1",
            Self::Swift => "lexical-swift/1",
            Self::Kotlin => "lexical-kotlin/1",
        }
    }
    fn branch_keywords(self) -> &'static [&'static str] {
        match self {
            Self::Rust => &["if", "match", "while", "for", "loop", "&&", "||", "?"],
            Self::TypeScript | Self::JavaScript => &[
                "if", "else", "switch", "case", "while", "for", "catch", "&&", "||", "?",
            ],
            Self::Swift => &[
                "if", "guard", "switch", "case", "while", "for", "catch", "&&", "||",
            ],
            Self::Kotlin => &["if", "when", "while", "for", "catch", "&&", "||"],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ParseStatus {
    Parsed,
    /// Unsupported/unbalanced syntax: metrics are absent, never zero.
    Partial {
        reason: String,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructureFileInput {
    pub path: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructureConfig {
    pub review_loc_threshold: u64,
    pub duplicate_min_tokens: usize,
    /// Root-qualified token languages for which native duplication may replace
    /// jscpd. Empty until root records a qualification; unqualified duplicate
    /// spans remain facts with `qualified: false`.
    pub qualified_token_languages: BTreeSet<StructureLanguage>,
    /// Reviewer/root-supplied invariant evidence, keyed by normalized span
    /// digest. A shared-abstraction suggestion exists only with this.
    pub shared_invariants: Vec<SharedInvariant>,
}

impl Default for StructureConfig {
    fn default() -> Self {
        Self {
            review_loc_threshold: DEFAULT_REVIEW_LOC_THRESHOLD,
            duplicate_min_tokens: DEFAULT_DUPLICATE_MIN_TOKENS,
            qualified_token_languages: BTreeSet::new(),
            shared_invariants: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedInvariant {
    pub normalized_digest: String,
    pub invariant: String,
    pub owner: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMetric {
    pub name: String,
    pub start_line: u64,
    pub end_line: u64,
    pub code_lines: u64,
    /// Branch-keyword count inside the lexical span (cyclomatic proxy + 1 is
    /// the reviewer's to derive; the raw count is the fact).
    pub branch_count: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetrics {
    pub physical_lines: u64,
    pub nonblank_lines: u64,
    pub code_lines: u64,
    pub comment_lines: u64,
    pub token_count: u64,
    pub max_nesting_depth: u64,
    pub branch_count: u64,
    pub functions: Vec<FunctionMetric>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UncertaintyKind {
    DynamicImport,
    Reflection,
    RouteDiscovery,
    MacroExpansion,
    SwiftSelector,
    AndroidResource,
    R8Shrinking,
    GeneratedBinding,
    Entrypoint,
    PublicApi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeamKind {
    DependencyInjection,
    Test,
    Security,
    Barrel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionReason {
    VendorPath,
    GeneratedPath,
    GeneratedMarker,
    MinifiedArtifact,
    UnsupportedLanguage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exclusion {
    pub path: String,
    pub reason: ExclusionReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentFacts {
    pub path: String,
    /// Top-level declaration names (lexical): the responsibilities a reviewer
    /// judges for coherence. Many names is a fact, not a defect.
    pub responsibilities: Vec<String>,
    pub state: Vec<String>,
    pub effects: Vec<String>,
    /// Files with a graph/lexical edge into this file, `path (confidence)`.
    pub callers: Vec<String>,
    pub seams: Vec<SeamKind>,
    /// One-implementation abstractions found; a seam above explains why they
    /// are not automatic `yagni`.
    pub single_impl_abstractions: Vec<String>,
    pub investigation_priority: InvestigationPriority,
    pub priority_reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvestigationPriority {
    /// Includes clean large coherent modules and preserved seams/barrels.
    None,
    Review,
    Elevated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileStructure {
    pub path: String,
    pub language: StructureLanguage,
    pub grammar: String,
    pub metric_suite: String,
    pub parse_status: ParseStatus,
    /// `None` iff parse is partial/unsupported — never zero-filled.
    pub metrics: Option<FileMetrics>,
    pub uncertainties: Vec<UncertaintyKind>,
    pub component: ComponentFacts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DuplicateKind {
    Exact,
    Near,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanRef {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateSpan {
    pub kind: DuplicateKind,
    pub language: StructureLanguage,
    pub grammar: String,
    pub token_normalizer: String,
    pub token_count: u64,
    pub normalized_digest: String,
    pub occurrences: Vec<SpanRef>,
    /// True only when root qualified this token language/metric; only then
    /// may native duplication stand in for jscpd.
    pub qualified: bool,
    /// Present only with root/reviewer invariant + ownership evidence.
    pub shared_abstraction: Option<SharedInvariant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnusedCandidate {
    pub symbol: String,
    pub path: String,
    pub line: u64,
    /// `no-graph-callers` | `no-lexical-callers` — a lead, never proof.
    pub evidence: String,
    pub uncertainties: Vec<UncertaintyKind>,
    /// Always `false`: reflexion/routes/macros/selectors/resources keep any
    /// no-callers symbol uncertified. Deletion is a reviewer decision.
    pub certifies_dead: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalModule {
    pub id: String,
    pub member_paths: Vec<String>,
    /// Member metrics summed: a mechanical split keeps its logical size.
    pub aggregated_code_lines: u64,
    pub aggregated_branch_count: u64,
    pub aggregated_function_count: u64,
    pub mechanical_split: bool,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinimizeSuggestion {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    /// Behavior-preserving boundary: the declaration/duplicate span that can
    /// be extracted without moving observable behavior.
    pub extraction_boundary: String,
    pub state_ownership: String,
    pub callers: Vec<String>,
    pub estimated_line_savings: u64,
    /// Line savings never set severity or release outcome.
    pub severity: Option<String>,
    pub release_outcome_effect: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructureFacts {
    pub version: u32,
    pub metric_suite: String,
    pub token_normalizer: String,
    pub files: Vec<FileStructure>,
    pub duplicates: Vec<DuplicateSpan>,
    pub unused_candidates: Vec<UnusedCandidate>,
    pub logical_modules: Vec<LogicalModule>,
    pub suggestions: Vec<MinimizeSuggestion>,
    /// Generated/vendor/unsupported inputs, recorded — never silently dropped.
    pub exclusions: Vec<Exclusion>,
    /// Token languages with at least one qualified duplicate span.
    pub replaces_jscpd_for: Vec<StructureLanguage>,
    pub partial: bool,
    pub gaps: Vec<String>,
    /// Always `false`, mirroring `BlastRadiusContext::proves_dead_code`.
    pub proves_dead_code: bool,
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Transparent exclusion classification (generated/vendor stay recorded).
pub fn classify_exclusion(path: &str, text: &str) -> Option<ExclusionReason> {
    let normalized = path.replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();
    if segments
        .iter()
        .any(|s| matches!(*s, "vendor" | "node_modules" | "third_party" | "Pods"))
    {
        return Some(ExclusionReason::VendorPath);
    }
    let name = file_name(&normalized).to_ascii_lowercase();
    if name.contains(".min.") {
        return Some(ExclusionReason::MinifiedArtifact);
    }
    if segments
        .iter()
        .any(|s| matches!(*s, "generated" | "gen" | "__generated__"))
        || name.contains(".g.")
        || name.contains(".pb.")
        || name.contains(".generated.")
    {
        return Some(ExclusionReason::GeneratedPath);
    }
    let head: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
    if head.contains("@generated")
        || head.contains("Code generated")
        || head.contains("DO NOT EDIT")
        || head.contains("auto-generated")
    {
        return Some(ExclusionReason::GeneratedMarker);
    }
    None
}

/// Dynamic reachability barriers. Presence of any keeps no-callers symbols
/// in the containing file uncertified.
pub fn detect_uncertainties(
    language: StructureLanguage,
    path: &str,
    text: &str,
) -> Vec<UncertaintyKind> {
    let mut found = BTreeSet::new();
    let has = |needles: &[&str]| needles.iter().any(|n| text.contains(n));
    if has(&["import(", "require(", "System.import", "__import__"]) {
        found.insert(UncertaintyKind::DynamicImport);
    }
    if has(&[
        "reflect",
        "Reflect.",
        "Class.forName",
        "::class",
        "NSClassFromString",
        "objc_msgSend",
        "getattr",
        "eval(",
        "Function(",
        "KClass",
        "Mirror(",
    ]) {
        found.insert(UncertaintyKind::Reflection);
    }
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    if lower.contains("/routes/")
        || lower.contains("/app/")
        || file_name(&lower).starts_with("page.")
        || file_name(&lower).starts_with("route.")
        || file_name(&lower).starts_with("routes.")
        || has(&[
            "@Get(",
            "@Post(",
            "@Route",
            "#[get(",
            "#[post(",
            ".route(",
            "@Composable",
        ])
    {
        found.insert(UncertaintyKind::RouteDiscovery);
    }
    if language == StructureLanguage::Rust
        && has(&["macro_rules!", "proc_macro", "#[derive", "include!("])
    {
        found.insert(UncertaintyKind::MacroExpansion);
    }
    if language == StructureLanguage::Swift
        && has(&["@objc", "#selector", "Selector(", "@IBAction", "@IBOutlet"])
    {
        found.insert(UncertaintyKind::SwiftSelector);
    }
    if language == StructureLanguage::Kotlin {
        if has(&[
            "R.",
            "resources.getIdentifier",
            "@AndroidEntryPoint",
            "R8",
            "keepnames",
        ]) {
            found.insert(UncertaintyKind::AndroidResource);
        }
        if has(&["proguard", "minifyEnabled", "shrinkResources"]) {
            found.insert(UncertaintyKind::R8Shrinking);
        }
    }
    if has(&[
        "@Generated",
        "generated binding",
        "ViewBinding",
        "GeneratedMessage",
    ]) {
        found.insert(UncertaintyKind::GeneratedBinding);
    }
    let name = file_name(&lower);
    if matches!(
        name,
        "main.rs"
            | "lib.rs"
            | "mod.rs"
            | "main.ts"
            | "main.tsx"
            | "main.js"
            | "main.swift"
            | "mainactivity.kt"
            | "application.kt"
    ) || name.starts_with("index.")
        || has(&["@main", "fn main(", "fun main(", "static void Main"])
    {
        found.insert(UncertaintyKind::Entrypoint);
    }
    found.into_iter().collect()
}

/// Strip strings/comments crudely for brace accounting; an unbalanced result
/// marks the file partial rather than fabricating metrics.
fn brace_profile(text: &str) -> Option<(u64, Vec<i64>)> {
    let mut depth: i64 = 0;
    let mut max_depth = 0u64;
    let mut per_line_depth = Vec::new();
    let mut in_block_comment = false;
    for line in text.lines() {
        let mut chars = line.chars().peekable();
        let mut quote: Option<char> = None;
        while let Some(c) = chars.next() {
            if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            if let Some(q) = quote {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' | '`' => quote = Some(c),
                '/' if chars.peek() == Some(&'/') => break,
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    in_block_comment = true;
                }
                '{' => {
                    depth += 1;
                    max_depth = max_depth.max(depth as u64);
                }
                '}' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return None;
            }
        }
        per_line_depth.push(depth);
    }
    (depth == 0 && !in_block_comment).then_some((max_depth, per_line_depth))
}

#[derive(Clone, Debug)]
pub struct NormalizedToken {
    /// Exact token text (identifiers/literals preserved).
    pub exact: String,
    /// Near form: identifiers -> `ID`, literals -> `LIT`.
    pub near: String,
    pub line: u64,
}

/// Token-normalized stream shared by metrics and duplicate detection.
/// Comments are dropped; literals stay as one token.
pub fn tokenize_normalized(text: &str) -> Vec<NormalizedToken> {
    let mut tokens = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_no = index as u64 + 1;
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c.is_whitespace() {
                i += 1;
            } else if line[i..].starts_with("//") {
                break;
            } else if c == '"' || c == '\'' || c == '`' {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] as char != c {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(bytes.len());
                tokens.push(NormalizedToken {
                    exact: line[start..i].to_owned(),
                    near: "LIT".into(),
                    line: line_no,
                });
            } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
                let start = i;
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'$')
                {
                    i += 1;
                }
                let word = &line[start..i];
                let keyword = is_keyword(word);
                tokens.push(NormalizedToken {
                    exact: word.to_owned(),
                    near: if keyword {
                        word.to_owned()
                    } else {
                        "ID".into()
                    },
                    line: line_no,
                });
            } else if c.is_ascii_digit() {
                let start = i;
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'.')
                {
                    i += 1;
                }
                tokens.push(NormalizedToken {
                    exact: line[start..i].to_owned(),
                    near: "LIT".into(),
                    line: line_no,
                });
            } else {
                // Keep two-char operators the metrics count as branches.
                let two = line.get(i..i + 2).unwrap_or("");
                if ["&&", "||", "=>", "::", "?.", "??"].contains(&two) {
                    tokens.push(NormalizedToken {
                        exact: two.into(),
                        near: two.into(),
                        line: line_no,
                    });
                    i += 2;
                } else {
                    let ch_len = line[i..].chars().next().map(char::len_utf8).unwrap_or(1);
                    tokens.push(NormalizedToken {
                        exact: line[i..i + ch_len].to_owned(),
                        near: line[i..i + ch_len].to_owned(),
                        line: line_no,
                    });
                    i += ch_len;
                }
            }
        }
    }
    tokens
}

fn is_keyword(word: &str) -> bool {
    matches!(
        word,
        "fn" | "let"
            | "mut"
            | "if"
            | "else"
            | "match"
            | "for"
            | "while"
            | "loop"
            | "return"
            | "pub"
            | "struct"
            | "enum"
            | "trait"
            | "impl"
            | "use"
            | "mod"
            | "const"
            | "static"
            | "function"
            | "var"
            | "class"
            | "interface"
            | "export"
            | "import"
            | "from"
            | "switch"
            | "case"
            | "try"
            | "catch"
            | "new"
            | "typeof"
            | "func"
            | "guard"
            | "protocol"
            | "extension"
            | "fun"
            | "val"
            | "object"
            | "when"
            | "suspend"
            | "package"
            | "in"
            | "is"
            | "as"
            | "this"
            | "self"
            | "Self"
            | "true"
            | "false"
            | "null"
            | "nil"
            | "await"
            | "async"
            | "throws"
            | "throw"
            | "break"
            | "continue"
            | "where"
            | "type"
            | "data"
            | "sealed"
            | "override"
            | "private"
            | "public"
            | "internal"
            | "final"
            | "open"
    )
}

fn identifier_after(line: &str, marker: &str) -> Option<String> {
    let rest = line.split(marker).nth(1)?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn declared_symbols(language: StructureLanguage, text: &str) -> Vec<(String, u64, bool)> {
    // (name, line, exported/public)
    let mut symbols = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let line_no = index as u64 + 1;
        let exported = trimmed.starts_with("pub ")
            || trimmed.starts_with("pub(")
            || trimmed.starts_with("export ")
            || trimmed.contains("public ")
            || trimmed.contains("open ")
            || language == StructureLanguage::Kotlin && !trimmed.contains("private ");
        let name = match language {
            StructureLanguage::Rust => identifier_after(trimmed, "fn "),
            StructureLanguage::Swift => identifier_after(trimmed, "func "),
            StructureLanguage::Kotlin => identifier_after(trimmed, "fun "),
            StructureLanguage::TypeScript | StructureLanguage::JavaScript => {
                identifier_after(trimmed, "function ").or_else(|| {
                    (trimmed.starts_with("const ") || trimmed.starts_with("export const "))
                        .then(|| identifier_after(trimmed, "const "))
                        .flatten()
                        .filter(|_| trimmed.contains("=>") || trimmed.contains('('))
                })
            }
        };
        if let Some(name) = name {
            if !symbols.iter().any(|(n, _, _)| n == &name) {
                symbols.push((name, line_no, exported));
            }
        }
    }
    symbols
}

fn top_level_responsibilities(language: StructureLanguage, text: &str) -> Vec<String> {
    let markers: &[&str] = match language {
        StructureLanguage::Rust => &["struct ", "enum ", "trait ", "impl ", "fn ", "mod "],
        StructureLanguage::TypeScript | StructureLanguage::JavaScript => &[
            "class ",
            "interface ",
            "function ",
            "const ",
            "type ",
            "enum ",
        ],
        StructureLanguage::Swift => &["struct ", "class ", "enum ", "protocol ", "actor ", "func "],
        StructureLanguage::Kotlin => &["class ", "object ", "interface ", "fun ", "data class "],
    };
    let mut names = Vec::new();
    for line in text.lines() {
        // Top level = no leading indent (lexical approximation, grammar-noted).
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let trimmed = line
            .trim_start_matches("pub ")
            .trim_start_matches("export ")
            .trim_start_matches("default ")
            .trim_start_matches("public ")
            .trim_start_matches("final ");
        for marker in markers {
            if let Some(name) = trimmed.strip_prefix(marker).and_then(|rest| {
                let name: String = rest
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty()).then_some(name)
            }) {
                let label = format!("{}{name}", marker.trim());
                if !names.contains(&label) {
                    names.push(label);
                }
                break;
            }
        }
    }
    names
}

fn occurrences_of(text: &str, needles: &[&str]) -> Vec<String> {
    needles
        .iter()
        .filter(|needle| text.contains(**needle))
        .map(|needle| (*needle).to_owned())
        .collect()
}

fn state_and_effects(language: StructureLanguage, text: &str) -> (Vec<String>, Vec<String>) {
    let (state, effects): (&[&str], &[&str]) = match language {
        StructureLanguage::Rust => (
            &[
                "static mut",
                "Mutex<",
                "RwLock<",
                "RefCell<",
                "Atomic",
                "OnceLock<",
            ],
            &[
                "std::fs::",
                "Command::new",
                "reqwest",
                "tokio::spawn",
                "println!",
            ],
        ),
        StructureLanguage::TypeScript | StructureLanguage::JavaScript => (
            &[
                "useState(",
                "useReducer(",
                "useRef(",
                "createSignal(",
                "useStore(",
                "$state(",
            ],
            &[
                "useEffect(",
                "useVisibleTask$(",
                "fetch(",
                "addEventListener(",
                "setInterval(",
                "setTimeout(",
            ],
        ),
        StructureLanguage::Swift => (
            &[
                "@State",
                "@StateObject",
                "@ObservedObject",
                "@Published",
                "@Binding",
                "@AppStorage",
            ],
            &[
                ".task",
                ".onAppear",
                "URLSession",
                "Task {",
                "NotificationCenter",
            ],
        ),
        StructureLanguage::Kotlin => (
            &[
                "mutableStateOf(",
                "remember {",
                "StateFlow",
                "MutableState",
                "by lazy",
            ],
            &[
                "LaunchedEffect(",
                "DisposableEffect(",
                "SideEffect",
                "viewModelScope.launch",
                "Retrofit",
            ],
        ),
    };
    (occurrences_of(text, state), occurrences_of(text, effects))
}

fn measure_file(
    language: StructureLanguage,
    text: &str,
    tokens: &[NormalizedToken],
) -> (ParseStatus, Option<FileMetrics>) {
    let Some((max_depth, per_line_depth)) = brace_profile(text) else {
        return (
            ParseStatus::Partial {
                reason: "unbalanced-braces-unsupported-syntax".into(),
            },
            None,
        );
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut metrics = FileMetrics {
        physical_lines: lines.len() as u64,
        max_nesting_depth: max_depth,
        token_count: tokens.len() as u64,
        ..FileMetrics::default()
    };
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        metrics.nonblank_lines += 1;
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            metrics.comment_lines += 1;
        } else {
            metrics.code_lines += 1;
        }
    }
    let branches = language.branch_keywords();
    metrics.branch_count = tokens
        .iter()
        .filter(|t| branches.contains(&t.exact.as_str()))
        .count() as u64;
    // Lexical function spans: from a declaration line until brace depth
    // returns to the depth at that line. Nested decls share the outer span.
    let symbols = declared_symbols(language, text);
    for (name, start, _) in &symbols {
        let start_idx = (*start as usize).saturating_sub(1);
        let base = if start_idx == 0 {
            0
        } else {
            per_line_depth.get(start_idx - 1).copied().unwrap_or(0)
        };
        let mut end = lines.len();
        for idx in start_idx..lines.len() {
            if idx > start_idx && per_line_depth.get(idx).copied().unwrap_or(0) <= base {
                end = idx + 1;
                break;
            }
        }
        let span_tokens = tokens
            .iter()
            .filter(|t| t.line >= *start && t.line <= end as u64)
            .collect::<Vec<_>>();
        metrics.functions.push(FunctionMetric {
            name: name.clone(),
            start_line: *start,
            end_line: end as u64,
            code_lines: lines[start_idx..end]
                .iter()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//"))
                .count() as u64,
            branch_count: span_tokens
                .iter()
                .filter(|t| branches.contains(&t.exact.as_str()))
                .count() as u64,
        });
    }
    (ParseStatus::Parsed, Some(metrics))
}

fn abstraction_names(language: StructureLanguage, text: &str) -> Vec<String> {
    let markers: &[&str] = match language {
        StructureLanguage::Rust => &["trait "],
        StructureLanguage::TypeScript | StructureLanguage::JavaScript => &["interface "],
        StructureLanguage::Swift => &["protocol "],
        StructureLanguage::Kotlin => &["interface "],
    };
    let mut names = Vec::new();
    for line in text.lines() {
        for marker in markers {
            if let Some(name) = identifier_after(line.trim(), marker) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// (production implementations, has test double). A `Fake`/`Mock`/`Stub`
/// implementation is the test seam itself, not a second production impl.
fn impl_count(name: &str, corpus: &[(String, String)]) -> (usize, bool) {
    let mut production = 0usize;
    let mut has_double = false;
    for (_, text) in corpus {
        for needle in [format!("impl {name} for "), format!("implements {name}")] {
            for rest in text.split(&needle).skip(1) {
                let target: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let lower = target.to_ascii_lowercase();
                if ["fake", "mock", "stub", "double", "test"]
                    .iter()
                    .any(|w| lower.contains(w))
                {
                    has_double = true;
                } else {
                    production += 1;
                }
            }
        }
        // Swift/Kotlin conformance (`: Name`) and generic bounds are weaker
        // signals; count them only when no impl-style evidence exists.
        if production == 0 && !has_double {
            production += text.matches(&format!(": {name}")).count();
        }
    }
    (production, has_double)
}

fn is_barrel(text: &str) -> bool {
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .collect();
    if code.is_empty() {
        return false;
    }
    let reexports = code
        .iter()
        .filter(|l| {
            l.starts_with("pub use ")
                || l.starts_with("pub mod ")
                || l.starts_with("export ")
                || l.starts_with("export {")
                || l.starts_with("mod ")
        })
        .count();
    reexports * 5 >= code.len() * 4
}

fn is_part_file(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();
    let parent = segments
        .get(segments.len().wrapping_sub(2))
        .copied()
        .unwrap_or("");
    let parent_lower = parent.to_ascii_lowercase();
    if parent_lower == "parts" || parent_lower.ends_with("_parts") {
        return true;
    }
    let name = file_name(&normalized).to_ascii_lowercase();
    name.starts_with("part")
        && name
            .trim_start_matches("part")
            .trim_start_matches(['.', '_', '-'])
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
}

fn parent_dir(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit_once('/')
        .map(|(head, _)| head.to_owned())
        .unwrap_or_default()
}

/// Exact+near duplicate windows over normalized tokens. Windows are hashed,
/// grouped, and de-overlapped; a near group whose exact streams also match
/// is reported once as `Exact`.
fn find_duplicates(
    parsed: &[(String, StructureLanguage, Vec<NormalizedToken>)],
    config: &StructureConfig,
) -> Vec<DuplicateSpan> {
    let window = config.duplicate_min_tokens.max(8);
    let mut spans = Vec::new();
    for near_mode in [false, true] {
        let mut groups: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
        for (file_idx, (_, _, tokens)) in parsed.iter().enumerate() {
            if tokens.len() < window {
                continue;
            }
            for start in 0..=tokens.len() - window {
                let slice = &tokens[start..start + window];
                let joined = slice
                    .iter()
                    .map(|t| {
                        if near_mode {
                            t.near.as_str()
                        } else {
                            t.exact.as_str()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\u{1}");
                groups
                    .entry(digest_hex(joined.as_bytes()))
                    .or_default()
                    .push((file_idx, start));
            }
        }
        for (digest, hits) in groups {
            // De-overlap within each file.
            let mut kept: Vec<(usize, usize)> = Vec::new();
            for hit in hits {
                if kept
                    .iter()
                    .any(|(f, s)| *f == hit.0 && hit.1 < s + window && *s < hit.1 + window)
                {
                    continue;
                }
                kept.push(hit);
            }
            if kept.len() < 2 {
                continue;
            }
            let (first_file, _) = kept[0];
            let language = parsed[first_file].1;
            if kept.iter().any(|(f, _)| parsed[*f].1 != language) {
                continue; // duplicates are per-language facts
            }
            if near_mode {
                // Skip groups already exact (same first occurrence).
                let first_lines = (
                    parsed[first_file].0.clone(),
                    parsed[first_file].2[kept[0].1].line,
                );
                if spans.iter().any(|s: &DuplicateSpan| {
                    s.kind == DuplicateKind::Exact
                        && s.occurrences.first().is_some_and(|o| {
                            o.path == first_lines.0 && o.start_line == first_lines.1
                        })
                }) {
                    continue;
                }
            }
            let occurrences = kept
                .iter()
                .map(|(f, s)| {
                    let tokens = &parsed[*f].2;
                    SpanRef {
                        path: parsed[*f].0.clone(),
                        start_line: tokens[*s].line,
                        end_line: tokens[s + window - 1].line,
                    }
                })
                .collect::<Vec<_>>();
            let shared_abstraction = config
                .shared_invariants
                .iter()
                .find(|inv| inv.normalized_digest == digest)
                .cloned();
            spans.push(DuplicateSpan {
                kind: if near_mode {
                    DuplicateKind::Near
                } else {
                    DuplicateKind::Exact
                },
                language,
                grammar: language.grammar().into(),
                token_normalizer: TOKEN_NORMALIZER_VERSION.into(),
                token_count: window as u64,
                normalized_digest: digest,
                occurrences,
                qualified: config.qualified_token_languages.contains(&language),
                shared_abstraction,
            });
        }
    }
    spans.sort_by(|a, b| a.normalized_digest.cmp(&b.normalized_digest));
    spans
}

/// Entry point. `graph` is the canonical Blueprint context when root has one;
/// absence keeps lexical caller facts and a named gap — never dead proof.
pub fn analyze_structure(
    files: &[StructureFileInput],
    graph: Option<&GraphContext>,
    config: &StructureConfig,
) -> StructureFacts {
    let mut gaps = Vec::new();
    let mut exclusions = Vec::new();
    let mut included: Vec<(String, String)> = Vec::new(); // (path, text) corpus
    for file in files {
        match StructureLanguage::from_path(&file.path) {
            None => exclusions.push(Exclusion {
                path: file.path.clone(),
                reason: ExclusionReason::UnsupportedLanguage,
            }),
            Some(_) => match classify_exclusion(&file.path, &file.text) {
                Some(reason) => exclusions.push(Exclusion {
                    path: file.path.clone(),
                    reason,
                }),
                None => included.push((file.path.clone(), file.text.clone())),
            },
        }
    }
    if graph.is_none() {
        gaps.push("blueprint-unavailable; lexical caller facts only, dead code unproven".into());
    } else if let Some(graph) = graph {
        for unknown in &graph.unknowns {
            gaps.push(format!("graph-unknown: {}", unknown.cause));
        }
        if graph.truncated {
            gaps.push("graph-truncated; caller facts partial".into());
        }
    }

    // Callers: graph edges into a path, else lexical mention of its symbols.
    let mut graph_callers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(graph) = graph {
        for edge in &graph.edges {
            graph_callers
                .entry(edge.to.clone())
                .or_default()
                .push(format!(
                    "{} ({}/{})",
                    edge.from, edge.confidence, edge.source
                ));
        }
    }

    let mut parsed_tokens: Vec<(String, StructureLanguage, Vec<NormalizedToken>)> = Vec::new();
    let mut file_facts = Vec::new();
    let mut unused_candidates = Vec::new();
    for (path, text) in &included {
        let language = StructureLanguage::from_path(path).expect("filtered above");
        let tokens = tokenize_normalized(text);
        let (parse_status, metrics) = measure_file(language, text, &tokens);
        if parse_status == ParseStatus::Parsed {
            parsed_tokens.push((path.clone(), language, tokens));
        } else if let ParseStatus::Partial { reason } = &parse_status {
            gaps.push(format!("partial-parse:{path}:{reason}"));
        }
        let mut uncertainties = detect_uncertainties(language, path, text);
        let (state, effects) = state_and_effects(language, text);
        let responsibilities = top_level_responsibilities(language, text);
        let symbols = declared_symbols(language, text);
        if symbols.iter().any(|(_, _, exported)| *exported)
            && !uncertainties.contains(&UncertaintyKind::PublicApi)
        {
            uncertainties.push(UncertaintyKind::PublicApi);
            uncertainties.sort();
        }

        // Seams: a one-impl abstraction with a fake/mock/test double or an
        // injected (generic/constructor) use is a preserved seam, not yagni.
        let abstractions = abstraction_names(language, text);
        let mut single_impl = Vec::new();
        let mut seams = BTreeSet::new();
        for name in &abstractions {
            let (production_impls, has_double) = impl_count(name, &included);
            if production_impls <= 1 {
                single_impl.push(name.clone());
                if has_double {
                    seams.insert(SeamKind::Test);
                    seams.insert(SeamKind::DependencyInjection);
                } else if text.contains("dyn ") || text.contains(&format!("<{name}>")) {
                    seams.insert(SeamKind::DependencyInjection);
                }
            }
        }
        let lower_path = path.to_ascii_lowercase();
        if [
            "auth",
            "crypto",
            "secret",
            "token",
            "permission",
            "security",
        ]
        .iter()
        .any(|w| lower_path.contains(w))
        {
            seams.insert(SeamKind::Security);
        }
        if is_barrel(text) && !is_part_file(path) {
            seams.insert(SeamKind::Barrel);
        }

        let callers = graph_callers.get(path).cloned().unwrap_or_default();
        // Investigation priority only: large + (split responsibilities or
        // branch-dense) — a clean large coherent module stays `None`.
        let mut priority_reasons = Vec::new();
        let mut priority = InvestigationPriority::None;
        if let Some(m) = &metrics {
            let over = m.code_lines > config.review_loc_threshold;
            let branch_dense = m.branch_count * 4 > m.code_lines.max(1);
            if over && responsibilities.len() > 3 {
                priority = InvestigationPriority::Elevated;
                priority_reasons.push(format!(
                    "{} code lines over {} review trigger with {} top-level responsibilities",
                    m.code_lines,
                    config.review_loc_threshold,
                    responsibilities.len()
                ));
            } else if over && branch_dense {
                priority = InvestigationPriority::Review;
                priority_reasons.push(format!(
                    "{} code lines over {} review trigger and branch-dense ({} branches)",
                    m.code_lines, config.review_loc_threshold, m.branch_count
                ));
            } else if over {
                priority_reasons.push(format!(
                    "{} code lines over {} review trigger but coherent ({} responsibilities); no automatic defect",
                    m.code_lines,
                    config.review_loc_threshold,
                    responsibilities.len()
                ));
            }
        }
        if !seams.is_empty() && priority != InvestigationPriority::None {
            priority_reasons
                .push("preserved seam/barrel present; priority is investigation only".into());
        }

        // Unused candidates: no lexical/graph caller for a non-exported
        // symbol. Exported/reflected/route symbols keep their uncertainty
        // and are never certified dead.
        for (symbol, line, exported) in &symbols {
            if *exported {
                continue;
            }
            let mentioned_elsewhere = included.iter().any(|(other_path, other_text)| {
                other_path != path && other_text.contains(symbol.as_str())
            });
            let self_mentions = text.matches(symbol.as_str()).count();
            let has_graph_caller = !callers.is_empty();
            if !mentioned_elsewhere && self_mentions <= 1 && !has_graph_caller {
                unused_candidates.push(UnusedCandidate {
                    symbol: symbol.clone(),
                    path: path.clone(),
                    line: *line,
                    evidence: if graph.is_some() {
                        "no-graph-callers".into()
                    } else {
                        "no-lexical-callers".into()
                    },
                    uncertainties: uncertainties.clone(),
                    certifies_dead: false,
                });
            }
        }

        file_facts.push(FileStructure {
            path: path.clone(),
            language,
            grammar: language.grammar().into(),
            metric_suite: METRIC_SUITE_VERSION.into(),
            parse_status,
            metrics,
            uncertainties,
            component: ComponentFacts {
                path: path.clone(),
                responsibilities,
                state,
                effects,
                callers,
                seams: seams.into_iter().collect(),
                single_impl_abstractions: single_impl,
                investigation_priority: priority,
                priority_reasons,
            },
        });
    }

    let duplicates = find_duplicates(&parsed_tokens, config);
    let replaces_jscpd_for: Vec<StructureLanguage> = duplicates
        .iter()
        .filter(|d| d.qualified)
        .map(|d| d.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !duplicates.is_empty() && replaces_jscpd_for.is_empty() {
        gaps.push("duplication-unqualified; native spans do not replace jscpd until root qualifies token languages".into());
    }

    // Logical modules: mechanical partNN/*_parts groups (and include!-
    // stitched roots) aggregate; a named barrel directory aggregates
    // without the mechanical flag.
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for fact in &file_facts {
        if is_part_file(&fact.path) {
            by_dir
                .entry(parent_dir(&fact.path))
                .or_default()
                .push(fact.path.clone());
        }
    }
    let include_roots: Vec<String> = included
        .iter()
        .filter(|(_, text)| text.contains("include!("))
        .map(|(path, _)| path.clone())
        .collect();
    let mut logical_modules = Vec::new();
    for (dir, members) in &by_dir {
        if members.len() < 2 {
            continue;
        }
        let (mut lines, mut branches, mut functions) = (0u64, 0u64, 0u64);
        for member in members {
            if let Some(m) = file_facts
                .iter()
                .find(|f| &f.path == member)
                .and_then(|f| f.metrics.as_ref())
            {
                lines += m.code_lines;
                branches += m.branch_count;
                functions += m.functions.len() as u64;
            }
        }
        let mut evidence = vec![format!("{} part files under {dir}", members.len())];
        for root in &include_roots {
            if parent_dir(root) == parent_dir(dir) || dir.starts_with(&parent_dir(root)) {
                evidence.push(format!("stitched by include! in {root}"));
            }
        }
        logical_modules.push(LogicalModule {
            id: dir.clone(),
            member_paths: members.clone(),
            aggregated_code_lines: lines,
            aggregated_branch_count: branches,
            aggregated_function_count: functions,
            mechanical_split: true,
            evidence,
        });
    }

    // Minimize suggestions ride duplicate spans only, carry the extraction
    // boundary/state ownership/callers, and never a severity.
    let mut suggestions = Vec::new();
    for duplicate in &duplicates {
        if duplicate.occurrences.len() < 2 {
            continue;
        }
        let first = &duplicate.occurrences[0];
        let span_lines = first.end_line.saturating_sub(first.start_line) + 1;
        let callers = duplicate
            .occurrences
            .iter()
            .map(|o| format!("{}:{}", o.path, o.start_line))
            .collect::<Vec<_>>();
        suggestions.push(MinimizeSuggestion {
            path: first.path.clone(),
            start_line: first.start_line,
            end_line: first.end_line,
            extraction_boundary: format!(
                "extract {} span {}:{}-{} once; call sites keep their arguments and observable behavior",
                duplicate.language.label(),
                first.path,
                first.start_line,
                first.end_line
            ),
            state_ownership:
                "extracted unit owns no state unless the span's state facts move with it; callers retain their state"
                    .into(),
            callers,
            estimated_line_savings: span_lines * (duplicate.occurrences.len() as u64 - 1),
            severity: None,
            release_outcome_effect: "none".into(),
        });
    }

    let partial = file_facts
        .iter()
        .any(|f| f.parse_status != ParseStatus::Parsed)
        || !gaps.is_empty();
    StructureFacts {
        version: STRUCTURE_FACTS_VERSION,
        metric_suite: METRIC_SUITE_VERSION.into(),
        token_normalizer: TOKEN_NORMALIZER_VERSION.into(),
        files: file_facts,
        duplicates,
        unused_candidates,
        logical_modules,
        suggestions,
        exclusions,
        replaces_jscpd_for,
        partial,
        gaps,
        proves_dead_code: false,
    }
}
