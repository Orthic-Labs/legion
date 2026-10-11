//! providers/security-suite.mjs: heuristic candidate generation for the five
//! security packs (`credentials`, `insecure-defaults`, `misuse-resistance`,
//! `agentic-ci`, `agent-skill-mcp`).
//!
//! Production route: `native_providers::security::packs` runs these packs for
//! the registered providers `security.credentials`, `security.insecure-defaults`,
//! `security.misuse-resistance`, `security.agentic-ci` and
//! `security.agent-skill-mcp`, over each provider's frozen selector paths.
//!
//! Contract, enforced here and by the caller:
//!
//! * Detectors emit candidates only (`verdict: UNADJUDICATED`,
//!   `adjudicationRequired: true`); no detector adjudicates or closes anything.
//! * Every candidate anchors at an exact `{file, line}` inside the scanned set.
//! * A matched secret is never stored. A credential candidate carries
//!   `secretDigest` (sha256 scoped by path) and a redacted one-line excerpt;
//!   every candidate carries `excerptDigest` over the redacted excerpt.
//! * Reads are bounded (`Limits`): an oversized, unreadable, binary, symlinked,
//!   out-of-root or over-budget file is a named coverage gap, never silently
//!   dropped, and `coverage.scanned` lists only files actually read.
//! * Heuristics are deliberately narrow (request-derived taint, same-statement
//!   or short-window proximity, visible-sanitizer suppression); what they
//!   suppress is counted under `suppressed`, not hidden.

use super::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

macro_rules! re {
    ($pattern:expr) => {{
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| Regex::new($pattern).expect("static security-pack regex"))
    }};
}

pub const PACK_PROVIDERS: &[(&str, &str)] = &[
    ("credentials", "security.credentials"),
    ("insecure-defaults", "security.insecure-defaults"),
    ("misuse-resistance", "security.misuse-resistance"),
    ("agentic-ci", "security.agentic-ci"),
    ("agent-skill-mcp", "security.agent-skill-mcp"),
    ("all", "security.internal-suite"),
];

pub fn pack_provider(pack: &str) -> Option<&'static str> {
    PACK_PROVIDERS
        .iter()
        .find(|(k, _)| *k == pack)
        .map(|(_, v)| *v)
}

pub const POLICY_ID: &str = "audit-security-packs-v1";

/// Read bounds for one pack run.
#[derive(Clone, Debug)]
pub struct Limits {
    /// A larger file is not read; it is a `file-too-large` gap.
    pub max_file_bytes: usize,
    /// Total bytes read across the run; a file that would exceed it is a
    /// `total-byte-budget-exhausted` gap.
    pub max_total_bytes: usize,
    /// Candidates kept per file; excess is a `file-candidate-cap-reached` gap.
    pub max_candidates_per_file: usize,
    /// Candidates kept per run; later files become `candidate-cap-reached` gaps.
    pub max_candidates: usize,
    /// Paths named per gap (the gap still carries the full count).
    pub max_gap_paths: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_candidates_per_file: 200,
            max_candidates: 5000,
            max_gap_paths: 20,
        }
    }
}

type Suppressed = BTreeMap<&'static str, u64>;

fn suppress(suppressed: &mut Suppressed, key: &'static str) {
    *suppressed.entry(key).or_insert(0) += 1;
}

struct Hit {
    line: usize,
    metadata: Option<Value>,
    secret_digest: Option<String>,
}

impl Hit {
    fn at(line: usize) -> Self {
        Self {
            line,
            metadata: None,
            secret_digest: None,
        }
    }

    fn with(line: usize, metadata: Value) -> Self {
        Self {
            line,
            metadata: Some(metadata),
            secret_digest: None,
        }
    }
}

struct FileCtx<'a> {
    path: &'a str,
    text: &'a str,
    lines: Vec<&'a str>,
    starts: Vec<usize>,
    low_context: bool,
    doc: bool,
}

impl<'a> FileCtx<'a> {
    fn new(path: &'a str, text: &'a str) -> Self {
        let mut starts = vec![0usize];
        for (index, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(index + 1);
            }
        }
        let lines: Vec<&'a str> = text
            .split('\n')
            .map(|line| line.trim_end_matches('\r'))
            .collect();
        Self {
            path,
            text,
            lines,
            starts,
            low_context: low_context_path(path),
            doc: is_doc_path(path),
        }
    }

    /// 1-based line of a byte offset.
    fn line_of(&self, index: usize) -> usize {
        match self.starts.binary_search(&index) {
            Ok(position) => position + 1,
            Err(position) => position,
        }
    }
}

struct Rule {
    pack: &'static str,
    id: &'static str,
    severity_hint: &'static str,
    threat_model: &'static str,
    claim: &'static str,
    /// Also blank quoted literals in the stored excerpt (rules whose match
    /// text can itself be a secret value).
    redact_literals: bool,
    detect: fn(&FileCtx<'_>, &mut Suppressed) -> Vec<Hit>,
}

fn extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_doc_path(path: &str) -> bool {
    matches!(
        extension(path).as_str(),
        "md" | "mdx" | "markdown" | "txt" | "rst" | "adoc"
    )
}

fn low_context_path(path: &str) -> bool {
    let normalized = path.to_lowercase().replace('\\', "/");
    re!(r"(?:^|/)(?:test|tests|__tests__|spec|specs|fixtures?|examples?|docs?|testdata|mocks?|__mocks__|samples?)/|[._-](?:test|spec)\.[a-z0-9]+$")
        .is_match(&normalized)
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with("/*")
        || t.starts_with("* ")
        || t == "*"
        || t.starts_with("*/")
        || t.starts_with("<!--")
}

fn is_decl(line: &str) -> bool {
    re!(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?(?:def|function|fn|func)\s").is_match(line)
}

// ---------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------

const CREDENTIAL_RULE_ID: &str = "security.credential-literal";

fn shannon_entropy(value: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = value.chars().count() as f64;
    if len == 0.0 {
        return 0.0;
    }
    counts.values().fold(0.0, |entropy, &count| {
        let p = count as f64 / len;
        entropy - p * p.log2()
    })
}

fn is_placeholder(value: &str) -> bool {
    let normalized: String = value
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if normalized.is_empty() {
        return true;
    }
    re!(r"^(?:example|sample|dummy|test|testing|changeme|placeholder|notasecret|development|developmentsecret|devsecret|secret|password|token|apikey|your[a-z0-9]*)$").is_match(&normalized)
        || [
            "replacewith",
            "insert",
            "xxxxx",
            "example",
            "dummy",
            "changeme",
            "placeholder",
            "redacted",
            "notreal",
            "fakekey",
            "faketoken",
        ]
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn known_credential_format(value: &str) -> bool {
    re!(r"^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$").is_match(value)
}

fn template_like(value: &str) -> bool {
    value.contains("${")
        || value.contains("{{")
        || value.contains("<%")
        || value.contains("%(")
        || value.contains("$(")
        || value.starts_with('$')
        || (value.starts_with('<') && value.ends_with('>'))
}

/// Context of a path for credential qualification: `low` (tests, fixtures,
/// examples, docs), `high` (config and source), else `medium`.
fn security_relevant_context(path: &str) -> &'static str {
    if low_context_path(path) {
        return "low";
    }
    let normalized = path.to_lowercase().replace('\\', "/");
    let ext = format!(".{}", extension(path));
    const HIGH: &[&str] = &[
        ".env", ".ini", ".toml", ".yaml", ".yml", ".json", ".js", ".jsx", ".ts", ".tsx", ".py",
        ".rb", ".php", ".java", ".kt", ".cs", ".go", ".rs", ".swift", ".sh", ".ps1",
    ];
    if HIGH.contains(&ext.as_str()) || normalized.ends_with(".env") {
        "high"
    } else {
        "medium"
    }
}

fn credential_value_rejected(value: &str) -> bool {
    is_placeholder(value)
        || value.len() > 256
        || value.chars().any(char::is_whitespace)
        || template_like(value)
        || value.contains("://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

fn filter_stages(tier: &str, entropy: f64, context: &str) -> Value {
    json!({
        "filterStages": {
            "regexTier": tier,
            "entropy": (entropy * 1000.0).round() / 1000.0,
            "placeholderRejected": false,
            "fileContext": context,
        }
    })
}

fn d_credentials(ctx: &FileCtx<'_>, _suppressed: &mut Suppressed) -> Vec<Hit> {
    let assignment = re!(
        r#"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|client[_-]?secret)['"]?\s*(?:=|:)\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})')"#
    );
    let known = re!(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
    );
    let context = security_relevant_context(ctx.path);
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        let number = index + 1;
        for cap in assignment.captures_iter(line) {
            let value = match cap.get(1).or_else(|| cap.get(2)) {
                Some(m) => m.as_str(),
                None => continue,
            };
            if credential_value_rejected(value) {
                continue;
            }
            let format = known_credential_format(value);
            let entropy = shannon_entropy(value);
            if !format && (entropy < 3.2 || !value.bytes().any(|b| b.is_ascii_digit())) {
                continue;
            }
            if context == "low" && !format && entropy < 4.0 {
                continue;
            }
            hits.push(Hit {
                line: number,
                metadata: Some(filter_stages(
                    if format {
                        "known-format"
                    } else {
                        "named-assignment"
                    },
                    entropy,
                    context,
                )),
                secret_digest: Some(digest_id(&["credential-value", ctx.path, value])),
            });
        }
        for token in known.find_iter(line) {
            let value = token.as_str();
            if value.to_ascii_lowercase().contains("example") || is_placeholder(value) {
                continue;
            }
            let entropy = shannon_entropy(value);
            if value.starts_with("sk-")
                && (entropy < 3.5 || !value.bytes().any(|b| b.is_ascii_digit()))
            {
                continue;
            }
            hits.push(Hit {
                line: number,
                metadata: Some(filter_stages("known-format", entropy, context)),
                secret_digest: Some(digest_id(&["credential-value", ctx.path, value])),
            });
        }
    }
    hits
}

// ---------------------------------------------------------------------
// insecure-defaults
// ---------------------------------------------------------------------

fn d_insecure_secret(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    if ctx.low_context {
        suppress(
            suppressed,
            "security.insecure-default.secret:low-context-file",
        );
        return Vec::new();
    }
    let env_fallback = re!(
        r#"(?i)(?:^|[^A-Za-z0-9_])[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|JWT_KEY|PASSWORD)['"]?\s*[=:]\s*(?:process\.env\.[A-Z0-9_]+|os\.environ\.get\([^)]*\)|os\.getenv\([^)]*\)|ENV\[[^\]]*\])\s*(?:\|\||\?\?|or)\s*(?:"([^"\r\n]{3,})"|'([^'\r\n]{3,})')"#
    );
    let call_default = re!(
        r#"(?i)(?:os\.environ\.get|os\.getenv|getenv|env)\(\s*['"][A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|JWT_KEY|PASSWORD)[A-Z0-9_]*['"]\s*,\s*(?:"([^"\r\n]{3,})"|'([^'\r\n]{3,})')\s*\)"#
    );
    let bare = re!(
        r#"(?i)(?:^|[^A-Za-z0-9_])[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|JWT_KEY)['"]?\s*[=:]\s*(?:"([^"\r\n]{3,})"|'([^'\r\n]{3,})')"#
    );
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        let number = index + 1;
        let fallback = env_fallback
            .captures(line)
            .or_else(|| call_default.captures(line));
        if let Some(cap) = fallback {
            let value = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if !template_like(value) {
                hits.push(Hit::with(
                    number,
                    json!({"form": "environment-fallback-literal"}),
                ));
            }
            continue;
        }
        // A bare literal is this pack's concern only when it is a weak or
        // placeholder default; a strong-looking literal is the credentials pack's.
        if let Some(cap) = bare.captures(line) {
            let value = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if template_like(value) || value.chars().any(char::is_whitespace) {
                continue;
            }
            if is_placeholder(value) || shannon_entropy(value) < 3.2 {
                hits.push(Hit::with(number, json!({"form": "weak-literal-default"})));
            }
        }
    }
    hits
}

fn d_auth_disabled(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    if ctx.low_context {
        suppress(
            suppressed,
            "security.insecure-default.auth-disabled:low-context-file",
        );
        return Vec::new();
    }
    let off = re!(
        r#"(?i)(?:^|[^a-z0-9])(?:require_auth|auth_required|enable_auth|auth_enabled|authentication_enabled|authorization_enabled|enable_authentication|require_authentication)['"]?\s*[=:]\s*(?:false|0|no|off|"false"|'false'|"0"|'0')(?:[^a-z0-9]|$)"#
    );
    let disabled = re!(
        r#"(?i)(?:^|[^a-z0-9])(?:disable_auth|auth_disabled|disableauth|skip_auth|no_auth|allowanonymousbydefault|permitallbydefault|allow_anonymous)['"]?\s*[=:]\s*(?:true|1|yes|on|"true"|'true')(?:[^a-z0-9]|$)"#
    );
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        if off.is_match(line) || disabled.is_match(line) {
            hits.push(Hit::at(index + 1));
        }
    }
    hits
}

fn d_tls_disabled(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    if ctx.low_context {
        suppress(
            suppressed,
            "security.tls-verification-disabled:low-context-file",
        );
        return Vec::new();
    }
    let tls = re!(
        r"(?i)rejectUnauthorized\s*:\s*false|\bverify\s*=\s*False\b|danger_accept_invalid_certs\s*\(\s*true\s*\)|danger_accept_invalid_hostnames\s*\(\s*true\s*\)|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED['\x22]?\s*[=:,]\s*['\x22]?0|ServerCertificateCustomValidationCallback\s*=\s*[^;\n]*(?:true|=>\s*true)|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b"
    );
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        if tls.is_match(line) {
            hits.push(Hit::at(index + 1));
        }
    }
    hits
}

// ---------------------------------------------------------------------
// misuse-resistance
// ---------------------------------------------------------------------

fn request_taint() -> &'static Regex {
    re!(
        r"\breq\.(?:body|query|params|headers|cookies|files?)\b|\brequest\.(?:body|query|params|args|form|GET|POST|json|data|files|headers|cookies)\b|\bctx\.(?:query|params|request)\b|\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\bsearchParams\b|\bprocess\.argv\b|\bsys\.argv\b|\bargv\b|\buser(?:Input|_input)\b|\buntrusted\w*"
    )
}

fn exec_sink() -> &'static Regex {
    re!(
        r"(?:^|[^.\w$:])(?:execSync|execFileSync|exec|system|popen|shell_exec|passthru|proc_open|eval)\s*\(|\b(?:child_process|cp)\.(?:exec|execSync)\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\([^\n]*shell\s*=\s*True|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcess\.Start\s*\(|\bCommand::new\s*\(\s*[^\x22\s)]|\bnew\s+Function\s*\("
    )
}

fn d_command_injection(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    let sanitizer = re!(r"(?i)shell-?quote|shellescape|escapeshellarg|shlex\.quote|shellwords");
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || is_decl(line) {
            continue;
        }
        let Some(sink) = exec_sink().find(line) else {
            continue;
        };
        if !request_taint().is_match(&line[sink.start()..]) {
            continue;
        }
        if sanitizer.is_match(line) {
            suppress(suppressed, "security.command-injection:sanitizer-visible");
            continue;
        }
        hits.push(Hit::at(index + 1));
    }
    hits
}

fn d_path_traversal(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    let sink = re!(
        r"(?:^|[^.\w$])(?:open|readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|send_file|send_from_directory|unlink|readdir|include|include_once|require_once)\s*\(|\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|readdir)\s*\(|\bFile::open\s*\(|\bfs::(?:read|read_to_string|write|remove_file)\s*\(|\bPaths\.get\s*\(|\bPath\.Combine\s*\(|\bres\.(?:sendFile|download)\s*\(|\bStorage::disk\s*\("
    );
    let sanitizer = re!(
        r"(?i)basename|normalize|realpath|secure_filename|safe_join|sanitize|startsWith|starts_with|is_relative_to|canonicalize"
    );
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || is_decl(line) {
            continue;
        }
        let Some(found) = sink.find(line) else {
            continue;
        };
        if !request_taint().is_match(&line[found.start()..]) {
            continue;
        }
        if sanitizer.is_match(line) {
            suppress(suppressed, "security.path-traversal:sanitizer-visible");
            continue;
        }
        hits.push(Hit::at(index + 1));
    }
    hits
}

fn d_unsafe_deserialization(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc {
        return Vec::new();
    }
    let sink = re!(
        r"\bc?[pP]ickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\bjsonpickle\.decode\s*\(|\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bObjectInputStream\s*\(|\bMarshal\.load\s*\(|(?:^|[^.\w$])unserialize\s*\(|\byaml\.(?:load|load_all)\s*\("
    );
    let safe_yaml = re!(r"SafeLoader|safe_load|CSafeLoader|BaseLoader");
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || is_decl(line) {
            continue;
        }
        if !sink.is_match(line) {
            continue;
        }
        if line.contains("yaml.") && safe_yaml.is_match(line) {
            suppress(
                suppressed,
                "security.unsafe-deserialization:safe-yaml-loader",
            );
            continue;
        }
        hits.push(Hit::at(index + 1));
    }
    hits
}

// ---------------------------------------------------------------------
// agentic-ci
// ---------------------------------------------------------------------

fn agent_marker() -> &'static Regex {
    re!(
        r"(?i)claude-code-action|anthropics/|\bopenai\b|\bcodex\b|\bgemini\b|\bcopilot\b|\bllm\b|ai-inference|\blangchain\b|chat\.completions|messages\.create|generateText|\bgpt-?\d"
    )
}

fn d_prompt_injection(ctx: &FileCtx<'_>, _suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc || !agent_marker().is_match(ctx.text) {
        return Vec::new();
    }
    let untrusted = re!(
        r"(?i)\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion|head_commit)[\w.\[\]*-]*\.(?:body|title|message)|\$\{\{\s*github\.head_ref|\b(?:issue|pull_request|comment|review)\.(?:body|title)\b"
    );
    let prompt_key = re!(
        r"(?i)\b(?:prompt|direct_prompt|custom_instructions|instructions?|system_message|system_prompt|messages)\b"
    );
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || !untrusted.is_match(line) {
            continue;
        }
        let low = index.saturating_sub(12);
        let high = (index + 12).min(ctx.lines.len() - 1);
        let near =
            (low..=high).any(|j| !is_comment(ctx.lines[j]) && prompt_key.is_match(ctx.lines[j]));
        if near {
            hits.push(Hit::with(
                index + 1,
                json!({"boundary": "untrusted-content-to-agent-prompt"}),
            ));
        }
    }
    hits
}

fn d_unsafe_execution(ctx: &FileCtx<'_>, _suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc || !agent_marker().is_match(ctx.text) {
        return Vec::new();
    }
    let model_output = re!(
        r"(?i)\b(?:completions?|llm|assistant|openai|anthropic|claude|gpt\w*|agent|model)\w*(?:\.choices\[\d+\]\.message\.content|\.content(?:\[\d+\])?(?:\.text)?|\.text|\.output_text|\.output|\.message)\b|\bchoices\[\d+\]\.message\.content\b"
    );
    let step_output = re!(
        r"(?i)\$\{\{\s*steps\.[\w-]*(?:claude|agent|gpt|llm|codex|gemini|copilot|openai|anthropic)[\w-]*\.outputs\.[\w.-]+"
    );
    let mut hits = Vec::new();
    // Model output reaching an execution sink within the same or next two lines.
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || is_decl(line) || !model_output.is_match(line) {
            continue;
        }
        let high = (index + 2).min(ctx.lines.len() - 1);
        let sink_near =
            (index..=high).any(|j| !is_decl(ctx.lines[j]) && exec_sink().is_match(ctx.lines[j]));
        if sink_near {
            hits.push(Hit::with(
                index + 1,
                json!({"boundary": "model-output-to-execution"}),
            ));
        }
    }
    // CI: an agent step's output interpolated into a `run:` shell script.
    let mut run_indent: Option<usize> = None;
    for (index, &line) in ctx.lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let key = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(rest) = key.strip_prefix("run:") {
            let rest = rest.trim();
            if rest.is_empty() || rest == "|" || rest == ">" || rest == "|-" || rest == ">-" {
                run_indent = Some(indent);
                continue;
            }
            run_indent = None;
            if step_output.is_match(rest) {
                hits.push(Hit::with(
                    index + 1,
                    json!({"boundary": "agent-step-output-to-shell"}),
                ));
            }
            continue;
        }
        match run_indent {
            Some(base) if indent > base => {
                if !is_comment(line) && step_output.is_match(line) {
                    hits.push(Hit::with(
                        index + 1,
                        json!({"boundary": "agent-step-output-to-shell"}),
                    ));
                }
            }
            _ => run_indent = None,
        }
    }
    hits
}

fn d_tool_boundary_taint(ctx: &FileCtx<'_>, suppressed: &mut Suppressed) -> Vec<Hit> {
    if ctx.doc
        || matches!(
            extension(ctx.path).as_str(),
            "json" | "lock" | "svg" | "map"
        )
    {
        return Vec::new();
    }
    let source_re = re!(
        r"(?i)github\.event\.(?:issue|pull_request|comment)|\b(?:issue|pull_request|comment)\.body\b|\brequest\.(?:body|query|params)\b|\breq\.(?:body|query|params)\b|\buserContent\b|\buntrusted(?:Input|Text)\b|\bpromptInput\b"
    );
    let sink_re = re!(
        r"(?i)@tool\b|\b(?:callTool|invokeTool|executeTool|runTool)\s*\(|\bmcp\.(?:callTool|invoke)\s*\(|\btool_calls?\b|\btools\s*\[[^\]]+\]\s*\("
    );
    let validation = re!(
        r"(?i)schema\.(?:parse|safeParse)|validate|sanitize|allowlist|whitelist|authorization|permission|policyCheck|approvedTool"
    );
    const WINDOW: usize = 40;
    let sink_lines: Vec<usize> = ctx
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !is_comment(line) && sink_re.is_match(line))
        .map(|(index, _)| index)
        .collect();
    if sink_lines.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        let Some(source) = source_re.find(line) else {
            continue;
        };
        let nearest = sink_lines
            .iter()
            .copied()
            .filter(|sink| sink.abs_diff(index) <= WINDOW)
            .min_by_key(|sink| sink.abs_diff(index));
        let Some(sink) = nearest else {
            continue;
        };
        let (low, high) = (index.min(sink), index.max(sink));
        let between = ctx.lines[low..=high].join("\n");
        if validation.is_match(&between) {
            suppress(
                suppressed,
                "security.agent.tool-boundary-taint:validation-visible",
            );
            continue;
        }
        let sink_match = sink_re
            .find(ctx.lines[sink])
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();
        hits.push(Hit::with(
            index + 1,
            json!({
                "source": source.as_str(), "sourceLine": index + 1,
                "sink": sink_match, "sinkLine": sink + 1,
                "validationVisible": false, "boundary": "agent-to-tool",
            }),
        ));
    }
    hits
}

// ---------------------------------------------------------------------
// agent-skill-mcp
// ---------------------------------------------------------------------

fn d_skill_exfiltration(ctx: &FileCtx<'_>, _suppressed: &mut Suppressed) -> Vec<Hit> {
    if !matches!(
        extension(ctx.path).as_str(),
        "sh" | "bash" | "zsh" | "js" | "mjs" | "cjs" | "ts" | "py" | "ps1" | "rb"
    ) {
        return Vec::new();
    }
    let secret_read = re!(
        r"(?i)process\.env\.\w*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)\w*|os\.environ(?:\.get\s*\(|\s*\[)\s*['\x22]\w*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)\w*|\$\{?\w*(?:TOKEN|SECRET|API_KEY|PASSWORD)\w*\}?|\.ssh/|\.aws/|\.npmrc|\.netrc|\.git-credentials|find-generic-password|keychain"
    );
    let network = re!(
        r"(?i)\bfetch\s*\(|\baxios\b|\brequests\.(?:get|post|put|patch)\b|\bhttpx\.|\burllib\.request|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\bhttps?\.request\b|\bnc\s+-"
    );
    const WINDOW: usize = 30;
    let network_lines: Vec<usize> = ctx
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !is_comment(line) && network.is_match(line))
        .map(|(index, _)| index)
        .collect();
    if network_lines.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    // One candidate per network call: the earliest credential read near it.
    let mut reported_sends = std::collections::BTreeSet::new();
    for (index, &line) in ctx.lines.iter().enumerate() {
        if is_comment(line) || !secret_read.is_match(line) {
            continue;
        }
        let nearest = network_lines
            .iter()
            .copied()
            .filter(|send| send.abs_diff(index) <= WINDOW)
            .min_by_key(|send| send.abs_diff(index));
        if let Some(send) = nearest {
            if reported_sends.insert(send) {
                hits.push(Hit::with(
                    index + 1,
                    json!({"readLine": index + 1, "sendLine": send + 1}),
                ));
            }
        }
    }
    hits
}

fn d_hidden_unicode(ctx: &FileCtx<'_>, _suppressed: &mut Suppressed) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut previous: Option<char> = None;
    let mut chars = ctx.text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let code = c as u32;
        let class = match code {
            0x202a..=0x202e | 0x2066..=0x2069 => Some("bidi-control"),
            0x200b | 0x2060 => Some("zero-width"),
            // A byte-order mark at the start of the file is ordinary.
            0xfeff if index > 0 => Some("zero-width"),
            // Joiners are ordinary inside emoji and non-Latin scripts; between
            // ASCII alphanumerics they hide content.
            0x200c | 0x200d => {
                let next = chars.peek().map(|(_, n)| *n);
                if previous.is_some_and(|p| p.is_ascii_alphanumeric())
                    && next.is_some_and(|n| n.is_ascii_alphanumeric())
                {
                    Some("zero-width-joiner")
                } else {
                    None
                }
            }
            0xe0000..=0xe007f => Some("unicode-tag"),
            _ => None,
        };
        if let Some(class) = class {
            hits.push(Hit::with(
                ctx.line_of(index),
                json!({"class": class, "codePoint": format!("U+{code:04X}")}),
            ));
        }
        previous = Some(c);
    }
    hits
}

// ---------------------------------------------------------------------
// rule table
// ---------------------------------------------------------------------

static RULES: &[Rule] = &[
    Rule {
        pack: "credentials",
        id: CREDENTIAL_RULE_ID,
        severity_hint: "high",
        threat_model: "credential-exposure",
        claim: "A non-placeholder, credential-shaped literal is committed in a security-relevant file context.",
        redact_literals: true,
        detect: d_credentials,
    },
    Rule {
        pack: "insecure-defaults",
        id: "security.insecure-default.secret",
        severity_hint: "high",
        threat_model: "deployment-misconfiguration",
        claim: "A security-sensitive secret has a tracked fallback value instead of failing closed.",
        redact_literals: true,
        detect: d_insecure_secret,
    },
    Rule {
        pack: "insecure-defaults",
        id: "security.insecure-default.auth-disabled",
        severity_hint: "high",
        threat_model: "remote-unauthenticated",
        claim: "Authentication or authorization appears to default to disabled.",
        redact_literals: false,
        detect: d_auth_disabled,
    },
    Rule {
        pack: "insecure-defaults",
        id: "security.tls-verification-disabled",
        severity_hint: "high",
        threat_model: "network-attacker",
        claim: "TLS certificate verification is explicitly disabled.",
        redact_literals: false,
        detect: d_tls_disabled,
    },
    Rule {
        pack: "misuse-resistance",
        id: "security.command-injection",
        severity_hint: "critical",
        threat_model: "attacker-controlled-input",
        claim: "Potentially attacker-controlled input reaches a process or code-execution sink.",
        redact_literals: false,
        detect: d_command_injection,
    },
    Rule {
        pack: "misuse-resistance",
        id: "security.path-traversal",
        severity_hint: "high",
        threat_model: "attacker-controlled-file-path",
        claim: "Potentially attacker-controlled path data reaches a filesystem operation.",
        redact_literals: false,
        detect: d_path_traversal,
    },
    Rule {
        pack: "misuse-resistance",
        id: "security.unsafe-deserialization",
        severity_hint: "critical",
        threat_model: "attacker-controlled-serialized-data",
        claim: "A deserializer capable of constructing arbitrary object graphs is used.",
        redact_literals: false,
        detect: d_unsafe_deserialization,
    },
    Rule {
        pack: "agentic-ci",
        id: "security.agent.prompt-injection-flow",
        severity_hint: "high",
        threat_model: "malicious-repository-or-ticket-content",
        claim: "Untrusted issue, pull-request, or comment content appears to enter an agent prompt.",
        redact_literals: false,
        detect: d_prompt_injection,
    },
    Rule {
        pack: "agentic-ci",
        id: "security.agent.unsafe-execution",
        severity_hint: "critical",
        threat_model: "malicious-model-output",
        claim: "Model output appears to reach a code or shell execution sink.",
        redact_literals: false,
        detect: d_unsafe_execution,
    },
    Rule {
        pack: "agentic-ci",
        id: "security.agent.tool-boundary-taint",
        severity_hint: "high",
        threat_model: "malicious-prompt-or-request-content",
        claim: "Potentially untrusted prompt or request content crosses an agent tool boundary with no visible validation; adjudicate validation, authorization, and sink reachability.",
        redact_literals: false,
        detect: d_tool_boundary_taint,
    },
    Rule {
        pack: "agent-skill-mcp",
        id: "security.skill.exfiltration-chain",
        severity_hint: "critical",
        threat_model: "malicious-skill-or-hook",
        claim: "The same skill, hook, or tool script reads credential material and performs network I/O within a short span.",
        redact_literals: true,
        detect: d_skill_exfiltration,
    },
    Rule {
        pack: "agent-skill-mcp",
        id: "security.skill.hidden-unicode",
        severity_hint: "high",
        threat_model: "malicious-skill-content",
        claim: "Agent-facing content contains invisible or bidirectional Unicode controls.",
        redact_literals: false,
        detect: d_hidden_unicode,
    },
];

fn rules_for_pack(pack: &str) -> Result<Vec<&'static Rule>, String> {
    if pack == "all" {
        return Ok(RULES.iter().collect());
    }
    if pack_provider(pack).is_none() {
        return Err(format!("unknown security rule pack {pack}"));
    }
    Ok(RULES.iter().filter(|r| r.pack == pack).collect())
}

/// The rule ids a pack runs (for registry and test assertions).
pub fn pack_rule_ids(pack: &str) -> Vec<&'static str> {
    rules_for_pack(pack)
        .map(|rules| rules.iter().map(|r| r.id).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------
// candidates
// ---------------------------------------------------------------------

/// One-line excerpt with secret-shaped material removed: known token formats,
/// secret-named assignments, PEM markers and (for rules whose match text can
/// itself be a secret) every quoted literal. Redaction runs on the whole line
/// before truncation so a token cannot be split across the cut.
fn redacted_excerpt(line: &str, redact_literals: bool) -> String {
    let mut s: String = line.trim().chars().take(2000).collect();
    if s.contains("-----BEGIN") {
        return "[REDACTED: key material]".to_owned();
    }
    s = re!(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )
    .replace_all(&s, "[REDACTED]")
    .into_owned();
    s = re!(
        r#"(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|client[_-]?secret|credentials?)['"]?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"#
    )
    .replace_all(&s, "${1}[REDACTED]")
    .into_owned();
    if redact_literals {
        s = re!(r#""[^"\r\n]{6,}"|'[^'\r\n]{6,}'"#)
            .replace_all(&s, "[REDACTED]")
            .into_owned();
    }
    s.chars().take(160).collect()
}

fn build_candidate(rule: &Rule, provider: &str, ctx: &FileCtx<'_>, hit: &Hit) -> Value {
    let line_text = ctx
        .lines
        .get(hit.line.saturating_sub(1))
        .copied()
        .unwrap_or("");
    let excerpt = redacted_excerpt(line_text, rule.redact_literals);
    let mut obj = json!({
        "id": digest_id(&[provider, rule.id, &format!("{}:{}", ctx.path, hit.line)]),
        "ruleId": rule.id, "provider": provider, "role": "candidate-generator", "claim": rule.claim,
        "severityHint": rule.severity_hint, "threatModel": rule.threat_model,
        "evidence": [{ "file": ctx.path, "line": hit.line }], "evidenceStrength": "candidate",
        "verdict": "UNADJUDICATED", "adjudicationRequired": true,
        "excerptDigest": digest_id(&["excerpt", &excerpt]),
        "redactedExcerpt": excerpt,
    });
    if let Some(metadata) = &hit.metadata {
        obj["detectorMetadata"] = metadata.clone();
    }
    if let Some(digest) = &hit.secret_digest {
        obj["secretDigest"] = json!(digest);
    }
    obj
}

fn safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !p.is_absolute()
        && p.components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

pub fn generate_security_candidates(
    root: &Path,
    files: &[String],
    pack: &str,
    provider: Option<&str>,
) -> Result<Value, String> {
    generate_security_candidates_bounded(root, files, pack, provider, &Limits::default())
}

pub fn generate_security_candidates_bounded(
    root: &Path,
    files: &[String],
    pack: &str,
    provider: Option<&str>,
    limits: &Limits,
) -> Result<Value, String> {
    let provider = provider.map(String::from).unwrap_or_else(|| {
        pack_provider(pack)
            .map(String::from)
            .unwrap_or_else(|| format!("security.{pack}"))
    });
    let rules = rules_for_pack(pack)?;
    let mut candidates: Vec<Value> = Vec::new();
    let mut scanned: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, &'static str)> = Vec::new();
    let mut capped_files: Vec<String> = Vec::new();
    let mut suppressed: Suppressed = BTreeMap::new();
    let mut bytes_read: usize = 0;
    let mut sorted: Vec<String> = files.to_vec();
    sorted.sort();
    sorted.dedup();
    for path in &sorted {
        if !safe_relative(path) {
            skipped.push((path.clone(), "path-outside-root"));
            continue;
        }
        if candidates.len() >= limits.max_candidates {
            skipped.push((path.clone(), "candidate-cap-reached"));
            continue;
        }
        let full = root.join(path);
        let metadata = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => {
                skipped.push((path.clone(), "unreadable"));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            skipped.push((path.clone(), "symlink-not-followed"));
            continue;
        }
        if !metadata.is_file() {
            skipped.push((path.clone(), "unreadable"));
            continue;
        }
        let length = metadata.len() as usize;
        if length > limits.max_file_bytes {
            skipped.push((path.clone(), "file-too-large"));
            continue;
        }
        if bytes_read.saturating_add(length) > limits.max_total_bytes {
            skipped.push((path.clone(), "total-byte-budget-exhausted"));
            continue;
        }
        let bytes = match std::fs::read(&full) {
            Ok(b) => b,
            Err(_) => {
                skipped.push((path.clone(), "unreadable"));
                continue;
            }
        };
        if bytes.len() > limits.max_file_bytes {
            skipped.push((path.clone(), "file-too-large"));
            continue;
        }
        if bytes.contains(&0) {
            skipped.push((path.clone(), "binary-file"));
            continue;
        }
        bytes_read += bytes.len();
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        };
        scanned.push(path.clone());
        let ctx = FileCtx::new(path, &text);
        let mut file_candidates: Vec<Value> = Vec::new();
        for rule in &rules {
            let mut seen_lines = std::collections::HashSet::new();
            for hit in (rule.detect)(&ctx, &mut suppressed) {
                if !seen_lines.insert(hit.line) {
                    continue;
                }
                file_candidates.push(build_candidate(rule, &provider, &ctx, &hit));
            }
        }
        if file_candidates.len() > limits.max_candidates_per_file {
            file_candidates.truncate(limits.max_candidates_per_file);
            capped_files.push(path.clone());
        }
        candidates.extend(file_candidates);
    }
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<Value> = candidates
        .into_iter()
        .filter(|c| seen.insert(c["id"].as_str().unwrap_or_default().to_string()))
        .collect();
    let rule_ids: Vec<Value> = rules.iter().map(|r| json!(r.id)).collect();

    let mut by_reason: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for (path, reason) in &skipped {
        by_reason.entry(*reason).or_default().push(path.clone());
    }
    let mut gaps: Vec<Value> = Vec::new();
    for (reason, paths) in &by_reason {
        let shown: Vec<&String> = paths.iter().take(limits.max_gap_paths).collect();
        let mut gap = json!({
            "kind": reason, "count": paths.len(), "paths": shown,
            "truncated": paths.len() > limits.max_gap_paths,
        });
        if *reason == "file-too-large" {
            gap["limitBytes"] = json!(limits.max_file_bytes);
        }
        if *reason == "total-byte-budget-exhausted" {
            gap["limitBytes"] = json!(limits.max_total_bytes);
        }
        if *reason == "candidate-cap-reached" {
            gap["limit"] = json!(limits.max_candidates);
        }
        gaps.push(gap);
    }
    if !capped_files.is_empty() {
        let shown: Vec<&String> = capped_files.iter().take(limits.max_gap_paths).collect();
        gaps.push(json!({
            "kind": "file-candidate-cap-reached", "count": capped_files.len(), "paths": shown,
            "truncated": capped_files.len() > limits.max_gap_paths,
            "limit": limits.max_candidates_per_file,
        }));
    }
    let skipped_listing: Vec<Value> = skipped
        .iter()
        .take(limits.max_gap_paths.max(100))
        .map(|(path, reason)| json!({ "path": path, "reason": reason }))
        .collect();
    Ok(json!({
        "schemaVersion": 1, "kind": "audit-security-candidates", "provider": provider, "rulePack": pack,
        "policyId": POLICY_ID,
        "complete": gaps.is_empty(),
        "coverage": {
            "expectedFiles": sorted.len(), "scannedFiles": scanned.len(), "scanned": scanned,
            "skipped": skipped_listing, "bytesRead": bytes_read, "rules": rule_ids,
            "limits": {
                "maxFileBytes": limits.max_file_bytes, "maxTotalBytes": limits.max_total_bytes,
                "maxCandidatesPerFile": limits.max_candidates_per_file, "maxCandidates": limits.max_candidates,
            },
        },
        "suppressed": suppressed,
        "candidates": unique,
        "coverageGaps": gaps,
    }))
}

pub fn merge_security_candidate_reports(reports: &[Value]) -> Value {
    let mut seen = std::collections::HashSet::new();
    let candidates: Vec<Value> = reports
        .iter()
        .flat_map(|r| {
            r.get("candidates")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter(|c| seen.insert(c["id"].as_str().unwrap_or_default().to_string()))
        .collect();
    let complete = reports
        .iter()
        .all(|r| r.get("complete").and_then(Value::as_bool).unwrap_or(true));
    let provider_reports: Vec<Value> = reports
        .iter()
        .map(|r| {
            json!({
                "provider": r.get("provider").cloned().unwrap_or(Value::Null),
                "rulePack": r.get("rulePack").cloned().unwrap_or(Value::Null),
                "expectedFiles": r["coverage"]["expectedFiles"].clone(),
                "scannedFiles": r["coverage"]["scannedFiles"].clone(),
                "rules": r["coverage"]["rules"].clone(),
            })
        })
        .collect();
    let coverage_gaps: Vec<Value> = reports
        .iter()
        .flat_map(|r| {
            let provider = r.get("provider").cloned().unwrap_or(Value::Null);
            r.get("coverageGaps")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(move |mut gap| {
                    if let Value::Object(obj) = &mut gap {
                        obj.insert("provider".into(), provider.clone());
                    }
                    gap
                })
        })
        .collect();
    json!({
        "schemaVersion": 1, "kind": "audit-security-candidates", "provider": "security.multi-provider",
        "complete": complete, "coverage": { "providerReports": provider_reports },
        "candidates": candidates, "coverageGaps": coverage_gaps,
    })
}

pub fn derive_variant_queries(confirmed_finding: &Value) -> Result<Value, String> {
    let rule_id = confirmed_finding
        .get("ruleId")
        .and_then(Value::as_str)
        .ok_or("confirmed finding requires ruleId and evidence")?;
    let evidence = confirmed_finding
        .get("evidence")
        .and_then(Value::as_array)
        .filter(|e| !e.is_empty())
        .ok_or("confirmed finding requires ruleId and evidence")?;
    let first = &evidence[0];
    let file = first
        .get("file")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let line = first.get("line").cloned().unwrap_or(Value::Null);
    let same_sink_class = rule_id.split('.').take(2).collect::<Vec<_>>().join(".");
    Ok(json!({
        "schemaVersion": 1, "kind": "security-variant-plan",
        "findingId": confirmed_finding.get("id").cloned().unwrap_or(Value::Null),
        "ruleId": rule_id,
        "queries": [
            { "level": "exact", "key": format!("{rule_id}:{file}:{line}") },
            { "level": "same-rule", "key": rule_id },
            { "level": "same-sink-class", "key": same_sink_class },
        ],
    }))
}
