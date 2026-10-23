//! Native Nginx configuration facts and obligation candidates (packet A11,
//! `framework.nginx`).
//!
//! Honesty rules, in force everywhere in this module:
//! * Parsing is a bounded tokenizer + block parser (quotes, comments, `${var}`
//!   braces, blocks, `include` closure). It is never regex-only, and it never
//!   claims clean for text it did not fully understand: tokenizer/parse
//!   failures, unresolved/escaping/cyclic/missing includes, variable include
//!   targets, opaque `*_block` (Lua/njs) bodies, unsupported or unbound
//!   third-party modules, `if` blocks around modeled directives and templated
//!   config all become explicit [`NginxGap`]s and make the result partial.
//! * Source configuration proves what the file says, not what was delivered.
//!   Delivery claims come only from [`NginxRuntimeObservation`]s whose
//!   evidence the caller marked `verified` (A03 `verify_artifact_evidence`
//!   accepted it). Source-only results report `delivery = "source-only"`.
//! * No process is executed here. `nginx -t/-T` needs an admitted pinned
//!   executable (A01 owner admission); until admission exists the effective
//!   dump is simply absent and recorded as a gap by [`plan_effective_check`].
//!   A caller-supplied `-T` dump is accepted via [`split_effective_dump`] and
//!   must be exported through [`redact_effective_dump`].
//! * Candidates are policy/traffic-context first: rules that need a declared
//!   product requirement (private prefixes, required headers, body/timeout
//!   ceilings, request-id header, trusted proxy CIDRs) emit nothing without it
//!   and report the missing declaration as a gap where it matters. No generic
//!   health-check or rate-limit rule exists. A location with static content,
//!   `return`, or no `proxy_pass` is never classified unused/dead.
//! * Secret-shaped values (`Authorization`/cookie/token headers, key/password
//!   directives, credentialed upstream URLs) are replaced by a digest before
//!   they enter facts; raw file text is never retained, only a SHA-256.

use super::common::{gap, Analysis};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const NGINX_FACTS_VERSION: u32 = 1;
pub const PARSER_ID: &str = "nginx-bounded-parser/1";
/// `add_header_inherit` (and `proxy_set_header_inherit`-style merge) arrived
/// in nginx 1.29.3; older binaries reject the directive.
pub const ADD_HEADER_INHERIT_MIN_VERSION: (u32, u32, u32) = (1, 29, 3);
/// Default `ssl_protocols` dropped TLSv1/TLSv1.1 in 1.23.4.
pub const TLS_DEFAULT_MODERN_MIN_VERSION: (u32, u32, u32) = (1, 23, 4);
const MAX_INCLUDE_DEPTH: usize = 32;
const MAX_DIRECTIVES: usize = 200_000;
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_DEPTH: usize = 64;

// ---------------------------------------------------------------- inputs

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxFileInput {
    /// Path relative to the configuration prefix (or absolute under it).
    pub path: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigOrigin {
    /// Hand-written source files as committed.
    Source,
    /// Fully rendered config (generated output or `nginx -T` dump).
    Rendered,
    /// Source known to be a template; effective config not bound.
    Template,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxContext {
    /// Main file, relative to `conf_prefix`.
    pub main_file: String,
    /// Directory relative includes resolve against, and the only absolute
    /// prefix an include may use (`/etc/nginx`).
    pub conf_prefix: String,
    /// Deployed binary version `major.minor.patch`; `None` = unbound.
    pub version: Option<String>,
    /// Compiled/loaded module names (`headers-more`, `lua`, `njs`, ...);
    /// `None` = unbound.
    pub modules: Option<Vec<String>>,
    pub origin: ConfigOrigin,
}

impl Default for NginxContext {
    fn default() -> Self {
        Self {
            main_file: "nginx.conf".into(),
            conf_prefix: "/etc/nginx".into(),
            version: None,
            modules: None,
            origin: ConfigOrigin::Source,
        }
    }
}

/// Declared product/traffic requirements. Rules that need one stay silent
/// without it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxPolicy {
    pub required_headers: Vec<String>,
    /// Request path prefixes that serve per-user/private data.
    pub private_path_prefixes: Vec<String>,
    pub public_path_prefixes: Vec<String>,
    /// CIDRs of proxies/CDNs allowed in `set_real_ip_from`.
    pub trusted_proxy_cidrs: Vec<String>,
    pub request_id_header: Option<String>,
    pub max_body_bytes: Option<u64>,
    pub max_timeout_seconds: Option<u64>,
}

/// Observation from authenticated deployed tests. `verified` must come from an
/// accepted A03 `ImportVerdict`; unverified rows prove nothing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxRuntimeObservation {
    pub evidence_id: String,
    pub verified: bool,
    pub path: String,
    pub status: u16,
    /// Lower-cased header names.
    pub response_headers: BTreeMap<String, String>,
    pub cache_status: Option<String>,
    pub tls_protocol: Option<String>,
    /// `Some(false)` = request carried no credentials.
    pub authenticated: Option<bool>,
}

// ---------------------------------------------------------------- facts

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxGap {
    pub kind: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncludeEdge {
    pub from: String,
    pub line: u32,
    pub pattern: String,
    pub resolved: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderEntry {
    pub name: String,
    pub always: bool,
    /// Secret-shaped values are digests.
    pub value: String,
    pub file: String,
    pub line: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveFacts {
    pub headers: Vec<HeaderEntry>,
    pub headers_certain: bool,
    pub proxy_headers: Vec<HeaderEntry>,
    pub auth_request: Option<String>,
    pub auth_basic: bool,
    pub access_rules: bool,
    pub satisfy: Option<String>,
    pub cache_enabled: bool,
    pub cache_key: Option<String>,
    pub cache_no_cache: Vec<String>,
    pub cache_bypass: Vec<String>,
    pub cache_ignore_headers: Vec<String>,
    pub cache_valid_forced: bool,
    pub ssl_protocols: Option<Vec<String>>,
    pub client_max_body_size: Option<String>,
    pub timeouts: BTreeMap<String, String>,
    pub add_header_inherit: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocationKind {
    Proxy,
    Gateway,
    Alias,
    Return,
    Static,
    /// Only nested locations / inherited behavior. Never "dead".
    Unspecified,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationFact {
    pub id: String,
    pub modifier: String,
    pub pattern: String,
    pub file: String,
    pub line: u32,
    pub kind: LocationKind,
    pub proxy_pass: Option<String>,
    pub alias: Option<String>,
    pub returns: Option<String>,
    pub internal: bool,
    pub nested: usize,
    pub effective: EffectiveFacts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerFact {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub listen: Vec<String>,
    pub server_names: Vec<String>,
    pub tls: bool,
    pub real_ip_from: Vec<String>,
    pub real_ip_header: Option<String>,
    pub effective: EffectiveFacts,
    pub locations: Vec<LocationFact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxFacts {
    pub facts_version: u32,
    pub parser: String,
    pub version: Option<String>,
    pub modules: Option<Vec<String>>,
    pub loaded_modules: Vec<String>,
    /// path -> sha256 of file bytes. Text is not retained.
    pub files: BTreeMap<String, String>,
    pub includes: Vec<IncludeEdge>,
    pub servers: Vec<ServerFact>,
    pub gaps: Vec<NginxGap>,
}

impl NginxFacts {
    pub fn complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxCandidate {
    pub id: String,
    pub rule: String,
    /// `warning` only when a declared policy backs the rule, else `info`.
    pub severity: String,
    pub path: String,
    pub line: u32,
    pub message: String,
    pub policy_basis: Vec<String>,
    pub evidence: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxEvaluation {
    pub candidates: Vec<NginxCandidate>,
    pub gaps: Vec<NginxGap>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionState {
    Confirmed,
    Contradicted,
    Unproven,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAssertion {
    pub kind: String,
    pub path: String,
    pub state: AssertionState,
    pub evidence_id: String,
    pub detail: String,
}

/// Data-only description of the effective-config check root may run through
/// the A01-admitted seam. This module never spawns it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NginxEffectiveCheckPlan {
    pub argv: Vec<String>,
    pub requires_pinned_executable_digest: bool,
    pub requires_isolated_scratch: bool,
    pub requires_sanitized_config: bool,
    pub requires_controlled_module_loading: bool,
    pub output_must_pass: String,
    pub unbound_gap: NginxGap,
}

pub fn plan_effective_check(ctx: &NginxContext) -> NginxEffectiveCheckPlan {
    NginxEffectiveCheckPlan {
        argv: vec![
            "-T".into(),
            "-p".into(),
            "<scratch-prefix>".into(),
            "-c".into(),
            format!("<scratch-prefix>/{}", ctx.main_file),
        ],
        requires_pinned_executable_digest: true,
        requires_isolated_scratch: true,
        requires_sanitized_config: true,
        requires_controlled_module_loading: true,
        output_must_pass: "redact_effective_dump".into(),
        unbound_gap: NginxGap {
            kind: "nginx-executable-not-admitted".into(),
            file: None,
            line: None,
            detail: "no admitted pinned nginx -T result is bound; effective config is source closure only".into(),
        },
    }
}

// ---------------------------------------------------------------- secrets

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn redacted(value: &str) -> String {
    format!("[redacted:sha256:{}]", &digest_hex(value.as_bytes())[..16])
}

fn secret_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "token",
        "secret",
        "api-key",
        "apikey",
        "x-auth",
        "password",
        "credential",
        "signature",
    ]
    .iter()
    .any(|stem| n.contains(stem))
}

const SECRET_DIRECTIVES: &[&str] = &[
    "ssl_password_file",
    "ssl_session_ticket_key",
    "ssl_certificate_key",
    "auth_jwt_key_file",
    "auth_jwt_key_request",
    "secure_link_secret",
    "secure_link_md5",
    "auth_basic_user_file",
    "proxy_ssl_certificate_key",
    "proxy_ssl_password_file",
    "client_body_temp_path_secret",
];

fn secret_directive(name: &str) -> bool {
    SECRET_DIRECTIVES.contains(&name) || name.ends_with("_secret") || name.ends_with("_password")
}

fn scrub_url(url: &str) -> String {
    // scheme://user:pass@host/... -> credentials replaced by digest.
    if let Some(rest) = url.split_once("://") {
        let authority_end = rest.1.find('/').unwrap_or(rest.1.len());
        if let Some(at) = rest.1[..authority_end].rfind('@') {
            return format!(
                "{}://{}@{}",
                rest.0,
                redacted(&rest.1[..at]),
                &rest.1[at + 1..]
            );
        }
    }
    url.to_owned()
}

/// Redact secret-bearing directives of an `nginx -T` dump for evidence/export.
/// Token-scan per line on purpose: it must not depend on the dump parsing
/// cleanly, and it must catch directives written inline after `{` or `;`.
/// Multi-line quoted values are not joined; callers must treat the dump as
/// secret-bearing until this has run, and must never export the raw form.
pub fn redact_effective_dump(dump: &str) -> String {
    let mut out = String::with_capacity(dump.len());
    for line in dump.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let mut touched = false;
        let mut rebuilt: Vec<String> = Vec::with_capacity(words.len());
        let mut i = 0usize;
        while i < words.len() {
            let w = words[i];
            let start = i == 0
                || words[i - 1].ends_with('{')
                || words[i - 1].ends_with(';')
                || words[i - 1].ends_with('}');
            let next = words.get(i + 1).copied().unwrap_or("");
            let header_name = next.trim_matches(|c: char| c == '"' || c == '\'' || c == '$');
            let secret = start
                && (secret_directive(w)
                    || (matches!(
                        w,
                        "proxy_set_header" | "add_header" | "fastcgi_param" | "more_set_headers" | "more_set_input_headers" | "grpc_set_header" | "uwsgi_param"
                    ) && secret_header(header_name))
                    || (w == "set" && secret_header(header_name))
                    || (w == "proxy_pass" && next.contains('@')));
            if !secret {
                rebuilt.push(w.to_owned());
                i += 1;
                continue;
            }
            touched = true;
            rebuilt.push(w.to_owned());
            if !secret_directive(w) && w != "proxy_pass" && !next.is_empty() {
                rebuilt.push(next.to_owned());
            }
            // skip to the end of the directive (first word containing ';')
            let mut j = i + 1;
            let mut tail = String::new();
            while j < words.len() {
                if let Some(pos) = words[j].find(';') {
                    tail = words[j][pos + 1..].to_owned();
                    j += 1;
                    break;
                }
                j += 1;
            }
            rebuilt.push("[redacted];".to_owned());
            if !tail.is_empty() {
                rebuilt.push(tail);
            }
            i = j;
        }
        if touched {
            let indent = &line[..line.len() - line.trim_start().len()];
            out.push_str(indent);
            out.push_str(&rebuilt.join(" "));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Split an `nginx -T` dump (`# configuration file <path>:` markers) into
/// per-file inputs. Content before the first marker is ignored (`syntax is
/// ok` banners). Callers must retain only the redacted form as evidence.
pub fn split_effective_dump(dump: &str) -> Vec<NginxFileInput> {
    let mut files: Vec<NginxFileInput> = Vec::new();
    for line in dump.lines() {
        if let Some(rest) = line.strip_prefix("# configuration file ") {
            if let Some(path) = rest.strip_suffix(':') {
                files.push(NginxFileInput {
                    path: path.to_owned(),
                    text: String::new(),
                });
                continue;
            }
        }
        if let Some(current) = files.last_mut() {
            current.text.push_str(line);
            current.text.push('\n');
        }
    }
    files
}

// ---------------------------------------------------------------- tokenizer / parser

#[derive(Clone, Debug)]
enum Tok {
    Word { text: String, quoted: bool, line: u32 },
    Semi(u32),
    Open(u32),
    Close(u32),
}

#[derive(Clone, Debug)]
struct Arg {
    value: String,
    quoted: bool,
}

#[derive(Clone, Debug)]
struct Directive {
    name: String,
    args: Vec<Arg>,
    block: Option<Vec<Directive>>,
    file: String,
    line: u32,
    opaque: bool,
}

impl Directive {
    fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(|a| a.value.as_str())
    }
}

type ParseError = (String, u32);

fn tokenize(text: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = text.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0usize;
    let mut line = 1u32;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ';' => {
                toks.push(Tok::Semi(line));
                i += 1;
            }
            '{' => {
                toks.push(Tok::Open(line));
                i += 1;
            }
            '}' => {
                toks.push(Tok::Close(line));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                let start_line = line;
                i += 1;
                let mut word = String::new();
                let mut closed = false;
                while i < chars.len() {
                    let d = chars[i];
                    if d == '\\' && i + 1 < chars.len() {
                        let e = chars[i + 1];
                        if e == quote || e == '\\' {
                            word.push(e);
                        } else {
                            word.push('\\');
                            word.push(e);
                        }
                        if e == '\n' {
                            line += 1;
                        }
                        i += 2;
                        continue;
                    }
                    if d == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    if d == '\n' {
                        line += 1;
                    }
                    word.push(d);
                    i += 1;
                }
                if !closed {
                    return Err(("unterminated-quote".into(), start_line));
                }
                toks.push(Tok::Word { text: word, quoted: true, line: start_line });
            }
            _ => {
                let start_line = line;
                let mut word = String::new();
                while i < chars.len() {
                    let d = chars[i];
                    if d == '\\' && i + 1 < chars.len() {
                        word.push(d);
                        word.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if d == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
                        while i < chars.len() && chars[i] != '}' {
                            if chars[i] == '\n' {
                                return Err(("unterminated-variable-brace".into(), line));
                            }
                            word.push(chars[i]);
                            i += 1;
                        }
                        if i >= chars.len() {
                            return Err(("unterminated-variable-brace".into(), start_line));
                        }
                        word.push('}');
                        i += 1;
                        continue;
                    }
                    if d.is_whitespace() || d == ';' || d == '{' || d == '}' {
                        break;
                    }
                    word.push(d);
                    i += 1;
                }
                toks.push(Tok::Word { text: word, quoted: false, line: start_line });
            }
        }
    }
    Ok(toks)
}

fn opaque_block_name(name: &str) -> bool {
    name.ends_with("_block") || name == "lua" || name == "perl_set"
}

fn parse_block(
    toks: &[Tok],
    pos: &mut usize,
    file: &str,
    depth: usize,
    top: bool,
) -> Result<Vec<Directive>, ParseError> {
    if depth > MAX_BLOCK_DEPTH {
        return Err(("block-depth-exceeded".into(), 0));
    }
    let mut out = Vec::new();
    let mut words: Vec<(String, bool, u32)> = Vec::new();
    while *pos < toks.len() {
        let tok = toks[*pos].clone();
        *pos += 1;
        match tok {
            Tok::Word { text, quoted, line } => words.push((text, quoted, line)),
            Tok::Semi(line) => {
                if words.is_empty() {
                    return Err(("empty-directive".into(), line));
                }
                out.push(make_directive(&mut words, None, file, false));
            }
            Tok::Open(line) => {
                if words.is_empty() {
                    return Err(("block-without-directive".into(), line));
                }
                if opaque_block_name(&words[0].0) {
                    // Skip a balanced body without interpreting its contents.
                    let mut level = 1usize;
                    while *pos < toks.len() && level > 0 {
                        match toks[*pos] {
                            Tok::Open(_) => level += 1,
                            Tok::Close(_) => level -= 1,
                            _ => {}
                        }
                        *pos += 1;
                    }
                    if level != 0 {
                        return Err(("unclosed-block".into(), line));
                    }
                    out.push(make_directive(&mut words, Some(Vec::new()), file, true));
                } else {
                    let inner = parse_block(toks, pos, file, depth + 1, false)?;
                    out.push(make_directive(&mut words, Some(inner), file, false));
                }
            }
            Tok::Close(line) => {
                if top {
                    return Err(("unmatched-close-brace".into(), line));
                }
                if !words.is_empty() {
                    return Err(("missing-semicolon".into(), words[0].2));
                }
                return Ok(out);
            }
        }
    }
    if !words.is_empty() {
        return Err(("missing-semicolon".into(), words[0].2));
    }
    if !top {
        return Err(("unclosed-block".into(), 0));
    }
    Ok(out)
}

fn make_directive(
    words: &mut Vec<(String, bool, u32)>,
    block: Option<Vec<Directive>>,
    file: &str,
    opaque: bool,
) -> Directive {
    let taken = std::mem::take(words);
    let line = taken[0].2;
    let name = taken[0].0.clone();
    let args = taken
        .into_iter()
        .skip(1)
        .map(|(value, quoted, _)| Arg { value, quoted })
        .collect();
    Directive {
        name,
        args,
        block,
        file: file.to_owned(),
        line,
        opaque,
    }
}

// ---------------------------------------------------------------- include closure

fn normalize_path(raw: &str, prefix: &str) -> Result<String, String> {
    if raw.contains('\0') || raw.contains('\\') {
        return Err("illegal-character".into());
    }
    let mut rel = raw;
    let prefix_trim = prefix.trim_end_matches('/');
    if raw.starts_with('/') {
        match raw.strip_prefix(prefix_trim) {
            Some(rest) if rest.starts_with('/') => rel = rest,
            _ => return Err("absolute-outside-conf-prefix".into()),
        }
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("path-escape".into());
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err("empty-path".into());
    }
    Ok(parts.join("/"))
}

fn wildcard_match(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some(('*', rest)) => (0..=text.len()).any(|n| wildcard_match(rest, &text[n..])),
        Some(('?', rest)) => !text.is_empty() && wildcard_match(rest, &text[1..]),
        Some((c, rest)) => text.first() == Some(c) && wildcard_match(rest, &text[1..]),
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let t: Vec<&str> = path.split('/').collect();
    p.len() == t.len()
        && p.iter().zip(t.iter()).all(|(a, b)| {
            let a: Vec<char> = a.chars().collect();
            let b: Vec<char> = b.chars().collect();
            wildcard_match(&a, &b)
        })
}

struct Resolver<'a> {
    files: &'a BTreeMap<String, String>,
    prefix: String,
    edges: Vec<IncludeEdge>,
    gaps: Vec<NginxGap>,
    parsed: BTreeMap<String, Option<Vec<Directive>>>,
    count: usize,
    capped: bool,
}

impl<'a> Resolver<'a> {
    fn gap(&mut self, kind: &str, file: Option<&str>, line: Option<u32>, detail: impl Into<String>) {
        let g = NginxGap {
            kind: kind.into(),
            file: file.map(str::to_owned),
            line,
            detail: detail.into(),
        };
        if !self.gaps.contains(&g) {
            self.gaps.push(g);
        }
    }

    fn expand_file(&mut self, path: &str, stack: &mut Vec<String>) -> Vec<Directive> {
        if stack.iter().any(|p| p == path) {
            self.gap("include-cycle", Some(path), None, format!("cycle through {}", stack.join(" -> ")));
            return Vec::new();
        }
        if stack.len() >= MAX_INCLUDE_DEPTH {
            self.gap("include-depth-exceeded", Some(path), None, "include nesting limit reached");
            return Vec::new();
        }
        let files = self.files;
        if !self.parsed.contains_key(path) {
            let result = match files.get(path) {
                Some(text) if text.len() > MAX_FILE_BYTES => {
                    self.gap("file-too-large", Some(path), None, "file exceeds parser byte bound");
                    None
                }
                Some(text) => {
                    if text.contains("{{") || text.contains("{%") || text.contains("<%") {
                        self.gap("generated-config-template", Some(path), None, "template markers present; effective config not bound");
                    }
                    match tokenize(text).and_then(|toks| {
                        let mut pos = 0usize;
                        parse_block(&toks, &mut pos, path, 0, true)
                    }) {
                        Ok(ds) => Some(ds),
                        Err((kind, line)) => {
                            self.gap("parse-error", Some(path), Some(line), kind);
                            None
                        }
                    }
                }
                None => None,
            };
            self.parsed.insert(path.to_owned(), result);
        }
        let Some(Some(directives)) = self.parsed.get(path).cloned() else {
            return Vec::new();
        };
        stack.push(path.to_owned());
        let out = self.expand_directives(directives, stack);
        stack.pop();
        out
    }

    fn expand_directives(&mut self, ds: Vec<Directive>, stack: &mut Vec<String>) -> Vec<Directive> {
        let mut out = Vec::new();
        for mut d in ds {
            if self.capped {
                break;
            }
            self.count += 1;
            if self.count > MAX_DIRECTIVES {
                self.capped = true;
                self.gap("directive-cap", None, None, "directive count bound reached");
                break;
            }
            if d.name == "include" && d.block.is_none() {
                out.extend(self.expand_include(&d, stack));
                continue;
            }
            if let Some(block) = d.block.take() {
                d.block = Some(self.expand_directives(block, stack));
            }
            out.push(d);
        }
        out
    }

    fn expand_include(&mut self, d: &Directive, stack: &mut Vec<String>) -> Vec<Directive> {
        let (file, line) = (d.file.clone(), d.line);
        let pattern = match (d.args.len(), d.arg(0)) {
            (1, Some(p)) => p.to_owned(),
            _ => {
                self.gap("include-malformed", Some(&file), Some(line), "include needs exactly one argument");
                return Vec::new();
            }
        };
        if pattern.contains('$') {
            self.gap("include-variable-target", Some(&file), Some(line), "include path contains a variable; closure unresolved");
            return Vec::new();
        }
        let normalized = match normalize_path(&pattern, &self.prefix) {
            Ok(p) => p,
            Err(reason) => {
                self.gap("include-path-escape", Some(&file), Some(line), reason);
                return Vec::new();
            }
        };
        let wildcard = normalized.contains('*') || normalized.contains('?');
        let matches: Vec<String> = if wildcard {
            self.files
                .keys()
                .filter(|k| glob_match(&normalized, k))
                .cloned()
                .collect()
        } else if self.files.contains_key(&normalized) {
            vec![normalized.clone()]
        } else {
            Vec::new()
        };
        if matches.is_empty() {
            let kind = if wildcard { "include-glob-no-match" } else { "include-missing" };
            self.gap(kind, Some(&file), Some(line), pattern.clone());
        }
        self.edges.push(IncludeEdge {
            from: file,
            line,
            pattern,
            resolved: matches.clone(),
        });
        let mut out = Vec::new();
        for m in matches {
            out.extend(self.expand_file(&m, stack));
        }
        out
    }
}

// ---------------------------------------------------------------- version / units

fn parse_version(value: &str) -> Option<(u32, u32, u32)> {
    let core = value.trim().trim_start_matches("nginx/");
    let mut it = core.split(|c: char| c == '.' || c == '-' || c == ' ');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next().unwrap_or("0").parse().ok()?,
    ))
}

/// `Some(true/false)` when the version is bound, `None` when unbound.
fn version_at_least(version: Option<(u32, u32, u32)>, min: (u32, u32, u32)) -> Option<bool> {
    version.map(|v| v >= min)
}

fn parse_size(value: &str) -> Option<u64> {
    let v = value.trim().to_ascii_lowercase();
    let (digits, mult) = match v.chars().last()? {
        'k' => (&v[..v.len() - 1], 1024u64),
        'm' => (&v[..v.len() - 1], 1024 * 1024),
        'g' => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (&v[..], 1),
        _ => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

fn parse_seconds(value: &str) -> Option<u64> {
    let v = value.trim().to_ascii_lowercase();
    if let Some(n) = v.strip_suffix("ms") {
        return n.parse::<u64>().ok().map(|ms| ms / 1000);
    }
    let (digits, mult) = match v.chars().last()? {
        's' => (&v[..v.len() - 1], 1u64),
        'm' => (&v[..v.len() - 1], 60),
        'h' => (&v[..v.len() - 1], 3600),
        'd' => (&v[..v.len() - 1], 86400),
        c if c.is_ascii_digit() => (&v[..], 1),
        _ => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

// ---------------------------------------------------------------- effective lookup

fn eff1<'a>(chain: &[&'a [Directive]], name: &str) -> Option<&'a Directive> {
    chain
        .iter()
        .rev()
        .find_map(|level| level.iter().rev().find(|d| d.name == name))
}

fn eff_all<'a>(chain: &[&'a [Directive]], name: &str) -> Vec<&'a Directive> {
    for level in chain.iter().rev() {
        let found: Vec<&Directive> = level.iter().filter(|d| d.name == name).collect();
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn header_entry(d: &Directive, name_index: usize, value_index: usize) -> Option<HeaderEntry> {
    let name = d.arg(name_index)?.to_ascii_lowercase();
    let value = d.arg(value_index).unwrap_or("");
    let always = d.args.iter().skip(value_index + 1).any(|a| a.value == "always");
    Some(HeaderEntry {
        value: if secret_header(&name) { redacted(value) } else { value.to_owned() },
        name,
        always,
        file: d.file.clone(),
        line: d.line,
    })
}

/// Effective list with nginx array-inheritance: a level that defines any entry
/// replaces everything inherited, unless `inherit_aware` and that level's
/// `add_header_inherit` says `merge`/`off`. Returns `(entries, certain)`.
fn eff_headers(
    chain: &[&[Directive]],
    directive: &str,
    inherit_aware: bool,
    version: Option<(u32, u32, u32)>,
) -> (Vec<HeaderEntry>, bool) {
    let mut certain = true;
    let mut acc: Vec<HeaderEntry> = Vec::new();
    for (i, level) in chain.iter().enumerate() {
        let own: Vec<HeaderEntry> = level
            .iter()
            .filter(|d| d.name == directive)
            .filter_map(|d| header_entry(d, 0, 1))
            .collect();
        let mode = if inherit_aware {
            eff1(&chain[..=i], "add_header_inherit")
                .and_then(|d| d.arg(0))
                .unwrap_or("on")
                .to_ascii_lowercase()
        } else {
            "on".into()
        };
        if inherit_aware && level.iter().any(|d| d.name == "add_header_inherit")
            && version_at_least(version, ADD_HEADER_INHERIT_MIN_VERSION) != Some(true)
        {
            certain = false;
        }
        acc = match mode.as_str() {
            "off" => own,
            "merge" => {
                acc.extend(own);
                acc
            }
            _ => {
                if own.is_empty() {
                    acc
                } else {
                    own
                }
            }
        };
    }
    (acc, certain)
}

const MODELED: &[&str] = &[
    "add_header",
    "proxy_set_header",
    "proxy_pass",
    "auth_request",
    "auth_basic",
    "proxy_cache",
    "alias",
    "return",
    "allow",
    "deny",
    "expires",
    "more_set_headers",
];

fn has_modeled_if(level: &[Directive]) -> bool {
    level.iter().any(|d| {
        d.name == "if"
            && d.block
                .as_ref()
                .is_some_and(|b| b.iter().any(|i| MODELED.contains(&i.name.as_str())))
    })
}

fn effective(chain: &[&[Directive]], version: Option<(u32, u32, u32)>) -> EffectiveFacts {
    let (headers, headers_certain) = eff_headers(chain, "add_header", true, version);
    let (proxy_headers, ph_certain) = eff_headers(chain, "proxy_set_header", false, version);
    let args_of = |name: &str| -> Vec<String> {
        eff_all(chain, name)
            .iter()
            .flat_map(|d| d.args.iter().map(|a| a.value.clone()))
            .collect()
    };
    let cache = eff1(chain, "proxy_cache").or_else(|| eff1(chain, "fastcgi_cache"));
    let mut timeouts = BTreeMap::new();
    for name in [
        "proxy_read_timeout",
        "proxy_send_timeout",
        "proxy_connect_timeout",
        "client_body_timeout",
        "client_header_timeout",
        "send_timeout",
    ] {
        if let Some(d) = eff1(chain, name) {
            if let Some(v) = d.arg(0) {
                timeouts.insert(name.to_owned(), v.to_owned());
            }
        }
    }
    let ignore: Vec<String> = args_of("proxy_ignore_headers")
        .into_iter()
        .chain(args_of("fastcgi_ignore_headers"))
        .collect();
    EffectiveFacts {
        headers,
        headers_certain: headers_certain && ph_certain
            && !chain.iter().any(|l| has_modeled_if(l))
            && !chain.iter().any(|l| l.iter().any(|d| d.name.starts_with("more_") || d.opaque)),
        proxy_headers,
        auth_request: eff1(chain, "auth_request")
            .and_then(|d| d.arg(0))
            .filter(|v| *v != "off")
            .map(str::to_owned),
        auth_basic: eff1(chain, "auth_basic")
            .and_then(|d| d.arg(0))
            .is_some_and(|v| v != "off"),
        access_rules: !eff_all(chain, "allow").is_empty() || !eff_all(chain, "deny").is_empty(),
        satisfy: eff1(chain, "satisfy").and_then(|d| d.arg(0)).map(str::to_owned),
        cache_enabled: cache
            .and_then(|d| d.arg(0))
            .is_some_and(|v| v != "off"),
        cache_key: eff1(chain, "proxy_cache_key").and_then(|d| d.arg(0)).map(str::to_owned),
        cache_no_cache: args_of("proxy_no_cache"),
        cache_bypass: args_of("proxy_cache_bypass"),
        cache_ignore_headers: ignore,
        cache_valid_forced: eff1(chain, "proxy_cache_valid").is_some(),
        ssl_protocols: eff1(chain, "ssl_protocols")
            .map(|d| d.args.iter().map(|a| a.value.clone()).collect()),
        client_max_body_size: eff1(chain, "client_max_body_size")
            .and_then(|d| d.arg(0))
            .map(str::to_owned),
        timeouts,
        add_header_inherit: eff1(chain, "add_header_inherit")
            .and_then(|d| d.arg(0))
            .map(str::to_owned),
    }
}

// ---------------------------------------------------------------- fact building

const THIRD_PARTY_PREFIXES: &[(&str, &str)] = &[
    ("more_", "headers-more"),
    ("lua_", "lua"),
    ("set_by_lua", "lua"),
    ("access_by_lua", "lua"),
    ("content_by_lua", "lua"),
    ("rewrite_by_lua", "lua"),
    ("header_filter_by_lua", "lua"),
    ("js_", "njs"),
    ("perl", "perl"),
    ("modsecurity", "modsecurity"),
    ("naxsi", "naxsi"),
    ("brotli", "brotli"),
    ("vhost_traffic_status", "vts"),
];

fn third_party_module(name: &str) -> Option<&'static str> {
    THIRD_PARTY_PREFIXES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, module)| *module)
}

fn collect_modules(ds: &[Directive], found: &mut BTreeMap<&'static str, (String, u32)>) {
    for d in ds {
        if let Some(m) = third_party_module(&d.name) {
            found.entry(m).or_insert((d.file.clone(), d.line));
        }
        if let Some(b) = &d.block {
            collect_modules(b, found);
        }
    }
}

fn build_location(
    server_id: &str,
    index: &str,
    d: &Directive,
    parent_chain: &[&[Directive]],
    version: Option<(u32, u32, u32)>,
) -> LocationFact {
    let block: &[Directive] = d.block.as_deref().unwrap_or(&[]);
    let (modifier, pattern) = match d.args.len() {
        0 => (String::new(), String::new()),
        1 => (String::new(), d.args[0].value.clone()),
        _ => (d.args[0].value.clone(), d.args[1].value.clone()),
    };
    let mut chain: Vec<&[Directive]> = parent_chain.to_vec();
    chain.push(block);
    let own = |name: &str| block.iter().rev().find(|x| x.name == name);
    let proxy_pass = own("proxy_pass").and_then(|x| x.arg(0)).map(scrub_url);
    let alias = own("alias").and_then(|x| x.arg(0)).map(str::to_owned);
    let returns = own("return").map(|x| {
        x.args.iter().map(|a| a.value.as_str()).collect::<Vec<_>>().join(" ")
    });
    let gateway = ["fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"]
        .iter()
        .any(|n| own(n).is_some());
    let kind = if proxy_pass.is_some() {
        LocationKind::Proxy
    } else if gateway {
        LocationKind::Gateway
    } else if alias.is_some() {
        LocationKind::Alias
    } else if returns.is_some() {
        LocationKind::Return
    } else if ["root", "try_files", "index", "autoindex", "stub_status", "expires"]
        .iter()
        .any(|n| own(n).is_some())
    {
        LocationKind::Static
    } else {
        LocationKind::Unspecified
    };
    let nested = block.iter().filter(|x| x.name == "location").count();
    LocationFact {
        id: format!("{server_id}/loc{index}"),
        modifier,
        pattern,
        file: d.file.clone(),
        line: d.line,
        kind,
        proxy_pass,
        alias,
        returns,
        internal: own("internal").is_some(),
        nested,
        effective: effective(&chain, version),
    }
}

fn flatten_locations(
    server_id: &str,
    prefix: &str,
    level: &[Directive],
    chain: &[&[Directive]],
    version: Option<(u32, u32, u32)>,
    out: &mut Vec<LocationFact>,
    depth: usize,
) {
    let mut n = 0usize;
    for d in level.iter().filter(|d| d.name == "location") {
        n += 1;
        let index = format!("{prefix}{n}");
        out.push(build_location(server_id, &index, d, chain, version));
        if depth < MAX_BLOCK_DEPTH {
            let block: &[Directive] = d.block.as_deref().unwrap_or(&[]);
            let mut child: Vec<&[Directive]> = chain.to_vec();
            child.push(block);
            flatten_locations(server_id, &format!("{index}."), block, &child, version, out, depth + 1);
        }
    }
}

pub fn parse_nginx(inputs: &[NginxFileInput], ctx: &NginxContext) -> NginxFacts {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    let mut gaps: Vec<NginxGap> = Vec::new();
    for input in inputs {
        match normalize_path(&input.path, &ctx.conf_prefix) {
            Ok(path) => {
                digests.insert(path.clone(), digest_hex(input.text.as_bytes()));
                files.insert(path, input.text.clone());
            }
            Err(reason) => gaps.push(NginxGap {
                kind: "input-path-escape".into(),
                file: Some(input.path.clone()),
                line: None,
                detail: reason,
            }),
        }
    }
    let version = ctx.version.as_deref().and_then(parse_version);
    if ctx.version.is_some() && version.is_none() {
        gaps.push(NginxGap {
            kind: "version-unparsed".into(),
            file: None,
            line: None,
            detail: "context nginx version is not major.minor.patch".into(),
        });
    }
    if ctx.origin == ConfigOrigin::Template {
        gaps.push(NginxGap {
            kind: "generated-config-template".into(),
            file: None,
            line: None,
            detail: "source declared as template; render and bind output before certifying".into(),
        });
    }
    let mut facts = NginxFacts {
        facts_version: NGINX_FACTS_VERSION,
        parser: PARSER_ID.into(),
        version: ctx.version.clone(),
        modules: ctx.modules.clone(),
        loaded_modules: Vec::new(),
        files: digests,
        includes: Vec::new(),
        servers: Vec::new(),
        gaps: Vec::new(),
    };
    let main = match normalize_path(&ctx.main_file, &ctx.conf_prefix) {
        Ok(m) if files.contains_key(&m) => m,
        _ => {
            gaps.push(NginxGap {
                kind: "main-config-missing".into(),
                file: Some(ctx.main_file.clone()),
                line: None,
                detail: "main configuration file not supplied".into(),
            });
            facts.gaps = gaps;
            return facts;
        }
    };
    let mut resolver = Resolver {
        files: &files,
        prefix: ctx.conf_prefix.clone(),
        edges: Vec::new(),
        gaps,
        parsed: BTreeMap::new(),
        count: 0,
        capped: false,
    };
    let root = resolver.expand_file(&main, &mut Vec::new());
    facts.includes = std::mem::take(&mut resolver.edges);
    let mut gaps = std::mem::take(&mut resolver.gaps);

    // Modules: dynamic loads and unbound third-party directives.
    for d in root.iter().filter(|d| d.name == "load_module") {
        if let Some(path) = d.arg(0) {
            facts.loaded_modules.push(path.rsplit('/').next().unwrap_or(path).to_owned());
        }
    }
    let mut used: BTreeMap<&'static str, (String, u32)> = BTreeMap::new();
    collect_modules(&root, &mut used);
    for (module, (file, line)) in used {
        let bound = ctx
            .modules
            .as_ref()
            .is_some_and(|m| m.iter().any(|x| x.eq_ignore_ascii_case(module)));
        let kind = if ctx.modules.is_none() {
            "module-set-unbound"
        } else if !bound {
            "unknown-module"
        } else {
            "module-semantics-unmodeled"
        };
        gaps.push(NginxGap {
            kind: kind.into(),
            file: Some(file),
            line: Some(line),
            detail: format!("directives of module `{module}` are not modeled; effective headers/routing partial"),
        });
    }
    for d in root.iter().filter(|d| d.name == "stream") {
        gaps.push(NginxGap {
            kind: "stream-context-unmodeled".into(),
            file: Some(d.file.clone()),
            line: Some(d.line),
            detail: "stream block is not analyzed".into(),
        });
    }

    let root_chain: Vec<&[Directive]> = vec![&root[..]];
    let mut server_no = 0usize;
    for http in root.iter().filter(|d| d.name == "http") {
        let http_block: &[Directive] = http.block.as_deref().unwrap_or(&[]);
        for server in http_block.iter().filter(|d| d.name == "server") {
            server_no += 1;
            let sblock: &[Directive] = server.block.as_deref().unwrap_or(&[]);
            let server_id = format!("srv{server_no}");
            let chain: Vec<&[Directive]> = vec![root_chain[0], http_block, sblock];
            let listen: Vec<String> = sblock
                .iter()
                .filter(|d| d.name == "listen")
                .map(|d| d.args.iter().map(|a| a.value.as_str()).collect::<Vec<_>>().join(" "))
                .collect();
            let tls = sblock.iter().filter(|d| d.name == "listen").any(|d| {
                d.args.iter().any(|a| a.value == "ssl" || a.value == "quic")
            });
            let mut locations = Vec::new();
            flatten_locations(&server_id, "", sblock, &chain, version, &mut locations, 0);
            facts.servers.push(ServerFact {
                id: server_id,
                file: server.file.clone(),
                line: server.line,
                listen,
                server_names: sblock
                    .iter()
                    .filter(|d| d.name == "server_name")
                    .flat_map(|d| d.args.iter().map(|a| a.value.clone()))
                    .collect(),
                tls,
                real_ip_from: eff_all(&chain, "set_real_ip_from")
                    .iter()
                    .filter_map(|d| d.arg(0).map(str::to_owned))
                    .collect(),
                real_ip_header: eff1(&chain, "real_ip_header").and_then(|d| d.arg(0)).map(str::to_owned),
                effective: effective(&chain, version),
                locations,
            });
        }
    }
    if facts.servers.is_empty() {
        gaps.push(NginxGap {
            kind: "no-server-blocks".into(),
            file: None,
            line: None,
            detail: "no http/server blocks resolved; nothing certifiable".into(),
        });
    }
    for server in &facts.servers {
        for loc in &server.locations {
            if !loc.effective.headers_certain {
                let g = NginxGap {
                    kind: "header-state-unproven".into(),
                    file: Some(loc.file.clone()),
                    line: Some(loc.line),
                    detail: "if-block, headers-more, opaque block or version-unbound add_header_inherit makes effective headers uncertain".into(),
                };
                if !gaps.contains(&g) {
                    gaps.push(g);
                }
            }
        }
    }
    facts.gaps = gaps;
    facts
}

// ---------------------------------------------------------------- evaluation

enum Selection<'a> {
    Location(&'a LocationFact),
    ServerLevel,
    Unresolved(String),
}

fn select_location<'a>(server: &'a ServerFact, path: &str) -> Selection<'a> {
    let top: Vec<&LocationFact> = server
        .locations
        .iter()
        .filter(|l| !l.id[server.id.len() + 4..].contains('.'))
        .collect();
    if let Some(l) = top.iter().copied().find(|l| l.modifier == "=" && l.pattern == path) {
        return finish_selection(l);
    }
    let best = top
        .iter()
        .copied()
        .filter(|l| (l.modifier.is_empty() || l.modifier == "^~") && path.starts_with(&l.pattern))
        .max_by_key(|l| l.pattern.len());
    if let Some(l) = best {
        if l.modifier == "^~" {
            return finish_selection(l);
        }
    }
    if top.iter().any(|l| l.modifier == "~" || l.modifier == "~*") {
        return Selection::Unresolved("regex-location-precedence".into());
    }
    match best {
        Some(l) => finish_selection(l),
        None => Selection::ServerLevel,
    }
}

fn finish_selection<'a>(l: &'a LocationFact) -> Selection<'a> {
    if l.nested > 0 {
        Selection::Unresolved("nested-location-selection".into())
    } else {
        Selection::Location(l)
    }
}

fn has_cacheless_partition(e: &EffectiveFacts) -> bool {
    let partition = |items: &[String]| {
        items
            .iter()
            .any(|v| v.contains("$http_authorization") || v.contains("$cookie_") || v.contains("$http_cookie"))
    };
    partition(&e.cache_no_cache)
        || partition(&e.cache_bypass)
        || e.cache_key.as_deref().is_some_and(|k| {
            k.contains("$http_authorization") || k.contains("$cookie_") || k.contains("$http_cookie")
        })
}

fn candidate(
    rule: &str,
    loc_id: &str,
    n: usize,
    file: &str,
    line: u32,
    message: String,
    basis: Vec<String>,
    evidence: Value,
) -> NginxCandidate {
    NginxCandidate {
        id: format!("nginx:{rule}:{loc_id}:{n}"),
        rule: rule.into(),
        severity: if basis.is_empty() { "info" } else { "warning" }.into(),
        path: file.into(),
        line,
        message,
        policy_basis: basis,
        evidence,
    }
}

pub fn evaluate_nginx(facts: &NginxFacts, policy: &NginxPolicy) -> NginxEvaluation {
    let mut out = NginxEvaluation::default();
    let version = facts.version.as_deref().and_then(parse_version);
    let mut serial = 0usize;
    let push = |out: &mut NginxEvaluation, c: NginxCandidate| out.candidates.push(c);
    let add_gap = |out: &mut NginxEvaluation, kind: &str, file: &str, line: u32, detail: String| {
        let g = NginxGap {
            kind: kind.into(),
            file: Some(file.into()),
            line: Some(line),
            detail,
        };
        if !out.gaps.contains(&g) {
            out.gaps.push(g);
        }
    };
    let required: Vec<String> = policy.required_headers.iter().map(|h| h.to_ascii_lowercase()).collect();
    let request_id = policy.request_id_header.as_ref().map(|h| h.to_ascii_lowercase());

    for server in &facts.servers {
        // ---- TLS protocol floor (server level, version aware)
        if server.tls {
            let weak = |p: &str| matches!(p.to_ascii_lowercase().as_str(), "sslv2" | "sslv3" | "tlsv1" | "tlsv1.1");
            match &server.effective.ssl_protocols {
                Some(list) if list.iter().any(|p| weak(p)) => {
                    serial += 1;
                    push(&mut out, candidate(
                        "tls-weak-protocol", &server.id, serial, &server.file, server.line,
                        "TLS listener enables a deprecated protocol".into(), Vec::new(),
                        json!({"sslProtocols": list}),
                    ));
                }
                Some(_) => {}
                None => match version_at_least(version, TLS_DEFAULT_MODERN_MIN_VERSION) {
                    Some(false) => {
                        serial += 1;
                        push(&mut out, candidate(
                            "tls-weak-protocol", &server.id, serial, &server.file, server.line,
                            "ssl_protocols unset and this nginx version defaults to TLSv1/TLSv1.1".into(),
                            Vec::new(), json!({"version": facts.version, "default": "TLSv1 TLSv1.1 TLSv1.2"}),
                        ));
                    }
                    Some(true) => {}
                    None => add_gap(&mut out, "version-unbound-tls-default", &server.file, server.line,
                        "ssl_protocols unset; protocol default depends on unbound nginx version".into()),
                },
            }
        }
        // ---- trusted forwarded identity at server level
        for from in &server.real_ip_from {
            let broad = matches!(from.as_str(), "0.0.0.0/0" | "::/0" | "all");
            let outside = !policy.trusted_proxy_cidrs.is_empty()
                && !policy.trusted_proxy_cidrs.iter().any(|c| c == from);
            if broad || outside {
                serial += 1;
                let basis = if outside { vec!["trustedProxyCidrs".to_owned()] } else { Vec::new() };
                push(&mut out, candidate(
                    "forwarded-host-trust", &server.id, serial, &server.file, server.line,
                    "set_real_ip_from trusts a source outside the declared edge".into(), basis,
                    json!({"setRealIpFrom": from, "broad": broad}),
                ));
            }
        }
        // ---- body limit at server level
        if let Some(max) = policy.max_body_bytes {
            let configured = server.effective.client_max_body_size.as_deref();
            let limit = configured.map(parse_size).unwrap_or(Some(1024 * 1024));
            match limit {
                Some(0) => {
                    serial += 1;
                    push(&mut out, candidate("body-limit", &server.id, serial, &server.file, server.line,
                        "client_max_body_size 0 disables the body limit".into(),
                        vec!["maxBodyBytes".into()], json!({"configured": configured})));
                }
                Some(n) if n > max => {
                    serial += 1;
                    push(&mut out, candidate("body-limit", &server.id, serial, &server.file, server.line,
                        "client_max_body_size exceeds declared ceiling".into(),
                        vec!["maxBodyBytes".into()], json!({"configured": configured, "max": max})));
                }
                None => add_gap(&mut out, "body-limit-unparsed", &server.file, server.line,
                    "client_max_body_size value not understood".into()),
                _ => {}
            }
        }

        for loc in &server.locations {
            let e = &loc.effective;
            let proxying = matches!(loc.kind, LocationKind::Proxy | LocationKind::Gateway);

            // ---- header inheritance loss (version aware)
            if !required.is_empty() {
                if e.headers_certain {
                    for want in &required {
                        let entry = e.headers.iter().find(|h| &h.name == want);
                        match entry {
                            None => {
                                serial += 1;
                                push(&mut out, candidate(
                                    "header-inheritance-loss", &loc.id, serial, &loc.file, loc.line,
                                    format!("required header `{want}` absent from effective response headers (add_header replaces inherited sets unless merged)"),
                                    vec!["requiredHeaders".into()],
                                    json!({"effectiveHeaders": e.headers.iter().map(|h| &h.name).collect::<Vec<_>>(),
                                           "addHeaderInherit": e.add_header_inherit, "version": facts.version}),
                                ));
                            }
                            Some(h) if !h.always => {
                                serial += 1;
                                push(&mut out, candidate(
                                    "header-status-coverage", &loc.id, serial, &h.file, h.line,
                                    format!("required header `{want}` lacks `always`; not sent on 4xx/5xx"),
                                    vec!["requiredHeaders".into()], json!({"header": want}),
                                ));
                            }
                            _ => {}
                        }
                    }
                } else {
                    add_gap(&mut out, "header-state-unproven", &loc.file, loc.line,
                        "required-header evaluation skipped: effective headers uncertain".into());
                }
            }
            if let Some(mode) = &e.add_header_inherit {
                if version_at_least(version, ADD_HEADER_INHERIT_MIN_VERSION) == Some(false) {
                    serial += 1;
                    push(&mut out, candidate(
                        "add-header-inherit-version", &loc.id, serial, &loc.file, loc.line,
                        "add_header_inherit used but deployed nginx predates it (1.29.3); nginx -t would reject it and merge semantics do not apply".into(),
                        Vec::new(), json!({"mode": mode, "version": facts.version}),
                    ));
                }
            }

            // ---- alias path handling
            if let Some(alias) = &loc.alias {
                let prefix_loc = loc.modifier.is_empty() || loc.modifier == "^~";
                if prefix_loc && !loc.pattern.ends_with('/') && alias.ends_with('/') {
                    serial += 1;
                    push(&mut out, candidate(
                        "alias-path-traversal", &loc.id, serial, &loc.file, loc.line,
                        "prefix location without trailing slash + alias with trailing slash permits path escape (off-by-slash)".into(),
                        Vec::new(), json!({"location": loc.pattern, "alias": alias}),
                    ));
                } else if prefix_loc && loc.pattern.ends_with('/') && !alias.ends_with('/') {
                    serial += 1;
                    push(&mut out, candidate(
                        "alias-path-mismatch", &loc.id, serial, &loc.file, loc.line,
                        "location ends with slash but alias does not; resolved paths are malformed".into(),
                        Vec::new(), json!({"location": loc.pattern, "alias": alias}),
                    ));
                }
            }

            // ---- proxy_pass path & target handling
            if let Some(target) = &loc.proxy_pass {
                let after_scheme = target.split_once("://").map(|x| x.1).unwrap_or(target);
                let uri_start = after_scheme.find('/');
                let uri = uri_start.map(|i| &after_scheme[i..]);
                if target.contains('$') {
                    let client_controlled = ["$http_", "$arg_", "$host", "$uri", "$request_uri", "$cookie_", "$args"]
                        .iter()
                        .any(|v| target.contains(v));
                    if client_controlled {
                        serial += 1;
                        push(&mut out, candidate(
                            "proxy-pass-client-target", &loc.id, serial, &loc.file, loc.line,
                            "proxy_pass target derives from client-controlled variable".into(),
                            Vec::new(), json!({"target": target}),
                        ));
                    }
                    add_gap(&mut out, "proxy-pass-variable-target", &loc.file, loc.line,
                        "variable proxy_pass target: URI rewriting and routing not statically resolvable".into());
                } else if loc.modifier.is_empty() || loc.modifier == "^~" {
                    match uri {
                        Some("/") if !loc.pattern.ends_with('/') => {
                            serial += 1;
                            push(&mut out, candidate(
                                "proxy-pass-slash-mismatch", &loc.id, serial, &loc.file, loc.line,
                                "prefix location without trailing slash proxied to a `/` URI yields double-slash/path confusion".into(),
                                Vec::new(), json!({"location": loc.pattern, "proxyPass": target}),
                            ));
                        }
                        Some(u) if loc.pattern.ends_with('/') && !u.ends_with('/') => {
                            serial += 1;
                            push(&mut out, candidate(
                                "proxy-pass-slash-mismatch", &loc.id, serial, &loc.file, loc.line,
                                "location ends with slash but proxy_pass URI does not; joined path loses its separator".into(),
                                Vec::new(), json!({"location": loc.pattern, "proxyPass": target}),
                            ));
                        }
                        _ => {}
                    }
                }
            }

            // ---- forwarded host/address trust
            if proxying {
                for h in &e.proxy_headers {
                    let v = h.value.as_str();
                    let bad = match h.name.as_str() {
                        "host" => v == "$http_host" || v == "$http_x_forwarded_host",
                        "x-forwarded-host" => v == "$http_x_forwarded_host" || v == "$http_host",
                        "x-forwarded-for" => v == "$http_x_forwarded_for",
                        "x-real-ip" | "x-forwarded-proto" => v.starts_with("$http_"),
                        _ => false,
                    };
                    if bad {
                        serial += 1;
                        push(&mut out, candidate(
                            "forwarded-host-trust", &loc.id, serial, &h.file, h.line,
                            format!("`{}` forwards a client-supplied value unvalidated", h.name),
                            Vec::new(), json!({"header": h.name, "value": h.value}),
                        ));
                    }
                }
            }

            // ---- request-id propagation (replacement inheritance)
            if proxying {
                if let Some(rid) = &request_id {
                    let bare = rid.replace('-', "_");
                    let propagated = e.proxy_headers.iter().any(|h| {
                        &h.name == rid && (h.value.contains("$request_id") || h.value.contains(&format!("$http_{bare}")))
                    });
                    if !propagated {
                        serial += 1;
                        push(&mut out, candidate(
                            "request-id-propagation", &loc.id, serial, &loc.file, loc.line,
                            format!("proxied location does not set `{rid}` upstream (proxy_set_header replaces inherited sets)"),
                            vec!["requestIdHeader".into()],
                            json!({"effectiveProxyHeaders": e.proxy_headers.iter().map(|h| &h.name).collect::<Vec<_>>()}),
                        ));
                    }
                }
            }

            // ---- timeout ceiling
            if let Some(max) = policy.max_timeout_seconds {
                for (name, value) in &e.timeouts {
                    match parse_seconds(value) {
                        Some(s) if s > max => {
                            serial += 1;
                            push(&mut out, candidate(
                                "timeout-ceiling", &loc.id, serial, &loc.file, loc.line,
                                format!("{name} exceeds declared ceiling"),
                                vec!["maxTimeoutSeconds".into()],
                                json!({"directive": name, "value": value, "max": max}),
                            ));
                        }
                        None => add_gap(&mut out, "timeout-unparsed", &loc.file, loc.line,
                            format!("{name} value not understood")),
                        _ => {}
                    }
                }
            }

            // ---- auth + cache without declared policy
            let authed = e.auth_request.is_some() || e.auth_basic;
            if authed && e.cache_enabled && !has_cacheless_partition(e) {
                serial += 1;
                push(&mut out, candidate(
                    "cache-private-shared", &loc.id, serial, &loc.file, loc.line,
                    "authenticated location enables a shared cache without credential partitioning (confirm with runtime evidence)".into(),
                    Vec::new(),
                    json!({"cacheKey": e.cache_key, "ignoreHeaders": e.cache_ignore_headers}),
                ));
            }
            if e.auth_request.as_deref().is_some_and(|t| t.starts_with('/') && !t.contains('$')) {
                let target = e.auth_request.clone().unwrap_or_default();
                let exists = server.locations.iter().any(|l| {
                    (l.modifier == "=" && l.pattern == target)
                        || ((l.modifier.is_empty() || l.modifier == "^~") && target.starts_with(&l.pattern))
                        || l.modifier == "~" || l.modifier == "~*"
                });
                if !exists {
                    serial += 1;
                    push(&mut out, candidate(
                        "auth-request-target-missing", &loc.id, serial, &loc.file, loc.line,
                        "auth_request subrequest target has no matching location in this server".into(),
                        Vec::new(), json!({"target": target}),
                    ));
                }
            }
            if e.satisfy.as_deref() == Some("any") && e.access_rules && authed {
                serial += 1;
                push(&mut out, candidate(
                    "satisfy-any-bypass", &loc.id, serial, &loc.file, loc.line,
                    "satisfy any lets an allow rule bypass authentication".into(),
                    Vec::new(), json!({"satisfy": "any"}),
                ));
            }
            if matches!(loc.kind, LocationKind::Proxy) && e.cache_enabled
                && policy.private_path_prefixes.is_empty() && policy.public_path_prefixes.is_empty() {
                add_gap(&mut out, "cache-policy-undeclared", &loc.file, loc.line,
                    "cache enabled but no public/private path policy declared; privacy cannot be judged".into());
            }
        }

        // ---- policy-declared private prefixes: auth routing + cache privacy
        for prefix in &policy.private_path_prefixes {
            let (e, kind_id, file, line, internal, ret): (&EffectiveFacts, String, String, u32, bool, Option<&String>) =
                match select_location(server, prefix) {
                    Selection::Location(l) => (&l.effective, l.id.clone(), l.file.clone(), l.line, l.internal, l.returns.as_ref()),
                    Selection::ServerLevel => (&server.effective, server.id.clone(), server.file.clone(), server.line, false, None),
                    Selection::Unresolved(reason) => {
                        add_gap(&mut out, "private-prefix-unresolved", &server.file, server.line,
                            format!("{prefix}: {reason}; location selection needs regex evaluation"));
                        continue;
                    }
                };
            let denied = ret.is_some_and(|r| r.starts_with("403") || r.starts_with("404") || r.starts_with("401"))
                || internal;
            let authed = e.auth_request.is_some() || e.auth_basic;
            if !authed && !denied {
                serial += 1;
                push(&mut out, candidate(
                    "auth-routing-gap", &kind_id, serial, &file, line,
                    format!("declared private prefix `{prefix}` resolves to a location with no auth_request/auth_basic"),
                    vec!["privatePathPrefixes".into()], json!({"prefix": prefix}),
                ));
            }
            if e.cache_enabled {
                let ignores = e.cache_ignore_headers.iter().any(|h| {
                    matches!(h.to_ascii_lowercase().as_str(), "cache-control" | "set-cookie" | "expires")
                });
                if ignores || !has_cacheless_partition(e) {
                    serial += 1;
                    push(&mut out, candidate(
                        "cache-private-shared", &kind_id, serial, &file, line,
                        format!("declared private prefix `{prefix}` is served from a shared cache without credential partitioning"),
                        vec!["privatePathPrefixes".into()],
                        json!({"prefix": prefix, "ignoresUpstreamCacheControl": ignores, "cacheKey": e.cache_key}),
                    ));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- runtime reconciliation

pub fn reconcile_runtime(
    facts: &NginxFacts,
    policy: &NginxPolicy,
    observations: &[NginxRuntimeObservation],
) -> Vec<RuntimeAssertion> {
    let _ = facts;
    let mut out = Vec::new();
    for o in observations {
        let mut push = |kind: &str, state: AssertionState, detail: String| {
            out.push(RuntimeAssertion {
                kind: kind.into(),
                path: o.path.clone(),
                state,
                evidence_id: o.evidence_id.clone(),
                detail,
            });
        };
        if !o.verified {
            push("runtime-evidence-unverified", AssertionState::Unproven,
                "observation lacks accepted authenticated evidence; source headers prove nothing about delivery".into());
            continue;
        }
        for want in &policy.required_headers {
            let present = o.response_headers.contains_key(&want.to_ascii_lowercase());
            push("runtime-header",
                if present { AssertionState::Confirmed } else { AssertionState::Contradicted },
                format!("{want} at status {}", o.status));
        }
        let private = policy.private_path_prefixes.iter().any(|p| o.path.starts_with(p.as_str()));
        if private {
            let hit = o.cache_status.as_deref().is_some_and(|c| c.eq_ignore_ascii_case("hit"));
            if hit && o.authenticated == Some(false) {
                push("runtime-private-cache", AssertionState::Contradicted,
                    "private path served from cache to an unauthenticated request".into());
            } else if o.cache_status.is_some() {
                push("runtime-private-cache", AssertionState::Confirmed,
                    "private path not served from shared cache to unauthenticated request".into());
            } else {
                push("runtime-private-cache", AssertionState::Unproven,
                    "no cache status observed".into());
            }
        }
        if let Some(tls) = &o.tls_protocol {
            let weak = matches!(tls.to_ascii_lowercase().as_str(), "tlsv1" | "tlsv1.0" | "tlsv1.1" | "sslv3");
            push("runtime-tls",
                if weak { AssertionState::Contradicted } else { AssertionState::Confirmed },
                format!("negotiated {tls}"));
        }
    }
    out
}

// ---------------------------------------------------------------- Analysis adapter

pub fn analyze_nginx(
    inputs: &[NginxFileInput],
    ctx: &NginxContext,
    policy: &NginxPolicy,
    observations: &[NginxRuntimeObservation],
) -> Analysis {
    let facts = parse_nginx(inputs, ctx);
    let evaluation = evaluate_nginx(&facts, policy);
    let runtime = reconcile_runtime(&facts, policy, observations);
    let mut gaps: Vec<NginxGap> = facts.gaps.clone();
    for g in &evaluation.gaps {
        if !gaps.contains(g) {
            gaps.push(g.clone());
        }
    }
    let effective_unbound = ctx.origin != ConfigOrigin::Rendered;
    if effective_unbound {
        gaps.push(plan_effective_check(ctx).unbound_gap);
    }
    let kinds: BTreeSet<String> = gaps.iter().map(|g| g.kind.clone()).collect();
    let findings: Vec<Value> = evaluation
        .candidates
        .iter()
        .map(|c| {
            json!({
                "id": c.id, "rule": c.rule, "severity": c.severity, "path": c.path,
                "line": c.line, "message": c.message, "policyBasis": c.policy_basis,
                "evidence": c.evidence, "provider": "framework.nginx"
            })
        })
        .collect();
    let contradicted = runtime.iter().any(|a| a.state == AssertionState::Contradicted);
    let status = if !gaps.is_empty() {
        "unproven"
    } else if !findings.is_empty() || contradicted {
        "fail"
    } else {
        "pass"
    };
    let verified_runtime = runtime.iter().any(|a| a.state != AssertionState::Unproven);
    let mut analysis = Analysis::new(
        status,
        gaps.is_empty() && findings.is_empty() && !contradicted,
        json!({"kind":"nginx-config","expected": facts.files.len(), "examined": facts.files.len(),
               "servers": facts.servers.len(), "locations": facts.servers.iter().map(|s| s.locations.len()).sum::<usize>()}),
    );
    analysis.findings = findings;
    analysis.coverage_gaps = kinds.iter().map(|k| gap(k)).collect();
    analysis.extras.insert(
        "nginxGaps".into(),
        serde_json::to_value(&gaps).unwrap_or(Value::Null),
    );
    analysis.extras.insert(
        "nginxFacts".into(),
        serde_json::to_value(&facts).unwrap_or(Value::Null),
    );
    analysis.extras.insert(
        "runtimeAssertions".into(),
        serde_json::to_value(&runtime).unwrap_or(Value::Null),
    );
    analysis.extras.insert(
        "delivery".into(),
        Value::String(if verified_runtime { "runtime-observed" } else { "source-only" }.into()),
    );
    analysis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_delimiters_are_not_structure() {
        let toks = tokenize("add_header X \"a;b{c}\"; # c;\n").unwrap();
        assert_eq!(toks.len(), 4);
    }

    #[test]
    fn escape_is_rejected() {
        assert!(normalize_path("../x", "/etc/nginx").is_err());
        assert!(normalize_path("/etc/other/x", "/etc/nginx").is_err());
        assert_eq!(normalize_path("/etc/nginx/conf.d/a.conf", "/etc/nginx").unwrap(), "conf.d/a.conf");
    }
}
