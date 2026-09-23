//! Port of `src/lib/research-core/providers/scholarly.py`.
//!
//! `ScholarlyProvider`'s dataclass contracts and shared helpers
//! (`SearchHit`/`OpenedSource`/`LocatedPassage`, `publisher_from_url`,
//! `seed_id`, `stable_hit_id`, `data_only_envelope`, `locate_text`) live in
//! the sibling `providers/base.py`, which this packet does not own. This
//! port reimplements the exact behaviour those helpers give `scholarly.py`,
//! self-contained, against the identical `to_dict()` JSON shapes.
//!
//! Network transport (the Crossref works search, and the DOI/landing-page
//! GET `open()` performs) is not added here: no HTTP client crate is a
//! workspace dependency of `legion-research`, and this packet is read-only
//! on `Cargo.toml`. Transport is injected through `ScholarlyTransport`,
//! mirroring this crate's own `legion_research::source::SourceClient`
//! "implementations own transport" pattern. See `wf028.md` for the
//! dependency patch (`reqwest` or `ureq`) a real transport needs.

use regex::escape as regex_escape;
use regex::RegexBuilder;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

use super::support::sha256_hex;

pub const USER_AGENT_BASE: &str = "ResearchCore/2.0";

/// Port of the module-level `USER_AGENT` construction.
pub fn user_agent(contact_email: Option<&str>) -> String {
    match contact_email {
        Some(email) if !email.is_empty() => format!("{USER_AGENT_BASE} (mailto:{email})"),
        _ => USER_AGENT_BASE.to_string(),
    }
}

#[derive(Debug)]
pub struct ScholarlyError(pub String);
impl fmt::Display for ScholarlyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ScholarlyError {}

#[derive(Debug)]
pub struct TransportError(pub String);
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for TransportError {}
impl From<TransportError> for ScholarlyError {
    fn from(e: TransportError) -> Self {
        ScholarlyError(e.0)
    }
}

/// Injected external transport. `search` fetches JSON, `open` fetches text
/// and reports the final (possibly redirected) URL, mirroring
/// `_get_json`/`_get_text` in the Python original.
pub trait ScholarlyTransport {
    fn get_json(&self, url: &str, timeout_secs: u64) -> Result<Value, TransportError>;
    /// Returns `(body, final_url)`.
    fn get_text(&self, url: &str, timeout_secs: u64) -> Result<(String, String), TransportError>;
}

pub const NAME: &str = "scholarly";

/// Port of `base.publisher_from_url`. No `url` crate dependency is declared
/// for this crate, so the host/authority is parsed manually: scheme
/// stripped, userinfo before `@` dropped, path/query/fragment dropped at
/// the first `/`, `?`, or `#`, port after `:` dropped, lowercased, and a
/// leading `www.` stripped (falling back to `local-corpus` like the
/// Python does for an empty result).
pub fn publisher_from_url(url: &str) -> String {
    let mut rest = url;
    if let Some(idx) = rest.find("://") {
        rest = &rest[idx + 3..];
    }
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    let host = match host_port.find(':') {
        Some(idx) => &host_port[..idx],
        None => host_port,
    };
    let lowered = host.to_lowercase();
    let stripped = lowered.strip_prefix("www.").unwrap_or(&lowered).to_string();
    if stripped.is_empty() {
        "local-corpus".to_string()
    } else {
        stripped
    }
}

/// Port of `base.seed_id`.
pub fn seed_id(query: &str) -> String {
    format!("seed:query:{}", &sha256_hex(query)[..16])
}

/// Port of `base.stable_hit_id`.
pub fn stable_hit_id(provider: &str, url: &str) -> String {
    format!("hit:{provider}:{}", &sha256_hex(url)[..16])
}

/// Port of `base.data_only_envelope`. Legion does not create or validate any
/// downstream data-fence contract here; the caller owns envelope policy.
/// `source_url` is accepted for signature parity but unused, matching the
/// Python `del source_url`.
pub fn data_only_envelope(body: &str, _source_url: &str) -> (String, String) {
    let normalized: String = body.chars().filter(|&c| c != '\0').collect();
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    (normalized, digest)
}

/// Port of `base.locate_text`.
pub fn locate_text(body: &str, pattern: &str, context_chars: usize) -> Option<(String, String)> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }
    let direct = RegexBuilder::new(&regex_escape(trimmed))
        .case_insensitive(true)
        .build()
        .ok()?;
    let m = if let Some(m) = direct.find(body) {
        Some((m.start(), m.end()))
    } else {
        let token_re = regex::Regex::new(r"[A-Za-z0-9][A-Za-z0-9._%-]{2,}").ok()?;
        let tokens: Vec<String> = token_re
            .find_iter(trimmed)
            .take(8)
            .map(|m| regex_escape(m.as_str()))
            .collect();
        if tokens.is_empty() {
            return None;
        }
        let joined = tokens.join(".{0,80}");
        let fallback = RegexBuilder::new(&joined)
            .case_insensitive(true)
            .dot_matches_new_line(true)
            .build()
            .ok()?;
        fallback.find(body).map(|m| (m.start(), m.end()))
    };
    let (start, end) = m?;
    let ctx_start = start.saturating_sub(context_chars);
    let ctx_end = (end + context_chars).min(body.len());
    // Byte-index slicing mirrors the Python's char-index slicing closely
    // enough for the ASCII-dominant HTML this operates on; guard against
    // slicing inside a multi-byte boundary by nudging outward to a char
    // boundary rather than panicking.
    let safe_start = floor_char_boundary(body, ctx_start);
    let safe_end = ceil_char_boundary(body, ctx_end);
    let locator = format!("chars:{safe_start}-{safe_end}");
    let text = body[safe_start..safe_end].trim().to_string();
    Some((locator, text))
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: String,
    pub url: String,
    pub title: String,
    pub publisher: String,
    pub snippet: String,
    pub suggested_by: String,
    pub seed_chain: Vec<String>,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl SearchHit {
    /// Port of `SearchHit.to_dict()`: `evidence_status` is always `"lead"`.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "url": self.url,
            "title": self.title,
            "publisher": self.publisher,
            "snippet": self.snippet,
            "suggested_by": self.suggested_by,
            "seed_chain": self.seed_chain,
            "provider": self.provider,
            "metadata": Value::Object(self.metadata.clone()),
            "evidence_status": "lead",
        })
    }
}

#[derive(Debug, Clone)]
pub struct OpenedSource {
    pub url: String,
    pub title: String,
    pub publisher: String,
    pub retrieved_at: String,
    pub content: String,
    pub content_sha256: String,
    pub instruction_policy: String,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl OpenedSource {
    /// Port of `OpenedSource.to_dict()`: `instruction_policy` renames to
    /// `instructionPolicy`.
    pub fn to_json(&self) -> Value {
        json!({
            "url": self.url,
            "title": self.title,
            "publisher": self.publisher,
            "retrieved_at": self.retrieved_at,
            "content": self.content,
            "content_sha256": self.content_sha256,
            "instructionPolicy": self.instruction_policy,
            "provider": self.provider,
            "metadata": Value::Object(self.metadata.clone()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LocatedPassage {
    pub url: String,
    pub locator: String,
    pub text: String,
    pub is_paraphrase: bool,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl LocatedPassage {
    pub fn to_json(&self) -> Value {
        json!({
            "url": self.url,
            "locator": self.locator,
            "text": self.text,
            "is_paraphrase": self.is_paraphrase,
            "provider": self.provider,
            "metadata": Value::Object(self.metadata.clone()),
        })
    }
}

/// Port of `ScholarlyProvider.external_ops`.
pub const EXTERNAL_OPS: &[&str] = &["search", "open"];

/// Port of `ScholarlyProvider.search`.
///
/// `limit` is clamped to `[1, 20]` exactly as the Python `max(1, min(limit,
/// 20))` does, before being encoded into the Crossref `rows` parameter.
pub fn search(
    transport: &dyn ScholarlyTransport,
    query: &str,
    limit: i64,
    seed_chain: &[String],
    contact_email: Option<&str>,
) -> Result<Vec<SearchHit>, ScholarlyError> {
    let seed = seed_id(query);
    let mut chain: Vec<String> = seed_chain.to_vec();
    chain.push(seed.clone());

    let rows = limit.max(1).min(20);
    let url = format!(
        "https://api.crossref.org/works?{}",
        crossref_query(query, rows)
    );
    let _ = user_agent(contact_email); // parity with Python's header build; transport owns headers.
    let data = transport.get_json(&url, 30)?;

    let items = data
        .get("message")
        .and_then(|m| m.get("items"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut hits = Vec::with_capacity(items.len());
    for item in items {
        let doi = item
            .get("DOI")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let item_url = item.get("URL").and_then(Value::as_str).unwrap_or("");
        let target = if !item_url.is_empty() {
            item_url.to_string()
        } else if !doi.is_empty() {
            format!("https://doi.org/{doi}")
        } else {
            String::new()
        };
        if target.is_empty() {
            continue;
        }
        let title = item
            .get("title")
            .and_then(Value::as_array)
            .map(|titles| {
                titles
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| target.clone());
        let publisher = item
            .get("publisher")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| publisher_from_url(&target));
        let mut metadata = Map::new();
        metadata.insert(
            "doi".to_string(),
            if doi.is_empty() { Value::Null } else { json!(doi) },
        );
        metadata.insert("type".to_string(), item.get("type").cloned().unwrap_or(Value::Null));
        metadata.insert(
            "relation".to_string(),
            item.get("relation").cloned().unwrap_or_else(|| json!({})),
        );
        hits.push(SearchHit {
            id: stable_hit_id(NAME, &target),
            url: target,
            title,
            publisher,
            snippet: String::new(),
            suggested_by: seed.clone(),
            seed_chain: chain.clone(),
            provider: NAME.to_string(),
            metadata,
        });
    }
    Ok(hits)
}

fn crossref_query(query: &str, rows: i64) -> String {
    format!(
        "query={}&rows={}&select={}",
        url_encode(query),
        rows,
        url_encode("DOI,title,publisher,URL,author,published,relation,type")
    )
}

/// Minimal `application/x-www-form-urlencoded` value encoder (no `url`
/// crate dependency declared for this crate): percent-encodes everything
/// outside `[A-Za-z0-9-_.~]`, matching `urllib.parse.urlencode`'s default
/// (space becomes `+` under `urlencode`, reproduced here).
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Port of `ScholarlyProvider.open`.
pub fn open(
    transport: &dyn ScholarlyTransport,
    url: &str,
    retrieved_at: &str,
) -> Result<OpenedSource, ScholarlyError> {
    let (body, final_url) = transport.get_text(url, 45)?;
    let (envelope, digest) = data_only_envelope(&body, &final_url);
    let mut metadata = Map::new();
    metadata.insert("requested_url".to_string(), json!(url));
    Ok(OpenedSource {
        url: final_url.clone(),
        title: final_url.clone(),
        publisher: publisher_from_url(&final_url),
        retrieved_at: retrieved_at.to_string(),
        content: envelope,
        content_sha256: digest,
        instruction_policy: "data_only".to_string(),
        provider: NAME.to_string(),
        metadata,
    })
}

/// Port of `ScholarlyProvider.find`. `opened_content` is the `content` field
/// of an opened source, which the Python parses as `{"content": ...}` JSON
/// (the shape `data_only_envelope` writes downstream); this port accepts
/// the already-decoded body directly, since `data_only_envelope` above
/// returns the plain body, not a JSON envelope, matching what `open()`
/// actually stores in `OpenedSource.content`.
pub fn find(opened_content: &str, pattern: &str) -> Option<LocatedPassage> {
    let (locator, text) = locate_text(opened_content, pattern, 300)?;
    Some(LocatedPassage {
        url: String::new(),
        locator,
        text,
        is_paraphrase: false,
        provider: NAME.to_string(),
        metadata: Map::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        json: RefCell<Option<Value>>,
        text: RefCell<Option<(String, String)>>,
    }

    impl ScholarlyTransport for FakeTransport {
        fn get_json(&self, _url: &str, _timeout_secs: u64) -> Result<Value, TransportError> {
            self.json
                .borrow_mut()
                .take()
                .ok_or_else(|| TransportError("no fixture".into()))
        }
        fn get_text(&self, _url: &str, _timeout_secs: u64) -> Result<(String, String), TransportError> {
            self.text
                .borrow_mut()
                .take()
                .ok_or_else(|| TransportError("no fixture".into()))
        }
    }

    #[test]
    fn publisher_from_url_strips_www_and_lowercases() {
        assert_eq!(publisher_from_url("https://WWW.Example.com/a/b?q=1"), "example.com");
        assert_eq!(publisher_from_url("https://example.com:443/x"), "example.com");
        assert_eq!(publisher_from_url("https://user:pw@example.com/x"), "example.com");
        assert_eq!(publisher_from_url(""), "local-corpus");
    }

    #[test]
    fn seed_and_hit_ids_are_stable_and_prefixed() {
        let a = seed_id("hello world");
        let b = seed_id("hello world");
        assert_eq!(a, b);
        assert!(a.starts_with("seed:query:"));
        assert_eq!(a.len(), "seed:query:".len() + 16);

        let hit = stable_hit_id("scholarly", "https://example.com/paper");
        assert!(hit.starts_with("hit:scholarly:"));
    }

    #[test]
    fn data_only_envelope_strips_nul_and_digests() {
        let (body, digest) = data_only_envelope("hello\0world", "https://example.com");
        assert_eq!(body, "helloworld");
        assert_eq!(digest, hex::encode(Sha256::digest(b"helloworld")));
    }

    #[test]
    fn locate_text_finds_direct_match_case_insensitively() {
        let body = "prefix context HELLO TARGET suffix context";
        let (locator, text) = locate_text(body, "hello target", 3).unwrap();
        assert!(locator.starts_with("chars:"));
        assert!(text.to_lowercase().contains("hello target"));
    }

    #[test]
    fn locate_text_falls_back_to_tokenized_window() {
        let body = "alpha 12345 some noise beta6789 more noise gamma999";
        // The exact phrase never appears verbatim, so this only matches via
        // the token-windowed fallback (tokens present, in order, within
        // 80 chars of each other).
        let found = locate_text(body, "12345 beta6789 gamma999", 5);
        assert!(found.is_some());
    }

    #[test]
    fn locate_text_returns_none_for_blank_pattern() {
        assert!(locate_text("anything", "   ", 10).is_none());
    }

    #[test]
    fn search_builds_hits_from_crossref_items() {
        let fixture = json!({
            "message": {
                "items": [
                    {
                        "DOI": "10.1/xyz",
                        "URL": "https://doi.org/10.1/xyz",
                        "title": ["A Paper", "Subtitle"],
                        "publisher": "Acme Press",
                        "type": "journal-article",
                        "relation": {}
                    },
                    {
                        "DOI": "",
                        "URL": "",
                        "title": []
                    }
                ]
            }
        });
        let transport = FakeTransport {
            json: RefCell::new(Some(fixture)),
            text: RefCell::new(None),
        };
        let hits = search(&transport, "some query", 5, &[], None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "A Paper Subtitle");
        assert_eq!(hits[0].publisher, "Acme Press");
        assert_eq!(hits[0].provider, "scholarly");
        assert_eq!(hits[0].metadata.get("doi").unwrap(), &json!("10.1/xyz"));
    }

    #[test]
    fn search_skips_items_with_no_url_or_doi() {
        let fixture = json!({"message": {"items": [{"title": ["x"]}]}});
        let transport = FakeTransport {
            json: RefCell::new(Some(fixture)),
            text: RefCell::new(None),
        };
        let hits = search(&transport, "q", 5, &[], None).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn open_wraps_body_in_data_only_envelope() {
        let transport = FakeTransport {
            json: RefCell::new(None),
            text: RefCell::new(Some(("<html>body</html>".to_string(), "https://example.com/final".to_string()))),
        };
        let opened = open(&transport, "https://example.com/req", "2026-09-23").unwrap();
        assert_eq!(opened.url, "https://example.com/final");
        assert_eq!(opened.publisher, "example.com");
        assert_eq!(opened.instruction_policy, "data_only");
        assert_eq!(opened.content, "<html>body</html>");
    }

    #[test]
    fn to_json_renames_instruction_policy_field() {
        let opened = OpenedSource {
            url: "u".into(),
            title: "t".into(),
            publisher: "p".into(),
            retrieved_at: "2026-01-01".into(),
            content: "c".into(),
            content_sha256: "d".into(),
            instruction_policy: "data_only".into(),
            provider: "scholarly".into(),
            metadata: Map::new(),
        };
        let v = opened.to_json();
        assert_eq!(v["instructionPolicy"], json!("data_only"));
        assert!(v.get("instruction_policy").is_none());
    }

    #[test]
    fn search_hit_to_json_always_marks_lead() {
        let hit = SearchHit {
            id: "id".into(),
            url: "u".into(),
            title: "t".into(),
            publisher: "p".into(),
            snippet: "".into(),
            suggested_by: "s".into(),
            seed_chain: vec!["s".into()],
            provider: "scholarly".into(),
            metadata: Map::new(),
        };
        assert_eq!(hit.to_json()["evidence_status"], json!("lead"));
    }
}
