use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use crate::{error::ResearchError, workflow::Cancellation};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Web,
    Scholarly,
    Authority,
    LocalCorpus,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub schema_version: u32,
    pub source_id: String,
    pub kind: SourceKind,
    pub provider: String,
    pub uri: String,
    pub title: Option<String>,
    pub retrieved_at: Option<String>,
    pub content_digest: String,
    pub byte_length: u64,
    /// Source material is opaque data. It is never interpreted as workflow instructions.
    pub text: String,
    pub metadata: BTreeMap<String, String>,
}

/// Wire shape of a host-written source record. `content_digest` and `byte_length` may be
/// omitted; the route then computes them from `text` (see [`SourceRecord::from_host_json`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecordInput {
    schema_version: u32,
    source_id: String,
    kind: SourceKind,
    provider: String,
    uri: String,
    title: Option<String>,
    retrieved_at: Option<String>,
    content_digest: Option<String>,
    byte_length: Option<u64>,
    text: String,
    metadata: BTreeMap<String, String>,
}

impl SourceRecord {
    /// Parse a host-written record. When `content_digest` and/or `byte_length` are absent they
    /// are computed from `text`; the returned flag is true if either was computed by the route.
    /// Present values are kept verbatim so `validate` still rejects mismatches.
    pub fn from_host_json(bytes: &[u8]) -> Result<(Self, bool), serde_json::Error> {
        let input: SourceRecordInput = serde_json::from_slice(bytes)?;
        let computed = input.content_digest.is_none() || input.byte_length.is_none();
        let content_digest = input.content_digest.unwrap_or_else(|| {
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(input.text.as_bytes()))
            )
        });
        let byte_length = input.byte_length.unwrap_or(input.text.len() as u64);
        Ok((
            Self {
                schema_version: input.schema_version,
                source_id: input.source_id,
                kind: input.kind,
                provider: input.provider,
                uri: input.uri,
                title: input.title,
                retrieved_at: input.retrieved_at,
                content_digest,
                byte_length,
                text: input.text,
                metadata: input.metadata,
            },
            computed,
        ))
    }

    /// The smallest stable locator supplied by a host for this opened source.
    ///
    /// Hosts may provide a passage locator in metadata.  A source URI remains a
    /// valid whole-document locator for host records that do not expose a more
    /// precise passage.
    pub fn evidence_locator(&self) -> Option<String> {
        self.metadata
            .get("locator")
            .filter(|locator| !locator.trim().is_empty())
            .cloned()
            .or_else(|| (!self.uri.trim().is_empty()).then(|| self.uri.clone()))
    }

    /// Search hits, snippets, model answers, and NotebookLM answers are leads.
    /// They cannot be promoted to opened-source evidence by this boundary.
    pub fn is_lead(&self) -> bool {
        let status = self
            .metadata
            .get("evidence_status")
            .or_else(|| self.metadata.get("status"))
            .map(|value| value.trim().to_ascii_lowercase());
        let source_type = self
            .metadata
            .get("source_type")
            .map(|value| value.trim().to_ascii_lowercase());
        matches!(
            self.provider.trim().to_ascii_lowercase().as_str(),
            "notebooklm"
        ) || matches!(status.as_deref(), Some("lead" | "snippet" | "summary"))
            || matches!(
                source_type.as_deref(),
                Some(
                    "search-hit"
                        | "search-snippet"
                        | "snippet"
                        | "ai-summary"
                        | "provider-answer"
                        | "notebooklm-answer"
                )
            )
    }

    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::InvalidSource(
                "unsupported source schema version".into(),
            ));
        }
        for (field, value) in [
            ("source_id", &self.source_id),
            ("provider", &self.provider),
            ("uri", &self.uri),
            ("content_digest", &self.content_digest),
        ] {
            if value.trim().is_empty() {
                return Err(ResearchError::InvalidSource(format!(
                    "{field} must be non-empty"
                )));
            }
        }
        let actual = self.text.len() as u64;
        if actual != self.byte_length {
            return Err(ResearchError::InvalidSource(format!(
                "byte_length {0} does not match source text length {actual}",
                self.byte_length
            )));
        }
        let actual_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.text.as_bytes()))
        );
        if self.content_digest != actual_digest {
            return Err(ResearchError::InvalidSource(
                "content_digest does not match source text".into(),
            ));
        }
        if self.text.trim().is_empty() {
            return Err(ResearchError::InvalidSource(
                "source text must be non-empty".into(),
            ));
        }
        if is_fetch_error_text(&self.text) {
            return Err(ResearchError::InvalidSource(
                "fetch-error-text: source text is a fetch failure, not opened page content".into(),
            ));
        }
        if self.is_lead() {
            return Err(ResearchError::InvalidSource(
                "lead-only source records cannot enter evidence".into(),
            ));
        }
        if self.evidence_locator().is_none() {
            return Err(ResearchError::InvalidSource(
                "opened source requires a locator".into(),
            ));
        }
        if self
            .metadata
            .get("instruction_policy")
            .map(|policy| policy != "data_only")
            .unwrap_or(false)
        {
            return Err(ResearchError::InvalidSource(
                "source instruction_policy must be data_only".into(),
            ));
        }
        if matches!(
            self.kind,
            SourceKind::Web | SourceKind::Scholarly | SourceKind::Authority
        ) {
            if self.retrieved_at.as_deref().is_none_or(str::is_empty) {
                return Err(ResearchError::InvalidSource(
                    "external source requires retrieved_at".into(),
                ));
            }
            if let Some(retrieved_at) = self.retrieved_at.as_deref() {
                let date = retrieved_at.get(..10).unwrap_or_default();
                let valid_date = date.len() == 10
                    && date.as_bytes()[4] == b'-'
                    && date.as_bytes()[7] == b'-'
                    && date
                        .bytes()
                        .enumerate()
                        .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
                if !valid_date {
                    return Err(ResearchError::InvalidSource(
                        "external source retrieved_at must begin with an ISO date".into(),
                    ));
                }
            }
            if self
                .metadata
                .get("request_receipt")
                .map(String::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ResearchError::InvalidSource(
                    "external source requires request_receipt provenance".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Conservative detector for host records whose `text` is a fetch failure stub rather than
/// page content. Only short texts (under 200 characters) are considered, so long genuine
/// content that merely mentions a status code or phrase is never rejected.
fn is_fetch_error_text(text: &str) -> bool {
    const MAX_STUB_CHARS: usize = 200;
    let trimmed = text.trim();
    if trimmed.chars().count() >= MAX_STUB_CHARS {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    const PHRASES: [&str; 7] = [
        "failed to fetch",
        "403 forbidden",
        "404 not found",
        "access denied",
        "request blocked",
        "error fetching",
        "unable to fetch",
    ];
    // A phrase counts only when nothing content-like follows it, so an excerpt that merely
    // opens with "Access denied to minors…" is kept.
    if let Some(phrase) = PHRASES.iter().find(|phrase| lower.starts_with(**phrase)) {
        let rest = lower[phrase.len()..].trim_start();
        return rest.is_empty()
            || rest
                .starts_with(|c: char| matches!(c, '.' | ':' | '!' | ',' | '-' | '(' | '|' | '['))
            || rest.starts_with("http")
            || rest.starts_with("by ")
            || rest.starts_with("for ");
    }
    // Status-line forms: "HTTP 404", "HTTP/1.1 503 ...", "HTTP error 429", "Error: 500 ...".
    let mut words = lower.split(|c: char| c.is_whitespace() || c == ':' || c == '/');
    let first = words.next().unwrap_or_default();
    let is_status = |w: &str| {
        w.len() == 3
            && matches!(w.as_bytes()[0], b'4' | b'5')
            && w.bytes().all(|b| b.is_ascii_digit())
    };
    if first == "http" || first == "error" {
        return words.take(4).any(is_status);
    }
    false
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHit {
    pub source_id: String,
    pub uri: String,
    pub title: Option<String>,
    pub provider: String,
    pub relevance: Option<u32>,
}

impl SourceHit {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.source_id.trim().is_empty()
            || self.uri.trim().is_empty()
            || self.provider.trim().is_empty()
        {
            return Err(ResearchError::InvalidSource(
                "source hit requires id, uri, and provider".into(),
            ));
        }
        Ok(())
    }
}

/// Injected external source client. Implementations own transport; this crate owns bounds and provenance.
pub trait SourceClient: Send + Sync {
    fn provider(&self) -> &str;
    /// Upper bound reserved before `open` is called. Zero means the workflow uses one byte.
    fn estimated_bytes(&self, _hit: &SourceHit) -> u64 {
        0
    }
    fn estimated_call_cost_micros(&self) -> u64 {
        0
    }
    fn search(
        &self,
        query: &str,
        limit: u32,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> Result<Vec<SourceHit>, ResearchError>;
    fn open(
        &self,
        hit: &SourceHit,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> Result<SourceRecord, ResearchError>;
}

/// How a source's independence key was derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceBasis {
    /// Derived from the host/registrable domain of the record's canonical URL.
    SourceIdentity,
    /// No usable URL: the key is the free-text `provider` label the host supplied.
    SelfDeclared,
}

/// Independence key of one source record plus how it was derived.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndependenceKey {
    pub key: String,
    pub basis: IndependenceBasis,
}

/// Independence tally over a set of source records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndependenceSummary {
    /// Distinct keys derived from source identity (domains).
    pub source_identity_keys: Vec<String>,
    /// Distinct provider labels used only because a record had no usable URL.
    pub self_declared_keys: Vec<String>,
}

impl IndependenceSummary {
    /// Independent-source count. Self-declared keys count only when explicitly allowed.
    pub fn count(&self, allow_self_declared: bool) -> usize {
        self.source_identity_keys.len()
            + if allow_self_declared {
                self.self_declared_keys.len()
            } else {
                0
            }
    }
}

/// Normalized registrable-domain approximation of an http(s) URL: lowercase, userinfo, port,
/// path and leading `www.` removed; hosts reduce to their last two labels (three under common
/// two-letter-country second-level suffixes such as `co.uk`). IP literals are kept whole. The
/// approximation errs toward merging hosts, so it can under-count but not inflate independence.
pub fn registrable_domain(uri: &str) -> Option<String> {
    let trimmed = uri.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        let inner = stripped.split(']').next()?;
        return (!inner.is_empty()).then(|| format!("[{}]", inner.to_ascii_lowercase()));
    } else {
        authority.split(':').next()?
    };
    // Alternate spellings of one host (unicode vs punycode, percent-encoding) would
    // otherwise yield distinct keys; such hosts fall back to self-declared independence.
    if !host.is_ascii() || host.contains('%') {
        return None;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    if host.is_empty() {
        return None;
    }
    if !host.contains('.') {
        return Some(host);
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels
        .iter()
        .all(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        return Some(host);
    }
    let n = labels.len();
    if n <= 2 {
        return Some(host);
    }
    let second_level = matches!(
        labels[n - 2],
        "co" | "com" | "org" | "net" | "gov" | "edu" | "ac" | "or" | "ne" | "go"
    );
    let take = if second_level && labels[n - 1].len() == 2 {
        3
    } else {
        2
    };
    Some(labels[n - take.min(n)..].join("."))
}

impl SourceRecord {
    /// Independence key from source identity: `metadata.canonical_url` when present, else `uri`,
    /// reduced to a registrable domain. Falls back to the `provider` label (flagged
    /// self-declared) only when neither is an http(s) URL.
    pub fn independence_key(&self) -> IndependenceKey {
        let canonical = self.metadata.get("canonical_url").map(String::as_str);
        if let Some(domain) = canonical
            .and_then(registrable_domain)
            .or_else(|| registrable_domain(&self.uri))
        {
            return IndependenceKey {
                key: domain,
                basis: IndependenceBasis::SourceIdentity,
            };
        }
        IndependenceKey {
            key: self.provider.trim().to_ascii_lowercase(),
            basis: IndependenceBasis::SelfDeclared,
        }
    }
}

/// Tally independent keys across records. The `provider` label never contributes to a
/// source-identity key.
pub fn summarize_independence<'a>(
    records: impl IntoIterator<Item = &'a SourceRecord>,
) -> IndependenceSummary {
    let mut identity = std::collections::BTreeSet::new();
    let mut declared = std::collections::BTreeSet::new();
    for record in records {
        let key = record.independence_key();
        match key.basis {
            IndependenceBasis::SourceIdentity => identity.insert(key.key),
            IndependenceBasis::SelfDeclared => declared.insert(key.key),
        };
    }
    IndependenceSummary {
        source_identity_keys: identity.into_iter().collect(),
        self_declared_keys: declared.into_iter().collect(),
    }
}

pub type InjectedSource = Arc<dyn SourceClient>;

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SourceRecord {
        let text = "opened source text";
        SourceRecord {
            schema_version: 1,
            source_id: "source-1".into(),
            kind: SourceKind::Web,
            provider: "browser".into(),
            uri: "https://example.test/source".into(),
            title: Some("Source".into()),
            retrieved_at: Some("2026-08-26T00:00:00Z".into()),
            content_digest: format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes()))),
            byte_length: text.len() as u64,
            text: text.into(),
            metadata: BTreeMap::from([("request_receipt".into(), "request-1".into())]),
        }
    }

    fn rec(provider: &str, uri: &str) -> SourceRecord {
        let mut record = source();
        record.provider = provider.into();
        record.uri = uri.into();
        record
    }

    #[test]
    fn same_label_different_domains_are_independent() {
        let a = rec("webfetch", "https://www.cpsc.gov/faq");
        let b = rec("webfetch", "https://helmets.org:443/replace/");
        let summary = summarize_independence([&a, &b]);
        assert_eq!(summary.count(false), 2);
        assert!(summary.self_declared_keys.is_empty());
    }

    #[test]
    fn different_labels_same_domain_are_not_independent() {
        let a = rec("alpha", "https://news.example.co.uk/a");
        let b = rec("beta", "https://WWW.Example.co.uk:8080/b?x=1");
        let c = rec("gamma", "https://example.co.uk/c");
        let summary = summarize_independence([&a, &b, &c]);
        assert_eq!(summary.count(false), 1);
        assert_eq!(summary.count(true), 1);
    }

    #[test]
    fn missing_url_is_self_declared_and_not_strictly_independent() {
        let a = rec("one", "urn:corpus:doc-1");
        let b = rec("two", "corpus/doc-2.txt");
        let summary = summarize_independence([&a, &b]);
        assert!(summary.source_identity_keys.is_empty());
        assert_eq!(summary.self_declared_keys.len(), 2);
        assert_eq!(summary.count(false), 0);
        assert_eq!(summary.count(true), 2);
        assert_eq!(a.independence_key().basis, IndependenceBasis::SelfDeclared);
    }

    #[test]
    fn canonical_url_metadata_overrides_uri() {
        let mut a = rec("x", "https://r.jina.ai/https://cpsc.gov/faq");
        a.metadata
            .insert("canonical_url".into(), "https://cpsc.gov/faq".into());
        assert_eq!(a.independence_key().key, "cpsc.gov");
    }

    fn with_text(text: &str) -> SourceRecord {
        let mut record = source();
        record.text = text.into();
        record.byte_length = text.len() as u64;
        record.content_digest = format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())));
        record
    }

    #[test]
    fn fetch_error_stub_is_rejected() {
        for stub in [
            "Failed to fetch https://example.test/source: connection reset",
            "HTTP 403 Forbidden",
            "HTTP/1.1 503 Service Unavailable",
            "403 Forbidden",
            "Access Denied",
            "Request blocked by network policy.",
        ] {
            let err = with_text(stub).validate().unwrap_err().to_string();
            assert!(err.contains("fetch-error-text"), "{stub}: {err}");
        }
    }

    #[test]
    fn long_article_mentioning_403_is_accepted() {
        let mut text = String::from("Guide to HTTP status codes. A 403 Forbidden response means the server refuses access; access denied pages are common. ");
        text.push_str(&"The status code family is explained in detail here. ".repeat(12));
        assert!(text.len() > 400);
        with_text(&text).validate().unwrap();
        with_text("The 403 response is discussed in this short note.")
            .validate()
            .unwrap();
        with_text("Access denied to minors under 13 without parental consent.")
            .validate()
            .unwrap();
    }

    #[test]
    fn empty_text_is_rejected() {
        assert!(with_text("  \n").validate().is_err());
    }

    #[test]
    fn lead_source_is_rejected_before_ledger_admission() {
        let mut lead = source();
        lead.metadata
            .insert("evidence_status".into(), "lead".into());
        assert!(lead.validate().is_err());
    }

    #[test]
    fn opened_source_exposes_locator() {
        let mut opened = source();
        opened.metadata.insert(
            "locator".into(),
            "https://example.test/source#passage-1".into(),
        );
        assert_eq!(
            opened.evidence_locator().as_deref(),
            Some("https://example.test/source#passage-1")
        );
    }

    fn record_json(digest: Option<&str>, byte_length: Option<u64>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "schema_version": 1,
            "source_id": "source-1",
            "kind": "web",
            "provider": "browser",
            "uri": "https://example.test/source",
            "retrieved_at": "2026-08-26",
            "text": "opened source text",
            "metadata": {"request_receipt": "request-1"}
        });
        if let Some(digest) = digest {
            value["content_digest"] = digest.into();
        }
        if let Some(length) = byte_length {
            value["byte_length"] = length.into();
        }
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn absent_digest_and_length_are_computed_and_flagged() {
        let (record, computed) = SourceRecord::from_host_json(&record_json(None, None)).unwrap();
        assert!(computed);
        assert_eq!(record.byte_length, "opened source text".len() as u64);
        assert_eq!(record.content_digest, source().content_digest);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn present_correct_values_are_accepted_without_flag() {
        let good = source();
        let (record, computed) = SourceRecord::from_host_json(&record_json(
            Some(&good.content_digest),
            Some(good.byte_length),
        ))
        .unwrap();
        assert!(!computed);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn present_wrong_values_are_rejected() {
        let good = source();
        let (wrong_digest, _) =
            SourceRecord::from_host_json(&record_json(Some("sha256:00"), None)).unwrap();
        assert!(wrong_digest.validate().is_err());
        let (wrong_length, _) =
            SourceRecord::from_host_json(&record_json(Some(&good.content_digest), Some(1)))
                .unwrap();
        assert!(wrong_length.validate().is_err());
        let (wrong_length_only, _) =
            SourceRecord::from_host_json(&record_json(None, Some(1))).unwrap();
        assert!(wrong_length_only.validate().is_err());
    }
}
