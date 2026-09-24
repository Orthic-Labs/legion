//! Port of `src/lib/research-core/providers/search_open_find.py`'s
//! provider-neutral dispatch and metering logic.
//!
//! The Python CLI selects amongst five providers (`browser`,
//! `domain-default`, `local-corpus`, `scholarly`, `legal-authority`).
//! `provider()` below is the real equivalent of the Python function of the
//! same name: it constructs and returns an actual provider instance, not
//! merely a name. All five names are now backed by real Rust
//! implementations, wired against sibling packets already ported in this
//! crate:
//! - `local-corpus` -> `wf027::LocalCorpusProvider`
//! - `browser`/`domain-default` -> `wf027::CommandBridgeProvider('browser',
//!   'RESEARCH_BROWSER_CMD')`
//! - `legal-authority` -> `wf027::CommandBridgeProvider('legal-authority',
//!   'RESEARCH_AUTHORITY_CMD')`
//! - `scholarly` -> [`ScholarlyProviderAdapter`], a thin `wf027::Provider`
//!   wrapper around this packet's own `super::scholarly` free functions,
//!   backed by `wf027::ReqwestTransport` (real network transport, wired in
//!   `wf027::http_browser`'s `ScholarlyTransport` impl for that type).
//!
//! `meter()` mirrors the Python `meter()` helper exactly: a no-op when
//! `run_id` is `None`/absent, otherwise `super::wf026`'s `meter::consume`
//! contract (`effect="external_request"`), raising on `{"ok": false}`.
//! Metering here calls into this crate's already-ported `wf026::meter`
//! module directly, exactly as the Python imports `meter as research_meter`
//! from the sibling `meter.py` (ported in wf026).

use std::fmt;

use crate::wf_port::wf026::meter;
use crate::wf_port::wf027::{CommandBridgeProvider, LocalCorpusProvider, ReqwestTransport};
use crate::wf_port::wf027::types::{
    LocatedPassage as WfLocatedPassage, OpenedSource as WfOpenedSource, Provider,
    SearchHit as WfSearchHit,
};
use crate::wf_port::wf027::support::WfError;

#[derive(Debug)]
pub enum DispatchError {
    /// Port of `ValueError(f'provider {name!r} does not expose search/open/find')`
    /// and of `ValueError('--corpus is required for local-corpus')`.
    InvalidProvider(String),
    /// Port of a `RuntimeError` raised while constructing the provider
    /// (e.g. `CommandBridgeProvider.__init__`'s missing-env-var check, or
    /// `LocalCorpusProvider.__init__`'s missing-root check).
    Construction(String),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchError::InvalidProvider(msg) => write!(f, "{msg}"),
            DispatchError::Construction(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for DispatchError {}

impl From<WfError> for DispatchError {
    fn from(e: WfError) -> Self {
        DispatchError::Construction(e.to_string())
    }
}

/// The five provider names `search_open_find.py`'s `--provider` choices
/// accept.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProviderName {
    Browser,
    DomainDefault,
    LocalCorpus,
    Scholarly,
    LegalAuthority,
}

impl ProviderName {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "browser" => Some(Self::Browser),
            "domain-default" => Some(Self::DomainDefault),
            "local-corpus" => Some(Self::LocalCorpus),
            "scholarly" => Some(Self::Scholarly),
            "legal-authority" => Some(Self::LegalAuthority),
            _ => None,
        }
    }
}

/// `super::scholarly`'s free-function provider, adapted to the shared
/// `wf027::types::Provider` trait so it can be returned from `provider()`
/// alongside `CommandBridgeProvider`/`LocalCorpusProvider` as one
/// `Box<dyn Provider>`. `super::scholarly` deliberately keeps its own
/// self-contained `SearchHit`/`OpenedSource`/`LocatedPassage` (see that
/// module's doc comment); the field shapes are identical to `wf027::types`'
/// (confirmed against both `to_json`/`to_dict` outputs), so conversion
/// between them is a straight field-for-field copy.
pub struct ScholarlyProviderAdapter<T: super::scholarly::ScholarlyTransport> {
    transport: T,
    contact_email: Option<String>,
}

impl<T: super::scholarly::ScholarlyTransport> ScholarlyProviderAdapter<T> {
    pub fn new(transport: T, contact_email: Option<String>) -> Self {
        Self { transport, contact_email }
    }
}

fn hit_to_wf(h: super::scholarly::SearchHit) -> WfSearchHit {
    WfSearchHit {
        id: h.id,
        url: h.url,
        title: h.title,
        publisher: h.publisher,
        snippet: h.snippet,
        suggested_by: h.suggested_by,
        seed_chain: h.seed_chain,
        provider: h.provider,
        metadata: h.metadata,
    }
}

fn opened_to_wf(o: super::scholarly::OpenedSource) -> WfOpenedSource {
    WfOpenedSource {
        url: o.url,
        title: o.title,
        publisher: o.publisher,
        retrieved_at: o.retrieved_at,
        content: o.content,
        content_sha256: o.content_sha256,
        instruction_policy: o.instruction_policy,
        provider: o.provider,
        metadata: o.metadata,
    }
}

fn opened_to_scholarly(o: &WfOpenedSource) -> super::scholarly::OpenedSource {
    super::scholarly::OpenedSource {
        url: o.url.clone(),
        title: o.title.clone(),
        publisher: o.publisher.clone(),
        retrieved_at: o.retrieved_at.clone(),
        content: o.content.clone(),
        content_sha256: o.content_sha256.clone(),
        instruction_policy: o.instruction_policy.clone(),
        provider: o.provider.clone(),
        metadata: o.metadata.clone(),
    }
}

fn passage_to_wf(p: super::scholarly::LocatedPassage) -> WfLocatedPassage {
    WfLocatedPassage {
        url: p.url,
        locator: p.locator,
        text: p.text,
        is_paraphrase: p.is_paraphrase,
        provider: p.provider,
        metadata: p.metadata,
    }
}

impl<T: super::scholarly::ScholarlyTransport> Provider for ScholarlyProviderAdapter<T> {
    fn name(&self) -> &str {
        super::scholarly::NAME
    }

    fn search(
        &self,
        query: &str,
        limit: usize,
        seed_chain: &[String],
    ) -> Result<Vec<WfSearchHit>, WfError> {
        let hits = super::scholarly::search(
            &self.transport,
            query,
            limit as i64,
            seed_chain,
            self.contact_email.as_deref(),
        )
        .map_err(|e| WfError::Provider(e.to_string()))?;
        Ok(hits.into_iter().map(hit_to_wf).collect())
    }

    fn open(&self, url: &str) -> Result<WfOpenedSource, WfError> {
        let retrieved_at = super::support::today();
        let opened = super::scholarly::open(&self.transport, url, &retrieved_at)
            .map_err(|e| WfError::Provider(e.to_string()))?;
        Ok(opened_to_wf(opened))
    }

    fn find(&self, opened: &WfOpenedSource, pattern: &str) -> Result<Option<WfLocatedPassage>, WfError> {
        let scholarly_opened = opened_to_scholarly(opened);
        Ok(super::scholarly::find(&scholarly_opened.content, pattern).map(|mut p| {
            // `scholarly::find` (mirroring the Python) leaves `url` blank;
            // the dispatcher-level caller (like `run.py`'s `acquire`) uses
            // the opened source's own URL for the located passage.
            p.url = opened.url.clone();
            passage_to_wf(p)
        }))
    }
}

/// Port of `provider()`: constructs and returns the real provider instance
/// for `name`, exactly as the Python does (`ValueError` for an unknown
/// name or a missing `--corpus`; a `RuntimeError` from the provider's own
/// constructor propagates as [`DispatchError::Construction`]).
pub fn provider(name: &str, corpus: Option<&str>) -> Result<Box<dyn Provider>, DispatchError> {
    let Some(parsed) = ProviderName::parse(name) else {
        return Err(DispatchError::InvalidProvider(format!(
            "provider {name:?} does not expose search/open/find"
        )));
    };
    match parsed {
        ProviderName::LocalCorpus => {
            let Some(corpus) = corpus.filter(|s| !s.is_empty()) else {
                return Err(DispatchError::InvalidProvider(
                    "--corpus is required for local-corpus".to_string(),
                ));
            };
            Ok(Box::new(LocalCorpusProvider::new(corpus)?))
        }
        ProviderName::Browser | ProviderName::DomainDefault => Ok(Box::new(CommandBridgeProvider::new(
            "browser",
            "RESEARCH_BROWSER_CMD",
        )?)),
        ProviderName::LegalAuthority => Ok(Box::new(CommandBridgeProvider::new(
            "legal-authority",
            "RESEARCH_AUTHORITY_CMD",
        )?)),
        ProviderName::Scholarly => {
            let contact_email = std::env::var("RESEARCH_CONTACT_EMAIL")
                .ok()
                .filter(|s| !s.is_empty());
            Ok(Box::new(ScholarlyProviderAdapter::new(
                ReqwestTransport::new(),
                contact_email,
            )))
        }
    }
}

/// Port of `main()`'s `meter()` helper: a no-op with no `run_id`; otherwise
/// runs `meter.consume(workspace, run_id, effect)` (wf026) and raises the
/// same `RuntimeError(result['reason'])` on `{"ok": false}`.
pub fn meter_effect(
    run_dir: Option<&std::path::Path>,
    effect: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(run_dir) = run_dir else {
        return Ok(());
    };
    let result = meter::consume(run_dir, effect, 1, None)?;
    if result["ok"] != serde_json::json!(true) {
        let reason = result["reason"].as_str().unwrap_or("research budget exceeded").to_string();
        return Err(reason.into());
    }
    Ok(())
}

/// Port of `EXTERNAL_OPS` gating in `main()`, for every provider `provider()`
/// can now return: `CommandBridgeProvider.external_ops` is `{'search',
/// 'open', 'find'}`, `LocalCorpusProvider` has none (no `external_ops`
/// class attribute in the Python original, matching
/// `getattr(impl, 'external_ops', ())` defaulting to empty), and
/// `scholarly.external_ops` is `{'search', 'open'}`.
pub fn is_metered_op(provider: ProviderName, op: &str) -> bool {
    match provider {
        ProviderName::Scholarly => super::scholarly::EXTERNAL_OPS.contains(&op),
        ProviderName::Browser | ProviderName::DomainDefault | ProviderName::LegalAuthority => {
            CommandBridgeProvider::EXTERNAL_OPS.contains(&op)
        }
        ProviderName::LocalCorpus => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scholarly_is_backed_by_a_real_provider() {
        let p = provider("scholarly", None).unwrap();
        assert_eq!(p.name(), "scholarly");
    }

    #[test]
    fn unknown_provider_is_invalid() {
        let err = provider("made-up", None).unwrap_err();
        assert!(matches!(err, DispatchError::InvalidProvider(_)));
    }

    #[test]
    fn local_corpus_without_corpus_flag_is_invalid() {
        let err = provider("local-corpus", None).unwrap_err();
        assert!(matches!(err, DispatchError::InvalidProvider(_)));
    }

    #[test]
    fn local_corpus_with_corpus_flag_constructs_a_real_provider() {
        let dir = std::env::temp_dir().join(format!(
            "wf028_search_open_find_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = provider("local-corpus", Some(dir.to_str().unwrap())).unwrap();
        assert_eq!(p.name(), "local-corpus");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn browser_and_legal_authority_error_without_configured_command() {
        let unset = [
            "WF028_SEARCH_OPEN_FIND_TEST_RESEARCH_BROWSER_CMD",
            "RESEARCH_BROWSER_CMD",
        ];
        for var in unset {
            std::env::remove_var(var);
        }
        std::env::remove_var("RESEARCH_BROWSER_CMD");
        std::env::remove_var("RESEARCH_AUTHORITY_CMD");
        assert!(matches!(
            provider("browser", None).unwrap_err(),
            DispatchError::Construction(_)
        ));
        assert!(matches!(
            provider("legal-authority", None).unwrap_err(),
            DispatchError::Construction(_)
        ));
    }

    #[test]
    fn scholarly_search_and_open_are_metered_but_find_is_not() {
        assert!(is_metered_op(ProviderName::Scholarly, "search"));
        assert!(is_metered_op(ProviderName::Scholarly, "open"));
        assert!(!is_metered_op(ProviderName::Scholarly, "find"));
    }

    #[test]
    fn browser_is_metered_on_search_open_and_find() {
        assert!(is_metered_op(ProviderName::Browser, "search"));
        assert!(is_metered_op(ProviderName::Browser, "open"));
        assert!(is_metered_op(ProviderName::Browser, "find"));
    }

    #[test]
    fn local_corpus_is_never_metered() {
        assert!(!is_metered_op(ProviderName::LocalCorpus, "search"));
    }

    #[test]
    fn meter_effect_is_noop_without_run_dir() {
        assert!(meter_effect(None, "external_request").is_ok());
    }
}
