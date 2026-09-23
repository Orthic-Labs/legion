//! Port of `src/lib/research-core/providers/search_open_find.py`'s
//! provider-neutral dispatch and metering logic.
//!
//! The Python CLI selects amongst five providers (`browser`,
//! `domain-default`, `local-corpus`, `scholarly`, `legal-authority`), three
//! of which (`local-corpus` -> `local_corpus.py`, `browser`/`domain-default`
//! -> `command_bridge.py`'s `CommandBridgeProvider('browser', ...)`,
//! `legal-authority` -> the same bridge with a different command env var)
//! live in sibling files this packet does not own. Only `scholarly` (this
//! packet's own `super::scholarly`) is backed here. `provider()` below
//! mirrors the exact dispatch/error behaviour for all five names, but the
//! three out-of-scope providers report [`DispatchError::NotPorted`] with the
//! Python module they would delegate to, instead of performing the
//! delegation, since that delegation's own logic is a different packet's
//! scope to port.
//!
//! `meter()` mirrors the Python `meter()` helper exactly: a no-op when
//! `run_id` is `None`/absent, otherwise `super::wf026`'s `meter::consume`
//! contract (`effect="external_request"`), raising on `{"ok": false}`.
//! Metering here calls into this crate's already-ported `wf026::meter`
//! module directly, exactly as the Python imports `meter as research_meter`
//! from the sibling `meter.py` (ported in wf026).

use std::fmt;

use crate::wf_port::wf026::meter;

#[derive(Debug)]
pub enum DispatchError {
    /// Port of `ValueError(f'provider {name!r} does not expose search/open/find')`
    /// and of `ValueError('--corpus is required for local-corpus')`.
    InvalidProvider(String),
    /// The named provider is real in the Python original but is backed by a
    /// sibling file this packet does not own; see the module doc above.
    NotPorted { provider: &'static str, python_module: &'static str },
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchError::InvalidProvider(msg) => write!(f, "{msg}"),
            DispatchError::NotPorted { provider, python_module } => write!(
                f,
                "provider {provider:?} is not ported in this packet (backed by {python_module} in the Python original)"
            ),
        }
    }
}
impl std::error::Error for DispatchError {}

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

/// Port of `provider()`'s dispatch/validation. Returns `Ok(ProviderName::Scholarly)`
/// only for a provider this packet actually backs; other valid names surface
/// as `DispatchError::NotPorted` rather than silently returning something
/// that behaves differently from the Python original.
pub fn provider(name: &str, corpus: Option<&str>) -> Result<ProviderName, DispatchError> {
    let Some(parsed) = ProviderName::parse(name) else {
        return Err(DispatchError::InvalidProvider(format!(
            "provider {name:?} does not expose search/open/find"
        )));
    };
    match parsed {
        ProviderName::LocalCorpus => {
            if corpus.is_none_or(str::is_empty) {
                return Err(DispatchError::InvalidProvider(
                    "--corpus is required for local-corpus".to_string(),
                ));
            }
            Err(DispatchError::NotPorted {
                provider: "local-corpus",
                python_module: "local_corpus.py",
            })
        }
        ProviderName::Browser | ProviderName::DomainDefault => Err(DispatchError::NotPorted {
            provider: "browser/domain-default",
            python_module: "command_bridge.py",
        }),
        ProviderName::LegalAuthority => Err(DispatchError::NotPorted {
            provider: "legal-authority",
            python_module: "command_bridge.py",
        }),
        ProviderName::Scholarly => Ok(ProviderName::Scholarly),
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

/// Port of `EXTERNAL_OPS` gating in `main()`: `scholarly.external_ops` is
/// `{'search', 'open'}` (see `super::scholarly::EXTERNAL_OPS`), so `search`
/// and `open` are metered, `find` is not.
pub fn is_metered_op(provider: ProviderName, op: &str) -> bool {
    match provider {
        ProviderName::Scholarly => super::scholarly::EXTERNAL_OPS.contains(&op),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scholarly_is_the_only_backed_provider() {
        assert!(matches!(provider("scholarly", None), Ok(ProviderName::Scholarly)));
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
    fn local_corpus_with_corpus_flag_is_not_ported() {
        let err = provider("local-corpus", Some("/tmp/corpus")).unwrap_err();
        assert!(matches!(err, DispatchError::NotPorted { .. }));
    }

    #[test]
    fn browser_and_legal_authority_are_not_ported() {
        assert!(matches!(provider("browser", None).unwrap_err(), DispatchError::NotPorted { .. }));
        assert!(matches!(
            provider("legal-authority", None).unwrap_err(),
            DispatchError::NotPorted { .. }
        ));
    }

    #[test]
    fn scholarly_search_and_open_are_metered_but_find_is_not() {
        assert!(is_metered_op(ProviderName::Scholarly, "search"));
        assert!(is_metered_op(ProviderName::Scholarly, "open"));
        assert!(!is_metered_op(ProviderName::Scholarly, "find"));
    }

    #[test]
    fn meter_effect_is_noop_without_run_dir() {
        assert!(meter_effect(None, "external_request").is_ok());
    }
}
