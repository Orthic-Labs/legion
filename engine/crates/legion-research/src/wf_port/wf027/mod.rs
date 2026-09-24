//! wf027 — port of `src/lib/research-core/providers/{base,command_bridge,
//! http_browser,local_corpus,notebooklm}.py` into `legion-research`.
//!
//! Membrane/Blueprint are moving to another product; `data_only_envelope`'s
//! docstring in the Python source described Membrane owning envelope/data-
//! fence policy downstream of this crate. That framing is dropped here (see
//! `support.rs`); the function's own behaviour is unchanged and is exactly
//! what `test_research_provider_fence.py` (ported in
//! `tests/wf_wf027.rs`) asserts. No other file in this chunk referenced
//! Membrane or Blueprint.

pub mod command_bridge;
pub mod http_browser;
pub mod local_corpus;
pub mod notebooklm;
pub mod support;
pub mod types;

pub use command_bridge::CommandBridgeProvider;
pub use http_browser::{HttpBrowserProvider, HttpResponse, HttpTransport, ReqwestTransport};
pub use local_corpus::LocalCorpusProvider;
pub use notebooklm::NotebookLmAdapter;
pub use support::WfError;
pub use types::{LocatedPassage, OpenedSource, Provider, SearchHit};
