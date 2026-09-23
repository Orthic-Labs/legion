//! wf019 — `src/lib/report` editor surface and family-summary families.
//!
//! Port of `src/lib/report/editor/index.mjs` (`editorDiagnostics`) and of
//! `src/lib/report/families/shared.mjs`'s `buildFamilySummary`, which
//! `architecture.mjs`, `code.mjs`, `compatibility.mjs`, and
//! `data-integrity.mjs` each re-export verbatim as their entire body
//! (`export {buildFamilySummary} from './shared.mjs';`). Those four family
//! files carry no behaviour of their own beyond that re-export, so this
//! module ports `buildFamilySummary` once and exposes it under names for
//! each of the four owned families plus the generic entry point.
//!
//! `shared.mjs` is also re-exported by family files this chunk does not
//! own (`data-privacy.mjs`, `docs-contract.mjs`, `governance.mjs`,
//! `requirements.mjs`, `supply-chain.mjs`, `test-quality.mjs`); those are
//! out of scope here and, if not already ported by another chunk, are
//! identical callers of the same underlying summary logic.

pub mod editor_diagnostics;
pub mod family_summary;

pub use editor_diagnostics::{editor_diagnostics, EditorDiagnostic, EditorInput};
pub use family_summary::{
    build_family_summary, Denominator, FamilyResult, FamilySummary, ProviderSummary, SummaryGap,
};
