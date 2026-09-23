//! L1b literal port of `src/lib/decision_provider.py`.
//!
//! Ports the pure candidate-set/lifecycle logic (`produce_candidate_set`,
//! `CandidateSpec`, `ContextCandidateSet`, `ProviderWarning`,
//! `LifecycleError`, freshness/scoring/supersession helpers). Store I/O
//! (`DecisionStore.iter_records`) is not re-implemented here — callers pass
//! records already loaded via `DecisionStore::all()`.

pub mod provider;

pub use provider::{
    produce_candidate_set, CandidateSpec, ContextCandidateSet, LifecycleError, ProviderWarning,
    INSTRUCTION_POLICY, LAYER, PROVIDER_NAME, SCHEMA_VERSION_CONTRACT, SOURCE_KIND, TRUST_CLASS,
};
