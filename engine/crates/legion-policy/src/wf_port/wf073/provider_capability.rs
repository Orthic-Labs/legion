//! Port of `src/lib/verification/arcane/provider-capability.mjs` —
//! `ProviderCapabilityRegistry` and `verifyExternalProviderCapability`.
//!
//! Catalog metadata is not evidence: an adapter must persist an *observed*
//! capability record before gateability exists. `ProviderAdapter` here is
//! the Rust equivalent of the JS module's deliberately-small duck-typed
//! adapter (`{ get/read/readProviderCapability, set/write/writeProviderCapability }`)
//! so a host-owned durable store can provide it without this module
//! inventing another persistence plane.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapability {
    pub adapter_id: String,
    pub machine_readable: bool,
    pub gateable: bool,
    pub downloadable: bool,
    pub trusted_retrieval: bool,
    pub trajectory_bindable: bool,
}

/// Same admission-gate check the JS `adapterState()` free function performs:
/// every boolean flag other than the id must be `true` for the adapter to
/// establish machine-gate capability at all.
fn adapter_state(adapter: &AdapterCapability) -> Option<AdapterCapability> {
    if adapter.machine_readable
        && adapter.gateable
        && adapter.downloadable
        && adapter.trusted_retrieval
        && adapter.trajectory_bindable
    {
        Some(adapter.clone())
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilityRecord {
    pub provider_id: String,
    pub adapter: AdapterCapability,
    pub observed_at: String,
    pub valid_until: Option<String>,
    pub sensitivity: String,
    pub retention: Option<String>,
    pub deletion_owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDecision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub admission: Option<&'static str>,
}

fn allow(message: impl Into<String>) -> CapabilityDecision {
    CapabilityDecision { allowed: true, code: None, message: message.into(), admission: None }
}

fn deny(code: &'static str, message: impl Into<String>, admission: Option<&'static str>) -> CapabilityDecision {
    CapabilityDecision { allowed: false, code: Some(code), message: message.into(), admission }
}

/// Durable adapter-backed store this registry writes/reads through. Kept as
/// a trait (rather than a concrete map) so a host-owned durable store can
/// implement it directly, mirroring the JS module's duck-typed adapter.
pub trait ProviderCapabilityStore {
    fn get(&self, provider_id: &str) -> Option<ProviderCapabilityRecord>;
    fn set(&mut self, provider_id: &str, record: ProviderCapabilityRecord);
}

/// A simple in-memory `ProviderCapabilityStore`, useful for tests and for a
/// host that has no other durable adapter available yet. The JS module
/// treats "no adapter write method" as `ARC_UNSOUND_SEAL` /
/// `INFORMATIONAL_ONLY`; callers that want that behaviour natively should
/// use `ProviderCapabilityRegistry::without_store` instead of this type.
#[derive(Debug, Default)]
pub struct InMemoryProviderCapabilityStore {
    records: std::collections::HashMap<String, ProviderCapabilityRecord>,
}

impl ProviderCapabilityStore for InMemoryProviderCapabilityStore {
    fn get(&self, provider_id: &str) -> Option<ProviderCapabilityRecord> {
        self.records.get(provider_id).cloned()
    }

    fn set(&mut self, provider_id: &str, record: ProviderCapabilityRecord) {
        self.records.insert(provider_id.to_string(), record);
    }
}

pub struct ProviderCapabilityRegistry<S: ProviderCapabilityStore> {
    store: Option<S>,
}

impl<S: ProviderCapabilityStore> ProviderCapabilityRegistry<S> {
    pub fn new(store: S) -> Self {
        Self { store: Some(store) }
    }

    /// A registry with no durable adapter at all — every `record()` call
    /// returns `ARC_UNSOUND_SEAL` / `INFORMATIONAL_ONLY`, matching the JS
    /// `hasAdapterWrite(this.#adapter)` check when no adapter was passed to
    /// the constructor.
    pub fn without_store() -> Self {
        Self { store: None }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        provider_id: &str,
        adapter: &AdapterCapability,
        observed_at: &str,
        valid_until: Option<&str>,
        sensitivity: &str,
        retention: Option<&str>,
        deletion_owner: Option<&str>,
    ) -> CapabilityDecision {
        let Some(state) = adapter_state(adapter) else {
            return deny(
                "ARC_UNSOUND_SEAL",
                "provider adapter cannot establish machine-gate capability",
                Some("INFORMATIONAL_ONLY"),
            );
        };
        if sensitivity == "sensitive" && (retention.is_none() || deletion_owner.is_none()) {
            return deny(
                "ARC_UNSOUND_SEAL",
                "sensitive provider capability lacks retention or deletion ownership",
                Some("DENIED"),
            );
        }
        let record = ProviderCapabilityRecord {
            provider_id: provider_id.to_string(),
            adapter: state,
            observed_at: observed_at.to_string(),
            valid_until: valid_until.map(str::to_string),
            sensitivity: sensitivity.to_string(),
            retention: retention.map(str::to_string),
            deletion_owner: deletion_owner.map(str::to_string),
        };
        let Some(store) = self.store.as_mut() else {
            return deny(
                "ARC_UNSOUND_SEAL",
                "provider capability has no durable adapter-backed state",
                Some("INFORMATIONAL_ONLY"),
            );
        };
        store.set(provider_id, record);
        allow("adapter-backed provider capability recorded")
    }

    pub fn get(&self, provider_id: &str) -> Option<ProviderCapabilityRecord> {
        self.store.as_ref().and_then(|s| s.get(provider_id))
    }

    pub fn verify(&self, provider_id: &str, now_ms: i64, parse_iso_ms: impl Fn(&str) -> i64) -> CapabilityDecision {
        let Some(record) = self.get(provider_id) else {
            return deny(
                "ARC_UNSOUND_SEAL",
                "provider capability is not durably recorded",
                Some("INFORMATIONAL_ONLY"),
            );
        };
        if let Some(valid_until) = &record.valid_until {
            if parse_iso_ms(valid_until) < now_ms {
                return deny(
                    "ARC_EVIDENCE_STALE",
                    "provider capability observation requires refresh",
                    Some("REFRESH_REQUIRED"),
                );
            }
        }
        verify_external_provider_capability(
            &record.adapter,
            &record.sensitivity,
            record.retention.as_deref(),
            record.deletion_owner.as_deref(),
            provider_id,
        )
    }
}

/// Free-function equivalent of the JS `verifyExternalProviderCapability`:
/// checks an externally-supplied capability description (not necessarily
/// one this registry recorded) can support closure-grade evidence.
pub fn verify_external_provider_capability(
    adapter: &AdapterCapability,
    sensitivity: &str,
    retention: Option<&str>,
    deletion_owner: Option<&str>,
    provider_id: &str,
) -> CapabilityDecision {
    if adapter.adapter_id.is_empty() {
        return deny("ARC_UNSOUND_SEAL", "external provider capability is incomplete or substituted", None);
    }
    if !(adapter.machine_readable
        && adapter.gateable
        && adapter.downloadable
        && adapter.trusted_retrieval)
    {
        return deny("ARC_UNSOUND_SEAL", "external provider cannot produce closure-grade evidence", None);
    }
    if sensitivity == "sensitive" && (retention.is_none() || deletion_owner.is_none()) {
        return deny(
            "ARC_UNSOUND_SEAL",
            "sensitive provider evidence lacks retention or deletion ownership",
            None,
        );
    }
    let _ = provider_id;
    allow("external provider capability supports closure-grade evidence")
}
