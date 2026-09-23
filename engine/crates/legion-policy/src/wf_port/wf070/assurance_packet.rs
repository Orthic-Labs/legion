//! Faithful port of `src/lib/verification/arcane/assurance-packet.mjs`.
//!
//! A packet transports frozen material, never a producer's conclusion.

use super::canon::{digest_value, CanonVal};

#[derive(Debug, Clone)]
pub struct AssuranceArtifact {
    pub acceptance_id: String,
    pub authenticated: bool,
    pub integrated_state: CanonVal,
    pub producer: String,
    pub verifier: String,
    pub completion_consumer: String,
    /// Dropped from the compiled packet, exactly as the JS source drops
    /// `producerNarrative` via destructuring before freezing `artifacts`.
    pub producer_narrative: Option<String>,
    /// Extra fields carried through onto the packet's artifact entry
    /// verbatim (the JS source spreads `...artifact`).
    pub extra: CanonVal,
}

pub trait EvidenceRegistry {
    fn get(&self, acceptance_id: &str) -> Option<EvidenceBinding>;
}

#[derive(Debug, Clone)]
pub struct EvidenceBinding {
    pub producer: String,
    pub verifier: String,
    pub completion_consumer: String,
}

#[derive(Debug, Clone)]
pub struct AssurancePacketOutcome {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    /// Present only when `allowed`.
    pub packet: Option<CanonVal>,
    pub packet_digest: Option<String>,
    pub failing_acceptance_ids: Vec<Option<String>>,
}

fn artifact_to_canon(artifact: &AssuranceArtifact) -> CanonVal {
    let mut v = artifact.extra.clone();
    v = v
        .set("acceptance_id", CanonVal::Str(artifact.acceptance_id.clone()))
        .set("authenticated", CanonVal::Bool(artifact.authenticated))
        .set("producer", CanonVal::Str(artifact.producer.clone()))
        .set("verifier", CanonVal::Str(artifact.verifier.clone()))
        .set("completion_consumer", CanonVal::Str(artifact.completion_consumer.clone()))
        .set("integrated_state", artifact.integrated_state.clone());
    v
}

/// Mirrors `buildAssurancePacket`.
pub fn build_assurance_packet(
    frozen_contract: Option<&CanonVal>,
    artifacts: &[AssuranceArtifact],
    evidence_registry: &dyn EvidenceRegistry,
    producer_authority: Option<&str>,
    reviewer_authority: Option<&str>,
    integrated_state: Option<&CanonVal>,
) -> AssurancePacketOutcome {
    let deny = |code: &'static str, message: &str| AssurancePacketOutcome {
        allowed: false,
        code: Some(code),
        message: message.to_string(),
        packet: None,
        packet_digest: None,
        failing_acceptance_ids: Vec::new(),
    };

    let (frozen_contract, integrated_state, producer_authority, reviewer_authority) =
        match (frozen_contract, integrated_state, producer_authority, reviewer_authority) {
            (Some(fc), Some(is), Some(pa), Some(ra)) => (fc, is, pa, ra),
            _ => {
                return deny(
                    "ARC_SCHEMA_INVALID",
                    "assurance packet requires frozen contract, exact state, producer, and reviewer",
                )
            }
        };

    if producer_authority == reviewer_authority {
        return deny("ARC_SELF_CERTIFICATION", "producer cannot independently certify its own outcome");
    }

    if artifacts.is_empty()
        || artifacts
            .iter()
            .any(|a| !a.authenticated || &a.integrated_state != integrated_state)
    {
        return deny("ARC_EVIDENCE_INSUFFICIENT", "assurance packet lacks authenticated exact-state artifacts");
    }

    let unbound: Vec<&AssuranceArtifact> = artifacts
        .iter()
        .filter(|artifact| match evidence_registry.get(&artifact.acceptance_id) {
            None => true,
            Some(binding) => {
                artifact.producer == artifact.verifier
                    || artifact.producer == artifact.completion_consumer
                    || artifact.producer != binding.producer
                    || artifact.verifier != binding.verifier
                    || artifact.completion_consumer != binding.completion_consumer
            }
        })
        .collect();

    if !unbound.is_empty() {
        return AssurancePacketOutcome {
            allowed: false,
            code: Some("ARC_BINDING_MISMATCH"),
            message: "assurance artifact identities do not match registry bindings".to_string(),
            packet: None,
            packet_digest: None,
            failing_acceptance_ids: unbound.iter().map(|a| Some(a.acceptance_id.clone())).collect(),
        };
    }

    let packet = CanonVal::obj()
        .set("kind", CanonVal::Str("arcane-assurance-packet".to_string()))
        .set("contract_digest", CanonVal::Str(digest_value(frozen_contract)))
        .set("integrated_state", integrated_state.clone())
        .set("producer_authority", CanonVal::Str(producer_authority.to_string()))
        .set("reviewer_authority", CanonVal::Str(reviewer_authority.to_string()))
        .set("artifacts", CanonVal::Arr(artifacts.iter().map(artifact_to_canon).collect()));
    let packet_digest = digest_value(&packet);

    AssurancePacketOutcome {
        allowed: true,
        code: None,
        message: "independent assurance packet compiled".to_string(),
        packet: Some(packet),
        packet_digest: Some(packet_digest),
        failing_acceptance_ids: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FakeRegistry(BTreeMap<String, EvidenceBinding>);
    impl EvidenceRegistry for FakeRegistry {
        fn get(&self, acceptance_id: &str) -> Option<EvidenceBinding> {
            self.0.get(acceptance_id).cloned()
        }
    }

    fn artifact(acceptance_id: &str, producer: &str, verifier: &str, consumer: &str, state: &CanonVal) -> AssuranceArtifact {
        AssuranceArtifact {
            acceptance_id: acceptance_id.to_string(),
            authenticated: true,
            integrated_state: state.clone(),
            producer: producer.to_string(),
            verifier: verifier.to_string(),
            completion_consumer: consumer.to_string(),
            producer_narrative: Some("narrative that must be dropped".to_string()),
            extra: CanonVal::obj(),
        }
    }

    #[test]
    fn rejects_missing_required_material() {
        let registry = FakeRegistry(BTreeMap::new());
        let outcome = build_assurance_packet(None, &[], &registry, None, None, None);
        assert!(!outcome.allowed);
        assert_eq!(outcome.code, Some("ARC_SCHEMA_INVALID"));
    }

    #[test]
    fn rejects_self_certification() {
        let registry = FakeRegistry(BTreeMap::new());
        let state = CanonVal::obj();
        let contract = CanonVal::obj();
        let outcome = build_assurance_packet(Some(&contract), &[], &registry, Some("alchemist"), Some("alchemist"), Some(&state));
        assert!(!outcome.allowed);
        assert_eq!(outcome.code, Some("ARC_SELF_CERTIFICATION"));
    }

    #[test]
    fn rejects_unauthenticated_or_mismatched_state_artifacts() {
        let registry = FakeRegistry(BTreeMap::new());
        let state = CanonVal::obj();
        let contract = CanonVal::obj();
        let mut bad = artifact("acc-1", "worker", "oracle", "legion", &state);
        bad.authenticated = false;
        let outcome = build_assurance_packet(Some(&contract), &[bad], &registry, Some("alchemist"), Some("oracle"), Some(&state));
        assert!(!outcome.allowed);
        assert_eq!(outcome.code, Some("ARC_EVIDENCE_INSUFFICIENT"));
    }

    #[test]
    fn rejects_binding_mismatch_and_self_producer_roles() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "acc-1".to_string(),
            EvidenceBinding { producer: "worker".to_string(), verifier: "oracle".to_string(), completion_consumer: "legion".to_string() },
        );
        let registry = FakeRegistry(bindings);
        let state = CanonVal::obj();
        let contract = CanonVal::obj();

        let self_producer = artifact("acc-1", "worker", "worker", "legion", &state);
        let outcome = build_assurance_packet(Some(&contract), &[self_producer], &registry, Some("alchemist"), Some("oracle"), Some(&state));
        assert_eq!(outcome.code, Some("ARC_BINDING_MISMATCH"));

        let mismatched = artifact("acc-1", "worker", "someone_else", "legion", &state);
        let outcome2 = build_assurance_packet(Some(&contract), &[mismatched], &registry, Some("alchemist"), Some("oracle"), Some(&state));
        assert_eq!(outcome2.code, Some("ARC_BINDING_MISMATCH"));
        assert_eq!(outcome2.failing_acceptance_ids, vec![Some("acc-1".to_string())]);
    }

    #[test]
    fn compiles_a_valid_packet_and_drops_producer_narrative() {
        let mut bindings = BTreeMap::new();
        bindings.insert(
            "acc-1".to_string(),
            EvidenceBinding { producer: "worker".to_string(), verifier: "oracle".to_string(), completion_consumer: "legion".to_string() },
        );
        let registry = FakeRegistry(bindings);
        let state = CanonVal::obj().set("status", CanonVal::Str("VERIFIED".into()));
        let contract = CanonVal::obj().set("id", CanonVal::Str("EC-1".into()));
        let good = artifact("acc-1", "worker", "oracle", "legion", &state);
        let outcome = build_assurance_packet(Some(&contract), &[good], &registry, Some("alchemist"), Some("oracle"), Some(&state));
        assert!(outcome.allowed, "{:?}", outcome.message);
        let packet = outcome.packet.unwrap();
        let artifacts = packet.get("artifacts").unwrap().as_arr().unwrap();
        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].get("producer_narrative").is_none());
        assert!(outcome.packet_digest.unwrap().starts_with("sha256:"));
    }
}
