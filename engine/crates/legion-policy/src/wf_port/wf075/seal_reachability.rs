//! Faithful port of `src/lib/verification/arcane/seal-reachability.mjs` and
//! the `verifyExternalProviderCapability` half of
//! `src/lib/verification/arcane/provider-capability.mjs` it calls.
//!
//! "S05 seal compiler: no requirement reaches a seal without its executable
//! lifecycle." A minimal local `Decision` stands in for the JS `decision()`
//! helper (`src/lib/contracts/arcane/errors.mjs`) — `legion-policy` cannot
//! take a dependency on `legion-arcane`'s `decision.rs` (Cargo.toml is not
//! this owner's file; see the wf075 report's shared-file patch) and this
//! port only needs the two fields (`allowed`, `code`) any caller of
//! `compileSealReachability` actually branches on, plus `message`/`detail`
//! for parity with the JS return shape.

/// Mirrors the frozen object `decision(...)` returns, narrowed to what this
/// module's callers need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    /// `None` on an allowed decision, mirroring JS's `code: null`.
    pub code: Option<&'static str>,
    pub message: String,
}

fn allow(message: impl Into<String>) -> Decision {
    Decision { allowed: true, code: None, message: message.into() }
}

fn deny(code: &'static str, message: impl Into<String>) -> Decision {
    Decision { allowed: false, code: Some(code), message: message.into() }
}

/// A required evidence lifecycle step. `producer`, `verifier`, and
/// `completion_consumer` are identity-bearing (JS compares them to each
/// other by value, e.g. `requirement.producer === requirement.verifier`),
/// so they are modelled as `Option<String>`; `durable_store`,
/// `authenticated_persistence`, and `close_path` are plain attestation
/// flags in every caller of this module, so they are modelled as `bool`.
#[derive(Debug, Clone, Default)]
pub struct SealRequirement {
    pub id: Option<String>,
    pub producer: Option<String>,
    pub durable_store: bool,
    pub authenticated_persistence: bool,
    pub verifier: Option<String>,
    pub completion_consumer: Option<String>,
    pub close_path: bool,
    pub external_provider: Option<String>,
    pub self_attested: bool,
    pub fixture_only: bool,
    pub generic_receipt: bool,
}

const REQUIRED_STEPS: &[&str] =
    &["producer", "durableStore", "authenticatedPersistence", "verifier", "completionConsumer", "closePath"];

impl SealRequirement {
    fn step_present(&self, step: &str) -> bool {
        match step {
            "producer" => self.producer.as_deref().is_some_and(|s| !s.is_empty()),
            "durableStore" => self.durable_store,
            "authenticatedPersistence" => self.authenticated_persistence,
            "verifier" => self.verifier.as_deref().is_some_and(|s| !s.is_empty()),
            "completionConsumer" => self.completion_consumer.as_deref().is_some_and(|s| !s.is_empty()),
            "closePath" => self.close_path,
            _ => false,
        }
    }

    fn missing_steps(&self) -> Vec<&'static str> {
        REQUIRED_STEPS.iter().copied().filter(|step| !self.step_present(step)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryPath {
    pub requirement_id: String,
    pub authenticated: bool,
    pub close_path: bool,
}

/// Mirrors `provider-capability.mjs`'s `REQUIRED` list for
/// `verifyExternalProviderCapability`.
#[derive(Debug, Clone, Default)]
pub struct ProviderCapability {
    pub provider_id: Option<String>,
    pub machine_readable: bool,
    pub gateable: bool,
    pub downloadable: bool,
    pub trusted_retrieval: bool,
    pub trajectory_bindable: bool,
    pub sensitivity: Option<String>,
    pub retention: Option<String>,
    pub deletion_owner: Option<String>,
}

/// Faithful port of `verifyExternalProviderCapability`. `capability` is
/// `None` where the JS source would have received `undefined` (no matching
/// entry in the caller's `providerCapabilities` map) — `missingFields`
/// against `undefined` reports every required field missing, which this
/// mirrors by returning the full "incomplete or substituted" denial.
pub fn verify_external_provider_capability(capability: Option<&ProviderCapability>, provider_id: &str) -> Decision {
    let missing_all = || {
        deny(
            "ARC_UNSOUND_SEAL",
            format!("external provider capability is incomplete or substituted for {provider_id}"),
        )
    };
    let Some(capability) = capability else {
        return missing_all();
    };
    if capability.provider_id.as_deref() != Some(provider_id) {
        return missing_all();
    }
    // JS's `missingFields(capability, REQUIRED)` (over the full REQUIRED
    // list, including `sensitivity`/`retention`/`deletionOwner`) also gates
    // this same "incomplete or substituted" denial — a capability record
    // missing any required field, not only the five booleans checked below,
    // fails here first.
    let non_empty = |s: &Option<String>| s.as_deref().is_some_and(|v| !v.is_empty());
    if !non_empty(&capability.sensitivity) || !non_empty(&capability.retention) || !non_empty(&capability.deletion_owner) {
        return missing_all();
    }
    // Fields [1..6) of REQUIRED (machineReadable..trajectoryBindable) must
    // all be `true`.
    if !(capability.machine_readable
        && capability.gateable
        && capability.downloadable
        && capability.trusted_retrieval
        && capability.trajectory_bindable)
    {
        return deny(
            "ARC_UNSOUND_SEAL",
            format!("external provider cannot produce closure-grade evidence for {provider_id}"),
        );
    }
    if capability.sensitivity.as_deref() == Some("sensitive")
        && (capability.retention.is_none() || capability.deletion_owner.is_none())
    {
        return deny(
            "ARC_UNSOUND_SEAL",
            format!("sensitive provider evidence lacks retention or deletion ownership for {provider_id}"),
        );
    }
    allow(format!("external provider capability supports closure-grade evidence for {provider_id}"))
}

#[derive(Debug, Clone)]
pub struct SealFailure {
    pub requirement_id: Option<String>,
    pub reason: &'static str,
}

/// Faithful port of `compileSealReachability`.
pub fn compile_seal_reachability(
    requirements: &[SealRequirement],
    provider_capabilities: &[ProviderCapability],
    recovery_paths: &[RecoveryPath],
) -> Decision {
    let mut failures: Vec<SealFailure> = Vec::new();
    for requirement in requirements {
        let missing = requirement.missing_steps();
        if !missing.is_empty() {
            failures.push(SealFailure { requirement_id: requirement.id.clone(), reason: "missing-lifecycle-step" });
            continue;
        }
        if requirement.producer.is_some() && requirement.producer == requirement.verifier
            || requirement.producer.is_some() && requirement.producer == requirement.completion_consumer
            || requirement.self_attested
            || requirement.fixture_only
            || requirement.generic_receipt
        {
            failures.push(SealFailure { requirement_id: requirement.id.clone(), reason: "self-attested-or-nonproduction-path" });
            continue;
        }
        if let Some(external_provider) = &requirement.external_provider {
            let cap = provider_capabilities.iter().find(|c| c.provider_id.as_deref() == Some(external_provider.as_str()));
            let capability = verify_external_provider_capability(cap, external_provider);
            if !capability.allowed {
                failures.push(SealFailure { requirement_id: requirement.id.clone(), reason: "external-provider-capability-unreachable" });
                continue;
            }
        }
        let reachable = recovery_paths.iter().any(|path| {
            requirement.id.as_deref().is_some_and(|id| path.requirement_id == id) && path.authenticated && path.close_path
        });
        if !reachable {
            failures.push(SealFailure { requirement_id: requirement.id.clone(), reason: "recovery-close-unreachable" });
        }
    }
    if !failures.is_empty() {
        return deny("ARC_UNSOUND_SEAL", "required evidence lifecycle is not reachable");
    }
    allow("every required evidence lifecycle is reachable")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sound_requirement(id: &str) -> SealRequirement {
        SealRequirement {
            id: Some(id.to_string()),
            producer: Some("producer-a".to_string()),
            durable_store: true,
            authenticated_persistence: true,
            verifier: Some("verifier-b".to_string()),
            completion_consumer: Some("consumer-c".to_string()),
            close_path: true,
            ..Default::default()
        }
    }

    #[test]
    fn missing_lifecycle_step_fails() {
        let mut req = sound_requirement("r1");
        req.close_path = false;
        let d = compile_seal_reachability(&[req], &[], &[]);
        assert!(!d.allowed);
        assert_eq!(d.code, Some("ARC_UNSOUND_SEAL"));
    }

    #[test]
    fn self_attested_producer_equals_verifier_fails() {
        let mut req = sound_requirement("r1");
        req.verifier = req.producer.clone();
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
        let d = compile_seal_reachability(&[req], &[], &[path]);
        assert!(!d.allowed);
    }

    #[test]
    fn sound_seal_with_recovery_path_passes() {
        let req = sound_requirement("r1");
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
        let d = compile_seal_reachability(&[req], &[], &[path]);
        assert!(d.allowed);
        assert_eq!(d.code, None);
    }

    #[test]
    fn missing_recovery_close_path_fails() {
        let req = sound_requirement("r1");
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: false };
        let d = compile_seal_reachability(&[req], &[], &[path]);
        assert!(!d.allowed);
    }

    #[test]
    fn external_provider_unreachable_fails() {
        let mut req = sound_requirement("r1");
        req.external_provider = Some("prov-x".to_string());
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
        let d = compile_seal_reachability(&[req], &[], &[path]);
        assert!(!d.allowed);
    }

    #[test]
    fn external_provider_reachable_and_sound() {
        let mut req = sound_requirement("r1");
        req.external_provider = Some("prov-x".to_string());
        let cap = ProviderCapability {
            provider_id: Some("prov-x".to_string()),
            machine_readable: true,
            gateable: true,
            downloadable: true,
            trusted_retrieval: true,
            trajectory_bindable: true,
            sensitivity: Some("normal".to_string()),
            retention: Some("30d".to_string()),
            deletion_owner: Some("host".to_string()),
        };
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
        let d = compile_seal_reachability(&[req], &[cap], &[path]);
        assert!(d.allowed);
    }

    #[test]
    fn sensitive_external_provider_without_retention_fails() {
        let mut req = sound_requirement("r1");
        req.external_provider = Some("prov-x".to_string());
        let cap = ProviderCapability {
            provider_id: Some("prov-x".to_string()),
            machine_readable: true,
            gateable: true,
            downloadable: true,
            trusted_retrieval: true,
            trajectory_bindable: true,
            sensitivity: Some("sensitive".to_string()),
            retention: None,
            deletion_owner: None,
        };
        let path = RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
        let d = compile_seal_reachability(&[req], &[cap], &[path]);
        assert!(!d.allowed);
    }

    #[test]
    fn empty_requirements_are_sound() {
        let d = compile_seal_reachability(&[], &[], &[]);
        assert!(d.allowed);
    }
}
