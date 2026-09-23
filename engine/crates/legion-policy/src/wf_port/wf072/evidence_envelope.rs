//! Faithful port of `src/lib/verification/arcane/evidence-envelope.mjs`.
//!
//! Seals evidence-capability receipts and carries the full Arcane-side
//! dependency record the frozen receipt cannot express (16 dependency
//! dimensions, projected down to the frozen 6-value `dependsOn[].kind` enum).
//!
//! Deviations from the JS source (both necessary, both noted at point of
//! use):
//!   - `sealEvidence` calls `assertValid('evidence-capability-receipt-v1',
//!     receipt)` against the JSON-schema loaded from
//!     `packages/contracts/schemas/`. wf072 does not own a JSON-schema
//!     validator or that schema file, so `seal_evidence` here performs the
//!     receipt's *structural* shape checks it can faithfully reproduce
//!     (required fields present) without re-implementing full JSON-schema
//!     validation. This is a scope gap, not a behavior change — see the
//!     wf072 report.
//!   - `mintKernelId` (Kernel-binding-based, provisional-when-unbound id
//!     minting) is out of this chunk's ownership; `seal_evidence` takes the
//!     minted `evidence_id` and `provisional` flag as caller-supplied
//!     inputs instead of minting them itself. This keeps the module pure
//!     and deterministic for testing, and the caller (once wired to a real
//!     Kernel binding) supplies exactly what `mintKernelId('evidenceReceipt')`
//!     would have produced.

use super::support::{digest_value, ArcCode, Json};

/// The full dependency-dimension set Arcane tracks for invalidation.
/// Mirrors JS `DEPENDENCY_DIMENSION` exactly (order and membership).
pub const DEPENDENCY_DIMENSION: &[&str] = &[
    "source-digest",
    "git-revision",
    "worktree-dirty",
    "lockfile-version",
    "config-digest",
    "schema-version",
    "fixture-digest",
    "tool-version",
    "environment",
    "method-fingerprint",
    "policy-version",
    "topology",
    "external-source-revision",
    "approval-authority",
    "upstream-contract-revision",
    "evidence",
];

/// Frozen receipt `dependsOn[].kind` enum (6 values), mirroring
/// `evidence-capability-receipt-v1.schema.json`'s `dependsOn.items.kind.enum`.
pub const FROZEN_KIND: &[&str] =
    &["decision", "source-revision", "config-digest", "tool-digest", "policy-digest", "evidence"];

/// dimension -> (kind, faithful, note). Mirrors JS `DEPENDENCY_KIND_PROJECTION`.
pub fn dependency_kind_projection(dimension: &str) -> Option<(&'static str, bool, &'static str)> {
    Some(match dimension {
        "source-digest" => ("source-revision", true, "a content digest identifying source state is what source-revision means"),
        "git-revision" => ("source-revision", true, "exact match"),
        "worktree-dirty" => ("source-revision", false, "a dirty/clean flag is not a revision identifier; no faithful bucket exists"),
        "lockfile-version" => ("config-digest", false, "dependency-graph version is a distinct concept from generic config"),
        "config-digest" => ("config-digest", true, "exact match"),
        "schema-version" => ("config-digest", false, "a contract/schema version is not config"),
        "fixture-digest" => ("source-revision", false, "test/fixture data digest conflated with source-code revision"),
        "tool-version" => ("tool-digest", true, "version stands in for digest; close enough"),
        "environment" => ("tool-digest", false, "host/platform identity is not a tool"),
        "method-fingerprint" => ("tool-digest", false, "describes the producer's method, not tool identity"),
        "policy-version" => ("policy-digest", true, "version stands in for digest; close enough"),
        "topology" => ("config-digest", false, "structural target/component topology is not a config value"),
        "external-source-revision" => ("source-revision", true, "exact match"),
        "approval-authority" => ("decision", false, "an approval/waiver authority binding is not itself a sealed decision"),
        "upstream-contract-revision" => ("decision", false, "a contract revision is closer to source-revision than decision, but contracts derive from decisions; ambiguous either way"),
        "evidence" => ("evidence", true, "exact match; the only dimension the frozen enum models precisely for transitive edges"),
        _ => return None,
    })
}

/// Dimensions with no faithful projection. Mirrors JS `UNFAITHFUL_DIMENSIONS`.
pub fn unfaithful_dimensions() -> Vec<&'static str> {
    DEPENDENCY_DIMENSION
        .iter()
        .filter(|d| matches!(dependency_kind_projection(d), Some((_, false, _))))
        .copied()
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dependency {
    pub dimension: String,
    pub reference: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedDependency {
    pub kind: &'static str,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopeError {
    pub code: ArcCode,
    pub message: String,
}

/// Mirrors JS `projectDependency`.
fn project_dependency(dep: &Dependency) -> Result<ProjectedDependency, EnvelopeError> {
    let Some((kind, _faithful, _note)) = dependency_kind_projection(&dep.dimension) else {
        return Err(EnvelopeError {
            code: ArcCode::ArcDependencyUnknown,
            message: format!("unknown dependency dimension: {}", dep.dimension),
        });
    };
    if dep.reference.is_empty() {
        return Err(EnvelopeError {
            code: ArcCode::ArcSchemaInvalid,
            message: "dependency ref must be a non-empty string".to_string(),
        });
    }
    // Fold the original dimension into `ref` so the projection never
    // silently discards which dimension actually changed.
    Ok(ProjectedDependency { kind, reference: format!("{}:{}", dep.dimension, dep.reference) })
}

#[derive(Debug, Clone, PartialEq)]
pub struct SealEvidenceInput {
    pub evidence_id: String,
    pub provisional: bool,
    pub run_id: String,
    pub task_id: Option<String>,
    pub contract_id: Option<String>,
    pub producer_authority: String,
    pub capability: String,
    pub observation: Json,
    pub evidence_class: String,
    pub source_revision: Option<String>,
    pub dependencies: Vec<Dependency>,
    /// `authentication.verificationMethod`, if any — used only to derive
    /// `trustClass`, matching JS `authentication?.verificationMethod === 'unauthenticated'`.
    pub authentication_verification_method: Option<String>,
    pub authentication: Json,
    pub replay_defense: Json,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SealedEvidence {
    pub receipt: Json,
    pub envelope: Json,
    pub envelope_digest: String,
}

/// Seal an observation into an evidence-capability receipt plus the richer
/// Arcane-side envelope. Mirrors JS `sealEvidence`.
pub fn seal_evidence(input: SealEvidenceInput) -> Result<SealedEvidence, EnvelopeError> {
    let mut depends_on = Vec::with_capacity(input.dependencies.len());
    for dep in &input.dependencies {
        depends_on.push(project_dependency(dep)?);
    }

    let depends_on_json = Json::Arr(
        depends_on
            .iter()
            .map(|d| Json::Obj(vec![("kind".into(), Json::str(d.kind)), ("ref".into(), Json::str(d.reference.clone()))]))
            .collect(),
    );

    let receipt = Json::Obj(vec![
        ("schemaVersion".into(), Json::I64(1)),
        ("kind".into(), Json::str("legion-evidence-capability-receipt")),
        ("evidenceId".into(), Json::str(input.evidence_id.clone())),
        ("runId".into(), Json::str(input.run_id.clone())),
        ("taskId".into(), input.task_id.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("contractId".into(), input.contract_id.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("producerAuthority".into(), Json::str(input.producer_authority.clone())),
        ("capability".into(), Json::str(input.capability.clone())),
        ("observation".into(), input.observation.clone()),
        ("evidenceClass".into(), Json::str(input.evidence_class.clone())),
        ("authentication".into(), input.authentication.clone()),
        ("replayDefense".into(), input.replay_defense.clone()),
        ("sourceRevision".into(), input.source_revision.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("dependsOn".into(), depends_on_json),
        ("stale".into(), Json::Bool(false)),
        ("observedAt".into(), Json::str(input.observed_at.clone())),
    ]);

    // Scope-limited structural check in place of full JSON-schema validation
    // (see module doc). runId/producerAuthority/capability/evidenceClass/
    // observedAt are the receipt's own non-nullable required fields.
    if input.run_id.is_empty()
        || input.producer_authority.is_empty()
        || input.capability.is_empty()
        || input.evidence_class.is_empty()
        || input.observed_at.is_empty()
    {
        return Err(EnvelopeError {
            code: ArcCode::ArcSchemaInvalid,
            message: "evidence-capability-receipt-v1 is missing a required field".to_string(),
        });
    }

    let receipt_digest = digest_value(&receipt);

    let trust_class = if input.authentication_verification_method.as_deref() == Some("unauthenticated") {
        "unauthenticated"
    } else {
        "authenticated"
    };

    let dependencies_json = Json::Arr(
        input
            .dependencies
            .iter()
            .map(|d| {
                Json::Obj(vec![
                    ("dimension".into(), Json::str(d.dimension.clone())),
                    ("ref".into(), Json::str(d.reference.clone())),
                    ("digest".into(), d.digest.clone().map(Json::Str).unwrap_or(Json::Null)),
                ])
            })
            .collect(),
    );

    let envelope_core = Json::Obj(vec![
        ("evidenceId".into(), Json::str(input.evidence_id.clone())),
        ("runId".into(), Json::str(input.run_id.clone())),
        ("taskId".into(), input.task_id.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("contractId".into(), input.contract_id.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("producerAuthority".into(), Json::str(input.producer_authority.clone())),
        ("capability".into(), Json::str(input.capability.clone())),
        ("observation".into(), input.observation.clone()),
        ("evidenceClass".into(), Json::str(input.evidence_class.clone())),
        ("sourceRevision".into(), input.source_revision.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("dependencies".into(), dependencies_json),
        ("authentication".into(), input.authentication.clone()),
        ("replayDefense".into(), input.replay_defense.clone()),
        ("observedAt".into(), Json::str(input.observed_at.clone())),
        ("stale".into(), Json::Bool(false)),
        ("provisionalId".into(), Json::Bool(input.provisional)),
        ("trustClass".into(), Json::str(trust_class)),
        ("receiptDigest".into(), Json::str(receipt_digest)),
    ]);

    let env_digest = envelope_digest(&envelope_core);
    let envelope = with_envelope_digest(&envelope_core, &env_digest);

    Ok(SealedEvidence { receipt, envelope, envelope_digest: env_digest })
}

/// Digest of an envelope's content (excludes any pre-existing
/// `envelopeDigest` field, so it is idempotent to call on an
/// already-digested envelope). Mirrors JS `envelopeDigest`.
pub fn envelope_digest(envelope: &Json) -> String {
    let Json::Obj(pairs) = envelope else {
        return digest_value(envelope);
    };
    let rest: Vec<(String, Json)> = pairs.iter().filter(|(k, _)| k != "envelopeDigest").cloned().collect();
    digest_value(&Json::Obj(rest))
}

fn with_envelope_digest(core: &Json, env_digest: &str) -> Json {
    let Json::Obj(pairs) = core else { return core.clone() };
    let mut out = pairs.clone();
    out.push(("envelopeDigest".into(), Json::str(env_digest)));
    Json::Obj(out)
}

// ---------------------------------------------------------------------
// Legacy import (WP4 action 7) — additive helper, not in the binding list.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct LegacyEnvelope {
    pub kind: String,
    pub legacy_kind: String,
    pub payload: Json,
    pub authenticated: bool,
    pub source_revision: Option<String>,
    pub source: String,
    pub captured_at: String,
    pub provisional_mapping_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportedLegacyEvidence {
    pub evidence_id: String,
    pub run_id: Option<String>,
    pub legacy_kind: String,
    pub capability: String,
    pub observation: Json,
    pub evidence_class: String,
    pub source_revision: Option<String>,
    pub authentication_issuer_identity: String,
    pub trust_class: String,
    pub never_qualifying: bool,
    pub provisional_mapping_ref: Option<String>,
    pub observed_at: String,
    pub stale: bool,
}

/// Import a legacy-envelope-v1-shaped record as an Arcane evidence envelope
/// that can never gain trust. Mirrors JS `importLegacyEvidence`.
///
/// `evidence_id` is caller-supplied (see module doc: minting is out of
/// this chunk's ownership) in place of `mintKernelId('evidenceReceipt')`.
pub fn import_legacy_evidence(
    legacy: &LegacyEnvelope,
    evidence_id: String,
    run_id: Option<String>,
    capability: Option<String>,
    observed_at: Option<String>,
) -> Result<ImportedLegacyEvidence, EnvelopeError> {
    if legacy.kind != "legion-legacy-envelope" {
        return Err(EnvelopeError {
            code: ArcCode::ArcSchemaInvalid,
            message: format!("expected a legacy-envelope-v1 shaped record (kind: legion-legacy-envelope), got: {}", legacy.kind),
        });
    }
    if legacy.authenticated {
        return Err(EnvelopeError {
            code: ArcCode::ArcAuthLegacyDigest,
            message: "legacy envelope provenance.authenticated must be false".to_string(),
        });
    }

    let payload_digest = digest_value(&legacy.payload);

    Ok(ImportedLegacyEvidence {
        evidence_id,
        run_id,
        legacy_kind: legacy.legacy_kind.clone(),
        capability: capability.unwrap_or_else(|| "legacy-import".to_string()),
        observation: Json::Obj(vec![("legacyPayloadDigest".into(), Json::str(payload_digest))]),
        evidence_class: "external".to_string(),
        source_revision: legacy.source_revision.clone(),
        authentication_issuer_identity: legacy.source.clone(),
        trust_class: "legacy-unauthenticated".to_string(),
        never_qualifying: true,
        provisional_mapping_ref: legacy.provisional_mapping_ref.clone(),
        observed_at: observed_at.unwrap_or_else(|| legacy.captured_at.clone()),
        stale: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SealEvidenceInput {
        SealEvidenceInput {
            evidence_id: "ev-1".into(),
            provisional: false,
            run_id: "run-1".into(),
            task_id: None,
            contract_id: None,
            producer_authority: "capability:foo".into(),
            capability: "foo".into(),
            observation: Json::Obj(vec![("k".into(), Json::str("v"))]),
            evidence_class: "internal".into(),
            source_revision: Some("git:abc".into()),
            dependencies: vec![],
            authentication_verification_method: Some("mac".into()),
            authentication: Json::Null,
            replay_defense: Json::Null,
            observed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn seal_evidence_projects_dependencies_and_folds_dimension_into_ref() {
        let mut input = base_input();
        input.dependencies = vec![Dependency { dimension: "source-digest".into(), reference: "sha256:aa".into(), digest: Some("sha256:aa".into()) }];
        let sealed = seal_evidence(input).unwrap();
        let Json::Obj(receipt) = &sealed.receipt else { panic!() };
        let depends_on = receipt.iter().find(|(k, _)| k == "dependsOn").unwrap();
        let Json::Arr(items) = &depends_on.1 else { panic!() };
        assert_eq!(items.len(), 1);
        let Json::Obj(item) = &items[0] else { panic!() };
        assert_eq!(item.iter().find(|(k, _)| k == "kind").unwrap().1, Json::str("source-revision"));
        assert_eq!(item.iter().find(|(k, _)| k == "ref").unwrap().1, Json::str("source-digest:sha256:aa"));
    }

    #[test]
    fn seal_evidence_rejects_unknown_dimension() {
        let mut input = base_input();
        input.dependencies = vec![Dependency { dimension: "bogus".into(), reference: "x".into(), digest: None }];
        let err = seal_evidence(input).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcDependencyUnknown);
    }

    #[test]
    fn seal_evidence_rejects_empty_dependency_ref() {
        let mut input = base_input();
        input.dependencies = vec![Dependency { dimension: "source-digest".into(), reference: "".into(), digest: None }];
        let err = seal_evidence(input).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcSchemaInvalid);
    }

    #[test]
    fn seal_evidence_derives_unauthenticated_trust_class() {
        let mut input = base_input();
        input.authentication_verification_method = Some("unauthenticated".into());
        let sealed = seal_evidence(input).unwrap();
        let Json::Obj(env) = &sealed.envelope else { panic!() };
        assert_eq!(env.iter().find(|(k, _)| k == "trustClass").unwrap().1, Json::str("unauthenticated"));
    }

    #[test]
    fn envelope_digest_is_idempotent_across_pre_and_post_digested_envelope() {
        let sealed = seal_evidence(base_input()).unwrap();
        let redigested = envelope_digest(&sealed.envelope);
        assert_eq!(redigested, sealed.envelope_digest);
    }

    #[test]
    fn unfaithful_dimensions_matches_js_count() {
        // JS: 9 of 16 dimensions have no faithful bucket.
        assert_eq!(unfaithful_dimensions().len(), 9);
        assert_eq!(DEPENDENCY_DIMENSION.len(), 16);
    }

    #[test]
    fn import_legacy_evidence_rejects_wrong_kind() {
        let legacy = LegacyEnvelope {
            kind: "not-legacy".into(),
            legacy_kind: "x".into(),
            payload: Json::Null,
            authenticated: false,
            source_revision: None,
            source: "s".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            provisional_mapping_ref: None,
        };
        let err = import_legacy_evidence(&legacy, "ev-2".into(), None, None, None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcSchemaInvalid);
    }

    #[test]
    fn import_legacy_evidence_rejects_authenticated_true() {
        let legacy = LegacyEnvelope {
            kind: "legion-legacy-envelope".into(),
            legacy_kind: "x".into(),
            payload: Json::Null,
            authenticated: true,
            source_revision: None,
            source: "s".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            provisional_mapping_ref: None,
        };
        let err = import_legacy_evidence(&legacy, "ev-3".into(), None, None, None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthLegacyDigest);
    }

    #[test]
    fn import_legacy_evidence_never_qualifies_and_is_unauthenticated() {
        let legacy = LegacyEnvelope {
            kind: "legion-legacy-envelope".into(),
            legacy_kind: "x".into(),
            payload: Json::str("p"),
            authenticated: false,
            source_revision: Some("git:1".into()),
            source: "legacy-tool".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            provisional_mapping_ref: Some("map-1".into()),
        };
        let imported = import_legacy_evidence(&legacy, "ev-4".into(), None, None, None).unwrap();
        assert_eq!(imported.trust_class, "legacy-unauthenticated");
        assert!(imported.never_qualifying);
        assert_eq!(imported.observed_at, "2026-01-01T00:00:00Z");
    }
}
