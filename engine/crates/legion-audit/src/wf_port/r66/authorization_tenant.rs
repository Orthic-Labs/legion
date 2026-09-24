//! Port of `src/providers/security/packs/authorization-tenant.mjs` per
//! Security Appendix §52.2: object read/write/delete without
//! ownership/tenant policy, privileged functions, mass assignment, tenant
//! filters, background workers, impersonation.
//!
//! Scope: `analyze(context)` is ported faithfully. `variantStrategies`
//! (`rootCause`/`enumerate`, present only for
//! `authorization.object-write.missing-owner-check` in the JS source) is
//! coverage-report bookkeeping over the same matches `analyze()` already
//! finds; it is not ported here, mirroring the scope decision documented in
//! wf060's `common.rs`.
//!
//! Note: the JS source declares four rule ids in its `rules` list
//! (`authorization.object-write.missing-owner-check`,
//! `authorization.object-read.missing-owner-check`,
//! `authorization.privileged-function.missing-role-check`,
//! `authorization.mass-assignment`) but `analyze` only ever emits the first
//! and third; the other two are declared but dead in the JS source. This
//! port preserves that exactly: only two detectors run.

use super::{Context, Fact, Observation};
use regex::Regex;
use std::sync::LazyLock;

static OBJECT_WRITE_SINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:update|patch|put|set|save)\w*\s*\([^)]*(?:id|params|request)").unwrap());
static OBJECT_WRITE_GUARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)owner|tenant|org_?id|authorize|canAccess|permission").unwrap());

static PRIVILEGED_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:delete|remove|grant|promote|impersonate|admin)\w*\s*\(").unwrap());
static PRIVILEGED_FUNCTION_GUARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)role|permission|isAdmin|requireAdmin|authorize").unwrap());

pub const ID: &str = "security.authorization-tenant";
pub const CANDIDATE_CLASS: &str = "authorization";

/// Mirrors the JS pack's `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        let artifact_id = artifact.map(|e| e.id.clone());

        // Object write keyed by request id without visible owner check.
        if OBJECT_WRITE_SINK.is_match(text) && !OBJECT_WRITE_GUARD.is_match(text) {
            observations.push(Observation {
                rule_id: "authorization.object-write.missing-owner-check".to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: "A request-derived object identifier reaches a write without a visible ownership or tenant control."
                    .to_string(),
                severity_hint: "high".to_string(),
                sources: artifact_id.clone().into_iter().collect(),
                sinks: artifact_id.clone().into_iter().collect(),
                attacker_capabilities: vec!["authenticated-low-privilege".to_string()],
                preconditions: vec![Fact {
                    kind: "principal-access".to_string(),
                    subject: "actor:external".to_string(),
                    action: "authenticate".to_string(),
                    object: None,
                    scope: Some("low-privilege".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                effects: vec![Fact {
                    kind: "object-access".to_string(),
                    subject: "actor:external".to_string(),
                    action: "write".to_string(),
                    object: artifact_id.clone(),
                    scope: Some("cross-tenant".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: vec!["starter".to_string(), "privilege-escalation".to_string(), "impact".to_string()],
                evidence_refs: vec![],
                detector_metadata: serde_json::json!({
                    "file": file,
                    "sourceKind": "request-object-identifier",
                    "sinkKind": "tenant-object-write",
                }),
                uncertainty: vec!["A global authorization policy may exist outside the modeled path.".to_string()],
            });
        }

        // Privileged function without a visible role check.
        if PRIVILEGED_FUNCTION.is_match(text) && !PRIVILEGED_FUNCTION_GUARD.is_match(text) {
            observations.push(Observation {
                rule_id: "authorization.privileged-function.missing-role-check".to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: "A privileged function has no visible role or policy enforcement.".to_string(),
                severity_hint: "high".to_string(),
                sources: artifact_id.clone().into_iter().collect(),
                sinks: artifact_id.clone().into_iter().collect(),
                attacker_capabilities: vec!["authenticated-low-privilege".to_string()],
                preconditions: vec![Fact {
                    kind: "principal-access".to_string(),
                    subject: "actor:external".to_string(),
                    action: "authenticate".to_string(),
                    object: None,
                    scope: Some("low-privilege".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                effects: vec![Fact {
                    kind: "object-access".to_string(),
                    subject: "actor:external".to_string(),
                    action: "write".to_string(),
                    object: None,
                    scope: Some("privileged".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: vec!["privilege-escalation".to_string(), "impact".to_string()],
                evidence_refs: vec![],
                detector_metadata: serde_json::json!({
                    "file": file,
                    "sourceKind": "privileged-function",
                }),
                uncertainty: vec!["A framework-level policy may enforce roles outside this call path.".to_string()],
            });
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_write_without_owner_check_emits_candidate() {
        let ctx = Context::new().with_file("api.mjs", "function updateUser(id, params) { db.save(id, params); }");
        let obs = analyze(&ctx);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].rule_id, "authorization.object-write.missing-owner-check");
        assert_eq!(obs[0].severity_hint, "high");
    }

    #[test]
    fn object_write_with_owner_check_is_suppressed() {
        let ctx = Context::new()
            .with_file("api.mjs", "function updateUser(id, params) { if (!canAccess(id)) throw x; db.save(id, params); }");
        assert!(analyze(&ctx).is_empty());
    }

    #[test]
    fn privileged_function_without_role_check_emits_candidate() {
        let ctx = Context::new().with_file("admin.mjs", "function deleteUser(id) { db.remove(id); }");
        let obs = analyze(&ctx);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].rule_id, "authorization.privileged-function.missing-role-check");
    }

    #[test]
    fn privileged_function_with_role_check_is_suppressed() {
        let ctx = Context::new()
            .with_file("admin.mjs", "function deleteUser(id) { requireAdmin(); db.remove(id); }");
        assert!(analyze(&ctx).is_empty());
    }

    #[test]
    fn both_rules_can_fire_on_the_same_file() {
        let ctx = Context::new().with_file(
            "admin.mjs",
            "function updateAccount(id, params) { db.set(id, params); }\nfunction promoteUser(id) { db.grant(id); }",
        );
        let obs = analyze(&ctx);
        assert_eq!(obs.len(), 2);
    }
}
