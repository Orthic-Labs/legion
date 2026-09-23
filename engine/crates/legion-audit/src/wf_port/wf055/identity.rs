//! Port of `src/providers/security/model-extractors/identity.mjs`.
//!
//! Identity extractor per Security Appendix §11.3: auth middleware/guards,
//! role/permission checks, session/token creation, service accounts,
//! OAuth/SAML callbacks, tenant identifiers, approval controls.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

use crate::wf_port::wf052::contracts::stable_id;
use crate::wf_port::wf055::common::{entity, relation};

static AUTH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)auth|session|jwt|oauth|saml|passport|getServerSession|login_required|requireAuth|middleware")
        .expect("valid regex")
});

static TENANT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)tenant|workspace|org_?id|company_id").expect("valid regex")
});

/// Result shape mirroring the JS extractor's
/// `{ entities, relations, evidence, initialFacts, coverageGaps }` return.
#[derive(Default, Clone)]
pub struct IdentityExtraction {
    pub entities: Vec<Value>,
    pub relations: Vec<Value>,
    pub evidence: Vec<Value>,
    pub initial_facts: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
}

/// Port of `extractIdentity({ root, plan, projection, files, lensRegistry })`.
///
/// `files` is `(path, source_text)` pairs standing in for the JS
/// `files` array plus `projection.sourceText[file]` lookup (this chunk owns
/// no projection/plan Rust type, so the caller supplies text directly, as
/// wf052's ported files do for their own upstream inputs).
pub fn extract_identity(files: &[(String, String)]) -> IdentityExtraction {
    let mut out = IdentityExtraction::default();

    for (file, text) in files {
        if text.is_empty() {
            continue;
        }
        if AUTH_PATTERN.is_match(text) {
            let evidence_ref = stable_id("identity-evidence", &json!({ "file": file }));
            let control = entity(
                "control",
                &format!("auth control {file}"),
                json!({ "controlType": "authentication" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let principal = entity(
                "principal",
                &format!("authenticated principal {file}"),
                json!({ "environment": "application" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let control_id = control["id"].as_str().unwrap_or_default().to_string();
            out.entities.push(control);
            out.entities.push(principal);

            let scope_from = stable_id("identity-scope", &json!({ "file": file }));
            out.relations.push(relation(
                "protected-by",
                &scope_from,
                &control_id,
                &[evidence_ref.clone()],
                json!({}),
                Some("observed"),
                None,
            ));
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Identity control",
            }));
        }
        if TENANT_PATTERN.is_match(text) {
            let evidence_ref = stable_id("tenant-evidence", &json!({ "file": file }));
            let boundary = entity(
                "trust-boundary",
                &format!("tenant boundary {file}"),
                json!({ "boundaryType": "tenant" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            out.entities.push(boundary);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Tenant boundary",
            }));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_entities() {
        let out = extract_identity(&[]);
        assert!(out.entities.is_empty());
        assert!(out.relations.is_empty());
        assert!(out.evidence.is_empty());
        assert!(out.coverage_gaps.is_empty());
        assert!(out.initial_facts.is_empty());
    }

    #[test]
    fn empty_source_text_is_skipped() {
        let out = extract_identity(&[("src/foo.js".into(), String::new())]);
        assert!(out.entities.is_empty());
    }

    #[test]
    fn auth_marker_produces_control_and_principal_with_protected_by_relation() {
        let out = extract_identity(&[(
            "src/middleware/auth.js".into(),
            "export function requireAuth(req, res, next) { /* jwt check */ }".into(),
        )]);
        assert_eq!(out.entities.len(), 2);
        let control = out
            .entities
            .iter()
            .find(|e| e["kind"] == "control")
            .expect("control entity present");
        assert_eq!(control["attributes"]["controlType"], "authentication");
        assert_eq!(control["name"], "auth control src/middleware/auth.js");
        let principal = out
            .entities
            .iter()
            .find(|e| e["kind"] == "principal")
            .expect("principal entity present");
        assert_eq!(principal["attributes"]["environment"], "application");

        assert_eq!(out.relations.len(), 1);
        assert_eq!(out.relations[0]["kind"], "protected-by");
        assert_eq!(out.relations[0]["to"], control["id"]);

        assert_eq!(out.evidence.len(), 1);
        assert_eq!(out.evidence[0]["description"], "Identity control");
    }

    #[test]
    fn tenant_marker_produces_trust_boundary_only() {
        let out = extract_identity(&[(
            "src/db/scope.js".into(),
            "const tenantId = req.headers['x-tenant-id'];".into(),
        )]);
        assert_eq!(out.entities.len(), 1);
        assert_eq!(out.entities[0]["kind"], "trust-boundary");
        assert_eq!(out.entities[0]["attributes"]["boundaryType"], "tenant");
        assert!(out.relations.is_empty());
    }

    #[test]
    fn both_markers_in_one_file_produce_three_entities() {
        let out = extract_identity(&[(
            "src/handlers/org.js".into(),
            "requireAuth(); const orgId = session.orgId;".into(),
        )]);
        // auth control + principal + tenant boundary
        assert_eq!(out.entities.len(), 3);
    }

    #[test]
    fn no_markers_yields_nothing_for_that_file() {
        let out = extract_identity(&[("src/utils/math.js".into(), "export const add = (a, b) => a + b;".into())]);
        assert!(out.entities.is_empty());
        assert!(out.evidence.is_empty());
    }

    #[test]
    fn extraction_is_deterministic_across_runs() {
        let files = vec![("src/a.js".into(), "requireAuth".to_string())];
        let out1 = extract_identity(&files);
        let out2 = extract_identity(&files);
        assert_eq!(out1.entities, out2.entities);
        assert_eq!(out1.relations, out2.relations);
    }
}
