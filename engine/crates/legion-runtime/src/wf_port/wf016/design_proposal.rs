//! Port of `src/lib/remediation/design-proposal.mjs`.
//!
//! Designer remediation proposals (B7-032). Layout, style, and assets
//! only — and every approved text digest the packet declared must come
//! back unchanged, so a visual fix can never quietly reword the product.
//!
//! `design-proposal.mjs` imports `reasoningProposal` from
//! `./reasoning-packets.mjs`, which is **not** part of this chunk (wf016
//! owns only `design-proposal.mjs`, `effect-graph.mjs`, `fix-contract.mjs`,
//! `mechanical.mjs`, and `producers/config.mjs`) and has no native coverage
//! yet — it itself depends on `../review/untrusted-evidence-envelope.mjs`
//! (`wrapUntrustedEvidence`/`detectOverrideAttempts`), further outside this
//! chunk. [`reasoning_proposal_scaffold`] below is a faithful port of only
//! `reasoningProposal`'s own body-construction logic (the part
//! `designProposal` actually calls through to), taking the packet's
//! already-built `owner`/`findingIds`/`producer`/`digest`/`scope` fields as
//! plain `serde_json::Value` input rather than reconstructing
//! `buildProposalPacket`'s full envelope/evidence machinery. Whoever ports
//! `reasoning-packets.mjs` for real should replace this scaffold with a call
//! into that port; the JSON shape produced here matches `reasoningProposal`'s
//! output exactly for the fields `designProposal` populates.

use serde_json::{json, Value};

use super::util::{digest_of, matches_glob};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct DesignProposalError(pub String);

impl std::fmt::Display for DesignProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Faithful port of `assertApprovedTextPreserved`.
fn assert_approved_text_preserved(packet: &Value, preserved_text_digests: &Value) -> Result<(), DesignProposalError> {
    let approved = packet.get("approvedTextDigests").and_then(Value::as_object);
    let Some(approved) = approved else { return Ok(()) };
    for (content_item_id, approved_digest) in approved {
        let returned = preserved_text_digests.get(content_item_id.as_str());
        if returned != Some(approved_digest) {
            return Err(DesignProposalError(format!(
                "approved text digest for {content_item_id} changed: a designer proposal may not alter approved text"
            )));
        }
    }
    Ok(())
}

/// Faithful port of `reasoningProposal`'s body construction, scoped to what
/// `designProposal` needs (see the module doc comment for what is
/// deliberately not reproduced here: `assertOwnerAuthority`/
/// `assertPathAllowed`'s full change-kind/protected-surface checks are
/// folded into the two checks below, matching what a `designer`-owner call
/// with `change.kind` always `'style'|'layout'|'asset'` actually exercises).
fn reasoning_proposal_scaffold(packet: &Value, owner: &str, changes: &[Value], binding: &Value, extra: Value) -> Result<Value, DesignProposalError> {
    let packet_owner = packet.get("owner").and_then(Value::as_str).unwrap_or_default();
    if packet_owner != owner {
        return Err(DesignProposalError(format!("packet owner {packet_owner} cannot produce a {owner} proposal")));
    }
    if changes.is_empty() {
        return Err(DesignProposalError("a proposal requires at least one change".to_string()));
    }
    let scope: Vec<String> = packet.get("scope").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
    let protected_surfaces: Vec<String> = packet
        .get("protectedSurfaces")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let mut target_paths: Vec<String> = Vec::new();
    for change in changes {
        let path = change.get("path").and_then(Value::as_str).unwrap_or_default();
        if protected_surfaces.iter().any(|pattern| matches_glob(pattern, path)) {
            return Err(DesignProposalError(format!("{path} is a protected surface in this packet")));
        }
        let allowed = scope.iter().any(|pattern| pattern == path || matches_glob(pattern, path));
        if !allowed {
            return Err(DesignProposalError(format!("{path} is outside the packet scope")));
        }
        if !target_paths.iter().any(|p| p == path) {
            target_paths.push(path.to_string());
        }
    }
    target_paths.sort();

    let finding_ids = packet.get("findingIds").cloned().unwrap_or(json!([]));
    let producer = packet.get("producer").cloned().unwrap_or(json!({}));
    let packet_digest = packet.get("digest").cloned().unwrap_or(Value::Null);

    let mut body = json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-proposal",
        "findingIds": finding_ids,
        "owner": owner,
        "producer": producer,
        "packetDigest": packet_digest,
        "targetPaths": target_paths,
        "preconditions": [format!("changes stay within packet scope {}", scope.join(", "))],
        "changes": changes,
        "patch": Value::Null,
        "expectedBehavior": Vec::<Value>::new(),
        "publicSurfaceChanges": Vec::<Value>::new(),
        "affectedFamilies": Vec::<Value>::new(),
        "validationPlan": Vec::<Value>::new(),
        "rollback": { "strategy": "restore-checkpoint", "checkpointRequired": true },
        "tier": "DESIGN",
        "binding": binding,
    });
    let body_obj = body.as_object_mut().expect("body is an object");
    if let Value::Object(extra_obj) = extra {
        for (k, v) in extra_obj {
            body_obj.insert(k, v);
        }
    }
    let id = digest_of("remediation-proposal", &body);
    body.as_object_mut().unwrap().insert("id".to_string(), Value::String(id));
    Ok(body)
}

/// Input to [`design_proposal`], mirroring the JS destructured parameter
/// object. `preserved_text_digests` defaults to `{}` like JS's `= {}`.
#[derive(Debug, Clone)]
pub struct DesignProposalInput {
    pub packet: Value,
    pub changes: Vec<Value>,
    pub preserved_text_digests: Value,
    pub binding: Value,
}

/// Faithful port of `designProposal`.
pub fn design_proposal(input: DesignProposalInput) -> Result<Value, DesignProposalError> {
    assert_approved_text_preserved(&input.packet, &input.preserved_text_digests)?;
    let preserved: Value = if let Value::Object(m) = &input.preserved_text_digests { Value::Object(m.clone()) } else { json!({}) };
    let extra = json!({
        "expectedBehavior": ["the named surfaces render as proposed with approved text intact"],
        "affectedFamilies": ["design", "ux", "visual"],
        "validationPlan": ["affected-provider-rerun:visual", "affected-provider-rerun:ux", "approved-text-digest-recheck"],
        "preservedTextDigests": preserved,
    });
    reasoning_proposal_scaffold(&input.packet, "designer", &input.changes, &input.binding, extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Value {
        json!({
            "owner": "designer",
            "findingIds": ["f1"],
            "producer": { "id": "designer-agent" },
            "digest": "sha256:packetdigest",
            "scope": ["src/ui/**"],
            "protectedSurfaces": [],
            "approvedTextDigests": { "hero-copy": "sha256:approved" },
        })
    }

    #[test]
    fn design_proposal_rejects_changed_approved_text() {
        let err = design_proposal(DesignProposalInput {
            packet: packet(),
            changes: vec![json!({ "kind": "style", "path": "src/ui/Hero.css" })],
            preserved_text_digests: json!({ "hero-copy": "sha256:different" }),
            binding: json!({ "runId": "r1" }),
        })
        .unwrap_err();
        assert!(err.0.contains("hero-copy"));
        assert!(err.0.contains("may not alter approved text"));
    }

    #[test]
    fn design_proposal_accepts_preserved_text_and_builds_proposal() {
        let proposal = design_proposal(DesignProposalInput {
            packet: packet(),
            changes: vec![json!({ "kind": "style", "path": "src/ui/Hero.css" })],
            preserved_text_digests: json!({ "hero-copy": "sha256:approved" }),
            binding: json!({ "runId": "r1" }),
        })
        .unwrap();
        assert_eq!(proposal["owner"], json!("designer"));
        assert_eq!(proposal["tier"], json!("DESIGN"));
        assert_eq!(proposal["targetPaths"], json!(["src/ui/Hero.css"]));
        assert_eq!(proposal["affectedFamilies"], json!(["design", "ux", "visual"]));
        assert_eq!(proposal["preservedTextDigests"], json!({ "hero-copy": "sha256:approved" }));
        assert!(proposal["id"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn design_proposal_rejects_path_outside_scope() {
        let err = design_proposal(DesignProposalInput {
            packet: packet(),
            changes: vec![json!({ "kind": "style", "path": "src/server/handler.rs" })],
            preserved_text_digests: json!({ "hero-copy": "sha256:approved" }),
            binding: json!({}),
        })
        .unwrap_err();
        assert!(err.0.contains("outside the packet scope"));
    }

    #[test]
    fn design_proposal_requires_at_least_one_change() {
        let err = design_proposal(DesignProposalInput {
            packet: packet(),
            changes: vec![],
            preserved_text_digests: json!({ "hero-copy": "sha256:approved" }),
            binding: json!({}),
        })
        .unwrap_err();
        assert_eq!(err.0, "a proposal requires at least one change");
    }

    #[test]
    fn design_proposal_rejects_owner_mismatch() {
        let mut mismatched = packet();
        mismatched["owner"] = json!("writing");
        let err = design_proposal(DesignProposalInput {
            packet: mismatched,
            changes: vec![json!({ "kind": "style", "path": "src/ui/Hero.css" })],
            preserved_text_digests: json!({ "hero-copy": "sha256:approved" }),
            binding: json!({}),
        })
        .unwrap_err();
        assert!(err.0.contains("cannot produce a designer proposal"));
    }
}
