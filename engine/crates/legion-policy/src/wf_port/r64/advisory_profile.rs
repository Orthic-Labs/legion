//! Port of `src/lib/verification/arcane/advisory-profile.mjs`
//! (`compileAdvisoryProfile`, `requireCanonicalAdvisoryProfile`).
//!
//! GAP: the JS reads the manifest file directly (`readFileSync` under
//! `manifestRoot`) and validates it with `validateSkillBundle` from
//! `src/lib/skills/contracts.mjs` — file I/O and a sibling module outside
//! this packet's file list. Both are taken as injected traits
//! (`ManifestSource`, `SkillBundleValidator`) rather than hard-wired, same
//! pattern as packet Q4's `completion_evidence` treating its unported
//! collaborators as trait objects. All decision logic — id-grammar
//! validation, manifest/bundle-id agreement, profile shape validation, the
//! exact digest domains, and the canonical-binding equality check in
//! `require_canonical_advisory_profile` — is ported byte-for-byte.

use legion_contracts::canonical::{canonical_digest, canonical_json_bytes};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct ProfileError {
    pub code: &'static str, // always "ARC_PROFILE_BINDING_MISMATCH", mirroring JS `fail()`
    pub message: String,
    pub detail: Value,
}

fn fail<T>(message: impl Into<String>, detail: Value) -> Result<T, ProfileError> {
    Err(ProfileError { code: "ARC_PROFILE_BINDING_MISMATCH", message: message.into(), detail })
}

/// Mirrors JS `ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/`.
fn is_valid_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut prev_dash = false;
    for (i, c) in s.char_indices() {
        if c == '-' {
            if i == 0 || prev_dash {
                return false;
            }
            prev_dash = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            prev_dash = false;
        } else {
            return false;
        }
    }
    !prev_dash
}

/// Injected in place of `readFileSync(resolve(manifestRoot, bundleId+'.json'))`.
pub trait ManifestSource {
    /// Returns the parsed JSON manifest for `bundle_id`, or `None` if it
    /// cannot be read/parsed (JS: `try { ... } catch { fail(...) }`).
    fn load(&self, bundle_id: &str) -> Option<Value>;
}

/// Injected in place of `validateSkillBundle` (`src/lib/skills/contracts.mjs`).
pub trait SkillBundleValidator {
    /// `Ok(())` mirrors the JS function returning without throwing;
    /// `Err(message)` mirrors it throwing.
    fn validate(&self, manifest: &Value) -> Result<(), String>;
}

fn digest_value(v: &Value) -> String {
    canonical_digest(v).expect("advisory manifest/profile must be canonicalizable")
}

fn canonical_json_string(v: &Value) -> Vec<u8> {
    canonical_json_bytes(v).expect("advisory binding must be canonicalizable")
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryProfileBinding {
    pub schema_version: i64,
    pub kind: &'static str,
    pub bundle_id: String,
    pub bundle_version: Value,
    pub profile_id: String,
    pub manifest_digest: String,
    pub profile_digest: String,
    pub mutation_allowed: bool,
    pub publish_allowed: bool,
    pub external_only: bool,
}

impl AdvisoryProfileBinding {
    /// The exact JSON shape `canonicalJson(binding)` compares against in
    /// `requireCanonicalAdvisoryProfile`.
    pub fn to_json(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "bundleId": self.bundle_id,
            "bundleVersion": self.bundle_version,
            "profileId": self.profile_id,
            "manifestDigest": self.manifest_digest,
            "profileDigest": self.profile_digest,
            "mutationAllowed": self.mutation_allowed,
            "publishAllowed": self.publish_allowed,
            "externalOnly": self.external_only,
        })
    }
}

/// Mirrors JS `compileAdvisoryProfile({ bundleId, profileId })`
/// (`manifestRoot` is folded into the injected `ManifestSource`).
pub fn compile_advisory_profile(
    bundle_id: &str,
    profile_id: &str,
    manifests: &dyn ManifestSource,
    validator: &dyn SkillBundleValidator,
) -> Result<AdvisoryProfileBinding, ProfileError> {
    if !is_valid_id(bundle_id) || !is_valid_id(profile_id) {
        return fail("invalid advisory bundle or profile id", json!({}));
    }
    let manifest = match manifests.load(bundle_id) {
        Some(m) => m,
        None => return fail("canonical advisory manifest is unavailable", json!({"bundleId": bundle_id})),
    };
    if let Err(cause) = validator.validate(&manifest) {
        return fail("canonical advisory manifest is invalid", json!({"bundleId": bundle_id, "cause": cause}));
    }
    let manifest_id = manifest.get("id").and_then(Value::as_str);
    if manifest_id != Some(bundle_id) {
        return fail(
            "canonical advisory manifest id differs",
            json!({"bundleId": bundle_id, "actual": manifest_id}),
        );
    }
    let profile = manifest.get("profiles").and_then(|p| p.get(profile_id));
    let (mutation, publish) = match profile {
        Some(p) => (p.get("mutation").and_then(Value::as_bool), p.get("publish").and_then(Value::as_bool)),
        None => (None, None),
    };
    let (mutation, publish) = match (mutation, publish) {
        (Some(m), Some(p)) => (m, p),
        _ => return fail("canonical advisory profile is invalid", json!({"bundleId": bundle_id, "profileId": profile_id})),
    };
    let external_only = profile
        .and_then(|p| p.get("externalOnly"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let bundle_version = manifest.get("version").cloned().unwrap_or(Value::Null);

    let manifest_digest = digest_value(&manifest);
    let profile_digest = digest_value(&json!({
        "domain": "arcane.advisory-profile.v1",
        "values": [bundle_id, bundle_version, profile_id, profile],
    }));

    Ok(AdvisoryProfileBinding {
        schema_version: 1,
        kind: "arcane-advisory-profile-binding",
        bundle_id: bundle_id.to_string(),
        bundle_version,
        profile_id: profile_id.to_string(),
        manifest_digest,
        profile_digest,
        mutation_allowed: mutation,
        publish_allowed: publish,
        external_only,
    })
}

/// Mirrors JS `requireCanonicalAdvisoryProfile(binding, options)`.
/// `Ok(None)` mirrors `binding == null` returning `null`.
pub fn require_canonical_advisory_profile(
    binding: Option<&Value>,
    manifests: &dyn ManifestSource,
    validator: &dyn SkillBundleValidator,
) -> Result<Option<AdvisoryProfileBinding>, ProfileError> {
    let binding = match binding {
        None => return Ok(None),
        Some(b) => b,
    };
    if !binding.is_object() {
        return fail("advisory profile binding must be an object", json!({}));
    }
    let bundle_id = binding.get("bundleId").and_then(Value::as_str).unwrap_or("");
    let profile_id = binding.get("profileId").and_then(Value::as_str).unwrap_or("");
    let canonical = compile_advisory_profile(bundle_id, profile_id, manifests, validator)?;
    if canonical_json_string(binding) != canonical_json_string(&canonical.to_json()) {
        return fail(
            "advisory profile binding differs from canonical package manifest",
            json!({"bundleId": bundle_id, "profileId": profile_id}),
        );
    }
    Ok(Some(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FakeManifests(BTreeMap<&'static str, Value>);
    impl ManifestSource for FakeManifests {
        fn load(&self, bundle_id: &str) -> Option<Value> {
            self.0.get(bundle_id).cloned()
        }
    }
    struct AlwaysValid;
    impl SkillBundleValidator for AlwaysValid {
        fn validate(&self, _manifest: &Value) -> Result<(), String> {
            Ok(())
        }
    }

    fn manifest() -> Value {
        json!({
            "id": "review-bundle",
            "version": "1.0.0",
            "profiles": {
                "audit": {"mutation": false, "publish": false},
            },
        })
    }

    #[test]
    fn invalid_id_grammar_fails() {
        let manifests = FakeManifests(BTreeMap::new());
        let err = compile_advisory_profile("Not_Valid", "audit", &manifests, &AlwaysValid).unwrap_err();
        assert_eq!(err.code, "ARC_PROFILE_BINDING_MISMATCH");
    }

    #[test]
    fn missing_manifest_fails() {
        let manifests = FakeManifests(BTreeMap::new());
        let err = compile_advisory_profile("review-bundle", "audit", &manifests, &AlwaysValid).unwrap_err();
        assert!(err.message.contains("unavailable"));
    }

    #[test]
    fn valid_manifest_compiles_and_digests() {
        let mut m = BTreeMap::new();
        m.insert("review-bundle", manifest());
        let manifests = FakeManifests(m);
        let binding = compile_advisory_profile("review-bundle", "audit", &manifests, &AlwaysValid).unwrap();
        assert!(!binding.mutation_allowed);
        assert!(!binding.publish_allowed);
        assert!(binding.manifest_digest.starts_with("sha256:"));
        assert!(binding.profile_digest.starts_with("sha256:"));
    }

    #[test]
    fn canonical_binding_round_trips() {
        let mut m = BTreeMap::new();
        m.insert("review-bundle", manifest());
        let manifests = FakeManifests(m);
        let compiled = compile_advisory_profile("review-bundle", "audit", &manifests, &AlwaysValid).unwrap();
        let as_binding = compiled.to_json();
        let result = require_canonical_advisory_profile(Some(&as_binding), &manifests, &AlwaysValid).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn tampered_binding_is_rejected() {
        let mut m = BTreeMap::new();
        m.insert("review-bundle", manifest());
        let manifests = FakeManifests(m);
        let compiled = compile_advisory_profile("review-bundle", "audit", &manifests, &AlwaysValid).unwrap();
        let mut tampered = compiled.to_json();
        tampered["mutationAllowed"] = json!(true);
        let err = require_canonical_advisory_profile(Some(&tampered), &manifests, &AlwaysValid).unwrap_err();
        assert!(err.message.contains("differs"));
    }

    #[test]
    fn null_binding_returns_none() {
        let manifests = FakeManifests(BTreeMap::new());
        let result = require_canonical_advisory_profile(None, &manifests, &AlwaysValid).unwrap();
        assert!(result.is_none());
    }
}
