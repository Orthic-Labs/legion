//! Deterministic explicit-invocation resolver (M-018).
//!
//! Ported from `src/lib/skills/resolver.mjs`.
//!
//! Natural-language semantic classification is NOT performed here: it is the
//! always-on Legion orchestration model's job, over the compact canonical
//! catalog in context. This module only resolves explicit slash commands and
//! aliases deterministically, and validates that the selected canonical id is
//! packaged and available.
//!
//! The JS original defaults `root` to `resolve(import.meta.dirname,
//! '../../..')` (the package root, from `src/lib/skills/resolver.mjs`).
//! Rust has no equivalent implicit module-relative default, so every
//! function here takes `root` explicitly; callers pass the package root.

use crate::l5_skills::contracts::validate_skill_bundle;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

static COMMAND: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^/([a-z][a-z0-9-]*)(?:\s|$)").unwrap());

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationResolution {
    NotExplicitCommand,
    AliasCycle {
        requested: String,
    },
    NotFound {
        requested: String,
        canonical: Option<String>,
    },
    Resolved {
        requested: String,
        canonical: String,
        argument_text: String,
        resolved_invocation: String,
        manifest_path: String,
        manifest: Value,
    },
}

/// Port of `resolveSkillInvocation`.
pub fn resolve_skill_invocation(input: &str, root: &Path) -> Result<InvocationResolution, String> {
    let text = input.trim();
    let Some(captures) = COMMAND.captures(text) else {
        return Ok(InvocationResolution::NotExplicitCommand);
    };
    let command = &captures[1];
    let requested = format!("/{command}");
    let supplied_arguments = text[captures[0].len()..].trim().to_string();

    let aliases_doc = read_json(&root.join("src/config/capability-aliases.json"))?;
    let aliases = aliases_doc.get("aliases").and_then(Value::as_object).cloned().unwrap_or_default();

    let mut target = requested.clone();
    let mut alias_arguments = String::new();
    let mut seen = BTreeSet::new();
    loop {
        let Some(declaration) = aliases.get(&target).and_then(Value::as_str) else {
            break;
        };
        if !declaration.starts_with('/') {
            break;
        }
        if seen.contains(&target) {
            return Ok(InvocationResolution::AliasCycle { requested });
        }
        seen.insert(target.clone());
        let declaration = declaration.trim();
        let next_target = declaration.split_whitespace().next().unwrap_or(declaration).to_string();
        let declared_arguments = declaration[next_target.len()..].trim().to_string();
        alias_arguments = [declared_arguments, alias_arguments]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        target = next_target;
    }

    let canonical = target.trim_start_matches('/').to_string();
    let index = read_json(&root.join("src/registry/skills/index.json"))?;
    let bundles = index.get("bundles").and_then(Value::as_array).cloned().unwrap_or_default();
    let Some(record) = bundles.iter().find(|b| b.get("id").and_then(Value::as_str) == Some(canonical.as_str())) else {
        return Ok(InvocationResolution::NotFound { requested, canonical: Some(canonical) });
    };
    let manifest_path = record.get("manifest").and_then(Value::as_str).unwrap_or("").to_string();
    let manifest_doc = read_json(&root.join(&manifest_path))?;
    let manifest = validate_skill_bundle(&manifest_doc).map_err(|error| error.to_string())?.clone();

    let argument_text = [alias_arguments, supplied_arguments]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let resolved_invocation = if argument_text.is_empty() {
        target.clone()
    } else {
        format!("{target} {argument_text}")
    };

    Ok(InvocationResolution::Resolved {
        requested,
        canonical,
        argument_text,
        resolved_invocation,
        manifest_path,
        manifest,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionSource {
    Semantic,
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionInvalid {
    pub id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionResolved {
    pub id: String,
    pub manifest_path: String,
    pub manifest: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionResolution {
    pub status: &'static str, // "resolved" | "invalid"
    pub source: SelectionSource,
    pub resolved: Vec<SelectionResolved>,
    pub invalid: Vec<SelectionInvalid>,
}

/// Port of `validateCapabilitySelection`. Accepts an already-produced
/// selection — never raw natural language. The semantic classifier is the
/// Legion orchestration model; this runtime validates the selected ids.
pub fn validate_capability_selection(
    ids: &[String],
    source: SelectionSource,
    root: &Path,
) -> Result<SelectionResolution, String> {
    let index = read_json(&root.join("src/registry/skills/index.json"))?;
    let bundles = index.get("bundles").and_then(Value::as_array).cloned().unwrap_or_default();

    let mut resolved = Vec::new();
    let mut invalid = Vec::new();
    for id in ids {
        let Some(record) = bundles.iter().find(|b| b.get("id").and_then(Value::as_str) == Some(id.as_str())) else {
            invalid.push(SelectionInvalid { id: id.clone(), reason: "not-found" });
            continue;
        };
        if matches!(source, SelectionSource::Semantic) {
            if record.get("kind").and_then(Value::as_str) != Some("capability") {
                invalid.push(SelectionInvalid { id: id.clone(), reason: "not-capability" });
                continue;
            }
            if record.get("discoverability").and_then(Value::as_str) != Some("public") {
                invalid.push(SelectionInvalid { id: id.clone(), reason: "not-public" });
                continue;
            }
        }
        let manifest_path = record.get("manifest").and_then(Value::as_str).unwrap_or("").to_string();
        let manifest_doc = read_json(&root.join(&manifest_path))?;
        let manifest = validate_skill_bundle(&manifest_doc).map_err(|error| error.to_string())?.clone();
        resolved.push(SelectionResolved { id: id.clone(), manifest_path, manifest });
    }

    Ok(SelectionResolution {
        status: if invalid.is_empty() { "resolved" } else { "invalid" },
        source,
        resolved,
        invalid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::w2_056::test_support::TempDir;
    use serde_json::json;
    use std::fs;

    /// Contract-complete manifest for `id`: satisfies every field
    /// `l5_skills::contracts::validate_skill_bundle` requires (schema
    /// version, rights receipt, root URI, audit/authoring profile shape,
    /// and the entry file being declared), which `validate_capability_selection`
    /// applies to every manifest exactly as `resolver.mjs` does.
    fn valid_manifest(id: &str) -> Value {
        json!({
            "schemaVersion": 1, "id": id, "version": "1.0.0", "entry": "SKILL.md",
            "provenance": {}, "licenseState": "public-domain",
            "rightsReceipt": { "kind": "public-domain" },
            "rootUri": format!("legion-skill://{id}/"),
            "profiles": {
                "audit": {"mutation": false, "publish": false},
                "authoring": {"mutation": true, "publish": true},
            },
            "files": [
                {
                    "path": "SKILL.md",
                    "uri": format!("legion-skill://{id}/SKILL.md"),
                    "digest": format!("sha256:{}", "a".repeat(64)),
                },
            ],
        })
    }

    fn scaffold() -> TempDir {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("src/config")).unwrap();
        fs::create_dir_all(dir.path().join("src/registry/skills")).unwrap();
        fs::create_dir_all(dir.path().join("skills/foo")).unwrap();
        fs::write(
            dir.path().join("src/config/capability-aliases.json"),
            json!({"aliases": {"/f": "/foo", "/loop": "/loop"}}).to_string(),
        )
        .unwrap();
        fs::write(
            dir.path().join("src/registry/skills/index.json"),
            json!({"bundles": [{"id": "foo", "manifest": "skills/foo/manifest.json"}]}).to_string(),
        )
        .unwrap();
        fs::write(dir.path().join("skills/foo/manifest.json"), valid_manifest("foo").to_string()).unwrap();
        dir
    }

    #[test]
    fn not_explicit_command() {
        let dir = scaffold();
        let result = resolve_skill_invocation("just some text", dir.path()).unwrap();
        assert_eq!(result, InvocationResolution::NotExplicitCommand);
    }

    #[test]
    fn resolves_direct_command() {
        let dir = scaffold();
        let result = resolve_skill_invocation("/foo hello world", dir.path()).unwrap();
        match result {
            InvocationResolution::Resolved { canonical, argument_text, resolved_invocation, .. } => {
                assert_eq!(canonical, "foo");
                assert_eq!(argument_text, "hello world");
                assert_eq!(resolved_invocation, "/foo hello world");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn resolves_through_alias() {
        let dir = scaffold();
        let result = resolve_skill_invocation("/f arg1", dir.path()).unwrap();
        match result {
            InvocationResolution::Resolved { requested, canonical, argument_text, .. } => {
                assert_eq!(requested, "/f");
                assert_eq!(canonical, "foo");
                assert_eq!(argument_text, "arg1");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn detects_alias_cycle() {
        let dir = scaffold();
        let result = resolve_skill_invocation("/loop", dir.path()).unwrap();
        assert_eq!(result, InvocationResolution::AliasCycle { requested: "/loop".to_string() });
    }

    #[test]
    fn not_found_when_uncatalogued() {
        let dir = scaffold();
        let result = resolve_skill_invocation("/nope", dir.path()).unwrap();
        assert_eq!(
            result,
            InvocationResolution::NotFound { requested: "/nope".to_string(), canonical: Some("nope".to_string()) }
        );
    }

    #[test]
    fn validate_selection_semantic_rejects_non_public_non_capability() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("src/registry/skills")).unwrap();
        fs::create_dir_all(dir.path().join("skills/a")).unwrap();
        fs::create_dir_all(dir.path().join("skills/b")).unwrap();
        fs::write(
            dir.path().join("src/registry/skills/index.json"),
            json!({"bundles": [
                {"id": "a", "kind": "capability", "discoverability": "public", "manifest": "skills/a/manifest.json"},
                {"id": "b", "kind": "entrypoint", "discoverability": "public", "manifest": "skills/b/manifest.json"},
            ]})
            .to_string(),
        )
        .unwrap();
        fs::write(dir.path().join("skills/a/manifest.json"), valid_manifest("a").to_string()).unwrap();
        fs::write(dir.path().join("skills/b/manifest.json"), valid_manifest("b").to_string()).unwrap();

        let ids = vec!["a".to_string(), "b".to_string(), "missing".to_string()];
        let result = validate_capability_selection(&ids, SelectionSource::Semantic, dir.path()).unwrap();
        assert_eq!(result.status, "invalid");
        assert_eq!(result.resolved.len(), 1);
        assert_eq!(result.resolved[0].id, "a");
        assert_eq!(result.invalid.len(), 2);
        assert!(result.invalid.iter().any(|i| i.id == "b" && i.reason == "not-capability"));
        assert!(result.invalid.iter().any(|i| i.id == "missing" && i.reason == "not-found"));
    }

    #[test]
    fn validate_selection_explicit_skips_kind_checks() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("src/registry/skills")).unwrap();
        fs::create_dir_all(dir.path().join("skills/b")).unwrap();
        fs::write(
            dir.path().join("src/registry/skills/index.json"),
            json!({"bundles": [
                {"id": "b", "kind": "entrypoint", "discoverability": "explicit", "manifest": "skills/b/manifest.json"},
            ]})
            .to_string(),
        )
        .unwrap();
        fs::write(dir.path().join("skills/b/manifest.json"), valid_manifest("b").to_string()).unwrap();
        let result = validate_capability_selection(&["b".to_string()], SelectionSource::Explicit, dir.path()).unwrap();
        assert_eq!(result.status, "resolved");
        assert_eq!(result.resolved.len(), 1);
    }
}
