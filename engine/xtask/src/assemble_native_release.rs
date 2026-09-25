//! Rust port of `scripts/assemble-native-release.mjs`.
//!
//! Ports the JS script's own logic plus what it calls out to:
//! - `@rightkit/ax/plugin/portable-core.mjs` -> `portable_core.rs` (this crate).
//! - `@rightkit/release/cargo-target.mjs` `resolveTargetRoot` -> `resolve_target_root`
//!   below (shells out to `cargo metadata`, same as the JS did).
//! - `right-release.config.mjs`'s `nativeAssembly` fields used here
//!   (`cargoManifest`, `defaultProfile`, `localProvenanceScheme`,
//!   `signedProvenanceScheme`) are static repo constants; the config module
//!   also derives per-target packaging paths not used by this script, so
//!   those constants are inlined here rather than re-parsing the JS module.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::portable_core::{
    assemble_portable_core, client_projection_kinds, validate_portable_core, AgentInput, AssembleParams, SkillInput,
};

const CARGO_MANIFEST_REL: &str = "engine/Cargo.toml";
const DEFAULT_PROFILE: &str = "release";
const LOCAL_PROVENANCE_SCHEME: &str = "local-build";
const SIGNED_PROVENANCE_SCHEME: &str = "rightkit-release";

#[derive(Debug, Clone)]
pub struct WindowsTarget {
    pub installer_architecture: &'static str,
    pub target_triple: &'static str,
}

fn windows_targets() -> Vec<(&'static str, WindowsTarget)> {
    vec![
        ("x86_64", WindowsTarget { installer_architecture: "x64", target_triple: "x86_64-pc-windows-msvc" }),
        ("arm64", WindowsTarget { installer_architecture: "arm64", target_triple: "aarch64-pc-windows-msvc" }),
    ]
}

fn architecture_alias(value: &str) -> Option<&'static str> {
    match value.to_lowercase().as_str() {
        "x64" | "amd64" | "x86_64" => Some("x86_64"),
        "arm64" | "aarch64" => Some("arm64"),
        _ => None,
    }
}

fn generic_token_re() -> Regex {
    Regex::new(r"^[a-z0-9][a-z0-9_.-]*$").unwrap()
}

pub fn normalize_platform(value: &str) -> Result<String, String> {
    let platform = value.trim().to_lowercase();
    match platform.as_str() {
        "win" | "windows" => Ok("windows".to_string()),
        "mac" | "macos" | "darwin" => Ok("macos".to_string()),
        _ if generic_token_re().is_match(&platform) => Ok(platform),
        _ => Err(format!("invalid release platform: {value}")),
    }
}

pub fn normalize_architecture(value: &str, platform: &str) -> Result<String, String> {
    let normalized = architecture_alias(value.trim());
    if platform == "windows" {
        return match normalized {
            Some(n) if windows_targets().iter().any(|(k, _)| *k == n) => Ok(n.to_string()),
            _ => Err(format!("unsupported Windows architecture: {value}; expected x86_64 or arm64")),
        };
    }
    if let Some(n) = normalized {
        return Ok(if platform == "macos" && n == "arm64" { "aarch64".to_string() } else { n.to_string() });
    }
    if value.trim().is_empty() {
        return Ok(match std::env::consts::ARCH {
            "x86_64" => "x86_64".to_string(),
            "aarch64" => "aarch64".to_string(),
            other => other.to_string(),
        });
    }
    if !generic_token_re().is_match(value) {
        return Err(format!("invalid release architecture: {value}"));
    }
    Ok(value.to_string())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

fn files_below(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(directory).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("release asset is symlink: {}", path.display()));
        }
        if meta.is_dir() {
            files_below(root, &path, output)?;
        } else if meta.is_file() {
            let rel = path.strip_prefix(root).unwrap();
            output.push(rel.to_string_lossy().replace('\\', "/"));
        } else {
            return Err(format!("release asset is not regular file: {}", path.display()));
        }
    }
    Ok(())
}

fn directory_sha256(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    files_below(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let bytes = fs::read(root.join(&path)).map_err(|e| e.to_string())?;
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value).unwrap())).map_err(|e| e.to_string())
}

fn excluded_skill_artifact(path: &str) -> bool {
    let lower = path.to_lowercase();
    let excluded_segments = ["__pycache__", ".audit", ".cache", ".workbuddy-ai"];
    lower.split('/').any(|seg| excluded_segments.contains(&seg)) || lower.ends_with(".pyc")
}

fn copy_skill_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    files_below(source, source, &mut files)?;
    files.sort();
    for path in files {
        if excluded_skill_artifact(&path) {
            continue;
        }
        let target = destination.join(path.split('/').collect::<PathBuf>());
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(source.join(path.split('/').collect::<PathBuf>()), &target).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn resolve_target_root(manifest_path: &Path) -> Result<PathBuf, String> {
    let cwd = manifest_path.parent().unwrap_or(Path::new("."));
    let output = Command::new("cargo")
        .args(["metadata", "--offline", "--format-version", "1", "--no-deps", "--manifest-path"])
        .arg(manifest_path)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("metadata failed for {}: {e}", manifest_path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "metadata failed for {}: {}",
            manifest_path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let parsed: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let directory = parsed
        .get("target_directory")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && Path::new(s).is_absolute())
        .ok_or_else(|| format!("metadata for {} did not report an absolute target_directory", manifest_path.display()))?;
    Ok(PathBuf::from(directory))
}

pub struct AssembleArgs {
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub profile: Option<String>,
    pub target: Option<String>,
    pub bin_dir: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub force: bool,
    pub finalize_signed: bool,
    pub provenance: Option<String>,
}

/// Rust port of `assemble-native-release.mjs`'s top-level script.
pub fn run(repository_root: &Path, args: AssembleArgs) -> Result<Value, String> {
    let host_platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let platform = normalize_platform(args.platform.as_deref().unwrap_or(host_platform))?;

    let arch_input = args.architecture.clone().unwrap_or_else(|| {
        if platform == "windows" {
            std::env::var("LEGION_WINDOWS_ARCH").unwrap_or_else(|_| "x86_64".to_string())
        } else {
            String::new()
        }
    });
    let architecture = normalize_architecture(&arch_input, &platform)?;

    let explicit_windows_architecture =
        platform == "windows" && (args.architecture.is_some() || std::env::var("LEGION_WINDOWS_ARCH").is_ok());
    if platform == "windows" && host_platform != "windows" && !explicit_windows_architecture {
        return Err("cross-building Windows requires explicit --architecture x86_64 or arm64".to_string());
    }

    let windows_target = if platform == "windows" {
        windows_targets().into_iter().find(|(k, _)| *k == architecture).map(|(_, v)| v)
    } else {
        None
    };
    let executable_suffix = if windows_target.is_some() { ".exe" } else { "" };

    let version_record: Value = serde_json::from_str(
        &fs::read_to_string(repository_root.join("release/version.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if version_record.get("schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || version_record.get("kind").and_then(|v| v.as_str()) != Some("legion-release-version")
        || version_record.get("version").and_then(|v| v.as_str()).is_none()
    {
        return Err(format!(
            "invalid release version record: {}",
            repository_root.join("release/version.json").display()
        ));
    }
    let release_version = version_record["version"].as_str().unwrap().to_string();

    let cargo_manifest = repository_root.join(CARGO_MANIFEST_REL);
    let profile = args.profile.clone().unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    if !generic_profile_re().is_match(&profile) {
        return Err(format!("invalid Cargo profile: {profile}"));
    }

    let requested_cargo_target = args.target.clone().or_else(|| std::env::var("CARGO_BUILD_TARGET").ok());
    let cargo_target = if let Some(wt) = &windows_target {
        if explicit_windows_architecture || requested_cargo_target.is_some() {
            Some(wt.target_triple.to_string())
        } else {
            requested_cargo_target.clone()
        }
    } else {
        requested_cargo_target.clone()
    };
    let target_triple = windows_target.as_ref().map(|w| w.target_triple.to_string()).or_else(|| cargo_target.clone());
    if let Some(ct) = &cargo_target {
        if !generic_token_re().is_match(ct) {
            return Err(format!("invalid Cargo target: {ct}"));
        }
    }
    if let (Some(wt), Some(req)) = (&windows_target, &requested_cargo_target) {
        if req != wt.target_triple {
            return Err(format!(
                "Windows target identity mismatch: architecture {architecture} requires {}, received {req}",
                wt.target_triple
            ));
        }
    }

    let bin_directory = match &args.bin_dir {
        Some(dir) => dir.canonicalize().unwrap_or_else(|_| dir.clone()),
        None => {
            let mut dir = resolve_target_root(&cargo_manifest)?;
            if let Some(ct) = &cargo_target {
                dir.push(ct);
            }
            dir.push(&profile);
            dir
        }
    };

    let output = args.out.clone().unwrap_or_else(|| {
        repository_root
            .join("dist")
            .join("native")
            .join(format!("{platform}-{architecture}"))
            .join(format!("legion-{release_version}"))
    });
    let force = args.force;
    let finalize_signed = args.finalize_signed;

    if output.exists() {
        if !force && !finalize_signed {
            return Err(format!("release output exists: {}; pass --force to replace exact output", output.display()));
        }
        if !finalize_signed {
            fs::remove_dir_all(&output).map_err(|e| e.to_string())?;
        }
    } else if finalize_signed {
        return Err(format!("signed release output missing: {}", output.display()));
    }

    let binary_names: Vec<String> =
        ["legion", "legion-hook", "legion-mcp"].iter().map(|name| format!("{name}{executable_suffix}")).collect();
    for name in &binary_names {
        let source = if finalize_signed { output.join("bin").join(name) } else { bin_directory.join(name) };
        if !source.exists() {
            return Err(format!("release binary missing: {}", source.display()));
        }
        if !finalize_signed {
            fs::create_dir_all(output.join("bin")).map_err(|e| e.to_string())?;
            fs::copy(&source, output.join("bin").join(name)).map_err(|e| e.to_string())?;
        }
    }

    let share = output.join("share").join("legion");
    let assets = share.join("assets");
    let catalog_path = assets.join("registry").join("index.json");
    let provider_registry_path = assets.join("registry").join("providers.json");
    let schema_path = assets.join("schemas").join("mcp-tools.schema.json");
    let policy_path = assets.join("policy").join("arcane-m1-policy.json");
    let native_rule_manifest_path = assets.join("packs").join("native").join("manifest.v1.json");
    fs::create_dir_all(catalog_path.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::copy(repository_root.join("src/registry/skills/index.json"), &catalog_path).map_err(|e| e.to_string())?;
    fs::copy(repository_root.join("src/registry/providers.json"), &provider_registry_path).map_err(|e| e.to_string())?;
    copy_skill_tree(&repository_root.join("skills"), &assets.join("skills"))?;
    fs::create_dir_all(native_rule_manifest_path.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::copy(repository_root.join("packs/native/manifest.v1.json"), &native_rule_manifest_path).map_err(|e| e.to_string())?;

    let mcp_tool_schema = json!({
        "schemaVersion": 1,
        "kind": "legion-mcp-tool-schema",
        "tools": [
            {
                "name": "legion_m1_status",
                "inputSchema": { "type": "object", "required": [], "additionalProperties": false, "properties": {} }
            },
            {
                "name": "legion_m1_invoke",
                "inputSchema": {
                    "type": "object",
                    "required": ["capabilityId", "policyContext"],
                    "additionalProperties": false,
                    "properties": {
                        "capabilityId": { "type": "string", "minLength": 1 },
                        "policyContext": {}
                    }
                }
            }
        ]
    });
    write_json(&schema_path, &mcp_tool_schema)?;

    let source_policy: Value = serde_json::from_str(
        &fs::read_to_string(repository_root.join("src/lib/guard/compat/policy/arcane-policy-v1.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let effect_rules: Vec<Value> = source_policy
        .get("effectRules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|rule| {
            let effect_class = rule.get("effectClass").and_then(|v| v.as_str()).unwrap_or_default();
            json!({
                "schema_version": 1,
                "id": format!("installed-m1-{}", effect_class.to_lowercase().replace('_', "-")),
                "effect_class": effect_class,
                "rule": rule.get("rule").cloned().unwrap_or(Value::Null),
                "predicate": { "effect_class": effect_class },
                "approval_required": rule.get("approvalRequired").and_then(|v| v.as_bool()).unwrap_or(false),
                "trust_minimum": rule.get("trustMinimum").and_then(|v| v.as_str()).unwrap_or("capability-signature"),
                "required_enforcement": rule.get("requiredEnforcement").and_then(|v| v.as_str()).unwrap_or("strong"),
                "receipt_required": rule.get("receiptRequired").and_then(|v| v.as_bool()).unwrap_or(true),
                "exception_capable": rule.get("exceptionCapable").and_then(|v| v.as_bool()).unwrap_or(false),
                "note": rule.get("note").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    let policy_pack = json!({
        "schema_version": 1,
        "kind": "arcane-policy-pack",
        "policy_id": "legion-installed-m1",
        "version": 1,
        "contract_versions": [{ "name": "m1", "major": 1, "minor": 0 }],
        "unclassified_effect": "deny",
        "effect_rules": effect_rules,
        "capability": {
            "effects": [],
            "operations": [],
            "targets": [],
            "max_ttl_seconds": 60,
            "max_uses": 1,
            "delegable": false,
            "trust": "unauthenticated"
        },
        "leases": { "max_ttl_seconds": 60, "max_uses": 1, "delegable": false },
        "trust_minima": {
            "mutation": "capability-signature",
            "read_only": "unauthenticated",
            "claim_release": "capability-signature",
            "legacy_import": "capability-signature"
        },
        "host_enforcement": { "required_for_mutation": "strong", "required_for_read_only": "read_only" },
        "receipt_requirements": { "effect_receipt": true, "bind_policy_digest": true, "bind_capability_id": true }
    });
    write_json(&policy_path, &policy_pack)?;

    let runtime_path = output.join("bin").join(format!("legion{executable_suffix}"));
    let runtime_digest = file_sha256(&runtime_path)?;

    if finalize_signed && args.provenance.is_none() {
        return Err("--finalize-signed requires right-release provenance".to_string());
    }
    if let Some(p) = &args.provenance {
        if finalize_signed && !p.starts_with(&format!("{SIGNED_PROVENANCE_SCHEME}://")) {
            return Err("signed provenance must be minted by right-release".to_string());
        }
        if !finalize_signed && p.starts_with(&format!("{SIGNED_PROVENANCE_SCHEME}://")) {
            return Err("right-release provenance is reserved for signed finalization".to_string());
        }
    }
    let provenance = args
        .provenance
        .clone()
        .unwrap_or_else(|| format!("{LOCAL_PROVENANCE_SCHEME}://{platform}-{architecture}/{runtime_digest}"));

    let target_identity = json!({
        "platform": platform,
        "architecture": architecture,
        "targetTriple": target_triple,
        "executable": binary_names[0],
        "installerArchitecture": windows_target.as_ref().map(|w| w.installer_architecture),
    });

    let mut manifest = json!({
        "releaseVersion": release_version,
        "runtime": { "platform": platform, "architecture": architecture, "sha256": runtime_digest, "provenance": provenance },
        "capabilityCatalogSha256": file_sha256(&catalog_path)?,
        "mcpToolSchemaSha256": file_sha256(&schema_path)?,
        "declarativeAssetsSha256": directory_sha256(&assets)?,
        "stateSchemaVersion": 1,
        "rightkitAx": { "version": "0.2.1", "sourceCommit": "4c1a414269d8ffdb95b4b1e685440bd34784b41b" },
    });
    write_json(&share.join("release.json"), &manifest)?;
    write_json(
        &share.join("composition.json"),
        &json!({
            "schemaVersion": 1,
            "kind": "legion-m1-composition",
            "releaseManifestPath": "release.json",
            "catalogRoot": "assets",
            "catalogIndexPath": "registry/index.json",
            "providers": [{ "id": "m1-native-capability" }],
            "policyPack": policy_pack,
            "releaseBinding": {
                "runtimeProvenance": provenance,
                "catalogPath": "assets/registry/index.json",
                "mcpToolSchemaPath": "assets/schemas/mcp-tools.schema.json",
                "declarativeAssetsPath": "assets",
                "declarativeAssetsKind": "directory",
            }
        }),
    )?;

    let plugin_root = output.join("plugin");
    let plugin_surface: Value = serde_json::from_str(
        &fs::read_to_string(repository_root.join("src/registry/plugin-surface.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let portable_skill_source_root = output.join(".portable-skill-staging");
    let _ = fs::remove_dir_all(&portable_skill_source_root);

    let declared_agents: Vec<Value> = plugin_surface
        .get("surface")
        .and_then(|s| s.get("agents"))
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut public_agents = Vec::new();
    for agent in &declared_agents {
        let file = agent.get("file").and_then(|v| v.as_str()).unwrap_or_default();
        let source = repository_root.join(file);
        if !source.exists() {
            return Err(format!("declared agent is missing: {file}"));
        }
        public_agents.push(AgentInput {
            name: agent.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            source_root: repository_root.to_path_buf(),
            source_file: source,
        });
    }
    let declared_agent_count = plugin_surface
        .get("counts")
        .and_then(|c| c.get("agents"))
        .and_then(|v| v.as_i64())
        .unwrap_or(public_agents.len() as i64);
    if public_agents.len() as i64 != declared_agent_count {
        return Err("declared agent count does not match the plugin surface".to_string());
    }

    let skill_catalog: Value = serde_json::from_str(&fs::read_to_string(&catalog_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let bundles = skill_catalog.get("bundles").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let is_public = |b: &Value| {
        matches!(b.get("discoverability").and_then(|v| v.as_str()), Some("public") | Some("explicit"))
    };
    let mut public_skills = Vec::new();
    for bundle in bundles.iter().filter(|b| is_public(b)) {
        let id = bundle.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let name = bundle.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        if !skill_id_re().is_match(&id) || name != id {
            return Err(format!("canonical skill must use its plain name: {id}"));
        }
        let expected_source = format!("skills/{id}/SKILL.md");
        let source = bundle.get("source").and_then(|v| v.as_str()).unwrap_or_default();
        if source != expected_source {
            return Err(format!("canonical skill source mismatch for {id}: {source}"));
        }
        let source_dir = repository_root.join("skills").join(&id);
        let staged_dir = portable_skill_source_root.join(&id);
        copy_skill_tree(&source_dir, &staged_dir)?;
        public_skills.push(SkillInput { id, source_root: portable_skill_source_root.clone(), source_dir: staged_dir });
    }
    let mut expected_skill_ids: Vec<String> =
        bundles.iter().filter(|b| is_public(b)).map(|b| b.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string()).collect();
    expected_skill_ids.sort();
    let mut packaged_skill_ids: Vec<String> = public_skills.iter().map(|s| s.id.clone()).collect();
    packaged_skill_ids.sort();
    if expected_skill_ids.is_empty() {
        return Err("skill catalog declares no shippable skills".to_string());
    }
    let unique: HashSet<&String> = packaged_skill_ids.iter().collect();
    if unique.len() != packaged_skill_ids.len() || packaged_skill_ids != expected_skill_ids {
        let _ = fs::remove_dir_all(&portable_skill_source_root);
        return Err(format!(
            "portable core must package every canonical plain-name skill exactly once; expected [{}], packaged [{}]",
            expected_skill_ids.join(", "),
            packaged_skill_ids.join(", ")
        ));
    }

    let client_projections: Value =
        Value::Object(client_projection_kinds().into_iter().map(|(k, v)| (k.to_string(), v)).collect());

    let assemble_result = assemble_portable_core(AssembleParams {
        output_dir: &plugin_root,
        plugin_manifest_path: &repository_root.join("engine/assets/legion-plugin/plugin.json"),
        mcp_manifest_path: Some(&repository_root.join("engine/assets/legion-plugin/mcp.json")),
        hooks_manifest_path: Some(&repository_root.join("hooks/hooks.json")),
        skills: public_skills,
        agents: public_agents,
        client_projections,
    });
    let _ = fs::remove_dir_all(&portable_skill_source_root);
    assemble_result?;

    let installed_host_projection = plugin_root.join("share/legion/src/registry/host-projection.json");
    fs::create_dir_all(installed_host_projection.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::copy(repository_root.join("src/registry/host-projection.json"), &installed_host_projection).map_err(|e| e.to_string())?;

    let portable_core_path = plugin_root.join("rightax-portable-core.json");
    let mut portable_core: Value = serde_json::from_str(&fs::read_to_string(&portable_core_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    portable_core["publicFiles"]
        .as_array_mut()
        .ok_or("portable core publicFiles must be an array")?
        .push(Value::String("share/legion/src/registry/host-projection.json".to_string()));
    write_json(&portable_core_path, &portable_core)?;

    let validation = validate_portable_core(&plugin_root);
    if !validation.valid {
        return Err(format!("RightAX portable core validation failed: {}", validation.errors.join("; ")));
    }

    manifest["portableCoreSha256"] = Value::String(file_sha256(&portable_core_path)?);
    write_json(&share.join("release.json"), &manifest)?;

    Ok(json!({
        "status": "complete",
        "output": output.display().to_string(),
        "releaseVersion": release_version,
        "platform": platform,
        "architecture": architecture,
        "cargoTarget": cargo_target,
        "targetTriple": target_triple,
        "targetIdentity": target_identity,
        "finalizedSigned": finalize_signed,
        "runtimeSha256": runtime_digest,
        "assetsSha256": manifest["declarativeAssetsSha256"],
        "binaries": binary_names,
    }))
}

fn generic_profile_re() -> Regex {
    Regex::new(r"^[a-z0-9][a-z0-9_-]*$").unwrap()
}
fn skill_id_re() -> Regex {
    Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap()
}
