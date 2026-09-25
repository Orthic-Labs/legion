//! Port of `scripts/generate-manifest.mjs`.
//!
//! `src/registry/providers.json` ships `schemaVersion: 2, kind:
//! "legion-provider-registry"`, so `loadProviderRegistry`'s live path is
//! `adaptProviderV2Registry` → `validateProviderRegistry` (the extension
//! file is never consulted on that branch — see
//! `loadProviderRegistry`'s `if (raw.schemaVersion === 2 && ...) return`
//! early-return in `src/registry/provider-registry.mjs`). That path is
//! already ported at
//! `legion_audit::wf_port::wf010::provider_registry::load_provider_registry_v2`
//! + `render_manifest`; this module composes them with file I/O the way
//! `generate-manifest.mjs` does, rather than re-porting the registry.

use serde_json::Value;
use std::fs;
use std::path::Path;

use legion_audit::wf_port::wf010::provider_registry::{load_provider_registry_v2, render_manifest};

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `generatedManifestText(registryPath)`.
pub fn generated_manifest_text(registry_path: &Path) -> Result<String, String> {
    let raw = read_json(registry_path)?;
    let registry = load_provider_registry_v2(&raw).map_err(|e| e.to_string())?;
    let manifest = render_manifest(&registry);
    Ok(format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()))
}

struct Compatibility {
    valid: bool,
    errors: Vec<&'static str>,
    provider_mirror_present: bool,
}

/// `compatibleCheckedInManifest(actual, expected)`. `actual` is `None` when
/// the checked-in file is missing or fails to parse (JS's `catch {}`
/// leaves `actual` as `null`).
fn compatible_checked_in_manifest(actual: Option<&Value>, expected: &Value) -> Compatibility {
    let mut errors = Vec::new();
    let a_discovery = actual.and_then(|a| a.get("discovery_owner"));
    let e_discovery = expected.get("discovery_owner");
    if a_discovery != e_discovery {
        errors.push("discovery_owner");
    }
    let a_concurrency = actual.and_then(|a| a.get("concurrency"));
    let e_concurrency = expected.get("concurrency");
    if a_concurrency != e_concurrency {
        errors.push("concurrency");
    }
    let empty = Value::Array(vec![]);
    let a_checks = actual.and_then(|a| a.get("checks")).unwrap_or(&empty);
    let e_checks = expected.get("checks").unwrap_or(&empty);
    if a_checks != e_checks {
        errors.push("checks");
    }
    let provider_mirror_present = matches!(actual.and_then(|a| a.get("providers")), Some(Value::Array(_)));
    if provider_mirror_present {
        let a_providers = actual.and_then(|a| a.get("providers"));
        let e_providers = expected.get("providers");
        if a_providers != e_providers {
            errors.push("providers");
        }
    }
    Compatibility { valid: errors.is_empty(), errors, provider_mirror_present }
}

/// `legion-dev generate-manifest [--check] [--registry PATH] [--out PATH]`
pub fn run(root: &Path, check: bool, registry: Option<&Path>, out: Option<&Path>) -> bool {
    let registry_path = registry
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| root.join("src/registry/providers.json"));
    let out_path = out.map(|p| p.to_path_buf()).unwrap_or_else(|| root.join("manifest.json"));

    let expected_text = match generated_manifest_text(&registry_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("generate-manifest: {e}");
            return false;
        }
    };
    let expected: Value = serde_json::from_str(&expected_text).unwrap();

    if check {
        let actual: Option<Value> = fs::read_to_string(&out_path).ok().and_then(|s| serde_json::from_str(&s).ok());
        let compatibility = compatible_checked_in_manifest(actual.as_ref(), &expected);
        if !compatibility.valid {
            eprintln!(
                "manifest drift ({}): regenerate {} from the executed provider registry",
                compatibility.errors.join(", "),
                out_path.display()
            );
            return false;
        }
        if !compatibility.provider_mirror_present {
            println!(
                "manifest scanner checks match; complete provider contracts are validated directly from registry data. Regeneration will add the provider mirror: {}",
                out_path.display()
            );
        } else {
            println!("manifest matches complete executed provider registry: {}", out_path.display());
        }
        return true;
    }

    if let Err(e) = fs::write(&out_path, &expected_text) {
        eprintln!("generate-manifest: {e}");
        return false;
    }
    println!("{}", out_path.display());
    true
}
