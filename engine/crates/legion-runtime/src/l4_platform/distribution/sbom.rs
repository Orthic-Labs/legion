//! Port of `src/lib/distribution/sbom.mjs`.

use super::release_manifest::file_digest;
use serde_json::{json, Value};
use std::path::Path;

/// `cyclonedxSbom({ components, serialNumber })`. Panics (mirrors the JS
/// `throw`) when `components` is empty.
pub fn cyclonedx_sbom(components: &[Value], serial_number: Option<&str>) -> Value {
    let normalized: Vec<Value> = components
        .iter()
        .map(|component| {
            let license = component.get("license").and_then(Value::as_str);
            let path = component.get("path").and_then(Value::as_str);
            let digest = path.and_then(|p| file_digest(Path::new(p)));
            json!({
                "type": component.get("type").and_then(Value::as_str).unwrap_or("library"),
                "name": component.get("name").cloned().unwrap_or(Value::Null),
                "version": component.get("version").cloned().unwrap_or(Value::Null),
                "licenses": license.map(|l| json!([{"license": {"id": l}}])).unwrap_or_else(|| json!([])),
                "hashes": digest.map(|d| {
                    let hex = d.strip_prefix("sha256:").unwrap_or(&d).to_string();
                    json!([{"alg": "SHA-256", "content": hex}])
                }).unwrap_or_else(|| json!([])),
            })
        })
        .collect();
    if normalized.is_empty() {
        panic!("SBOM cannot be empty");
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "components": normalized,
    })
}

/// `spdxSbom({ name, components })`. Panics when `name` is empty or
/// `components` is empty.
pub fn spdx_sbom(name: &str, components: &[Value]) -> Value {
    if name.is_empty() || components.is_empty() {
        panic!("SPDX SBOM needs a package name and components");
    }
    json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "name": name,
        "dataLicense": "CC0-1.0",
        "packages": components,
    })
}

/// `generateSboms({ name, components, serialNumber })`.
pub fn generate_sboms(name: &str, components: &[Value], serial_number: Option<&str>) -> Value {
    json!({
        "cyclonedx": cyclonedx_sbom(components, serial_number),
        "spdx": spdx_sbom(name, components),
    })
}

/// `inventoryRuntimeDependencies({ packageManifest, provenance })`.
pub fn inventory_runtime_dependencies(package_manifest: &Value, provenance: &Value) -> Vec<Value> {
    let deps = package_manifest.get("dependencies").and_then(Value::as_object);
    let mut entries: Vec<(String, Value)> =
        deps.map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
        .map(|(name, version)| {
            let prov = provenance.get(&name);
            json!({
                "type": "library",
                "name": name,
                "version": version,
                "source": prov.and_then(|p| p.get("source")).cloned().unwrap_or_else(|| Value::String("npm".to_string())),
                "digest": prov.and_then(|p| p.get("digest")).cloned().unwrap_or(Value::Null),
                "license": prov.and_then(|p| p.get("license")).cloned().unwrap_or(Value::Null),
                "shipped": true,
                "distributionStatus": prov.and_then(|p| p.get("distributionStatus")).cloned().unwrap_or_else(|| Value::String("integrated".to_string())),
            })
        })
        .collect()
}

/// `inventoryDistribution({ runtime, externalTools, grammars, ruleMaterial, creatorMaterial })`.
pub fn inventory_distribution(groups: &[&[Value]]) -> Vec<Value> {
    let mut all: Vec<Value> = groups
        .iter()
        .flat_map(|group| group.iter())
        .map(|component| {
            json!({
                "type": component.get("type").and_then(Value::as_str).unwrap_or("library"),
                "name": component.get("name").cloned().unwrap_or(Value::Null),
                "version": component.get("version").cloned().unwrap_or(Value::Null),
                "source": component.get("source").cloned().unwrap_or(Value::Null),
                "digest": component.get("digest").cloned().unwrap_or(Value::Null),
                "license": component.get("license").cloned().unwrap_or(Value::Null),
                "shipped": component.get("shipped").and_then(Value::as_bool).unwrap_or(false),
                "distributionStatus": component.get("distributionStatus").cloned().unwrap_or_else(|| Value::String("reference-only".to_string())),
                "redistributionGrant": component.get("redistributionGrant").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    all.sort_by(|a, b| {
        let ka = format!("{}:{}", a["type"].as_str().unwrap_or(""), a["name"].as_str().unwrap_or(""));
        let kb = format!("{}:{}", b["type"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or(""));
        ka.cmp(&kb)
    });
    all
}

/// `reconcileDistributionContents(components, packageContents)`.
pub fn reconcile_distribution_contents(components: &[Value], package_contents: &[Value]) -> Value {
    let shipped: Vec<Value> =
        components.iter().filter(|c| c.get("shipped").and_then(Value::as_bool) == Some(true)).cloned().collect();
    let content_names: std::collections::HashSet<String> = package_contents
        .iter()
        .map(|entry| match entry {
            Value::String(s) => s.clone(),
            Value::Object(obj) => obj.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
            _ => String::new(),
        })
        .collect();
    let mut blockers: Vec<Value> = Vec::new();
    for component in &shipped {
        let name = component.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        if !content_names.contains(&name) {
            blockers.push(json!({"kind": "shipped-component-absent", "component": name}));
        }
        let digest = component.get("digest").and_then(Value::as_str);
        let license = component.get("license").and_then(Value::as_str);
        let source = component.get("source").and_then(Value::as_str);
        if digest.is_none() || license.is_none() || source.is_none() {
            blockers.push(json!({"kind": "component-metadata-incomplete", "component": name}));
        }
        let grant = component.get("redistributionGrant").and_then(Value::as_bool);
        if source == Some("external") && grant != Some(true) {
            blockers.push(json!({"kind": "redistribution-right-unresolved", "component": name}));
        }
    }
    let decision = if blockers.is_empty() { "QUALIFIED" } else { "BLOCKED" };
    json!({"components": shipped, "blockers": blockers, "decision": decision})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generates_nonempty_sboms() {
        let components = vec![json!({"name": "legion", "version": "1.0.0", "license": "SEE LICENSE", "source": "local", "shipped": true, "distributionStatus": "integrated"})];
        let sboms = generate_sboms("legion", &components, None);
        assert_eq!(sboms["cyclonedx"]["components"].as_array().unwrap().len(), 1);
        assert_eq!(sboms["spdx"]["packages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn runtime_inventory_matches_expected_shape() {
        let manifest = json!({"dependencies": {"alpha": "1.2.3"}});
        let provenance = json!({"alpha": {"source": "registry", "digest": "sha256:a", "license": "MIT"}});
        let inventory = inventory_runtime_dependencies(&manifest, &provenance);
        assert_eq!(
            inventory[0],
            json!({"type": "library", "name": "alpha", "version": "1.2.3", "source": "registry", "digest": "sha256:a", "license": "MIT", "shipped": true, "distributionStatus": "integrated"})
        );
    }

    #[test]
    fn reconcile_qualifies_when_content_present() {
        let manifest = json!({"dependencies": {"alpha": "1.2.3"}});
        let provenance = json!({"alpha": {"source": "registry", "digest": "sha256:a", "license": "MIT"}});
        let runtime = inventory_runtime_dependencies(&manifest, &provenance);
        let creator = vec![json!({"name": "designer", "shipped": false})];
        let distribution = inventory_distribution(&[&runtime, &creator]);
        assert_eq!(distribution[0]["name"], "alpha");
        assert_eq!(reconcile_distribution_contents(&distribution, &[json!("alpha")])["decision"], "QUALIFIED");
        assert_eq!(reconcile_distribution_contents(&distribution, &[])["decision"], "BLOCKED");
    }
}
