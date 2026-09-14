use serde_json::{json, Map, Value};
use std::path::Path;
use walkdir::WalkDir;

const EXCLUDED: &[&str] = &[".git", ".audit", "node_modules"];

pub fn build_projection(root: &Path) -> Result<Value, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let files = list_files(&root)?;
    let mut manifest = json!({});
    if files.iter().any(|path| path == "package.json") {
        let bytes = std::fs::read(root.join("package.json")).map_err(|error| error.to_string())?;
        manifest = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    }
    let dependencies = merge_dependency_maps(&manifest);
    let entrypoints = entrypoints_from_manifest(&manifest);
    let manifests = if files.iter().any(|path| path == "package.json") {
        let mut object = manifest.as_object().cloned().unwrap_or_default();
        object.insert("path".into(), json!("package.json"));
        vec![Value::Object(object)]
    } else {
        Vec::new()
    };
    Ok(json!({
        "files": files,
        "manifests": manifests,
        "dependencies": dependencies,
        "entrypoints": entrypoints,
        "buildOutputs": [],
    }))
}

fn list_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_dir() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        if relative
            .split('/')
            .any(|segment| EXCLUDED.contains(&segment))
        {
            continue;
        }
        files.push(relative);
    }
    files.sort();
    Ok(files)
}

fn merge_dependency_maps(manifest: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    for key in ["dependencies", "devDependencies"] {
        if let Some(object) = manifest.get(key).and_then(Value::as_object) {
            for (name, version) in object {
                out.insert(name.clone(), version.clone());
            }
        }
    }
    out
}

fn entrypoints_from_manifest(manifest: &Value) -> Vec<Value> {
    match manifest.get("bin") {
        Some(Value::String(path)) => vec![json!(path)],
        Some(Value::Object(map)) => map.values().cloned().collect(),
        _ => Vec::new(),
    }
}
