// Port of `scripts/check-publication-surface.mjs`. `package.json#files` and
// `MANIFEST.package.json#allowlistedTopLevel` must be exactly equal, in
// order and content, and every entry must exist.

use super::read_json;
use std::path::Path;

pub struct Result {
    pub ok: bool,
    pub message: String,
}

fn string_array(value: &serde_json::Value) -> Option<Vec<String>> {
    let arr = value.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(item.as_str()?.to_string());
    }
    Some(out)
}

pub fn check(root: &Path) -> Result {
    let pkg = match read_json(&root.join("package.json")) {
        Ok(v) => v,
        Err(e) => {
            return Result {
                ok: false,
                message: format!("publication surface contract failed: {e}"),
            }
        }
    };
    let manifest = match read_json(&root.join("MANIFEST.package.json")) {
        Ok(v) => v,
        Err(e) => {
            return Result {
                ok: false,
                message: format!("publication surface contract failed: {e}"),
            }
        }
    };

    let package_files_raw = pkg.get("files").cloned().unwrap_or(serde_json::Value::Null);
    let manifest_files_raw = manifest
        .get("allowlistedTopLevel")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let mut errors = Vec::new();
    let package_files = string_array(&package_files_raw);
    let manifest_files = string_array(&manifest_files_raw);

    if package_files.is_none() {
        errors.push("package.json#files must be an array".to_string());
    }
    if manifest_files.is_none() {
        errors.push("MANIFEST.package.json#allowlistedTopLevel must be an array".to_string());
    }

    if !errors.is_empty() {
        return Result {
            ok: false,
            message: format!("publication surface contract failed: {}", errors.join("; ")),
        };
    }

    let package_files = package_files.unwrap();
    let manifest_files = manifest_files.unwrap();

    for (label, entries) in [
        ("package.json#files", &package_files),
        ("MANIFEST.package.json#allowlistedTopLevel", &manifest_files),
    ] {
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            if entry.is_empty() {
                errors.push(format!("{label} contains an invalid path"));
                continue;
            }
            if !seen.insert(entry.clone()) {
                errors.push(format!("{label} contains duplicate path {entry}"));
            }
            if !root.join(entry).exists() {
                errors.push(format!("{label} names absent path {entry}"));
            }
        }
    }

    if package_files != manifest_files {
        errors.push(
            "package.json#files & MANIFEST.package.json#allowlistedTopLevel must be exactly equal in order & content"
                .to_string(),
        );
    }

    if errors.is_empty() {
        Result {
            ok: true,
            message: "publication surface contract passes".to_string(),
        }
    } else {
        Result {
            ok: false,
            message: format!("publication surface contract failed: {}", errors.join("; ")),
        }
    }
}

pub fn run(root: &Path) -> bool {
    let result = check(root);
    if result.ok {
        println!("{}", result.message);
    } else {
        eprintln!("{}", result.message);
    }
    result.ok
}
