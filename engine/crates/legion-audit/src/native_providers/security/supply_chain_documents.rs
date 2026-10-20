//! Strict source inventory & dual native SBOM reconciliation. No trust authority.
use super::common::digest;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn digest_json(value: &Value) -> String {
    digest(&legion_contracts::canonical_json_bytes(value).expect("JSON policy is canonicalizable"))
}

pub const SYFT_CONFIGURATION: &str = "check-for-app-update: false\njavascript:\n  include-dev-dependencies: true\n  search-remote-licenses: false\nexclude: []\n";

pub fn lock_kind(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next()?;
    Some(match name {
        "Cargo.lock" => "cargo",
        "poetry.lock" => "poetry",
        "package-lock.json" | "npm-shrinkwrap.json" => "npm",
        "pnpm-lock.yaml" => "pnpm",
        "yarn.lock" => "yarn",
        "go.sum" => "go",
        name if name.starts_with("requirements") && name.ends_with(".txt") => "pip",
        "uv.lock" | "composer.lock" | "Gemfile.lock" | "Pipfile.lock" | "packages.lock.json"
        | "Package.resolved" | "Podfile.lock" | "pubspec.lock" | "mix.lock" => "unsupported",
        _ => return None,
    })
}
fn identity(kind: &str, name: &str, version: &str) -> Result<String, String> {
    if name.is_empty()
        || version.is_empty()
        || name.chars().any(char::is_whitespace)
        || version.chars().any(char::is_whitespace)
        || version.contains(['?', '#'])
    {
        return Err("lockfile-package-identity-invalid".into());
    }
    let name = if kind == "pypi" {
        name.to_ascii_lowercase().replace(['_', '.'], "-")
    } else {
        name.to_owned()
    };
    Ok(format!("pkg:{kind}/{}@{version}", name.replace('@', "%40")))
}
pub fn package_identity(purl: &str) -> Result<String, String> {
    let base = purl.split(['?', '#']).next().ok_or("sbom-purl-invalid")?;
    let (kind, rest) = base
        .strip_prefix("pkg:")
        .and_then(|s| s.split_once('/'))
        .ok_or("sbom-purl-invalid")?;
    let (name, version) = rest.rsplit_once('@').ok_or("sbom-purl-version-missing")?;
    identity(
        kind,
        &name
            .replace("%40", "@")
            .replace("%2F", "/")
            .replace("%2f", "/"),
        version,
    )
}

/// All frozen entries are visited, including development, optional & nested dependencies.
/// Unrecognised syntax never becomes an empty successful inventory.
pub fn parse_lock(path: &str, raw: &str) -> Result<BTreeSet<String>, String> {
    let fail = || format!("dependency-manifest-unparsed:{path}");
    let mut packages = BTreeSet::new();
    let mut add = |kind: &str, name: &str, version: &str| -> Result<(), String> {
        packages.insert(identity(kind, name, version)?);
        Ok(())
    };
    match lock_kind(path).ok_or_else(fail)? {
        "cargo" | "poetry" => {
            let doc: toml::Value = toml::from_str(raw).map_err(|_| fail())?;
            let rows = doc
                .get("package")
                .and_then(toml::Value::as_array)
                .ok_or_else(fail)?;
            for row in rows {
                add(
                    if lock_kind(path) == Some("cargo") {
                        "cargo"
                    } else {
                        "pypi"
                    },
                    row.get("name")
                        .and_then(toml::Value::as_str)
                        .ok_or_else(fail)?,
                    row.get("version")
                        .and_then(toml::Value::as_str)
                        .ok_or_else(fail)?,
                )?;
            }
        }
        "npm" => {
            let doc: Value = serde_json::from_str(raw).map_err(|_| fail())?;
            if let Some(rows) = doc.get("packages").and_then(Value::as_object) {
                for (key, row) in rows {
                    if key.is_empty() {
                        continue;
                    }
                    // Workspaces/links require resolved inventory; don't omit them.
                    if row.get("link").and_then(Value::as_bool) == Some(true) {
                        return Err(fail());
                    }
                    let name = key
                        .rsplit_once("node_modules/")
                        .map(|(_, n)| n)
                        .ok_or_else(fail)?;
                    add(
                        "npm",
                        name,
                        row.get("version")
                            .and_then(Value::as_str)
                            .ok_or_else(fail)?,
                    )?;
                }
            } else {
                fn walk(
                    rows: &serde_json::Map<String, Value>,
                    out: &mut BTreeSet<String>,
                ) -> Result<(), String> {
                    for (name, row) in rows {
                        out.insert(identity(
                            "npm",
                            name,
                            row.get("version")
                                .and_then(Value::as_str)
                                .ok_or("dependency-manifest-unparsed")?,
                        )?);
                        if let Some(nested) = row.get("dependencies") {
                            walk(
                                nested.as_object().ok_or("dependency-manifest-unparsed")?,
                                out,
                            )?;
                        }
                    }
                    Ok(())
                }
                walk(
                    doc.get("dependencies")
                        .and_then(Value::as_object)
                        .ok_or_else(fail)?,
                    &mut packages,
                )?;
            }
        }
        "pnpm" => {
            let doc: Value = serde_yaml::from_str(raw).map_err(|_| fail())?;
            let rows = doc
                .get("packages")
                .and_then(Value::as_object)
                .ok_or_else(fail)?;
            for key in rows.keys() {
                let key = key
                    .trim_start_matches('/')
                    .split('(')
                    .next()
                    .ok_or_else(fail)?;
                let split = key
                    .rfind('@')
                    .filter(|i| *i > 0)
                    .or_else(|| key.rfind('/'))
                    .ok_or_else(fail)?;
                add("npm", &key[..split], &key[split + 1..])?;
            }
        }
        "yarn" => {
            // Accept complete YAML mappings only; unresolved classic syntax &
            // selector aliases require resolver evidence & remain gaps.
            let doc: Value = serde_yaml::from_str(raw).map_err(|_| fail())?;
            for (selector, row) in doc.as_object().ok_or_else(fail)? {
                if selector == "__metadata" {
                    continue;
                }
                let first = selector.split(',').next().ok_or_else(fail)?.trim();
                let split = first.rfind('@').filter(|i| *i > 0).ok_or_else(fail)?;
                let name = &first[..split];
                if first[split + 1..].contains("npm:")
                    || row
                        .get("resolution")
                        .and_then(Value::as_str)
                        .is_some_and(|r| r.contains("patch:") || r.contains("workspace:"))
                {
                    return Err(fail());
                }
                add(
                    "npm",
                    name,
                    row.get("version")
                        .and_then(Value::as_str)
                        .ok_or_else(fail)?,
                )?;
            }
        }
        "go" => {
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() != 3 || !parts[2].starts_with("h1:") {
                    return Err(fail());
                }
                add("golang", parts[0], parts[1].trim_end_matches("/go.mod"))?;
            }
        }
        "pip" => {
            for line in raw.lines() {
                let line = line.split(" #").next().unwrap_or("").trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Includes, markers, ranges, URLs & continuations need full resolver
                // evidence. Refuse them instead of dropping dependency rows.
                if line.contains([';', '\\']) || line.starts_with('-') {
                    return Err(fail());
                }
                let (name, version) = line.split_once("==").ok_or_else(fail)?;
                if version.contains(['=', '<', '>', '*', ',', '@']) {
                    return Err(fail());
                }
                add("pypi", name.trim(), version.trim())?;
            }
        }
        _ => return Err(format!("dependency-lock-format-unsupported:{path}")),
    }
    if packages.is_empty() {
        return Err(fail());
    }
    Ok(packages)
}

#[derive(Clone, Debug)]
pub struct Package {
    pub licenses: BTreeSet<String>,
}
pub fn parse_sbom(format: &str, raw: &[u8]) -> Result<BTreeMap<String, Package>, String> {
    let doc: Value = serde_json::from_slice(raw).map_err(|_| "sbom-json-invalid")?;
    let mut out = BTreeMap::new();
    let (rows, cdx) = match format {
        "cyclonedx"
            if doc["bomFormat"] == "CycloneDX"
                && matches!(doc["specVersion"].as_str(), Some("1.5" | "1.6" | "1.7")) =>
        {
            (
                doc["components"]
                    .as_array()
                    .ok_or("sbom-components-missing")?,
                true,
            )
        }
        "spdx" if doc["spdxVersion"] == "SPDX-2.3" && doc["SPDXID"] == "SPDXRef-DOCUMENT" => (
            doc["packages"].as_array().ok_or("sbom-packages-missing")?,
            false,
        ),
        _ => return Err("sbom-format-invalid".into()),
    };
    for row in rows {
        let purls: Vec<_> = if cdx {
            row.get("purl")
                .and_then(Value::as_str)
                .into_iter()
                .collect()
        } else {
            row.get("externalRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|r| r["referenceType"] == "purl")
                .filter_map(|r| r["referenceLocator"].as_str())
                .collect()
        };
        if purls.is_empty() {
            // SPDX's directory root & CycloneDX file components are not
            // dependency packages. An unidentified library stays a gap.
            if (cdx && matches!(row["type"].as_str(), Some("file" | "operating-system")))
                || (!cdx
                    && matches!(
                        row["primaryPackagePurpose"].as_str(),
                        Some("FILE" | "CONTAINER" | "OTHER")
                    ))
            {
                continue;
            }
            return Err("sbom-package-purl-missing".into());
        }
        if purls.len() != 1 {
            return Err("sbom-package-purl-ambiguous".into());
        }
        let id = package_identity(purls[0])?;
        let mut licenses = BTreeSet::new();
        if cdx {
            for license in row
                .get("licenses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let value = license
                    .get("expression")
                    .and_then(Value::as_str)
                    .or_else(|| license.pointer("/license/id").and_then(Value::as_str))
                    .or_else(|| license.pointer("/license/name").and_then(Value::as_str))
                    .ok_or("sbom-license-invalid")?;
                licenses.insert(value.to_owned());
            }
        } else {
            let value = row
                .get("licenseConcluded")
                .and_then(Value::as_str)
                .filter(|s| !matches!(*s, "NOASSERTION" | "NONE"))
                .or_else(|| row.get("licenseDeclared").and_then(Value::as_str));
            if let Some(value) = value {
                licenses.insert(value.to_owned());
            }
        }
        if out.insert(id, Package { licenses }).is_some() {
            return Err("sbom-package-duplicate".into());
        }
    }
    if out.is_empty() {
        return Err("sbom-package-inventory-empty".into());
    }
    Ok(out)
}

/// Explicit caller-owned policy evaluates whole SPDX expressions, never tokens.
/// Complex expressions require an exact policy entry; unsupported ones stay unknown.
pub fn reconcile(lock: &BTreeSet<String>, cdx: &[u8], spdx: &[u8], policy: &Value) -> Value {
    let mut gaps = Vec::new();
    let mut findings = Vec::new();
    let mut parsed = Vec::new();
    for (format, raw) in [("cyclonedx", cdx), ("spdx", spdx)] {
        match parse_sbom(format, raw) {
            Ok(packages) => parsed.push(packages),
            Err(reason) => gaps.push(json!({"kind":reason,"format":format})),
        }
    }
    let allowed: BTreeSet<&str> = policy
        .get("allow")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let denied: BTreeSet<&str> = policy
        .get("deny")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let policy_valid = policy["schema"] == "legion-supply-chain-license-policy/1"
        && policy["unknown"] == "unproven"
        && policy["allow"]
            .as_array()
            .is_some_and(|a| a.len() == allowed.len())
        && policy["deny"]
            .as_array()
            .is_some_and(|a| a.len() == denied.len())
        && !allowed.is_empty()
        && allowed.is_disjoint(&denied)
        && !allowed
            .iter()
            .chain(denied.iter())
            .any(|s| s.is_empty() || matches!(*s, "NONE" | "NOASSERTION"));
    if !policy_valid {
        gaps.push(json!({"kind":"supply-chain-license-policy-missing-or-invalid"}));
    }
    let mut examined = 0;
    if parsed.len() == 2 {
        for package in lock {
            let (Some(left), Some(right)) = (parsed[0].get(package), parsed[1].get(package)) else {
                gaps.push(json!({"kind":"sbom-package-missing","name":package}));
                continue;
            };
            examined += 1;
            if left.licenses != right.licenses {
                gaps.push(json!({"kind":"sbom-license-formats-disagree","name":package}));
                continue;
            }
            if !policy_valid {
                continue;
            }
            if left.licenses.is_empty() {
                gaps.push(json!({"kind":"sbom-package-license-missing","name":package}));
            }
            for license in &left.licenses {
                if denied.contains(license.as_str()) {
                    findings.push(json!({"ruleId":"supply-chain.license-policy-denied","package":package,"license":license,"severity":"high","evidence":"both-native-sbom-formats","policyDigest":digest_json(policy)}));
                } else if !allowed.contains(license.as_str()) {
                    gaps.push(json!({"kind":"supply-chain-license-undecided","name":package,"license":license}));
                }
            }
        }
        let left: BTreeSet<_> = parsed[0].keys().collect();
        let right: BTreeSet<_> = parsed[1].keys().collect();
        if left != right {
            gaps.push(json!({"kind":"sbom-package-formats-disagree"}));
        }
    }
    if lock.is_empty() {
        gaps.push(json!({"kind":"dependency-inventory-missing"}));
    }
    json!({"complete":gaps.is_empty(),"expected":lock.len(),"examined":examined,"findings":findings,"coverageGaps":gaps,"cycloneDxDigest":digest(cdx),"spdxDigest":digest(spdx),"licensePolicyDigest":digest_json(policy)})
}

pub fn source_snapshot(
    root: &std::path::Path,
    entries: &[crate::inventory::InventoryEntry],
) -> Value {
    let mut files = BTreeMap::new();
    let mut gaps = Vec::new();
    for entry in entries {
        let relative = std::path::Path::new(&entry.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            gaps.push(json!({"kind":"supply-chain-source-path-invalid","path":entry.path}));
            continue;
        }
        let mut path = root.to_path_buf();
        let mut safe = true;
        for component in relative.components() {
            path.push(component);
            if std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(true)
            {
                safe = false;
                break;
            }
        }
        if !safe {
            gaps.push(json!({"kind":"supply-chain-source-unreadable","path":entry.path}));
            continue;
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                let hash = digest(&bytes);
                if entry.digest.as_ref() != Some(&hash) {
                    gaps.push(json!({"kind":"supply-chain-source-drift","path":entry.path}));
                }
                files.insert(entry.path.clone(), hash);
            }
            Err(_) => gaps.push(json!({"kind":"supply-chain-source-unreadable","path":entry.path})),
        }
    }
    json!({"complete":gaps.is_empty()&&files.len()==entries.len(),"files":files,"coverageGaps":gaps})
}

/// Diagnostic observations, never an authenticated builder claim. RightKit's
/// existing in-toto validator is structural; its builder string is not identity.
pub fn provenance_observation(chain: &Value, binding: &Value) -> Value {
    let mut reasons = Vec::new();
    let Some(provenance) = chain.get("provenance") else {
        return json!({"present":false,"verified":false,"reasons":["absent","authority-unavailable"]});
    };
    if provenance.get("binding") != Some(binding) {
        reasons.push("binding-mismatch");
    }
    let receipt = &provenance["executionReceipt"];
    if receipt["complete"] != true
        || receipt["state"] != "completed"
        || receipt["exitCode"] != 0
        || receipt.pointer("/policy/allowed") != Some(&json!(true))
        || receipt.pointer("/processTree/reaped") != Some(&json!(true))
        || receipt["planId"] != binding["digest"]
    {
        reasons.push("malformed-receipt");
    }
    let statement = provenance["raw"]
        .as_str()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let Some(statement) = statement else {
        reasons.push("malformed-statement");
        reasons.push("authority-unavailable");
        return json!({"present":true,"verified":false,"reasons":reasons});
    };
    if statement["_type"] != "https://in-toto.io/Statement/v1"
        || statement["predicateType"] != "https://slsa.dev/provenance/v1"
        || !statement["predicate"].is_object()
    {
        reasons.push("malformed-statement");
    }
    let subject = &chain["subjectArtifact"];
    let bytes: Option<Vec<u8>> = subject["rawBytes"].as_array().and_then(|values| {
        values
            .iter()
            .map(|v| v.as_u64().filter(|n| *n <= 255).map(|n| n as u8))
            .collect()
    });
    let exact = bytes.is_some_and(|bytes| {
        let hash = digest(&bytes);
        subject["digest"] == hash
            && subject["path"]
                .as_str()
                .is_some_and(|path| chain["sourceBefore"]["files"][path] == hash)
            && statement["subject"].as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row["name"] == subject["path"]
                        && row["digest"]["sha256"].as_str()
                            == Some(hash.trim_start_matches("sha256:"))
                })
            })
    });
    if !exact {
        reasons.push("subject-mismatch");
    }
    reasons.push("authority-unavailable");
    json!({"present":true,"verified":false,"reasons":reasons})
}
