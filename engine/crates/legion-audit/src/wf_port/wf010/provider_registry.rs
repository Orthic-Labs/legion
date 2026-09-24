//! Port of `src/registry/provider-registry.mjs`.
//!
//! `src/registry/providers.json` ships `schemaVersion: 2, kind:
//! "legion-provider-registry"` (checked at port time), so `loadProviderRegistry`'s
//! live path is `adaptProviderV2Registry` → `validateProviderRegistry`; that
//! path is what this module ports in full, against `serde_json::Value` to
//! match this crate's convention for open (non-fixed-schema) JS objects
//! (see `wf064::plan`'s gap note naming this exact file as its blocker).
//!
//! NOT ported (file I/O, not pure logic — a loader composes these with a
//! JSON reader): `loadProviderRegistry`'s `readFileSync`/`JSON.parse`, the
//! v1 `expandProviderRegistry` legacy/runtime/reasoning-list path (the JS
//! schemaVersion===1 branch — dead on the shipped registry, which is v2),
//! `loadSecurityLensRegistry`/`expandSecurityLensProviders`/
//! `extendRegistryWithSecurityLenses`, and
//! `loadProviderRegistryExtension`/`extendRegistryWithNativeFamilies` (all
//! read a second/third JSON file from disk). Everything reachable from the
//! live v2 registry once loaded — `adaptProviderV2Registry`,
//! `validateProviderRegistry`, `buildSelectionContext`, `evaluateSelector`,
//! `selectProviders`, `evaluateCoverageFamilies`, `registryDigest`,
//! `renderManifest` — is ported below.

use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Map, Value};

use crate::wf_port::wf064::common::sha256_value;

fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key)
}
fn str_of(value: &Value) -> Option<&str> {
    value.as_str()
}
fn arr_of<'a>(value: &'a Value) -> &'a [Value] {
    value.as_array().map(|a| a.as_slice()).unwrap_or(&[])
}

/// Faithful port of `normalizePath`.
pub fn normalize_path(value: &str) -> String {
    let replaced = value.replace('\\', "/");
    let no_leading = replaced.strip_prefix("./").unwrap_or(&replaced);
    no_leading.trim_end_matches('/').to_string()
}

/// Faithful port of `globToRegExp` + `pathMatches`, implemented directly as
/// a matcher (no regex crate dependency) since the grammar is a small,
/// fixed glob subset (`**`, `*`, `?`, literal).
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<char> = normalize_path(pattern).chars().collect();
    let text: Vec<char> = normalize_path(path).chars().collect();
    return_match(&pat, &text)
}

fn return_match(pat: &[char], text: &[char]) -> bool {
    // Backtracking matcher over the compiled glob semantics of
    // globToRegExp: '**' + '/' -> "(?:.*/)?" (zero or more path segments),
    // bare '**' -> ".*", '*' -> "[^/]*", '?' -> "[^/]", else literal.
    fn helper(pat: &[char], pi: usize, text: &[char], ti: usize) -> bool {
        if pi == pat.len() {
            return ti == text.len();
        }
        if pat[pi] == '*' && pi + 1 < pat.len() && pat[pi + 1] == '*' {
            let followed_by_slash = pi + 2 < pat.len() && pat[pi + 2] == '/';
            let next_pi = if followed_by_slash { pi + 3 } else { pi + 2 };
            if followed_by_slash {
                // (?:.*/)? : optionally consume any prefix ending in '/'
                if helper(pat, next_pi, text, ti) {
                    return true;
                }
                for cut in ti..text.len() {
                    if text[cut] == '/' && helper(pat, next_pi, text, cut + 1) {
                        return true;
                    }
                }
                false
            } else {
                // '.*' : consume anything, including '/'
                for cut in ti..=text.len() {
                    if helper(pat, next_pi, text, cut) {
                        return true;
                    }
                }
                false
            }
        } else if pat[pi] == '*' {
            // [^/]* : consume any run of non-'/' chars
            let mut cut = ti;
            loop {
                if helper(pat, pi + 1, text, cut) {
                    return true;
                }
                if cut >= text.len() || text[cut] == '/' {
                    break;
                }
                cut += 1;
            }
            false
        } else if pat[pi] == '?' {
            if ti < text.len() && text[ti] != '/' {
                helper(pat, pi + 1, text, ti + 1)
            } else {
                false
            }
        } else {
            if ti < text.len() && text[ti] == pat[pi] {
                helper(pat, pi + 1, text, ti + 1)
            } else {
                false
            }
        }
    }
    helper(pat, 0, text, 0)
}

pub fn path_matches(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| glob_match(p, path))
}

fn union_paths(parts: &[Vec<String>]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for part in parts {
        for p in part {
            set.insert(p.clone());
        }
    }
    set.into_iter().collect()
}

/// Faithful port of `buildSelectionContext(projection)`.
#[derive(Debug, Default, Clone)]
pub struct SelectionContext {
    pub ready: bool,
    pub files: Vec<String>,
    pub file_set: HashSet<String>,
    pub source_files: Vec<String>,
    pub source_file_count: usize,
    pub extension_to_paths: BTreeMap<String, Vec<String>>,
    pub dependencies: HashSet<String>,
    pub dependency_evidence: BTreeMap<String, Vec<String>>,
    pub package_scripts: HashSet<String>,
    pub script_evidence: BTreeMap<String, Vec<String>>,
}

pub fn build_selection_context(projection: &Value) -> SelectionContext {
    let mut files_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in arr_of(get(projection, "files").unwrap_or(&Value::Null)) {
        if let Some(s) = f.as_str() {
            let n = normalize_path(s);
            if !n.is_empty() {
                files_set.insert(n);
            }
        }
    }
    let files: Vec<String> = files_set.into_iter().collect();

    let mut dependencies = HashSet::new();
    let mut package_scripts = HashSet::new();
    let mut dependency_evidence: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut script_evidence: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let audit_facts = get(projection, "auditFacts").cloned().unwrap_or(Value::Null);
    let package_manifests = get(&audit_facts, "packageManifests").cloned().unwrap_or(Value::Null);
    for record in arr_of(&package_manifests) {
        let path = get(record, "path").and_then(str_of).unwrap_or("").to_string();
        for dep in arr_of(get(record, "dependencies").unwrap_or(&Value::Null)) {
            if let Some(d) = dep.as_str() {
                dependencies.insert(d.to_string());
                dependency_evidence.entry(d.to_string()).or_default().push(path.clone());
            }
        }
        for script in arr_of(get(record, "scripts").unwrap_or(&Value::Null)) {
            if let Some(s) = script.as_str() {
                package_scripts.insert(s.to_string());
                script_evidence.entry(s.to_string()).or_default().push(path.clone());
            }
        }
    }

    let mut extension_to_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in &files {
        let base = path.rsplit('/').next().unwrap_or(path);
        if let Some(dot) = base.rfind('.') {
            let ext = base[dot + 1..].to_lowercase();
            extension_to_paths.entry(ext).or_default().push(path.clone());
        }
    }

    let parsed: HashSet<String> = arr_of(get(projection, "parsedExtensions").unwrap_or(&Value::Null))
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let source_files: Vec<String> = files
        .iter()
        .filter(|path| {
            let base = path.rsplit('/').next().unwrap_or(path.as_str());
            match base.rfind('.') {
                Some(dot) => parsed.contains(&base[dot + 1..].to_lowercase()),
                None => false,
            }
        })
        .cloned()
        .collect();

    let file_set: HashSet<String> = files.iter().cloned().collect();
    let ready = get(projection, "state").and_then(str_of) == Some("ready");

    SelectionContext {
        ready,
        source_file_count: source_files.len(),
        files,
        file_set,
        source_files,
        extension_to_paths,
        dependencies,
        dependency_evidence,
        package_scripts,
        script_evidence,
    }
}

fn source_denominator(context: &SelectionContext, evidence_paths: &[String]) -> Vec<String> {
    if !context.source_files.is_empty() {
        context.source_files.clone()
    } else {
        evidence_paths.to_vec()
    }
}

/// Result of evaluating one selector, mirrors `{matched, paths, reason}`.
#[derive(Debug, Clone, Default)]
pub struct SelectorVerdict {
    pub matched: bool,
    pub paths: Vec<String>,
    pub reason: String,
}

/// A `selected` provider record carries its own denominator paths for
/// `securityCandidatesSelected` to look at (`selectedProviders`), mirrored
/// as a minimal view rather than the full provider `Value`.
#[derive(Debug, Clone)]
pub struct SelectedRef {
    pub produces_security_candidates: bool,
    pub denominator_paths: Vec<String>,
}

/// Faithful port of `evaluateSelector(selector, context, selectedProviders)`.
/// Panics on an unsupported `op`, mirroring JS's `throw`.
pub fn evaluate_selector(
    selector: &Value,
    context: &SelectionContext,
    selected_providers: &[SelectedRef],
) -> SelectorVerdict {
    let op = get(selector, "op").and_then(str_of).unwrap_or_default();
    match op {
        "always" => SelectorVerdict { matched: true, paths: vec![], reason: "always".into() },
        "anyPath" => {
            let patterns: Vec<String> = arr_of(get(selector, "patterns").unwrap_or(&Value::Null))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let paths: Vec<String> = context.files.iter().filter(|p| path_matches(p, &patterns)).cloned().collect();
            let matched = !paths.is_empty();
            SelectorVerdict {
                reason: if matched { "path-match".into() } else { "no-path-match".into() },
                matched,
                paths,
            }
        }
        "anyExtension" => {
            let exts: Vec<String> = arr_of(get(selector, "extensions").unwrap_or(&Value::Null))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect();
            let parts: Vec<Vec<String>> = exts
                .iter()
                .map(|e| context.extension_to_paths.get(e).cloned().unwrap_or_default())
                .collect();
            let paths = union_paths(&parts);
            let matched = !paths.is_empty();
            SelectorVerdict {
                reason: if matched { "extension-match".into() } else { "no-extension-match".into() },
                matched,
                paths,
            }
        }
        "anyDependency" => {
            let names: Vec<String> = arr_of(get(selector, "names").unwrap_or(&Value::Null))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let matched_names: Vec<&String> = names.iter().filter(|n| context.dependencies.contains(*n)).collect();
            let evidence_parts: Vec<Vec<String>> = matched_names
                .iter()
                .map(|n| context.dependency_evidence.get(*n).cloned().unwrap_or_default())
                .collect();
            let evidence_paths = union_paths(&evidence_parts);
            let matched = !matched_names.is_empty();
            let paths = if matched { source_denominator(context, &evidence_paths) } else { vec![] };
            let reason = if matched {
                format!(
                    "dependencies:{};manifest-evidence:{}",
                    matched_names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
                    evidence_paths.join(",")
                )
            } else {
                "no-dependency-match".into()
            };
            SelectorVerdict { matched, paths, reason }
        }
        "anyPackageScript" => {
            let names: Vec<String> = arr_of(get(selector, "names").unwrap_or(&Value::Null))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let matched_names: Vec<&String> = names.iter().filter(|n| context.package_scripts.contains(*n)).collect();
            let evidence_parts: Vec<Vec<String>> = matched_names
                .iter()
                .map(|n| context.script_evidence.get(*n).cloned().unwrap_or_default())
                .collect();
            let evidence_paths = union_paths(&evidence_parts);
            let matched = !matched_names.is_empty();
            let paths = if matched { source_denominator(context, &evidence_paths) } else { vec![] };
            let reason = if matched {
                format!(
                    "scripts:{};manifest-evidence:{}",
                    matched_names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
                    evidence_paths.join(",")
                )
            } else {
                "no-script-match".into()
            };
            SelectorVerdict { matched, paths, reason }
        }
        "sourceFilesAtLeast" => {
            let count = get(selector, "count").and_then(|v| v.as_i64()).unwrap_or(1);
            let matched = (context.source_file_count as i64) >= count;
            SelectorVerdict {
                matched,
                paths: context.source_files.clone(),
                reason: format!("source-files:{}/{}", context.source_file_count, count),
            }
        }
        "any" | "all" => {
            let selectors = arr_of(get(selector, "selectors").unwrap_or(&Value::Null));
            let parts: Vec<SelectorVerdict> = selectors
                .iter()
                .map(|s| evaluate_selector(s, context, selected_providers))
                .collect();
            let matched = if op == "any" { parts.iter().any(|p| p.matched) } else { parts.iter().all(|p| p.matched) };
            let path_parts: Vec<Vec<String>> = parts.iter().filter(|p| p.matched).map(|p| p.paths.clone()).collect();
            let paths = union_paths(&path_parts);
            let reason = format!("{}:{}", op, parts.iter().map(|p| p.reason.clone()).collect::<Vec<_>>().join("|"));
            SelectorVerdict { matched, paths, reason }
        }
        "securityCandidatesSelected" => {
            let candidates: Vec<&SelectedRef> = selected_providers.iter().filter(|p| p.produces_security_candidates).collect();
            let path_parts: Vec<Vec<String>> = candidates.iter().map(|c| c.denominator_paths.clone()).collect();
            let matched = !candidates.is_empty();
            SelectorVerdict {
                matched,
                paths: union_paths(&path_parts),
                reason: format!("security-candidate-providers:{}", candidates.len()),
            }
        }
        "confirmedSecurityFinding" => SelectorVerdict { matched: false, paths: vec![], reason: "runtime-trigger-only".into() },
        other => panic!("unsupported provider selector op: {other}"),
    }
}

/// Faithful port of `denominator(paths, projection)`.
pub fn denominator(paths: &[String], projection: &Value) -> Value {
    let mut normalized: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in paths {
        normalized.insert(normalize_path(p));
    }
    let normalized: Vec<String> = normalized.into_iter().collect();
    if !normalized.is_empty() {
        json!({
            "source": "blueprint-selector",
            "pathCount": normalized.len(),
            "pathDigest": sha256_value(&json!(normalized)),
            "paths": normalized,
        })
    } else {
        let file_count = get(projection, "files").map(|f| arr_of(f).len()).unwrap_or(0);
        let path_digest = get(projection, "fileSetDigest")
            .and_then(str_of)
            .map(|s| s.to_string())
            .unwrap_or_else(|| sha256_value(&json!(Vec::<String>::new())));
        json!({
            "source": "repository",
            "pathCount": file_count,
            "pathDigest": path_digest,
        })
    }
}

/// Faithful port of `adaptProviderV2Registry(raw)`. `raw` is the parsed
/// `providers.json` document (`schemaVersion: 2, kind:
/// "legion-provider-registry"`).
pub fn adapt_provider_v2_registry(raw: &Value) -> Value {
    let mut providers: Vec<Value> = Vec::new();
    for provider in arr_of(get(raw, "providers").unwrap_or(&Value::Null)) {
        if get(provider, "selectable").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        let canonical_id = get(provider, "id").and_then(str_of).unwrap_or_default().to_string();
        let id = canonical_id.strip_prefix("legacy.").unwrap_or(&canonical_id).to_string();
        let runner = get(provider, "runner").cloned().unwrap_or(Value::Null);
        let role = get(provider, "role").and_then(str_of).unwrap_or_default().to_string();
        let candidate = role == "candidate-generator";
        let phase_in = get(provider, "phase").and_then(str_of).unwrap_or_default();
        let phase = match phase_in {
            "source" => "facts",
            "judgment" => "reasoning",
            other => other,
        };
        let runner_kind = get(&runner, "kind").and_then(str_of).unwrap_or_default();
        let out_runner = if runner_kind == "legacy-check" {
            json!({"kind": "legacy-check", "check": get(&runner, "check")})
        } else {
            runner.clone()
        };
        let mut out = Map::new();
        out.insert("id".into(), json!(id));
        out.insert("canonicalId".into(), json!(canonical_id));
        out.insert("providerVersion".into(), get(provider, "providerVersion").cloned().unwrap_or(Value::Null));
        out.insert("role".into(), json!(role));
        out.insert("phase".into(), json!(phase));
        out.insert("selector".into(), get(provider, "selector").cloned().unwrap_or(Value::Null));
        out.insert("allowWithoutBlueprint".into(), json!(id == "core.repo"));
        out.insert("runner".into(), out_runner);
        if runner_kind == "legacy-check" {
            let backs = get(&runner, "backs")
                .cloned()
                .or_else(|| get(provider, "lensIds").cloned())
                .unwrap_or(json!([]));
            let mut manifest = json!({
                "check": get(&runner, "check"),
                "tool": get(&runner, "tool"),
                "required_when": get(&runner, "requiredWhen"),
                "applies": get(&runner, "applies"),
                "parallel": get(&runner, "parallel").and_then(|v| v.as_bool()).unwrap_or(true),
                "backs": backs,
            });
            if phase_in == "runtime" {
                manifest.as_object_mut().unwrap().insert("phase".into(), json!("P2"));
            }
            out.insert("manifest".into(), manifest);
        }
        let benchmark_in = get(provider, "benchmark").cloned().unwrap_or(Value::Null);
        let mut benchmark = if benchmark_in.is_object() {
            benchmark_in
        } else {
            json!({"status": benchmark_in})
        };
        benchmark.as_object_mut().unwrap().insert("requiredForCleanClaim".into(), json!(true));
        out.insert("benchmark".into(), benchmark);
        out.insert("producesSecurityCandidates".into(), json!(candidate));
        out.insert("mayCloseOwnCandidates".into(), json!(!candidate));
        if role == "adjudicator" {
            out.insert("freshContextRequired".into(), json!(true));
        }
        providers.push(Value::Object(out));
    }

    let ids: HashSet<String> = providers
        .iter()
        .filter_map(|p| get(p, "id").and_then(str_of).map(|s| s.to_string()))
        .collect();

    let react_providers: Vec<Value> = ["react.hooks-config"].into_iter().filter(|id| ids.contains(*id)).map(|s| json!(s)).collect();
    let tauri_providers: Vec<Value> = ["tauri.contract-mirror", "tauri.capabilities"]
        .into_iter()
        .filter(|id| ids.contains(*id))
        .map(|s| json!(s))
        .collect();

    let coverage_families = vec![
        json!({
            "id": "framework.react", "kind": "framework", "qualification": "unproven",
            "selector": {"op": "anyDependency", "names": ["react", "react-dom"]},
            "providers": react_providers,
        }),
        json!({
            "id": "framework.tauri", "kind": "framework", "qualification": "unproven",
            "selector": {"op": "anyPath", "patterns": ["src-tauri/**"]},
            "providers": tauri_providers,
        }),
    ];

    json!({
        "schemaVersion": 1,
        "kind": "audit-provider-registry",
        "discoveryOwner": "blueprint",
        "planSeal": "sha256",
        "concurrency": "min(cpus-1,4)",
        "candidateAdjudication": "separate-context",
        "providers": providers,
        "coverageFamilies": coverage_families,
    })
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegistryValidationError {
    #[error("provider registry must be audit-provider-registry schemaVersion=1")]
    BadSchema,
    #[error("provider registry discoveryOwner must be blueprint")]
    BadDiscoveryOwner,
    #[error("provider registry must declare providers")]
    NoProviders,
    #[error("duplicate or missing provider id: {0}")]
    DuplicateOrMissingProviderId(String),
    #[error("provider {0} has no selector")]
    NoSelector(String),
    #[error("provider {0} has unsupported runner kind {1}")]
    UnsupportedRunnerKind(String, String),
    #[error("candidate generator {0} must set mayCloseOwnCandidates=false")]
    CandidateGeneratorMustCloseFalse(String),
    #[error("duplicate or missing legacy check: {0}")]
    DuplicateOrMissingCheck(String),
    #[error("provider {0} manifest.check must equal runner.check")]
    ManifestCheckMismatch(String),
    #[error("duplicate coverage family id: {0}")]
    DuplicateCoverageFamilyId(String),
    #[error("coverage family {0} has no selector")]
    CoverageFamilyNoSelector(String),
    #[error("coverage family {0} names unknown provider {1}")]
    CoverageFamilyUnknownProvider(String, String),
}

const RUNNER_KINDS: [&str; 3] = ["legacy-check", "runtime-script", "reasoning-contract"];

/// Faithful port of `validateProviderRegistry(registry)`. Returns the same
/// `registry` (by reference) on success, mirroring the JS `return registry`.
pub fn validate_provider_registry(registry: &Value) -> Result<(), RegistryValidationError> {
    if get(registry, "schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || get(registry, "kind").and_then(str_of) != Some("audit-provider-registry")
    {
        return Err(RegistryValidationError::BadSchema);
    }
    if get(registry, "discoveryOwner").and_then(str_of) != Some("blueprint") {
        return Err(RegistryValidationError::BadDiscoveryOwner);
    }
    let providers = arr_of(get(registry, "providers").unwrap_or(&Value::Null));
    if providers.is_empty() {
        return Err(RegistryValidationError::NoProviders);
    }
    let mut ids: HashSet<String> = HashSet::new();
    let mut checks: HashSet<String> = HashSet::new();
    for provider in providers {
        let id = get(provider, "id").and_then(str_of).unwrap_or_default().to_string();
        if id.is_empty() || !ids.insert(id.clone()) {
            return Err(RegistryValidationError::DuplicateOrMissingProviderId(id));
        }
        if get(provider, "selector").and_then(|s| get(s, "op")).and_then(str_of).is_none() {
            return Err(RegistryValidationError::NoSelector(id));
        }
        let runner_kind = get(provider, "runner").and_then(|r| get(r, "kind")).and_then(str_of).unwrap_or_default();
        if !RUNNER_KINDS.contains(&runner_kind) {
            return Err(RegistryValidationError::UnsupportedRunnerKind(id, runner_kind.to_string()));
        }
        let role = get(provider, "role").and_then(str_of).unwrap_or_default();
        if role == "candidate-generator" && get(provider, "mayCloseOwnCandidates").and_then(|v| v.as_bool()) != Some(false) {
            return Err(RegistryValidationError::CandidateGeneratorMustCloseFalse(id));
        }
        if runner_kind == "legacy-check" {
            let check = get(provider, "runner").and_then(|r| get(r, "check")).and_then(str_of).unwrap_or_default().to_string();
            if check.is_empty() || !checks.insert(check.clone()) {
                return Err(RegistryValidationError::DuplicateOrMissingCheck(check));
            }
            let manifest_check = get(provider, "manifest").and_then(|m| get(m, "check")).and_then(str_of);
            if manifest_check != Some(check.as_str()) {
                return Err(RegistryValidationError::ManifestCheckMismatch(id));
            }
        }
    }
    for family in arr_of(get(registry, "coverageFamilies").unwrap_or(&Value::Null)) {
        let id = get(family, "id").and_then(str_of).unwrap_or_default().to_string();
        if id.is_empty() || ids.contains(&id) {
            return Err(RegistryValidationError::DuplicateCoverageFamilyId(id));
        }
        ids.insert(id.clone());
        if get(family, "selector").and_then(|s| get(s, "op")).and_then(str_of).is_none() {
            return Err(RegistryValidationError::CoverageFamilyNoSelector(id));
        }
        for provider_id in arr_of(get(family, "providers").unwrap_or(&Value::Null)) {
            let pid = provider_id.as_str().unwrap_or_default();
            if !providers.iter().any(|p| get(p, "id").and_then(str_of) == Some(pid)) {
                return Err(RegistryValidationError::CoverageFamilyUnknownProvider(id, pid.to_string()));
            }
        }
    }
    Ok(())
}

/// Result of `selectProviders`, mirrors `{context, selected, excluded}`.
pub struct SelectionResult {
    pub context: SelectionContext,
    pub selected: Vec<Value>,
    pub excluded: Vec<Value>,
}

/// Options mirroring `{only, skip}`.
#[derive(Debug, Default, Clone)]
pub struct SelectOptions {
    pub only: Vec<String>,
    pub skip: Vec<String>,
}

/// Faithful port of `selectProviders(registry, projection, options)`.
pub fn select_providers(
    registry: &Value,
    projection: &Value,
    options: &SelectOptions,
) -> Result<SelectionResult, RegistryValidationError> {
    validate_provider_registry(registry)?;
    let context = build_selection_context(projection);
    let only: HashSet<&str> = options.only.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();
    let skip: HashSet<&str> = options.skip.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();

    let mut selected: Vec<Value> = Vec::new();
    let mut selected_refs: Vec<SelectedRef> = Vec::new();
    let mut excluded: Vec<Value> = Vec::new();

    let providers = arr_of(get(registry, "providers").unwrap_or(&Value::Null));
    for provider in providers {
        let op = get(provider, "selector").and_then(|s| get(s, "op")).and_then(str_of).unwrap_or_default();
        if op == "securityCandidatesSelected" || op == "confirmedSecurityFinding" {
            continue;
        }
        let id = get(provider, "id").and_then(str_of).unwrap_or_default().to_string();
        let runner_kind = get(provider, "runner").and_then(|r| get(r, "kind")).and_then(str_of).unwrap_or_default();
        let check = if runner_kind == "legacy-check" {
            get(provider, "runner").and_then(|r| get(r, "check")).and_then(str_of).map(|s| s.to_string())
        } else {
            None
        };
        if !only.is_empty() {
            if let Some(c) = &check {
                if !only.contains(c.as_str()) {
                    excluded.push(json!({"id": id, "check": check, "reason": "not-in-only-filter"}));
                    continue;
                }
            }
        }
        if let Some(c) = &check {
            if skip.contains(c.as_str()) {
                excluded.push(json!({"id": id, "check": check, "reason": "skipped-by-request"}));
                continue;
            }
        }
        let allow_without_blueprint = get(provider, "allowWithoutBlueprint").and_then(|v| v.as_bool()).unwrap_or(false);
        if !context.ready && !allow_without_blueprint {
            excluded.push(json!({"id": id, "check": check, "reason": "blueprint-unproven"}));
            continue;
        }
        let selector = get(provider, "selector").cloned().unwrap_or(Value::Null);
        let verdict = evaluate_selector(&selector, &context, &selected_refs);
        if !verdict.matched {
            excluded.push(json!({"id": id, "check": check, "reason": verdict.reason}));
            continue;
        }
        let mut rec = provider.clone();
        let obj = rec.as_object_mut().unwrap();
        obj.insert("selectionReason".into(), json!(verdict.reason));
        obj.insert("denominator".into(), denominator(&verdict.paths, projection));
        let produces = get(provider, "producesSecurityCandidates").and_then(|v| v.as_bool()).unwrap_or(false);
        selected_refs.push(SelectedRef { produces_security_candidates: produces, denominator_paths: verdict.paths.clone() });
        selected.push(rec);
    }

    // security.adjudication
    let adjudicator = providers.iter().find(|p| get(p, "id").and_then(str_of) == Some("security.adjudication"));
    let mut adjudicator_denominator: Option<Value> = None;
    if let Some(adjudicator) = adjudicator {
        let selector = get(adjudicator, "selector").cloned().unwrap_or(Value::Null);
        let verdict = evaluate_selector(&selector, &context, &selected_refs);
        if verdict.matched {
            let mut rec = adjudicator.clone();
            let denom = denominator(&verdict.paths, projection);
            let obj = rec.as_object_mut().unwrap();
            obj.insert("selectionReason".into(), json!(verdict.reason));
            obj.insert("denominator".into(), denom.clone());
            adjudicator_denominator = Some(denom);
            selected.push(rec);
        } else {
            excluded.push(json!({"id": get(adjudicator, "id"), "reason": verdict.reason}));
        }
    }

    // security.variant-analysis
    let variant = providers.iter().find(|p| get(p, "id").and_then(str_of) == Some("security.variant-analysis"));
    if let Some(variant) = variant {
        if let Some(denom) = &adjudicator_denominator {
            let mut rec = variant.clone();
            let obj = rec.as_object_mut().unwrap();
            obj.insert("selectionReason".into(), json!("conditional-on-confirmed-security-finding"));
            obj.insert("conditionalActivation".into(), json!("confirmed-security-finding"));
            obj.insert("denominator".into(), denom.clone());
            selected.push(rec);
        } else {
            excluded.push(json!({"id": get(variant, "id"), "reason": "no-security-adjudication-planned"}));
        }
    }

    Ok(SelectionResult { context, selected, excluded })
}

/// Result of `evaluateCoverageFamilies`, mirrors `{families, gaps}`.
pub struct CoverageResult {
    pub families: Vec<Value>,
    pub gaps: Vec<Value>,
}

/// Faithful port of `evaluateCoverageFamilies(registry, projection,
/// selectedProviders)`.
pub fn evaluate_coverage_families(registry: &Value, projection: &Value, selected_providers: &[Value]) -> CoverageResult {
    let context = build_selection_context(projection);
    let selected_refs: Vec<SelectedRef> = selected_providers
        .iter()
        .map(|p| SelectedRef {
            produces_security_candidates: get(p, "producesSecurityCandidates").and_then(|v| v.as_bool()).unwrap_or(false),
            denominator_paths: get(p, "denominator")
                .and_then(|d| get(d, "paths"))
                .map(|paths| arr_of(paths).iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
        })
        .collect();
    let selected_ids: HashSet<String> = selected_providers
        .iter()
        .filter_map(|p| get(p, "id").and_then(str_of).map(|s| s.to_string()))
        .collect();

    let mut families = Vec::new();
    let mut gaps = Vec::new();
    for family in arr_of(get(registry, "coverageFamilies").unwrap_or(&Value::Null)) {
        let selector = get(family, "selector").cloned().unwrap_or(Value::Null);
        let verdict = evaluate_selector(&selector, &context, &selected_refs);
        if !verdict.matched {
            continue;
        }
        let family_providers: Vec<String> = arr_of(get(family, "providers").unwrap_or(&Value::Null))
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let missing_providers: Vec<String> = family_providers.iter().filter(|id| !selected_ids.contains(*id)).cloned().collect();
        let qualification = get(family, "qualification").and_then(str_of).unwrap_or_default().to_string();
        let denom = denominator(&verdict.paths, projection);
        let record = json!({
            "id": get(family, "id"),
            "kind": get(family, "kind"),
            "qualification": qualification,
            "providers": family_providers,
            "missingProviders": missing_providers,
            "denominator": denom,
        });
        let family_id = get(family, "id").cloned().unwrap_or(Value::Null);
        if qualification != "complete" || !missing_providers.is_empty() {
            gaps.push(json!({
                "kind": "provider-coverage",
                "family": family_id,
                "qualification": qualification,
                "missingProviders": missing_providers,
                "evidence": record.get("denominator").cloned().unwrap_or(Value::Null),
            }));
        }
        families.push(record);
    }
    CoverageResult { families, gaps }
}

/// Faithful port of `registryDigest(registry)`.
pub fn registry_digest(registry: &Value) -> String {
    sha256_value(registry)
}

/// Faithful port of `renderManifest(registry)`.
pub fn render_manifest(registry: &Value) -> Value {
    let providers_in = arr_of(get(registry, "providers").unwrap_or(&Value::Null));
    let checks: Vec<Value> = providers_in
        .iter()
        .filter(|p| get(p, "manifest").and_then(|m| get(m, "check")).is_some())
        .map(|p| {
            let manifest = get(p, "manifest").cloned().unwrap_or(Value::Null);
            let mut obj = json!({
                "provider": get(p, "id"),
                "check": get(&manifest, "check"),
                "tool": get(&manifest, "tool"),
                "required_when": get(&manifest, "required_when"),
                "applies": get(&manifest, "applies"),
                "parallel": get(&manifest, "parallel"),
                "backs": get(&manifest, "backs"),
                "benchmark_status": get(p, "benchmark").and_then(|b| get(b, "status")).cloned().unwrap_or(json!("unproven")),
            });
            if get(&manifest, "flag_if_absent").and_then(|v| v.as_bool()) == Some(true) {
                obj.as_object_mut().unwrap().insert("flag_if_absent".into(), json!(true));
            }
            if let Some(phase) = get(&manifest, "phase") {
                obj.as_object_mut().unwrap().insert("phase".into(), phase.clone());
            }
            obj
        })
        .collect();
    let providers: Vec<Value> = providers_in
        .iter()
        .map(|p| {
            let role = get(p, "role").and_then(str_of).unwrap_or_default();
            let may_close_default = if role == "candidate-generator" {
                json!(false)
            } else {
                json!(get(p, "mayCloseOwnCandidates").and_then(|v| v.as_bool()).unwrap_or(true))
            };
            json!({
                "id": get(p, "id"),
                "role": get(p, "role"),
                "phase": get(p, "phase"),
                "runner": get(p, "runner"),
                "benchmark_status": get(p, "benchmark").and_then(|b| get(b, "status")).cloned().unwrap_or(json!("unproven")),
                "required_for_clean_claim": get(p, "benchmark").and_then(|b| get(b, "requiredForCleanClaim")).and_then(|v| v.as_bool()).unwrap_or(false),
                "allow_without_blueprint": get(p, "allowWithoutBlueprint").and_then(|v| v.as_bool()).unwrap_or(false),
                "produces_security_candidates": get(p, "producesSecurityCandidates").and_then(|v| v.as_bool()).unwrap_or(false),
                "fresh_context_required": get(p, "freshContextRequired").and_then(|v| v.as_bool()).unwrap_or(false),
                "may_close_own_candidates": may_close_default,
            })
        })
        .collect();
    json!({
        "version": 3,
        "generated_from": "src/registry/providers.json",
        "generated_sources": ["src/registry/providers.json", "src/registry/providers-runtime.json"],
        "discovery_owner": get(registry, "discoveryOwner"),
        "concurrency": get(registry, "concurrency"),
        "notes": "Generated from the complete declarative provider registry. Scanner checks remain backward-compatible; providers mirrors every executable provider contract.",
        "checks": checks,
        "providers": providers,
    })
}

/// Faithful port of `loadProviderRegistry`'s live (schemaVersion===2) path:
/// adapt then validate. Callers own reading `providers.json` off disk; pass
/// the parsed `Value` in as `raw`.
pub fn load_provider_registry_v2(raw: &Value) -> Result<Value, RegistryValidationError> {
    let registry = adapt_provider_v2_registry(raw);
    validate_provider_registry(&registry)?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_raw() -> Value {
        json!({
            "schemaVersion": 2,
            "kind": "legion-provider-registry",
            "providers": [
                {
                    "id": "core.repo",
                    "role": "context",
                    "phase": "source",
                    "selector": {"op": "always"},
                    "runner": {"kind": "legacy-check", "check": "core-repo", "tool": "git", "requiredWhen": "always", "applies": "all", "parallel": true},
                    "benchmark": "measured",
                },
                {
                    "id": "legacy.security.scan",
                    "role": "candidate-generator",
                    "phase": "runtime",
                    "selector": {"op": "anyDependency", "names": ["express"]},
                    "runner": {"kind": "runtime-script", "script": "x.mjs"},
                    "benchmark": {"status": "planned"},
                },
                {
                    "id": "react.hooks-config",
                    "role": "context",
                    "phase": "source",
                    "selector": {"op": "anyExtension", "extensions": ["tsx"]},
                    "runner": {"kind": "legacy-check", "check": "react-hooks", "tool": "eslint", "requiredWhen": "always", "applies": "react", "parallel": true},
                    "benchmark": "measured",
                },
            ],
        })
    }

    #[test]
    fn adapt_strips_legacy_prefix_and_sets_candidate_flags() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let providers = registry.get("providers").unwrap().as_array().unwrap();
        let scan = providers.iter().find(|p| p["canonicalId"] == "legacy.security.scan").unwrap();
        assert_eq!(scan["id"], "security.scan");
        assert_eq!(scan["producesSecurityCandidates"], true);
        assert_eq!(scan["mayCloseOwnCandidates"], false);
        let repo = providers.iter().find(|p| p["id"] == "core.repo").unwrap();
        assert_eq!(repo["allowWithoutBlueprint"], true);
    }

    #[test]
    fn adapt_builds_coverage_families_only_for_present_providers() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let families = registry.get("coverageFamilies").unwrap().as_array().unwrap();
        let react = families.iter().find(|f| f["id"] == "framework.react").unwrap();
        assert_eq!(react["providers"], json!(["react.hooks-config"]));
        let tauri = families.iter().find(|f| f["id"] == "framework.tauri").unwrap();
        assert_eq!(tauri["providers"], json!([]));
    }

    #[test]
    fn validate_accepts_adapted_registry() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        assert!(validate_provider_registry(&registry).is_ok());
    }

    #[test]
    fn validate_rejects_bad_discovery_owner() {
        let mut registry = adapt_provider_v2_registry(&sample_raw());
        registry["discoveryOwner"] = json!("not-blueprint");
        assert_eq!(validate_provider_registry(&registry), Err(RegistryValidationError::BadDiscoveryOwner));
    }

    #[test]
    fn glob_matches_double_star_prefix_and_extension() {
        assert!(path_matches("src/lib/core/index.mjs", &["src/**/*.mjs".to_string()]));
        assert!(path_matches("src-tauri/Cargo.toml", &["src-tauri/**".to_string()]));
        assert!(!path_matches("src/lib/core/index.rs", &["src/**/*.mjs".to_string()]));
    }

    #[test]
    fn select_providers_excludes_when_projection_not_ready_unless_allowed() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let projection = json!({"state": "pending", "files": []});
        let result = select_providers(&registry, &projection, &SelectOptions::default()).unwrap();
        let selected_ids: Vec<&str> = result.selected.iter().filter_map(|p| p["id"].as_str()).collect();
        assert!(selected_ids.contains(&"core.repo")); // allowWithoutBlueprint
        assert!(!selected_ids.contains(&"security.scan"));
    }

    #[test]
    fn select_providers_matches_ready_projection_with_dependency() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let projection = json!({
            "state": "ready",
            "files": ["package.json"],
            "auditFacts": {"packageManifests": [{"path": "package.json", "dependencies": ["express"], "scripts": []}]},
        });
        let result = select_providers(&registry, &projection, &SelectOptions::default()).unwrap();
        let selected_ids: Vec<&str> = result.selected.iter().filter_map(|p| p["id"].as_str()).collect();
        assert!(selected_ids.contains(&"security.scan"));
    }

    #[test]
    fn coverage_families_report_missing_providers_as_gaps() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let projection = json!({"state": "ready", "files": ["src-tauri/Cargo.toml"]});
        let result = evaluate_coverage_families(&registry, &projection, &[]);
        let tauri_gap = result.gaps.iter().find(|g| g["family"] == "framework.tauri");
        assert!(tauri_gap.is_some());
    }

    #[test]
    fn registry_digest_is_stable() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        assert_eq!(registry_digest(&registry), registry_digest(&registry));
    }

    #[test]
    fn render_manifest_only_includes_providers_with_manifest_check() {
        let registry = adapt_provider_v2_registry(&sample_raw());
        let manifest = render_manifest(&registry);
        let checks = manifest["checks"].as_array().unwrap();
        // legacy-check providers (core.repo, react.hooks-config) get a manifest entry;
        // the runtime-script provider (security.scan) does not.
        assert_eq!(checks.len(), 2);
        assert_eq!(manifest["version"], 3);
    }

    #[test]
    fn load_provider_registry_v2_adapts_and_validates() {
        let registry = load_provider_registry_v2(&sample_raw()).unwrap();
        assert_eq!(registry["kind"], "audit-provider-registry");
    }
}
