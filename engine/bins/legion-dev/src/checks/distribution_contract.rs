// Port of `scripts/check-distribution-contract.mjs`. Cross-validates
// release/distribution-contract.json, release/publication-policy.json,
// packaging/channels.json, package.json, and right-release.config.mjs
// against the frozen distribution invariants.

use super::read_json;
use serde_json::Value;
use std::path::Path;

const CONTRACT_PATH: &str = "release/distribution-contract.json";
const POLICY_PATH: &str = "release/publication-policy.json";
const CHANNELS_PATH: &str = "packaging/channels.json";
const RELEASE_CONFIG_PATH: &str = "right-release.config.mjs";
const BOOTSTRAP_URL: &str = "https://legion.orthiclabs.com/install.ps1";
const BOOTSTRAP_PROVIDER: &str = "rightkit-worker-r2";
const BOOTSTRAP_MODE: &str = "worker-r2-stable-object";
const BOOTSTRAP_OBJECT_KEY: &str = "legion/install.ps1";
const BOOTSTRAP_BUCKET: &str = "rightapps-downloads";
const RETIRED_PAGES_PATHS: &[&str] = &["docs/CNAME", "docs/install.ps1", "site/install.ps1"];
const PAYLOAD_AUTHORITY: &str = "immutable-github-release";
const MANIFEST_AUTHORITY: &str = "release-manifest.json+release-manifest.cat";
const MANIFEST_FILE: &str = "release-manifest.json";
const MANIFEST_SIGNATURE: &str = "release-manifest.cat";
const SIGNATURE_ALGORITHM: &str = "authenticode-catalog-sha256";
const SIGNATURE_PROVIDER: &str = "windows-authenticode-catalog";
const SIGNATURE_PROVIDER_VERSION: i64 = 1;
const CHECKSUMS_FILE: &str = "checksums.json";
const CHECKSUMS_ROLE: &str = "manifest-bound-convenience";
const PUBLISHER: &str = "rightkit-release";
const REQUIRED_EVIDENCE: &[&str] = &[
    "platform-artifacts",
    "platform-signatures",
    "provenance-attestations",
    "signed-release-manifest",
    "bootstrap-transaction",
    "rollback-transaction",
    "client-integration-health",
    "channel-authorization",
];

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn same(a: &Value, b: &Value) -> bool {
    a == b
}

fn check_manifest_authority(value: Option<&Value>, issues: &mut Vec<String>, label: &str) {
    let value = value.cloned().unwrap_or(Value::Null);
    if s(&value, "manifestAuthority") != Some(MANIFEST_AUTHORITY) {
        issues.push(format!("{label} must use release-manifest.json + release-manifest.cat"));
    }
    let manifest = value.get("manifest").cloned().unwrap_or(Value::Null);
    if s(&manifest, "file") != Some(MANIFEST_FILE) || s(&manifest, "signature") != Some(MANIFEST_SIGNATURE) {
        issues.push(format!("{label} manifest files are not release-manifest.json + release-manifest.cat"));
    }
    if s(&manifest, "signatureAlgorithm") != Some(SIGNATURE_ALGORITHM) {
        issues.push(format!("{label} manifest signature algorithm is not Authenticode catalog SHA-256"));
    }
    let provider_version_ok = manifest.get("signatureProviderVersion").and_then(|v| v.as_i64())
        == Some(SIGNATURE_PROVIDER_VERSION);
    if s(&manifest, "signatureProvider") != Some(SIGNATURE_PROVIDER) || !provider_version_ok {
        issues.push(format!("{label} manifest signature provider is not windows-authenticode-catalog v1"));
    }
    let checksums = value.get("checksums").cloned().unwrap_or(Value::Null);
    if s(&checksums, "file") != Some(CHECKSUMS_FILE) || s(&checksums, "role") != Some(CHECKSUMS_ROLE) {
        issues.push(format!("{label} checksums must be manifest-bound convenience evidence"));
    }
}

fn check_no_retired_claims(value: &Value, issues: &mut Vec<String>, label: &str) {
    let text = value.to_string().to_lowercase();
    if text.contains("release-manifest.sig") {
        issues.push(format!("{label} contains retired release-manifest.sig authority"));
    }
    if text.contains("cms") {
        issues.push(format!("{label} contains a detached CMS claim"));
    }
    if text.contains("bespoke uploader") || text.contains("custom uploader") {
        issues.push(format!("{label} contains a bespoke uploader claim"));
    }
}

pub struct Report {
    pub ok: bool,
    pub issues: Vec<String>,
}

pub fn validate(root: &Path) -> Report {
    let mut issues: Vec<String> = Vec::new();
    let contract = match read_json(&root.join(CONTRACT_PATH)) {
        Ok(v) => v,
        Err(e) => return Report { ok: false, issues: vec![e] },
    };
    let policy = match read_json(&root.join(POLICY_PATH)) {
        Ok(v) => v,
        Err(e) => return Report { ok: false, issues: vec![e] },
    };
    let channels = match read_json(&root.join(CHANNELS_PATH)) {
        Ok(v) => v,
        Err(e) => return Report { ok: false, issues: vec![e] },
    };
    let pkg = match read_json(&root.join("package.json")) {
        Ok(v) => v,
        Err(e) => return Report { ok: false, issues: vec![e] },
    };

    let null = Value::Null;
    if contract.get("schemaVersion").and_then(|v| v.as_i64()) != Some(2)
        || s(&contract, "kind") != Some("legion-distribution-contract")
    {
        issues.push("invalid release/distribution-contract.json".to_string());
    }
    let node_package = contract.get("nodePackage").unwrap_or(&null);
    if s(&pkg, "name") != s(node_package, "name") {
        issues.push("package name differs from distribution contract".to_string());
    }
    if s(node_package, "access") != Some("private-development-tooling")
        || node_package.get("public").and_then(|v| v.as_bool()) != Some(false)
        || pkg.get("private").and_then(|v| v.as_bool()) != Some(true)
    {
        issues.push("Node package must remain private development tooling".to_string());
    }
    if policy.get("schemaVersion").and_then(|v| v.as_i64()) != Some(2)
        || s(&policy, "kind") != Some("legion-publication-policy")
    {
        issues.push("invalid release/publication-policy.json".to_string());
    }
    if s(&policy, "contract") != Some(CONTRACT_PATH) {
        issues.push("publication policy is not bound to distribution contract".to_string());
    }
    let npm_channel = policy.pointer("/channels/npm").unwrap_or(&null);
    if npm_channel.get("allowed").and_then(|v| v.as_bool()) != Some(false)
        || s(npm_channel, "reason") != Some("private-development-tooling")
    {
        issues.push("npm publication must be denied as private development tooling".to_string());
    }
    let native = contract.get("nativeRelease").cloned().unwrap_or_else(|| serde_json::json!({}));
    let native_channel = s(&native, "channel").unwrap_or("");
    let grant = policy
        .get("channels")
        .and_then(|c| c.get(native_channel))
        .cloned()
        .unwrap_or(Value::Null);
    let native_status_available = s(&native, "status") == Some("available");
    let grant_allowed = grant.get("allowed").and_then(|v| v.as_bool());
    if grant.is_null() || grant_allowed != Some(native_status_available) {
        issues.push("native release policy differs from native release status".to_string());
    }
    let empty_arr = serde_json::json!([]);
    let grant_evidence = grant.get("requiredEvidence").unwrap_or(&empty_arr);
    let native_evidence = native.get("requiredEvidence").unwrap_or(&empty_arr);
    if !same(grant_evidence, native_evidence) {
        issues.push("native release evidence list differs from distribution contract".to_string());
    }
    let required_evidence_json: Value = serde_json::json!(REQUIRED_EVIDENCE);
    if !same(native_evidence, &required_evidence_json) {
        issues.push("native release evidence is incomplete or reordered".to_string());
    }
    if native_channel != "direct-bootstrap" {
        issues.push("native release must use direct-bootstrap".to_string());
    }
    if native.get("public").and_then(|v| v.as_bool()) != Some(true)
        || s(&native, "status") != Some("blocked")
    {
        issues.push("native direct-bootstrap publication must remain blocked until evidence is complete".to_string());
    }
    if s(&native, "payloadAuthority") != Some(PAYLOAD_AUTHORITY) {
        issues.push("native payload authority must be immutable GitHub Releases".to_string());
    }
    if s(&native, "bootstrapAuthority") != Some(BOOTSTRAP_URL) {
        issues.push("native bootstrap authority must be the stable Worker route".to_string());
    }
    if s(&native, "manifestAuthority") != Some(MANIFEST_AUTHORITY) {
        issues.push("signed release manifest catalog must be sole release authority".to_string());
    }
    if native
        .get("requiredEvidence")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|x| x.as_str() == Some("package-manager-metadata")))
        .unwrap_or(false)
    {
        issues.push("package-manager metadata cannot be required release evidence".to_string());
    }
    check_manifest_authority(policy.get("authority"), &mut issues, "publication policy authority");
    let policy_authority = policy.get("authority").unwrap_or(&null);
    if s(policy_authority, "payload") != Some(PAYLOAD_AUTHORITY)
        || s(policy_authority, "bootstrap") != Some("rightkit-worker-r2-stable-object")
        || s(&policy, "publisher") != Some(PUBLISHER)
    {
        issues.push(
            "publication policy authority is not frozen to GitHub payloads, RightKit Worker+R2 bootstrap, and RightKit Release"
                .to_string(),
        );
    }
    if s(&grant, "payloadAuthority") != Some(PAYLOAD_AUTHORITY)
        || s(&grant, "bootstrapProvider") != Some(BOOTSTRAP_PROVIDER)
        || s(&grant, "bootstrapMode") != Some(BOOTSTRAP_MODE)
        || s(&grant, "stableUrl") != Some(BOOTSTRAP_URL)
        || s(&grant, "publisher") != Some(PUBLISHER)
    {
        issues.push("direct-bootstrap policy authority is incomplete".to_string());
    }
    check_manifest_authority(Some(&grant), &mut issues, "direct-bootstrap policy");

    if channels.get("schemaVersion").and_then(|v| v.as_i64()) != Some(2)
        || s(&channels, "kind") != Some("legion-distribution-channels")
    {
        issues.push("invalid packaging/channels.json".to_string());
    }
    if s(&channels, "contract") != Some(CONTRACT_PATH) {
        issues.push("distribution channel ledger is not bound to distribution contract".to_string());
    }
    if s(&channels, "versionSource") != Some("release/version.json")
        || s(&channels, "artifactSource") != Some(PAYLOAD_AUTHORITY)
    {
        issues.push("distribution channel ledger is not bound to versioned immutable GitHub payloads".to_string());
    }
    if s(&channels, "publicationOwner") != Some("RightKit Release") {
        issues.push("distribution channel publisher must be RightKit Release".to_string());
    }
    let channels_bootstrap = channels.get("bootstrap").unwrap_or(&null);
    if s(channels_bootstrap, "provider") != Some(BOOTSTRAP_PROVIDER)
        || s(channels_bootstrap, "mode") != Some(BOOTSTRAP_MODE)
        || s(channels_bootstrap, "stableUrl") != Some(BOOTSTRAP_URL)
        || s(channels_bootstrap, "objectKey") != Some(BOOTSTRAP_OBJECT_KEY)
    {
        issues.push("distribution channel bootstrap must be the RightKit Worker+R2 stable object only".to_string());
    }
    let channel_manifest = channels.get("manifest").cloned().unwrap_or(Value::Null);
    let synthetic = serde_json::json!({
        "manifestAuthority": channel_manifest.get("authority").cloned().unwrap_or(Value::Null),
        "manifest": channel_manifest,
        "checksums": channels.get("checksums").cloned().unwrap_or(Value::Null),
    });
    check_manifest_authority(Some(&synthetic), &mut issues, "distribution channel authority");

    let channels_map = channels.get("channels").unwrap_or(&null);
    let native_ch = channels_map.get(native_channel).unwrap_or(&null);
    if s(native_ch, "status") != s(&native, "status") {
        issues.push("primary distribution channel differs from native release status".to_string());
    }
    if s(native_ch, "stableUrl") != s(&native, "bootstrapAuthority") {
        issues.push("bootstrap URL differs from distribution contract".to_string());
    }
    let direct = native_ch;
    if s(direct, "payloadAuthority") != Some(PAYLOAD_AUTHORITY)
        || s(direct, "bootstrapProvider") != Some(BOOTSTRAP_PROVIDER)
        || s(direct, "bootstrapMode") != Some(BOOTSTRAP_MODE)
        || s(direct, "manifestAuthority") != Some(MANIFEST_AUTHORITY)
        || s(direct, "publicationOwner") != Some("RightKit Release")
    {
        issues.push("direct-bootstrap channel authority is incomplete".to_string());
    }
    check_manifest_authority(Some(direct), &mut issues, "direct-bootstrap channel");

    if let Some(package_managers) = contract.get("packageManagers").and_then(|v| v.as_object()) {
        for (id, status) in package_managers {
            let ch = channels_map.get(id).unwrap_or(&null);
            if ch.get("status") != Some(status) {
                issues.push(format!("{id} status differs from distribution contract"));
            }
            if ch.get("required").and_then(|v| v.as_bool()) != Some(false) {
                issues.push(format!("{id} cannot be a required release channel"));
            }
        }
    }

    let config_path = root.join(RELEASE_CONFIG_PATH);
    if !config_path.is_file() {
        issues.push("right-release.config.mjs is missing".to_string());
    } else if let Ok(config) = std::fs::read_to_string(&config_path) {
        for marker in [
            "provider: \"github-releases\"",
            "repository: \"Orthic-Labs/legion\"",
            "payloadAuthority: \"immutable-github-release\"",
            "manifestAuthority: \"release-manifest.json+release-manifest.cat\"",
            "signatureAlgorithm: \"authenticode-catalog-sha256\"",
            "signatureProvider: \"windows-authenticode-catalog\"",
            "signatureProviderVersion: 1",
            "role: \"manifest-bound-convenience\"",
            "provider: \"rightkit-worker-r2\"",
            "mode: \"worker-r2-stable-object\"",
            "publisher: \"rightkit-release\"",
            "publishBlocked:",
        ] {
            if !config.contains(marker) {
                issues.push(format!("right-release config is missing {marker}"));
            }
        }
        let lower = config.to_lowercase();
        let retired_hit = lower.contains("release-manifest.sig")
            || regex_has_word(&lower, "cms")
            || lower.contains("bespoke uploader")
            || lower.contains("custom uploader")
            || lower.contains("packagemanager: \"winget\"")
            || lower.contains("packagemanager: \"homebrew\"")
            || lower.contains("packagemanager:\"winget\"")
            || lower.contains("packagemanager:\"homebrew\"");
        if retired_hit {
            issues.push("right-release config contains a retired distribution authority".to_string());
        }
    }

    let mut declared_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for candidate in [
        native.pointer("/bootstrap/stableKey").and_then(|v| v.as_str()),
        grant.get("objectKey").and_then(|v| v.as_str()),
        channels_bootstrap.get("objectKey").and_then(|v| v.as_str()),
        native_ch.get("objectKey").and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        declared_keys.insert(candidate.to_string());
    }
    if declared_keys.len() != 1 || !declared_keys.contains(BOOTSTRAP_OBJECT_KEY) {
        issues.push("bootstrap object key is missing or inconsistent across contract, policy, and channels".to_string());
    }
    match parse_https_url(BOOTSTRAP_URL) {
        Some((hostname, path)) => {
            let first_label = hostname.split('.').next().unwrap_or("");
            let projected = format!("{first_label}{path}");
            if projected != BOOTSTRAP_OBJECT_KEY {
                issues.push(format!("bootstrap stable URL does not project onto {BOOTSTRAP_OBJECT_KEY}"));
            }
        }
        None => issues.push("bootstrap stable URL must be HTTPS".to_string()),
    }
    for bucket in [
        native.pointer("/bootstrap/bucket").and_then(|v| v.as_str()),
        grant.get("bucket").and_then(|v| v.as_str()),
        channels_bootstrap.get("bucket").and_then(|v| v.as_str()),
    ] {
        if bucket != Some(BOOTSTRAP_BUCKET) {
            issues.push("bootstrap R2 bucket is missing or not the shared downloads bucket".to_string());
        }
    }
    for retired in RETIRED_PAGES_PATHS {
        if root.join(retired).exists() {
            issues.push(format!("retired GitHub Pages bootstrap path still present: {retired}"));
        }
    }
    check_no_retired_claims(&policy, &mut issues, "publication policy");
    check_no_retired_claims(&channels, &mut issues, "distribution channels");

    Report { ok: issues.is_empty(), issues }
}

/// Minimal `https://host/path` split (no query/fragment handling needed for
/// the one constant URL this function is called with).
fn parse_https_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let (host, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    Some((host.to_string(), path.to_string()))
}

fn regex_has_word(haystack: &str, word: &str) -> bool {
    // Manual `\bcms\b` boundary check (no lookaround needed here: word chars only).
    let bytes = haystack.as_bytes();
    let wb = word.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(word) {
        let abs = start + pos;
        let before_ok = abs == 0 || !is_word(bytes[abs - 1]);
        let end = abs + wb.len();
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

pub fn run(root: &Path) -> bool {
    let result = validate(root);
    if result.ok {
        println!("distribution contract: consistent");
    } else {
        for issue in &result.issues {
            eprintln!("{issue}");
        }
    }
    result.ok
}
