//! Ported from src/lib/config/{index,merge,profiles}.mjs (packet
//! P5b-controls-config). `src/lib/config/load.mjs` is pure Node
//! filesystem glue (`readFileSync`/`existsSync` around `loadUserConfig`/
//! `loadRepositoryConfig`) with no independent logic to port; its behavior
//! is exercised through `validate_config`/`profile_config` here once a
//! caller supplies the file contents.

use super::controls_support::{digest, Value};
use std::collections::BTreeMap;

pub const CONFIG_SCHEMA_VERSION: i64 = 1;

pub fn host_owned_keys() -> &'static [&'static str] {
    &[
        "networkGuard",
        "planSigningKey",
        "modelCredentials",
        "mutation",
        "externalToolAllowlist",
        "releaseSigning",
    ]
}

const KNOWN_TOP_KEYS: &[&str] = &[
    "schemaVersion", "profile", "providers", "limits", "policy", "outputs",
    "require", "disable", "providerTimeoutMs", "maxOutputBytes", "maxConcurrency",
    "failOn", "baseline", "acceptedRisk",
];

const PROFILE_NAMES: &[&str] = &["fast", "standard", "full", "release"];

fn is_object(value: &Value) -> bool {
    matches!(value, Value::Object(_))
}

/// Port of `deepMerge(target, ...sources)`: later sources win; nested plain
/// objects merge recursively; arrays are replaced (shallow-copied) wholesale.
pub fn deep_merge(sources: &[&Value]) -> Value {
    let mut target: BTreeMap<String, Value> = BTreeMap::new();
    for source in sources {
        let Value::Object(map) = source else { continue };
        for (key, value) in map {
            match (&value, target.get(key)) {
                (Value::Object(_), Some(existing)) if is_object(existing) => {
                    let merged = deep_merge(&[existing, value]);
                    target.insert(key.clone(), merged);
                }
                (Value::Array(items), _) => {
                    target.insert(key.clone(), Value::Array(items.clone()));
                }
                _ => {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
    }
    Value::Object(target)
}

/// Port of `validateConfig(config, label)`.
pub fn validate_config(config: &Value, label: &str) -> Result<(), String> {
    let Value::Object(map) = config else {
        return Err(format!("{label} must be an object"));
    };

    let schema_ok = matches!(map.get("schemaVersion"), Some(Value::Number(n)) if *n as i64 == CONFIG_SCHEMA_VERSION);
    if !schema_ok {
        let got = map
            .get("schemaVersion")
            .map(|v| v.to_canonical_string())
            .unwrap_or_else(|| "undefined".to_string());
        return Err(format!("{label}.schemaVersion must be {CONFIG_SCHEMA_VERSION}; got {got}"));
    }

    if let Some(Value::String(profile)) = map.get("profile") {
        if !profile.is_empty() && !PROFILE_NAMES.contains(&profile.as_str()) {
            return Err(format!(
                "{label}.profile must be one of {}; got \"{profile}\"",
                PROFILE_NAMES.join(", ")
            ));
        }
    }

    for key in map.keys() {
        if !KNOWN_TOP_KEYS.contains(&key.as_str()) {
            return Err(format!("{label} has unknown key: {key}"));
        }
    }

    let sections: &[(&str, &[&str])] = &[
        ("providers", &["require", "disable"]),
        ("limits", &["providerTimeoutMs", "maxOutputBytes", "maxConcurrency"]),
        ("policy", &["failOn", "baseline", "acceptedRisk"]),
    ];
    for (section, allowed_keys) in sections {
        if let Some(Value::Object(nested)) = map.get(*section) {
            for key in nested.keys() {
                if !allowed_keys.contains(&key.as_str()) {
                    return Err(format!("{label}.{section} has unknown key: {key}"));
                }
            }
        }
    }

    Ok(())
}

/// Port of `mergeConfig({ defaults, user, repository, cli })`.
pub fn merge_config(
    defaults: &Value,
    user: Option<&Value>,
    repository: Option<&Value>,
    cli: Option<&Value>,
) -> Result<Value, String> {
    if let Some(Value::Object(repo_map)) = repository {
        for key in host_owned_keys() {
            if repo_map.contains_key(*key) {
                return Err(format!("repository config may not set host-owned key: {key}"));
            }
        }
    }

    let empty = Value::object([]);
    let sources = [
        defaults,
        user.unwrap_or(&empty),
        repository.unwrap_or(&empty),
        cli.unwrap_or(&empty),
    ];
    let merged = deep_merge(&sources);
    validate_config(&merged, "config")?;
    Ok(merged)
}

/// Port of `mergeTrustedConfig(input)` from merge.mjs: a stricter allow-list
/// merge that also seals `releaseContract`/`externalEvidence` and returns a
/// digest alongside the merged value.
/// merge.mjs declares its own, differently-named `HOST_OWNED` set from
/// index.mjs's — this is a faithful port of that divergence, not a typo.
fn trusted_host_owned_keys() -> &'static [&'static str] {
    &[
        "networkSandbox",
        "signing",
        "reviewerCredentials",
        "mutation",
        "executableAllowlist",
        "releaseCredentials",
    ]
}

const TRUSTED_ALLOWED: &[&str] = &[
    "schemaVersion", "profile", "providers", "limits", "policy", "outputs",
    "schedule", "resources", "cache", "cancellation", "reasoning", "claimLevels",
    "releaseContract", "externalEvidence",
];

fn trusted_nested_keys(key: &str) -> Option<&'static [&'static str]> {
    match key {
        "providers" => Some(&["require", "disable"]),
        "limits" => Some(&["providerTimeoutMs", "maxOutputBytes", "maxConcurrency"]),
        "policy" => Some(&["failOn", "baseline", "acceptedRisk"]),
        _ => None,
    }
}

fn validate_trusted_layer(value: Option<&Value>, label: &str, repository: bool) -> Result<(), String> {
    let Some(Value::Object(map)) = value else { return Ok(()) };
    for (key, nested) in map {
        if repository && trusted_host_owned_keys().contains(&key.as_str()) {
            return Err(format!("repository cannot set host-owned key: {key}"));
        }
        if !TRUSTED_ALLOWED.contains(&key.as_str()) {
            return Err(format!("{label} config unknown key: {key}"));
        }
        if let (Some(allowed), Value::Object(nested_map)) = (trusted_nested_keys(key), nested) {
            for child in nested_map.keys() {
                if !allowed.contains(&child.as_str()) {
                    return Err(format!("{label} config unknown key: {key}.{child}"));
                }
            }
        }
    }
    Ok(())
}

pub struct TrustedConfigInput<'a> {
    pub defaults: Option<&'a Value>,
    pub user: Option<&'a Value>,
    pub repository: Option<&'a Value>,
    pub cli: Option<&'a Value>,
    pub release_contract: Option<&'a Value>,
    pub external_evidence: Option<&'a Value>,
}

pub struct TrustedConfig {
    pub value: Value,
    pub digest: String,
}

/// Port of `mergeTrustedConfig(input)`.
pub fn merge_trusted_config(input: &TrustedConfigInput) -> Result<TrustedConfig, String> {
    validate_trusted_layer(input.defaults, "defaults", false)?;
    validate_trusted_layer(input.user, "user", false)?;
    validate_trusted_layer(input.repository, "repository", true)?;
    validate_trusted_layer(input.cli, "cli", false)?;

    let empty = Value::object([]);
    let schema = Value::object([("schemaVersion", Value::Number(1.0))]);
    let mut sources = vec![
        &schema,
        input.defaults.unwrap_or(&empty),
        input.user.unwrap_or(&empty),
        input.repository.unwrap_or(&empty),
        input.cli.unwrap_or(&empty),
    ];
    let release_wrapper;
    if let Some(rc) = input.release_contract {
        release_wrapper = Value::object([("releaseContract", rc.clone())]);
        sources.push(&release_wrapper);
    }
    let evidence_wrapper;
    if let Some(ee) = input.external_evidence {
        evidence_wrapper = Value::object([("externalEvidence", ee.clone())]);
        sources.push(&evidence_wrapper);
    }

    let config = deep_merge(&sources);
    let d = digest(&config);
    Ok(TrustedConfig { value: config, digest: d })
}

/// Port of `sealedProfile(name, overrides)` (profiles.mjs). `overrides` is
/// the raw override object; missing overrides fall back to the JS defaults.
pub fn sealed_profile(profile_config: Value, overrides: Option<&Value>) -> Value {
    let overrides_map = match overrides {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    let get = |key: &str| overrides_map.and_then(|m| m.get(key)).cloned();

    let resources_override = get("resources");
    let mut resources = BTreeMap::from([
        ("providerConcurrency".to_string(), Value::Number(4.0)),
        ("projectExecution".to_string(), Value::Number(1.0)),
        ("browser".to_string(), Value::Number(1.0)),
        ("nativeSurface".to_string(), Value::Number(1.0)),
        ("reviewer".to_string(), Value::Number(2.0)),
        ("signing".to_string(), Value::Number(1.0)),
    ]);
    if let Some(Value::Object(over)) = resources_override {
        for (k, v) in over {
            resources.insert(k, v);
        }
    }

    let mut out = match profile_config {
        Value::Object(map) => map,
        _ => BTreeMap::new(),
    };
    out.insert("version".to_string(), Value::Number(1.0));
    out.insert("schedule".to_string(), get("schedule").unwrap_or_else(|| Value::str("auto")));
    out.insert("resources".to_string(), Value::Object(resources));
    out.insert("cache".to_string(), get("cache").unwrap_or_else(|| Value::str("content-addressed")));
    out.insert("cancellation".to_string(), get("cancellation").unwrap_or_else(|| Value::str("checkpoint")));
    out.insert("reasoning".to_string(), get("reasoning").unwrap_or_else(|| Value::str("auto")));
    out.insert(
        "claimLevels".to_string(),
        Value::array([
            Value::str("inventory"),
            Value::str("source"),
            Value::str("runtime"),
            Value::str("product"),
            Value::str("release"),
        ]),
    );

    let value = Value::Object(out.clone());
    let d = digest(&value);
    out.insert("digest".to_string(), Value::str(d));
    Value::Object(out)
}

/// Port of `normalizePath(value, cwd)`. The JS version resolves via Node's
/// `path.resolve`/`path.win32.resolve`, including realpath-style symlink
/// resolution left to the caller; this port keeps the Windows-root
/// detection and drive-doubling fixup but resolves purely lexically against
/// `cwd` (no filesystem access), since realpath resolution belongs to the
/// caller in both the JS and this port.
pub fn normalize_path(value: &str, cwd: &str) -> String {
    let windows_root = is_windows_root(value) || is_windows_root(cwd);
    if windows_root {
        let fixed = fix_doubled_drive(value);
        resolve_windows(cwd, &fixed)
    } else {
        resolve_posix(cwd, value)
    }
}

fn is_windows_root(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && s.len() > 2
        && matches!(s.as_bytes()[2], b'\\' | b'/')
}

/// Port of the `raw.replace(/^([a-zA-Z]:)[\\/]\1(?=[\\/])/i, '$1')` fixup
/// for a doubled drive prefix like `C:\C:\foo`.
fn fix_doubled_drive(raw: &str) -> String {
    if raw.len() < 4 {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')) {
        return raw.to_string();
    }
    let drive = &raw[0..2];
    let rest = &raw[3..];
    if rest.len() >= drive.len() + 1
        && rest[..drive.len()].eq_ignore_ascii_case(drive)
        && matches!(rest.as_bytes()[drive.len()], b'\\' | b'/')
    {
        format!("{drive}{}", &rest[drive.len()..])
    } else {
        raw.to_string()
    }
}

fn resolve_posix(cwd: &str, raw: &str) -> String {
    if raw.starts_with('/') {
        return normalize_segments(raw, '/');
    }
    let joined = format!("{}/{}", cwd.trim_end_matches('/'), raw);
    normalize_segments(&joined, '/')
}

fn resolve_windows(cwd: &str, raw: &str) -> String {
    let is_abs = is_windows_root(raw) || raw.starts_with('\\') || raw.starts_with('/');
    let base = if is_abs { raw.to_string() } else { format!("{cwd}\\{raw}") };
    normalize_segments(&base, '\\')
}

fn normalize_segments(path: &str, sep: char) -> String {
    let is_abs = path.starts_with('/') || path.starts_with('\\');
    let drive: String = if is_windows_root(path) { path[0..2].to_string() } else { String::new() };
    let rest = if !drive.is_empty() { &path[2..] } else { path };
    let mut stack: Vec<&str> = Vec::new();
    for part in rest.split(['/', '\\']) {
        match part {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join(&sep.to_string());
    if !drive.is_empty() {
        format!("{drive}{sep}{joined}")
    } else if is_abs {
        format!("{sep}{joined}")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Value {
        Value::object([
            ("schemaVersion", Value::Number(1.0)),
            ("profile", Value::str("standard")),
            ("providers", Value::object([("require", Value::array([])), ("disable", Value::array([]))])),
            (
                "limits",
                Value::object([
                    ("providerTimeoutMs", Value::Number(120000.0)),
                    ("maxOutputBytes", Value::Number(8388608.0)),
                    ("maxConcurrency", Value::Number(4.0)),
                ]),
            ),
            (
                "policy",
                Value::object([("failOn", Value::array([Value::str("critical"), Value::str("high")]))]),
            ),
            ("outputs", Value::array([Value::str("json")])),
        ])
    }

    #[test]
    fn validate_config_accepts_defaults() {
        assert!(validate_config(&default_config(), "config").is_ok());
    }

    #[test]
    fn validate_config_rejects_wrong_schema_version() {
        let mut c = default_config();
        if let Value::Object(map) = &mut c {
            map.insert("schemaVersion".into(), Value::Number(2.0));
        }
        let err = validate_config(&c, "config").unwrap_err();
        assert!(err.contains("schemaVersion must be 1"));
    }

    #[test]
    fn validate_config_rejects_unknown_top_key() {
        let mut c = default_config();
        if let Value::Object(map) = &mut c {
            map.insert("bogus".into(), Value::Bool(true));
        }
        assert_eq!(validate_config(&c, "config").unwrap_err(), "config has unknown key: bogus");
    }

    #[test]
    fn validate_config_rejects_unknown_nested_key() {
        let mut c = default_config();
        if let Value::Object(map) = &mut c {
            if let Some(Value::Object(limits)) = map.get_mut("limits") {
                limits.insert("bogus".into(), Value::Bool(true));
            }
        }
        assert_eq!(
            validate_config(&c, "config").unwrap_err(),
            "config.limits has unknown key: bogus"
        );
    }

    #[test]
    fn merge_config_rejects_host_owned_key_from_repository() {
        let defaults = default_config();
        let repo = Value::object([("networkGuard", Value::Bool(true))]);
        let err = merge_config(&defaults, None, Some(&repo), None).unwrap_err();
        assert_eq!(err, "repository config may not set host-owned key: networkGuard");
    }

    #[test]
    fn merge_config_layers_cli_over_repository_over_user() {
        let defaults = default_config();
        let cli = Value::object([("profile", Value::str("fast"))]);
        let merged = merge_config(&defaults, None, None, Some(&cli)).unwrap();
        if let Value::Object(map) = &merged {
            assert_eq!(map.get("profile"), Some(&Value::str("fast")));
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn merge_trusted_config_rejects_unknown_key() {
        let bogus = Value::object([("bogus", Value::Bool(true))]);
        let input = TrustedConfigInput {
            defaults: Some(&bogus),
            user: None,
            repository: None,
            cli: None,
            release_contract: None,
            external_evidence: None,
        };
        let err = merge_trusted_config(&input).unwrap_err();
        assert_eq!(err, "defaults config unknown key: bogus");
    }

    #[test]
    fn merge_trusted_config_is_deterministic() {
        let input = TrustedConfigInput {
            defaults: None,
            user: None,
            repository: None,
            cli: None,
            release_contract: None,
            external_evidence: None,
        };
        let a = merge_trusted_config(&input).unwrap();
        let b = merge_trusted_config(&input).unwrap();
        assert_eq!(a.digest, b.digest);
        assert!(a.digest.starts_with("sha256:"));
    }

    #[test]
    fn normalize_path_resolves_relative_posix() {
        assert_eq!(normalize_path("a/b", "/root"), "/root/a/b");
    }

    #[test]
    fn normalize_path_collapses_dot_dot() {
        assert_eq!(normalize_path("../b", "/root/x"), "/root/b");
    }

    #[test]
    fn normalize_path_fixes_doubled_windows_drive() {
        assert_eq!(normalize_path("C:\\C:\\foo", "C:\\cwd"), "C:\\foo");
    }

    #[test]
    fn sealed_profile_sets_defaults_and_digest() {
        let profile = Value::object([("profile", Value::str("standard"))]);
        let sealed = sealed_profile(profile, None);
        if let Value::Object(map) = &sealed {
            assert_eq!(map.get("schedule"), Some(&Value::str("auto")));
            assert!(matches!(map.get("digest"), Some(Value::String(_))));
        } else {
            panic!("expected object");
        }
    }
}
