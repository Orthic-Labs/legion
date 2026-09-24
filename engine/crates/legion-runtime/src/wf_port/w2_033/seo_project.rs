//! Rust port of `skills/seo/scripts/seo_project.py`: Legion SEO project state, provider
//! doctor, budget preflight, and cache helpers.
//!
//! `seo_project.py` reads/writes `.legion/seo/site.yaml` (JSON written to a `.yaml` path,
//! since JSON is a valid YAML 1.2 subset — the same trick this port keeps), inspects
//! environment variables, and reads/writes a disk cache. This module ports both the pure
//! arithmetic (`cache_key`, `PlannedCall`/`preflight`, `env_state`) and the filesystem /
//! environment IO (`load_site`/`save_site`, `setup_project`, `doctor`, `cache_put`/
//! `cache_get`), plus a [`run`] CLI entry point equivalent to the Python `main()`.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Port of `cache_key(provider, capability, target, *, country, language, device,
/// freshness_class)`. Mirrors Python's `json.dumps(..., sort_keys=True,
/// separators=(',', ':'))` followed by `hashlib.sha256(...).hexdigest()`: the six fields are
/// serialized as a JSON object with keys in alphabetical order and no extra whitespace.
pub fn cache_key(
    provider: &str,
    capability: &str,
    target: &str,
    country: &str,
    language: &str,
    device: &str,
    freshness_class: &str,
) -> String {
    // Field order matches Python `sort_keys=True`: alphabetical by key name.
    let payload = format!(
        "{{\"capability\":{cap},\"country\":{country},\"device\":{device},\"freshness_class\":{fresh},\"language\":{lang},\"provider\":{prov},\"target\":{target}}}",
        cap = serde_json::to_string(capability).unwrap(),
        country = serde_json::to_string(country).unwrap(),
        device = serde_json::to_string(device).unwrap(),
        fresh = serde_json::to_string(freshness_class).unwrap(),
        lang = serde_json::to_string(language).unwrap(),
        prov = serde_json::to_string(provider).unwrap(),
        target = serde_json::to_string(target).unwrap(),
    );
    let digest = Sha256::digest(payload.as_bytes());
    hex::encode(digest)
}

/// Port of the `PlannedCall` dataclass.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlannedCall {
    pub provider: String,
    pub capability: String,
    pub count: u64,
    pub estimated_unit_cost_usd: f64,
    pub cache_hits: u64,
}

impl PlannedCall {
    pub fn billable_count(&self) -> u64 {
        self.count.saturating_sub(self.cache_hits)
    }

    pub fn estimated_cost_usd(&self) -> f64 {
        round6(self.billable_count() as f64 * self.estimated_unit_cost_usd)
    }
}

fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlannedCallSummary {
    pub provider: String,
    pub capability: String,
    pub count: u64,
    pub estimated_unit_cost_usd: f64,
    pub cache_hits: u64,
    pub billable_count: u64,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PreflightResult {
    pub status: &'static str,
    pub estimated_paid_cost_usd: f64,
    pub ceiling_usd: Option<f64>,
    pub calls: Vec<PlannedCallSummary>,
}

/// Port of `preflight(calls, ceiling_usd)`.
pub fn preflight(calls: &[PlannedCall], ceiling_usd: Option<f64>) -> PreflightResult {
    let total = round6(calls.iter().map(PlannedCall::estimated_cost_usd).sum());
    let status = match ceiling_usd {
        Some(ceiling) if total > ceiling => "needs_authority",
        _ => "ok",
    };
    let summaries = calls
        .iter()
        .map(|c| PlannedCallSummary {
            provider: c.provider.clone(),
            capability: c.capability.clone(),
            count: c.count,
            estimated_unit_cost_usd: c.estimated_unit_cost_usd,
            cache_hits: c.cache_hits,
            billable_count: c.billable_count(),
            estimated_cost_usd: c.estimated_cost_usd(),
        })
        .collect();
    PreflightResult {
        status,
        estimated_paid_cost_usd: total,
        ceiling_usd,
        calls: summaries,
    }
}

/// Port of `env_state(names)`: classifies presence of a provider's required environment
/// variables given their already-read values (`None` for an unset variable), instead of
/// reading `os.environ` directly.
pub fn env_state(values: &[Option<&str>]) -> &'static str {
    if values.iter().all(|v| v.is_some()) {
        "present"
    } else if values.iter().any(|v| v.is_some()) {
        "partial"
    } else {
        "absent"
    }
}

/// Port of the module-level `STATE_DIR = Path('.legion') / 'seo'`.
pub const STATE_DIR_COMPONENTS: [&str; 2] = [".legion", "seo"];
/// Port of `SITE_FILE = 'site.yaml'`.
pub const SITE_FILE: &str = "site.yaml";
/// Port of `REQUIRED_STATE_DIRS`.
pub const REQUIRED_STATE_DIRS: &[&str] = &[
    "strategy", "baselines", "gsc", "ga4", "bing", "ai-visibility", "crawls", "keywords",
    "rank-tracking", "competitors", "backlinks", "briefs", "interventions", "reports", "cache",
];
/// Port of `PROVIDER_ENV`: provider name -> required environment variable names, in the
/// same iteration order as the Python dict literal (used by [`doctor`]'s output).
pub const PROVIDER_ENV: &[(&str, &[&str])] = &[
    ("google_api", &["GOOGLE_API_KEY"]),
    ("google_oauth_or_service", &["GOOGLE_APPLICATION_CREDENTIALS"]),
    ("gsc_property", &["GSC_PROPERTY"]),
    ("ga4_property", &["GA4_PROPERTY_ID"]),
    ("bing_webmaster", &["BING_API_KEY"]),
    ("indexnow", &["INDEXNOW_KEY"]),
    ("dataforseo", &["DATAFORSEO_LOGIN", "DATAFORSEO_PASSWORD"]),
];

/// Port of `utc_now()`: an ISO-8601 UTC timestamp with `Z` suffix and no fractional
/// seconds, matching `datetime.now(timezone.utc).replace(microsecond=0).isoformat()`
/// with `+00:00` swapped for `Z`. No chrono dependency (not in this packet's allowed
/// crates), so the civil date is computed with Howard Hinnant's days-from-civil algorithm,
/// mirroring the same technique already used elsewhere in this crate (see
/// `wf_port::r14::chrono_ish_now_iso8601`).
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let sod = secs % 86_400;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Port of `root_path(root) = Path(root).resolve()`. `resolve()` in Python performs a
/// filesystem-touching canonicalization; `std::fs::canonicalize` matches this closely
/// enough for a directory that already exists, and this port falls back to a lexical
/// absolutization (matching Python's behavior on a path that does not yet exist, where
/// `resolve()` degrades to `os.path.abspath`-like normalization) when the path is absent.
pub fn root_path(root: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(root) {
        strip_windows_verbatim_prefix(canon)
    } else {
        let cwd = std::env::current_dir().unwrap_or_default();
        normalize_lexically(&cwd.join(root))
    }
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Port of `state_path(root) = root_path(root) / STATE_DIR`.
pub fn state_path(root: &Path) -> PathBuf {
    let mut p = root_path(root);
    for c in STATE_DIR_COMPONENTS {
        p.push(c);
    }
    p
}

/// Port of `load_site(root)`. Returns `{}` when the file is absent, matching the Python
/// early-return, and an error string (matching the wrapped `ValueError` message shape)
/// when the file exists but is unreadable/invalid JSON.
pub fn load_site(root: &Path) -> Result<Map<String, Value>, String> {
    let path = state_path(root).join(SITE_FILE);
    if !path.exists() {
        return Ok(Map::new());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("invalid project state {}: {e}", path.display()))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(format!("invalid project state {}: not a JSON object", path.display())),
        Err(e) => Err(format!("invalid project state {}: {e}", path.display())),
    }
}

/// Port of `save_site(data, root)`.
pub fn save_site(data: &Map<String, Value>, root: &Path) -> std::io::Result<PathBuf> {
    let path = state_path(root).join(SITE_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_string_pretty(&Value::Object(data.clone()))
        .unwrap_or_else(|_| "{}".to_string());
    body.push('\n');
    std::fs::write(&path, body)?;
    Ok(path)
}

/// Port of `setup_project(root, *, domain, market, language, gsc_property, ga4_property,
/// bing_site, currency, devices)`. Creates the state directory tree, merges the new
/// fields over any existing `site.yaml`, and writes the result back.
#[allow(clippy::too_many_arguments)]
pub fn setup_project(
    root: &Path,
    domain: &str,
    market: &str,
    language: &str,
    gsc_property: Option<&str>,
    ga4_property: Option<&str>,
    bing_site: Option<&str>,
    currency: Option<&str>,
    devices: Option<Vec<String>>,
) -> Result<Map<String, Value>, String> {
    let base = state_path(root);
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    for name in REQUIRED_STATE_DIRS {
        std::fs::create_dir_all(base.join(name)).map_err(|e| e.to_string())?;
    }
    let existing = load_site(root)?;

    let mut project = existing.clone();
    project.insert("schema_version".into(), Value::from(1));
    project.insert("domain".into(), Value::from(domain));
    project.insert("market".into(), Value::from(market));
    project.insert("language".into(), Value::from(language));
    let currency_val = currency
        .map(Value::from)
        .unwrap_or_else(|| existing.get("currency").cloned().unwrap_or(Value::Null));
    project.insert("currency".into(), currency_val);
    let devices_val = match devices {
        Some(d) if !d.is_empty() => Value::from(d),
        _ => existing
            .get("devices")
            .cloned()
            .filter(|v| !matches!(v, Value::Null))
            .unwrap_or_else(|| Value::from(vec!["desktop".to_string(), "mobile".to_string()])),
    };
    project.insert("devices".into(), devices_val);

    let existing_props = existing
        .get("properties")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut properties = existing_props.clone();
    properties.insert(
        "gsc".into(),
        gsc_property
            .map(Value::from)
            .unwrap_or_else(|| existing_props.get("gsc").cloned().unwrap_or(Value::Null)),
    );
    properties.insert(
        "ga4".into(),
        ga4_property
            .map(Value::from)
            .unwrap_or_else(|| existing_props.get("ga4").cloned().unwrap_or(Value::Null)),
    );
    properties.insert(
        "bing".into(),
        bing_site
            .map(Value::from)
            .unwrap_or_else(|| existing_props.get("bing").cloned().unwrap_or(Value::Null)),
    );
    project.insert("properties".into(), Value::Object(properties));
    project.insert("updated_at".into(), Value::from(utc_now()));

    for (key, default) in [
        ("goals", Value::from(Vec::<Value>::new())),
        ("primary_conversions", Value::from(Vec::<Value>::new())),
        ("secondary_conversions", Value::from(Vec::<Value>::new())),
        ("important_page_families", Value::from(Vec::<Value>::new())),
        ("risk_flags", Value::from(Vec::<Value>::new())),
    ] {
        project.entry(key).or_insert(default);
    }
    project.entry("competitors").or_insert_with(|| {
        let mut m = Map::new();
        m.insert("business".into(), Value::from(Vec::<Value>::new()));
        m.insert("serp".into(), Value::from(Vec::<Value>::new()));
        m.insert("generative".into(), Value::from(Vec::<Value>::new()));
        m.insert("backlink".into(), Value::from(Vec::<Value>::new()));
        Value::Object(m)
    });

    save_site(&project, root).map_err(|e| e.to_string())?;
    Ok(project)
}

/// Port of `env_state(names)` reading directly from `std::env`, mirroring
/// `os.environ.get(name)`.
fn env_state_from_process(names: &[&str]) -> &'static str {
    let values: Vec<Option<String>> = names.iter().map(|n| std::env::var(n).ok()).collect();
    let refs: Vec<Option<&str>> = values.iter().map(|v| v.as_deref()).collect();
    env_state(&refs)
}

/// Port of `doctor(root)`.
pub fn doctor(root: &Path) -> Value {
    let site = load_site(root).unwrap_or_default();
    let mut providers = Map::new();
    for (name, envs) in PROVIDER_ENV {
        let mut entry = Map::new();
        entry.insert("state".into(), Value::from(env_state_from_process(envs)));
        entry.insert("env".into(), Value::from(envs.to_vec()));
        providers.insert((*name).to_string(), Value::Object(entry));
    }
    let state_dir = state_path(root);
    let writable_target = if state_dir.exists() {
        state_dir.clone()
    } else {
        state_dir.parent().map(Path::to_path_buf).unwrap_or(state_dir.clone())
    };
    let state_dir_writable = is_writable(&writable_target);

    let mut checks = Map::new();
    checks.insert(
        "project_state".into(),
        Value::from(if site.is_empty() { "absent" } else { "present" }),
    );
    checks.insert("state_dir_writable".into(), Value::from(state_dir_writable));
    checks.insert("python".into(), Value::from("n/a (rust port)"));

    let mut missing_mapping = Vec::new();
    if !site.is_empty() {
        let props = site.get("properties").and_then(|v| v.as_object());
        for key in ["gsc", "ga4", "bing"] {
            let present = props
                .and_then(|p| p.get(key))
                .map(|v| !v.is_null())
                .unwrap_or(false);
            if !present {
                missing_mapping.push(key);
            }
        }
    }

    let mut out = Map::new();
    out.insert("checked_at".into(), Value::from(utc_now()));
    out.insert("root".into(), Value::from(root_path(root).display().to_string()));
    out.insert("domain".into(), site.get("domain").cloned().unwrap_or(Value::Null));
    out.insert("market".into(), site.get("market").cloned().unwrap_or(Value::Null));
    out.insert("language".into(), site.get("language").cloned().unwrap_or(Value::Null));
    out.insert("providers".into(), Value::Object(providers));
    out.insert("checks".into(), Value::Object(checks));
    out.insert("missing_property_mappings".into(), Value::from(missing_mapping));
    out.insert("secrets_exposed".into(), Value::from(false));
    Value::Object(out)
}

#[cfg(unix)]
fn is_writable(path: &Path) -> bool {
    // Mirrors `os.access(path, os.W_OK)` closely enough for the doctor check: a
    // best-effort probe rather than a full permission-bit evaluation.
    std::fs::metadata(path)
        .map(|m| !m.permissions().readonly())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_writable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| !m.permissions().readonly())
        .unwrap_or(false)
}

/// Port of `cache_put(root, key, value)`.
pub fn cache_put(root: &Path, key: &str, value: &Value) -> std::io::Result<PathBuf> {
    let path = state_path(root).join("cache").join(format!("{key}.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut envelope = Map::new();
    envelope.insert("stored_at".into(), Value::from(utc_now()));
    envelope.insert("value".into(), value.clone());
    let mut body = serde_json::to_string_pretty(&Value::Object(envelope)).unwrap();
    body.push('\n');
    std::fs::write(&path, body)?;
    Ok(path)
}

/// Port of `cache_get(root, key)`.
pub fn cache_get(root: &Path, key: &str) -> Option<Value> {
    let path = state_path(root).join("cache").join(format!("{key}.json"));
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Port of the `argparse` CLI in `main()`. `args` excludes the program name (matches
/// `sys.argv[1:]`). Writes the same pretty-printed JSON envelope to stdout that Python's
/// `main()` prints, and returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let mut root = ".".to_string();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" && i + 1 < args.len() {
            root = args[i + 1].clone();
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    if rest.is_empty() {
        eprintln!("error: a command is required (setup, doctor, cache-key)");
        return 2;
    }
    let command = rest.remove(0);
    let opts = parse_opts(&rest);
    let root_path = PathBuf::from(&root);

    let out: Value = match command.as_str() {
        "setup" => {
            let domain = match opts.get("domain") {
                Some(v) => v.clone(),
                None => {
                    eprintln!("error: --domain is required");
                    return 2;
                }
            };
            let market = match opts.get("market") {
                Some(v) => v.clone(),
                None => {
                    eprintln!("error: --market is required");
                    return 2;
                }
            };
            let language = match opts.get("language") {
                Some(v) => v.clone(),
                None => {
                    eprintln!("error: --language is required");
                    return 2;
                }
            };
            let devices_arg = opts.get("devices").cloned().unwrap_or_else(|| "desktop,mobile".to_string());
            let devices: Vec<String> = devices_arg
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            match setup_project(
                &root_path,
                &domain,
                &market,
                &language,
                opts.get("gsc-property").map(|s| s.as_str()),
                opts.get("ga4-property").map(|s| s.as_str()),
                opts.get("bing-site").map(|s| s.as_str()),
                opts.get("currency").map(|s| s.as_str()),
                Some(devices),
            ) {
                Ok(project) => Value::Object(project),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            }
        }
        "doctor" => doctor(&root_path),
        "cache-key" => {
            let get = |k: &str| opts.get(k).cloned().unwrap_or_default();
            let provider = opts.get("provider").cloned();
            let capability = opts.get("capability").cloned();
            let target = opts.get("target").cloned();
            if provider.is_none() || capability.is_none() || target.is_none() {
                eprintln!("error: --provider, --capability, and --target are required");
                return 2;
            }
            let key = cache_key(
                &provider.unwrap(),
                &capability.unwrap(),
                &target.unwrap(),
                &get("country"),
                &get("language"),
                &get("device"),
                &get("freshness-class"),
            );
            let mut m = Map::new();
            m.insert("cache_key".into(), Value::from(key));
            Value::Object(m)
        }
        other => {
            eprintln!("error: unknown command {other}");
            return 2;
        }
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    0
}

fn parse_opts(args: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(flag) = args[i].strip_prefix("--") {
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                out.insert(flag.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                out.insert(flag.to_string(), String::new());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_deterministic_and_field_order_independent_input() {
        let a = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
        let b = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let c = cache_key("google_api", "serp", "example.com", "GB", "en", "desktop", "daily");
        assert_ne!(a, c);
    }

    #[test]
    fn preflight_computes_billable_cost_and_ceiling_status() {
        let calls = vec![
            PlannedCall {
                provider: "dataforseo".into(),
                capability: "serp".into(),
                count: 100,
                estimated_unit_cost_usd: 0.01,
                cache_hits: 40,
            },
            PlannedCall {
                provider: "google_pagespeed_crux".into(),
                capability: "psi".into(),
                count: 10,
                estimated_unit_cost_usd: 0.0,
                cache_hits: 0,
            },
        ];
        let ok = preflight(&calls, Some(1.0));
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.estimated_paid_cost_usd, 0.6);
        assert_eq!(ok.calls[0].billable_count, 60);

        let needs_authority = preflight(&calls, Some(0.5));
        assert_eq!(needs_authority.status, "needs_authority");

        let no_ceiling = preflight(&calls, None);
        assert_eq!(no_ceiling.status, "ok");
    }

    #[test]
    fn env_state_classifies_present_partial_absent() {
        assert_eq!(env_state(&[Some("a"), Some("b")]), "present");
        assert_eq!(env_state(&[Some("a"), None]), "partial");
        assert_eq!(env_state(&[None, None]), "absent");
        assert_eq!(env_state(&[]), "present");
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "legion-seo-project-{label}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn setup_project_creates_state_dirs_and_merges_over_existing() {
        let root = unique_temp_dir("setup");
        let first = setup_project(
            &root, "example.com", "US", "en",
            Some("sc-domain:example.com"), None, None, Some("USD"), None,
        )
        .expect("first setup");
        assert_eq!(first["domain"], Value::from("example.com"));
        assert_eq!(first["devices"], Value::from(vec!["desktop".to_string(), "mobile".to_string()]));
        assert_eq!(first["properties"]["gsc"], Value::from("sc-domain:example.com"));
        for name in REQUIRED_STATE_DIRS {
            assert!(state_path(&root).join(name).is_dir(), "missing state dir {name}");
        }

        // Second call without gsc_property must preserve the previously stored mapping.
        let second = setup_project(&root, "example.com", "US", "en", None, Some("properties/123"), None, None, None)
            .expect("second setup");
        assert_eq!(second["properties"]["gsc"], Value::from("sc-domain:example.com"));
        assert_eq!(second["properties"]["ga4"], Value::from("properties/123"));

        let loaded = load_site(&root).expect("load site");
        assert_eq!(loaded["domain"], Value::from("example.com"));
    }

    #[test]
    fn load_site_returns_empty_map_when_absent() {
        let root = unique_temp_dir("missing");
        let site = load_site(&root).expect("no error for missing file");
        assert!(site.is_empty());
    }

    #[test]
    fn cache_put_and_get_round_trip() {
        let root = unique_temp_dir("cache");
        let key = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
        let value = serde_json::json!({"rank": 3});
        cache_put(&root, &key, &value).expect("cache put");
        let fetched = cache_get(&root, &key).expect("cache get");
        assert_eq!(fetched["value"], value);
        assert!(fetched.get("stored_at").is_some());

        assert!(cache_get(&root, "does-not-exist").is_none());
    }

    #[test]
    fn doctor_reports_absent_project_state_with_no_site_yaml() {
        let root = unique_temp_dir("doctor");
        let report = doctor(&root);
        assert_eq!(report["checks"]["project_state"], Value::from("absent"));
        assert_eq!(report["secrets_exposed"], Value::from(false));
        assert!(report["providers"]["google_api"]["env"]
            .as_array()
            .unwrap()
            .contains(&Value::from("GOOGLE_API_KEY")));
    }

    #[test]
    fn utc_now_matches_iso8601_z_shape() {
        let ts = utc_now();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[10], b'T');
    }

    #[test]
    fn run_cache_key_command_prints_json_and_returns_zero() {
        let args: Vec<String> = [
            "cache-key", "--provider", "google_api", "--capability", "serp",
            "--target", "example.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(run(&args), 0);
    }
}
