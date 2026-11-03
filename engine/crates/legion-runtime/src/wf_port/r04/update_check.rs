//! Port of `context.mjs`'s best-effort skill self-update check
//! (`computeUpdateDirective`, `fetchLatestSkillVersion`, `compareSemver`,
//! `buildUpdateDirective`, `readLocalSkillVersion`, `readUpdateCache`,
//! `writeUpdateCache`, `updateCheckDisabledByConfig`).
//!
//! The original piggybacks a throttled, cached, anti-nagging poll of a
//! remote version endpoint onto every CLI boot, entirely best-effort: any
//! failure (offline, sandboxed, malformed cache, read-only home dir) must
//! never surface as an error, only as a silent `None`. That "swallow
//! everything" contract is preserved here: every fallible step degrades to
//! `None`/no-op rather than propagating an error.
//!
//! All I/O — the on-disk cache, the network fetch, and the shared/local
//! `.impeccable/config*.json` read — sits behind traits so the throttle,
//! cache, and anti-nag logic can be unit-tested without touching a real
//! filesystem or network.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// `24 * 60 * 60 * 1000` — throttle the network poll to once a day.
pub const CHECK_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
/// `7 * 24 * 60 * 60 * 1000` — don't re-surface the same version for a week.
pub const RENOTIFY_INTERVAL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Network fetch timeout, matching the JS `AbortSignal.timeout(1200)`.
pub const FETCH_TIMEOUT_MS: u64 = 1200;

const DEFAULT_UPDATE_HOST: &str = "https://designer.style";

/// The update-check host: always the default.
pub fn default_update_host() -> String {
    DEFAULT_UPDATE_HOST.trim_end_matches('/').to_string()
}

/// The update-check cache file.
pub fn default_update_cache_path() -> PathBuf {
    dirs_home().join(".impeccable").join("update-check.json")
}

fn dirs_home() -> PathBuf {
    // Mirrors Node's `os.homedir()` for the platforms this product ships on.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateCache {
    #[serde(rename = "lastCheck", skip_serializing_if = "Option::is_none")]
    pub last_check: Option<i64>,
    #[serde(rename = "latestVersion", skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    #[serde(rename = "notifiedVersion", skip_serializing_if = "Option::is_none")]
    pub notified_version: Option<String>,
    #[serde(rename = "notifiedAt", skip_serializing_if = "Option::is_none")]
    pub notified_at: Option<i64>,
}

/// Behind-a-trait cache store: `readUpdateCache` / `writeUpdateCache`.
pub trait CacheStore {
    fn read(&self) -> UpdateCache;
    /// Best-effort: a failure here is swallowed, exactly like the JS
    /// `catch { /* read-only home dir */ }`.
    fn write(&self, cache: &UpdateCache);
}

pub struct FsCacheStore {
    pub path: PathBuf,
}

impl CacheStore for FsCacheStore {
    fn read(&self) -> UpdateCache {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|body| serde_json::from_str(&body).ok())
            .unwrap_or_default()
    }

    fn write(&self, cache: &UpdateCache) {
        let Some(parent) = self.path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        if let Ok(body) = serde_json::to_vec(cache) {
            let _ = std::fs::write(&self.path, body);
        }
    }
}

/// Behind-a-trait network fetch: `fetchLatestSkillVersion`.
pub trait VersionFetcher {
    /// Returns `Some(version)` on a well-formed `{ "skills": "<version>" }`
    /// 2xx response, `None` on any other outcome (network error, timeout,
    /// non-2xx, malformed JSON, wrong shape) — all non-fatal in the JS.
    fn fetch_latest(&self, host: &str) -> Option<String>;
}

pub struct HttpVersionFetcher;

impl VersionFetcher for HttpVersionFetcher {
    fn fetch_latest(&self, host: &str) -> Option<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(FETCH_TIMEOUT_MS))
            .build()
            .ok()?;
        let res = client.get(format!("{host}/api/version")).send().ok()?;
        if !res.status().is_success() {
            return None;
        }
        let data: serde_json::Value = res.json().ok()?;
        data.get("skills")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

/// Behind-a-trait `.impeccable/config.json` + `config.local.json` read:
/// `updateCheckDisabledByConfig`.
pub trait ConfigReader {
    /// `Some(bool)` is the last `updateCheck` boolean found across
    /// `config.json` then `config.local.json` (local overrides shared,
    /// matching the JS loop order); `None` when neither file sets it.
    fn update_check_flag(&self, cwd: &Path) -> Option<bool>;
}

pub struct FsConfigReader;

impl ConfigReader for FsConfigReader {
    fn update_check_flag(&self, cwd: &Path) -> Option<bool> {
        let mut value = None;
        for name in ["config.json", "config.local.json"] {
            let path = cwd.join(".impeccable").join(name);
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(b) = json.get("updateCheck").and_then(|v| v.as_bool()) {
                        value = Some(b);
                    }
                }
            }
        }
        value
    }
}

pub fn update_check_disabled_by_config(reader: &dyn ConfigReader, cwd: &Path) -> bool {
    reader.update_check_flag(cwd) == Some(false)
}

/// Port of `readLocalSkillVersion`. The JS resolves `../SKILL.md` relative
/// to `context.mjs`'s own directory (`<skill>/scripts/context.mjs` ->
/// `<skill>/SKILL.md`); the Rust port takes that scripts directory
/// explicitly rather than reading it from the running binary's own path.
pub fn read_local_skill_version(scripts_dir: &Path) -> Option<String> {
    let skill_md = scripts_dir.join("..").join("SKILL.md");
    let content = std::fs::read_to_string(skill_md).ok()?;
    version_from_frontmatter(&content)
}

fn version_from_frontmatter(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("version:") {
            let trimmed = rest.trim();
            let unquoted = trimmed
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| {
                    trimmed
                        .strip_prefix('\'')
                        .and_then(|s| s.strip_suffix('\''))
                })
                .unwrap_or(trimmed);
            return Some(unquoted.to_string());
        }
    }
    None
}

/// Port of `compareSemver`: compares dotted numeric versions, `>0` when
/// `a` is newer than `b`. Non-numeric segments parse as `0`, matching the
/// JS `parseInt(n, 10) || 0`.
pub fn compare_semver(a: &str, b: &str) -> i64 {
    let pa = parse_dotted(a);
    let pb = parse_dotted(b);
    let len = pa.len().max(pb.len());
    for i in 0..len {
        let diff = *pa.get(i).unwrap_or(&0) - *pb.get(i).unwrap_or(&0);
        if diff != 0 {
            return diff;
        }
    }
    0
}

fn parse_dotted(v: &str) -> Vec<i64> {
    v.split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<i64>().unwrap_or(0)
        })
        .collect()
}

pub fn build_update_directive(local_version: &str, latest_version: &str) -> String {
    format!(
        "UPDATE_AVAILABLE: A newer Impeccable skill is available \
(installed v{local_version}, latest v{latest_version}). \
Before continuing, ask the user once: \"A newer Impeccable (v{latest_version}) is available. \
Update now? It runs `npx impeccable update`.\" \
If they agree, run `npx impeccable update` (the update applies to the next session, not this one). \
Either way, continue the current task without waiting, and do not raise this again."
    )
}

/// Options threaded through `computeUpdateDirective`, standing in for the
/// module-level state (`process.env`, the sibling `SKILL.md`, and the
/// injected I/O) the JS closes over.
pub struct UpdateCheckContext<'a> {
    pub now_ms: i64,
    pub cwd: &'a Path,
    pub scripts_dir: &'a Path,
    pub host: String,
    pub no_update_check_env: bool,
    pub cache: &'a dyn CacheStore,
    pub fetcher: &'a dyn VersionFetcher,
    pub config: &'a dyn ConfigReader,
}

/// Port of `computeUpdateDirective`. Returns `None` on any early-out or
/// failure, `Some(directive)` when a newer, not-recently-notified version
/// is found.
pub fn compute_update_directive(ctx: &UpdateCheckContext) -> Option<String> {
    if ctx.no_update_check_env {
        return None;
    }
    if update_check_disabled_by_config(ctx.config, ctx.cwd) {
        return None;
    }
    let local_version = read_local_skill_version(ctx.scripts_dir)?;

    let mut cache = ctx.cache.read();

    let expired = match cache.last_check {
        None => true,
        Some(last) => ctx.now_ms - last > CHECK_INTERVAL_MS,
    };
    if expired {
        let latest = ctx.fetcher.fetch_latest(&ctx.host);
        cache.last_check = Some(ctx.now_ms);
        if let Some(latest) = &latest {
            cache.latest_version = Some(latest.clone());
        }
        ctx.cache.write(&cache);
    }

    let latest = cache.latest_version.clone()?;
    if compare_semver(&latest, &local_version) <= 0 {
        return None;
    }

    if cache.notified_version.as_deref() == Some(latest.as_str()) {
        if let Some(notified_at) = cache.notified_at {
            if ctx.now_ms - notified_at < RENOTIFY_INTERVAL_MS {
                return None;
            }
        }
    }
    cache.notified_version = Some(latest.clone());
    cache.notified_at = Some(ctx.now_ms);
    ctx.cache.write(&cache);

    Some(build_update_directive(&local_version, &latest))
}
