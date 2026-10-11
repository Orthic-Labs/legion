//! Native marketplace identity and output parsing for supported plugin hosts.
//!
//! This module describes host CLI calls and validates their readback. It never
//! edits host-owned plugin databases, caches, or trust records.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const MARKETPLACE_NAME: &str = "legion-installed";
pub const PLUGIN_NAME: &str = "legion";
pub const PLUGIN_SOURCE: &str = "./plugin";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarketplaceClient {
    ClaudeCode,
    Codex,
}

impl MarketplaceClient {
    pub fn executable(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude",
            Self::Codex => "codex",
        }
    }

    pub fn manifest_relative_path(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".claude-plugin/marketplace.json",
            Self::Codex => ".agents/plugins/marketplace.json",
        }
    }

    pub fn installed_cache_root(self, home: &Path, version: Option<&str>) -> PathBuf {
        match self {
            Self::ClaudeCode => home
                .join("plugins/cache")
                .join(MARKETPLACE_NAME)
                .join(PLUGIN_NAME)
                .join(version.unwrap_or("local")),
            Self::Codex => home
                .join("plugins/cache")
                .join(MARKETPLACE_NAME)
                .join(PLUGIN_NAME)
                .join(version.unwrap_or("local")),
        }
    }

    pub fn marketplace_add_args(self, root: &Path) -> Vec<String> {
        match self {
            Self::ClaudeCode => vec![
                "plugin".into(),
                "marketplace".into(),
                "add".into(),
                root.to_string_lossy().into_owned(),
                "--scope".into(),
                "user".into(),
                "--json".into(),
            ],
            Self::Codex => vec![
                "plugin".into(),
                "marketplace".into(),
                "add".into(),
                root.to_string_lossy().into_owned(),
                "--json".into(),
            ],
        }
    }

    pub fn plugin_add_args(self) -> Vec<String> {
        match self {
            Self::ClaudeCode => vec![
                "plugin".into(),
                "install".into(),
                format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
                "--scope".into(),
                "user".into(),
                "--json".into(),
            ],
            Self::Codex => vec![
                "plugin".into(),
                "add".into(),
                format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
                "--json".into(),
            ],
        }
    }

    pub fn plugin_remove_args(self) -> Vec<String> {
        match self {
            Self::ClaudeCode => vec![
                "plugin".into(),
                "uninstall".into(),
                format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
                "--scope".into(),
                "user".into(),
                "--json".into(),
            ],
            Self::Codex => vec![
                "plugin".into(),
                "remove".into(),
                format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
                "--json".into(),
            ],
        }
    }

    pub fn plugin_list_args(self) -> Vec<String> {
        vec!["plugin".into(), "list".into(), "--json".into()]
    }

    pub fn marketplace_list_args(self) -> Vec<String> {
        vec![
            "plugin".into(),
            "marketplace".into(),
            "list".into(),
            "--json".into(),
        ]
    }

    pub fn marketplace_remove_args(self) -> Vec<String> {
        vec![
            "plugin".into(),
            "marketplace".into(),
            "remove".into(),
            MARKETPLACE_NAME.into(),
            "--json".into(),
        ]
    }

    pub fn plugin_toggle_args(self, enabled: bool) -> Option<Vec<String>> {
        match self {
            Self::ClaudeCode => Some(vec![
                "plugin".into(),
                if enabled { "enable" } else { "disable" }.into(),
                format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}"),
                "--scope".into(),
                "user".into(),
                "--json".into(),
            ]),
            Self::Codex => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketplaceBinding {
    pub client: MarketplaceClient,
    pub current_root: PathBuf,
    pub plugin_root: PathBuf,
}

impl MarketplaceBinding {
    pub fn new(client: MarketplaceClient, current_root: impl Into<PathBuf>) -> Self {
        let current_root = current_root.into();
        Self {
            client,
            plugin_root: current_root.join("plugin"),
            current_root,
        }
    }

    /// Validate that the active sealed payload declares exactly the source
    /// shape consumed by the native CLI. Contents remain read-only.
    pub fn validate_payload(&self) -> Result<(), String> {
        let path = self.current_root.join(self.client.manifest_relative_path());
        let bytes = std::fs::read(&path).map_err(|error| {
            format!(
                "marketplace manifest unavailable at {}: {error}",
                path.display()
            )
        })?;
        let manifest: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid marketplace manifest: {error}"))?;
        if manifest.get("name").and_then(Value::as_str) != Some(MARKETPLACE_NAME) {
            return Err("marketplace manifest name does not match installed identity".into());
        }
        let plugins = manifest
            .get("plugins")
            .and_then(Value::as_array)
            .ok_or_else(|| "marketplace manifest has no plugins array".to_owned())?;
        let plugin = plugins
            .iter()
            .find(|item| item.get("name").and_then(Value::as_str) == Some(PLUGIN_NAME))
            .ok_or_else(|| "marketplace manifest does not declare Legion".to_owned())?;
        let source_is_valid = match self.client {
            MarketplaceClient::ClaudeCode => {
                plugin.get("source").and_then(Value::as_str) == Some(PLUGIN_SOURCE)
            }
            MarketplaceClient::Codex => plugin.get("source").is_some_and(|source| {
                source.get("source").and_then(Value::as_str) == Some("local")
                    && source.get("path").and_then(Value::as_str) == Some(PLUGIN_SOURCE)
            }),
        };
        if !source_is_valid {
            return Err("marketplace plugin source is not the sealed local plugin".into());
        }
        if !self.plugin_root.is_dir() {
            return Err("sealed marketplace plugin directory is unavailable".into());
        }
        let release_manifest: Value = serde_json::from_slice(
            &std::fs::read(self.current_root.join("share/legion/release.json"))
                .map_err(|error| format!("sealed release manifest unavailable: {error}"))?,
        )
        .map_err(|error| format!("sealed release manifest is invalid: {error}"))?;
        let release_binding: Value = serde_json::from_slice(
            &std::fs::read(self.plugin_root.join("release-binding.json"))
                .map_err(|error| format!("sealed plugin release binding unavailable: {error}"))?,
        )
        .map_err(|error| format!("sealed plugin release binding is invalid: {error}"))?;
        if release_binding.get("kind").and_then(Value::as_str)
            != Some("legion-installed-plugin-release-binding")
            || release_binding.get("plugin").and_then(Value::as_str) != Some(PLUGIN_NAME)
        {
            return Err("sealed plugin release binding has wrong identity".into());
        }
        let release_version = release_binding
            .get("releaseVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| "sealed plugin release binding omitted version".to_owned())?;
        if release_manifest
            .get("releaseVersion")
            .and_then(Value::as_str)
            != Some(release_version)
        {
            return Err("sealed release and plugin binding versions differ".into());
        }
        for path in [".claude-plugin/plugin.json", ".codex-plugin/plugin.json"] {
            let manifest_path = self.plugin_root.join(path);
            let bytes = std::fs::read(&manifest_path).map_err(|error| {
                format!("native plugin manifest unavailable at {path}: {error}")
            })?;
            let native_manifest: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("native plugin manifest at {path} is invalid: {error}"))?;
            if native_manifest.get("name").and_then(Value::as_str) != Some(PLUGIN_NAME)
                || native_manifest.get("version").and_then(Value::as_str) != Some(release_version)
            {
                return Err(format!(
                    "native plugin manifest at {path} does not match release binding"
                ));
            }
        }
        let expected_plugin_sha256 = release_manifest
            .get("pluginSha256")
            .and_then(Value::as_str)
            .ok_or_else(|| "sealed release manifest omitted plugin digest".to_owned())?;
        if directory_sha256(&self.plugin_root)? != expected_plugin_sha256 {
            return Err("sealed plugin tree digest differs from release manifest".into());
        }
        let metadata = release_manifest
            .get("nativeMarketplaces")
            .ok_or_else(|| "sealed release manifest omitted marketplace identity".to_owned())?;
        if metadata.get("name").and_then(Value::as_str) != Some(MARKETPLACE_NAME)
            || metadata.get("plugin").and_then(Value::as_str) != Some(PLUGIN_NAME)
            || metadata.get("sourcePath").and_then(Value::as_str) != Some(PLUGIN_SOURCE)
        {
            return Err("sealed release marketplace identity does not match payload".into());
        }
        let files = metadata
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| "sealed release manifest omitted marketplace file digests".to_owned())?;
        for relative in [
            MarketplaceClient::ClaudeCode.manifest_relative_path(),
            MarketplaceClient::Codex.manifest_relative_path(),
        ] {
            let marketplace_path = self.current_root.join(relative);
            let marketplace_bytes = std::fs::read(&marketplace_path).map_err(|error| {
                format!("marketplace manifest unavailable at {relative}: {error}")
            })?;
            let expected = files
                .iter()
                .find(|entry| entry.get("path").and_then(Value::as_str) == Some(relative))
                .and_then(|entry| entry.get("sha256"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("sealed release manifest omitted digest for {relative}"))?;
            if sha256(&marketplace_bytes) != expected {
                return Err(format!(
                    "marketplace file digest differs from sealed release: {relative}"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePluginEntry {
    pub installed: bool,
    pub enabled: Option<bool>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub marketplace: Option<String>,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedReleaseBinding {
    pub release_version: String,
    pub runtime_sha256: String,
    pub cached_path: String,
    pub binding_sha256: String,
    pub portable_core_sha256: String,
    pub plugin_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexCacheLookup {
    NotConfigured,
    Missing,
    Found(PathBuf),
    Ambiguous(Vec<PathBuf>),
}

/// Locate Codex's one config-selected native local cache entry without opening
/// its private database. Invalid, missing, and ambiguous states stay distinct.
pub fn find_codex_plugin_cache(
    config_path: &Path,
    codex_home: &Path,
) -> Result<CodexCacheLookup, String> {
    find_codex_plugin_cache_version(config_path, codex_home, None)
}

/// Resolve Codex's exact native-list version when available; callers that lack
/// this authority should use `find_codex_plugin_cache` and surface ambiguity.
pub fn find_codex_plugin_cache_version(
    config_path: &Path,
    codex_home: &Path,
    expected_version: Option<&str>,
) -> Result<CodexCacheLookup, String> {
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CodexCacheLookup::NotConfigured)
        }
        Err(error) => return Err(format!("cannot read Codex config: {error}")),
    };
    let parsed: toml::Value =
        toml::from_str(&text).map_err(|error| format!("Codex config is invalid TOML: {error}"))?;
    let key = format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}");
    if parsed
        .get("plugins")
        .and_then(|plugins| plugins.get(&key))
        .is_none()
    {
        return Ok(CodexCacheLookup::NotConfigured);
    }
    let root = codex_home
        .join("plugins/cache")
        .join(MARKETPLACE_NAME)
        .join(PLUGIN_NAME);
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CodexCacheLookup::Missing)
        }
        Err(error) => return Err(format!("cannot read Codex plugin cache: {error}")),
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate Codex plugin cache: {error}"))?;
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|error| format!("cannot inspect Codex cache entry: {error}"))?
            .is_dir()
        {
            continue;
        }
        let version = entry.file_name().to_string_lossy().into_owned();
        if expected_version.is_some_and(|expected| expected != version) {
            continue;
        }
        let manifest_path = [".codex-plugin/plugin.json", "plugin.json"]
            .iter()
            .map(|relative| path.join(relative))
            .find(|candidate| candidate.is_file());
        let Some(manifest_path) = manifest_path else {
            continue;
        };
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(&manifest_path)
                .map_err(|error| format!("cannot read cached Codex plugin manifest: {error}"))?,
        )
        .map_err(|error| format!("cached Codex plugin manifest is invalid: {error}"))?;
        if manifest.get("name").and_then(Value::as_str) == Some(PLUGIN_NAME)
            && manifest.get("version").and_then(Value::as_str) == Some(version.as_str())
        {
            candidates.push(path);
        }
    }
    candidates.sort();
    Ok(match candidates.len() {
        0 => CodexCacheLookup::Missing,
        1 => CodexCacheLookup::Found(candidates.remove(0)),
        _ => CodexCacheLookup::Ambiguous(candidates),
    })
}

/// Verify native-list cache path against sealed payload release identity and
/// portable-core files. The host CLI supplies the path; this code only reads.
pub fn verify_cached_release(
    entry: &NativePluginEntry,
    plugin_root: &Path,
    expected_version: &str,
    expected_runtime_sha256: &str,
) -> Result<CachedReleaseBinding, String> {
    let cache_path = entry
        .path
        .as_deref()
        .ok_or_else(|| "native plugin list omitted installed cache path".to_owned())?;
    let cache_root = PathBuf::from(cache_path);
    if !cache_root.is_absolute() || !cache_root.is_dir() {
        return Err("native plugin cache path is unavailable".into());
    }
    let release_root = plugin_root
        .parent()
        .ok_or_else(|| "plugin root has no release parent".to_owned())?;
    let release_manifest: Value = serde_json::from_slice(
        &std::fs::read(release_root.join("share/legion/release.json"))
            .map_err(|error| format!("sealed release manifest unavailable: {error}"))?,
    )
    .map_err(|error| format!("sealed release manifest is invalid: {error}"))?;
    let expected_plugin_sha256 = release_manifest
        .get("pluginSha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "sealed release manifest omitted plugin digest".to_owned())?;
    let expected_portable_sha256 = release_manifest
        .get("portableCoreSha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "sealed release manifest omitted portable-core digest".to_owned())?;
    let local_binding = std::fs::read(plugin_root.join("release-binding.json"))
        .map_err(|error| format!("sealed release binding unavailable: {error}"))?;
    let cached_binding = std::fs::read(cache_root.join("release-binding.json"))
        .map_err(|error| format!("native cache release binding unavailable: {error}"))?;
    let binding: Value = serde_json::from_slice(&cached_binding)
        .map_err(|error| format!("native cache release binding is invalid: {error}"))?;
    if binding.get("kind").and_then(Value::as_str)
        != Some("legion-installed-plugin-release-binding")
        || binding.get("plugin").and_then(Value::as_str) != Some(PLUGIN_NAME)
        || binding.get("releaseVersion").and_then(Value::as_str) != Some(expected_version)
        || binding.get("runtimeSha256").and_then(Value::as_str) != Some(expected_runtime_sha256)
        || cached_binding != local_binding
    {
        return Err("native plugin cache release binding does not match active release".into());
    }
    let local_core = std::fs::read(plugin_root.join("rightax-portable-core.json"))
        .map_err(|error| format!("sealed portable-core identity unavailable: {error}"))?;
    let cached_core = std::fs::read(cache_root.join("rightax-portable-core.json"))
        .map_err(|error| format!("native cache portable-core identity unavailable: {error}"))?;
    if cached_core != local_core || sha256(&cached_core) != expected_portable_sha256 {
        return Err("native plugin cache portable-core digest differs from active release".into());
    }
    let sealed_plugin_sha256 = directory_sha256(plugin_root)?;
    let cached_plugin_sha256 = directory_sha256(&cache_root)?;
    if sealed_plugin_sha256 != expected_plugin_sha256
        || cached_plugin_sha256 != expected_plugin_sha256
    {
        return Err("native plugin cache content digest differs from active release".into());
    }
    Ok(CachedReleaseBinding {
        release_version: expected_version.into(),
        runtime_sha256: expected_runtime_sha256.into(),
        cached_path: cache_path.into(),
        binding_sha256: sha256(&cached_binding),
        portable_core_sha256: sha256(&cached_core),
        plugin_sha256: cached_plugin_sha256,
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn directory_sha256(root: &Path) -> Result<String, String> {
    fn files_below(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
        let entries = std::fs::read_dir(directory)
            .map_err(|error| format!("cannot read plugin cache directory: {error}"))?;
        let mut entries = entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate plugin cache directory: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect plugin cache entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("plugin tree contains a symbolic link".into());
            }
            if metadata.is_dir() {
                files_below(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "plugin path escaped its root".to_owned())?;
                files.push(relative.to_string_lossy().replace('\\', "/"));
            } else {
                return Err("plugin tree contains a non-regular entry".into());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    files_below(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for relative in files {
        let bytes = std::fs::read(root.join(&relative))
            .map_err(|error| format!("cannot read plugin file: {error}"))?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn plugin_tree_sha256(root: &Path) -> Result<String, String> {
    directory_sha256(root)
}

/// Read Codex's user-level enable choice from its documented config entry.
/// Missing config or key means the host default is enabled.
pub fn codex_enabled(config_path: &Path) -> Result<bool, String> {
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(format!("cannot read Codex config: {error}")),
    };
    let parsed: toml::Value =
        toml::from_str(&text).map_err(|error| format!("Codex config is invalid TOML: {error}"))?;
    let plugin_key = format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}");
    Ok(parsed
        .get("plugins")
        .and_then(|plugins| plugins.get(&plugin_key))
        .and_then(|plugin| plugin.get("enabled"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true))
}

/// Set only Codex's documented plugin enabled key, preserving every other
/// config byte. Refuses ambiguous or malformed target tables.
pub fn set_codex_enabled(config_path: &Path, enabled: bool) -> Result<(), String> {
    let existing = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read Codex config: {error}")),
    };
    let parsed: toml::Value = if !existing.trim().is_empty() {
        toml::from_str(&existing)
            .map_err(|error| format!("Codex config is invalid TOML: {error}"))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let key = format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}");
    let section = format!("[plugins.\"{key}\"]");
    let mut lines = existing.lines().map(str::to_owned).collect::<Vec<_>>();
    let target_table_exists = parsed
        .get("plugins")
        .and_then(|plugins| plugins.get(&key))
        .is_some();
    let section_index = lines
        .iter()
        .position(|line| is_codex_plugin_section(line, &key));
    if target_table_exists && section_index.is_none() {
        return Err(
            "Codex plugin table could not be located without risking unrelated config".into(),
        );
    }
    if let Some(section_index) = section_index {
        let end = lines
            .iter()
            .enumerate()
            .skip(section_index + 1)
            .find(|(_, line)| line.trim_start().starts_with('['))
            .map(|(index, _)| index)
            .unwrap_or(lines.len());
        let mut enabled_line = None;
        for (index, line) in lines.iter().enumerate().take(end).skip(section_index + 1) {
            if line
                .trim_start()
                .split_once('=')
                .is_some_and(|(key, _)| key.trim() == "enabled")
            {
                if enabled_line.replace(index).is_some() {
                    return Err("Codex plugin config has duplicate enabled keys".into());
                }
            }
        }
        if let Some(index) = enabled_line {
            let indent = lines[index]
                .chars()
                .take_while(|character| character.is_whitespace())
                .collect::<String>();
            let comment = lines[index]
                .split_once('#')
                .map(|(_, comment)| format!(" #{}", comment.trim()))
                .unwrap_or_default();
            lines[index] = format!("{indent}enabled = {enabled}{comment}");
        } else {
            lines.insert(end, format!("enabled = {enabled}"));
        }
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
            lines.push(String::new());
        }
        lines.push(section);
        lines.push(format!("enabled = {enabled}"));
    }
    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    let _: toml::Value = toml::from_str(&output)
        .map_err(|error| format!("Codex config edit is invalid TOML: {error}"))?;
    write_config_atomically(config_path, output.as_bytes())
}

fn is_codex_plugin_section(line: &str, plugin_key: &str) -> bool {
    if !line.trim_start().starts_with('[') || line.trim_start().starts_with("[[") {
        return false;
    }
    let candidate = format!("{}\nenabled = true", line.trim());
    toml::from_str::<toml::Value>(&candidate)
        .ok()
        .and_then(|value| {
            value
                .get("plugins")
                .and_then(|plugins| plugins.get(plugin_key))
                .cloned()
        })
        .is_some()
}

fn write_config_atomically(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| "Codex config has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create Codex config directory: {error}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let temporary = parent.join(format!(".{name}.legion-tmp-{}", std::process::id()));
    let permissions = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create Codex config transaction: {error}"))?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write Codex config transaction: {error}"))?;
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&temporary, permissions)
                .map_err(|error| format!("cannot preserve Codex config permissions: {error}"))?;
        }
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("cannot activate Codex config transaction: {error}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Extract Legion's native entry from a host's JSON plugin list. An absent
/// entry is a valid readback; malformed JSON is handled by the caller.
pub fn native_plugin_entry(value: &Value) -> NativePluginEntry {
    native_plugin_entry_scoped(value, None)
}

/// Extract Legion's native plugin record, optionally requiring a host scope.
/// Records without a scope remain compatible with older CLI JSON variants.
pub fn native_plugin_entry_scoped(
    value: &Value,
    required_scope: Option<&str>,
) -> NativePluginEntry {
    if let Some(installed) = value
        .as_object()
        .and_then(|object| object.get("installed"))
        .and_then(Value::as_array)
    {
        return native_plugin_entry_scoped(&Value::Array(installed.clone()), required_scope);
    }
    fn visit(value: &Value, required_scope: Option<&str>) -> Option<NativePluginEntry> {
        match value {
            Value::Array(items) => items.iter().find_map(|item| visit(item, required_scope)),
            Value::Object(object) => {
                if object.get("installed").and_then(Value::as_bool) == Some(false) {
                    return None;
                }
                let identity = ["id", "plugin", "name", "pluginName", "pluginId"]
                    .iter()
                    .filter_map(|key| object.get(*key).and_then(Value::as_str))
                    .any(|name| {
                        name == PLUGIN_NAME || name == format!("{PLUGIN_NAME}@{MARKETPLACE_NAME}")
                    });
                let scope_matches = required_scope.is_none_or(|required| {
                    object
                        .get("scope")
                        .and_then(Value::as_str)
                        .is_none_or(|scope| scope == required)
                });
                if identity && scope_matches {
                    let marketplace = object
                        .get("marketplace")
                        .or_else(|| object.get("marketplaceName"))
                        .and_then(|value| value.as_str().or_else(|| value.get("name")?.as_str()))
                        .map(str::to_owned)
                        .or_else(|| {
                            object.get("id").and_then(Value::as_str).and_then(|id| {
                                id.split_once('@').map(|(_, source)| source.to_owned())
                            })
                        });
                    if marketplace
                        .as_deref()
                        .is_none_or(|name| name == MARKETPLACE_NAME)
                    {
                        return Some(NativePluginEntry {
                            installed: true,
                            enabled: object.get("enabled").and_then(Value::as_bool),
                            version: ["version", "installedVersion"]
                                .iter()
                                .find_map(|key| object.get(*key).and_then(Value::as_str))
                                .map(str::to_owned),
                            path: ["path", "installPath", "pluginPath"]
                                .iter()
                                .find_map(|key| object.get(*key).and_then(Value::as_str))
                                .map(str::to_owned),
                            marketplace,
                            scope: object
                                .get("scope")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        });
                    }
                }
                object.values().find_map(|item| visit(item, required_scope))
            }
            _ => None,
        }
    }
    visit(value, required_scope).unwrap_or_default()
}

/// Read one exact legacy Claude plugin identity. Migration uses this only
/// when Legion's separate projection ledger proves ownership of the path.
pub fn claude_legacy_plugin_entry(value: &Value) -> NativePluginEntry {
    fn visit(value: &Value) -> Option<NativePluginEntry> {
        match value {
            Value::Array(values) => values.iter().find_map(visit),
            Value::Object(object) => {
                let id = object
                    .get("id")
                    .or_else(|| object.get("pluginId"))
                    .and_then(Value::as_str);
                if id == Some("legion@skills-dir")
                    && object
                        .get("scope")
                        .and_then(Value::as_str)
                        .is_none_or(|scope| scope == "user")
                {
                    return Some(NativePluginEntry {
                        installed: true,
                        enabled: object.get("enabled").and_then(Value::as_bool),
                        version: object
                            .get("version")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        path: ["path", "installPath", "pluginPath"]
                            .iter()
                            .find_map(|key| object.get(*key).and_then(Value::as_str))
                            .map(str::to_owned),
                        marketplace: Some("skills-dir".into()),
                        scope: object
                            .get("scope")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    });
                }
                object.values().find_map(visit)
            }
            _ => None,
        }
    }
    visit(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_args_are_explicit_and_host_scoped() {
        let root = Path::new("/opt/Legion/current");
        assert_eq!(
            MarketplaceClient::ClaudeCode.marketplace_add_args(root)[5],
            "user"
        );
        assert_eq!(
            MarketplaceClient::Codex.plugin_add_args(),
            ["plugin", "add", "legion@legion-installed", "--json"]
        );
        assert_eq!(
            MarketplaceClient::Codex.plugin_remove_args(),
            ["plugin", "remove", "legion@legion-installed", "--json"]
        );
    }

    #[test]
    fn native_list_readback_identifies_enabled_and_disabled_entries() {
        let enabled = native_plugin_entry(&json!({
            "plugins": [{
                "id": "legion@legion-installed",
                "enabled": true,
                "version": "1.2.3",
                "path": "/cache/legion"
            }]
        }));
        assert!(enabled.installed);
        assert_eq!(enabled.enabled, Some(true));
        assert_eq!(enabled.version.as_deref(), Some("1.2.3"));
        assert_eq!(enabled.path.as_deref(), Some("/cache/legion"));

        let disabled = native_plugin_entry(&json!({
            "plugins": [{"name": "legion", "marketplace": "legion-installed", "enabled": false}]
        }));
        assert!(disabled.installed);
        assert_eq!(disabled.enabled, Some(false));
    }

    #[test]
    fn codex_list_prefers_installed_array_and_legacy_claude_uses_exact_id() {
        let codex = native_plugin_entry(&json!({
            "available": [{"pluginId":"legion@legion-installed", "installed":false}],
            "installed": [{"pluginId":"legion@legion-installed", "installed":true, "version":"1.2.3"}]
        }));
        assert!(codex.installed);
        assert_eq!(codex.version.as_deref(), Some("1.2.3"));

        let legacy = claude_legacy_plugin_entry(&json!([
            {"id":"other@skills-dir", "enabled":false, "scope":"user"},
            {"id":"legion@skills-dir", "enabled":false, "scope":"user", "installPath":"/owned/legacy"}
        ]));
        assert!(legacy.installed);
        assert_eq!(legacy.enabled, Some(false));
        assert_eq!(legacy.path.as_deref(), Some("/owned/legacy"));
        assert!(
            !claude_legacy_plugin_entry(&json!([
                {"id":"legion@other-market", "enabled":false, "scope":"user"}
            ]))
            .installed
        );
    }

    #[test]
    fn codex_cache_lookup_uses_versioned_config_selected_entry() {
        let root = std::env::temp_dir().join(format!(
            "legion-codex-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let home = root.join("codex");
        let config = home.join("config.toml");
        let plugin = home
            .join("plugins/cache")
            .join(MARKETPLACE_NAME)
            .join(PLUGIN_NAME)
            .join("1.2.3");
        std::fs::create_dir_all(plugin.join(".codex-plugin")).expect("cache directory");
        std::fs::create_dir_all(config.parent().expect("config parent")).expect("home");
        std::fs::write(
            &config,
            format!("[plugins.\"{PLUGIN_NAME}@{MARKETPLACE_NAME}\"]\nenabled = false\n"),
        )
        .expect("config");
        std::fs::write(
            plugin.join(".codex-plugin/plugin.json"),
            r#"{"name":"legion","version":"1.2.3"}"#,
        )
        .expect("manifest");
        assert_eq!(
            find_codex_plugin_cache(&config, &home).expect("lookup"),
            CodexCacheLookup::Found(plugin.clone())
        );
        std::fs::create_dir_all(plugin.parent().expect("plugin parent").join("1.2.4"))
            .expect("second version");
        std::fs::write(
            plugin
                .parent()
                .expect("plugin parent")
                .join("1.2.4/.codex-plugin/plugin.json"),
            r#"{"name":"legion","version":"1.2.4"}"#,
        )
        .expect("second manifest");
        assert!(matches!(
            find_codex_plugin_cache(&config, &home).expect("ambiguous lookup"),
            CodexCacheLookup::Ambiguous(paths) if paths.len() == 2
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn codex_enabled_edit_preserves_unknown_config_and_matches_exact_key() {
        let root = std::env::temp_dir().join(format!(
            "legion-codex-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("config directory");
        let config = root.join("config.toml");
        let original = format!(
            "model = 'keep'\n[plugins.'{PLUGIN_NAME}@{MARKETPLACE_NAME}'] # native choice\nenabled_extra = true\nenabled = false # keep note\n[other]\nenabled = true\n"
        );
        std::fs::write(&config, &original).expect("config");
        assert!(!codex_enabled(&config).expect("disabled read"));
        set_codex_enabled(&config, false).expect("preserve disabled");
        let edited = std::fs::read_to_string(&config).expect("edited config");
        assert!(edited.contains("enabled_extra = true"));
        assert!(edited.contains("enabled = false # keep note"));
        assert!(edited.contains("[other]\nenabled = true"));
        set_codex_enabled(&config, true).expect("enable exact plugin");
        let enabled = std::fs::read_to_string(&config).expect("enabled config");
        assert!(enabled.contains("enabled = true # keep note"));
        assert!(enabled.contains("[other]\nenabled = true"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn unrelated_marketplace_entries_are_ignored() {
        let entry = native_plugin_entry(&json!({
            "plugins": [{"id": "legion@other-marketplace", "enabled": true}]
        }));
        assert!(!entry.installed);
    }

    #[test]
    fn codex_installed_collection_excludes_available_plugins() {
        let entry = native_plugin_entry(&json!({
            "available": [{
                "pluginId": "legion",
                "marketplaceName": "legion-installed",
                "installed": false,
                "version": "1.2.3"
            }],
            "installed": []
        }));
        assert!(!entry.installed);
    }

    #[test]
    fn codex_installed_collection_reads_entry_without_cache_path() {
        let entry = native_plugin_entry(&json!({
            "installed": [{
                "pluginId": "legion",
                "marketplaceName": "legion-installed",
                "version": "1.2.3",
                "enabled": false,
                "source": {"source": "local", "path": "/opt/Legion/current/plugin"}
            }],
            "available": []
        }));
        assert!(entry.installed);
        assert_eq!(entry.marketplace.as_deref(), Some("legion-installed"));
        assert_eq!(entry.enabled, Some(false));
        assert_eq!(entry.path, None);
    }
}
