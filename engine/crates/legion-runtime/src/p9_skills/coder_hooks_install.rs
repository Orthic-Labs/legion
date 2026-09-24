//! Packet U01: Rust port of `skills/coder/hooks/install.py`.
//!
//! Installs this repo's synced Claude Code hooks (`hooks.json`, sitting next
//! to the hook files) into the LOCAL machine's `~/.claude/settings.json`
//! (under the matching event/matcher) and `~/.claude/hooks/hooks-manifest.json`,
//! using this machine's absolute path to each hook file. Idempotent: re-running
//! dedupes by hook basename (`settings.json`) or hook id (`hooks-manifest.json`).
//!
//! File I/O sits behind [`InstallIo`] so tests never touch a real `~/.claude`
//! directory. The default [`RealInstallIo`] mirrors the Python script's
//! filesystem behaviour exactly, including the `settings.json` backup copy
//! written before any mutation.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError(pub String);

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for InstallError {}

/// Filesystem seam. Paths are always absolute, matching what the Python
/// script's `os.path` calls produce.
pub trait InstallIo {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn write_string(&self, path: &Path, contents: &str) -> std::io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
    fn copy_file(&self, src: &Path, dst: &Path) -> std::io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
}

pub struct RealInstallIo;

impl InstallIo for RealInstallIo {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
    fn write_string(&self, path: &Path, contents: &str) -> std::io::Result<()> {
        std::fs::write(path, contents)
    }
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
    fn copy_file(&self, src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::copy(src, dst).map(|_| ())
    }
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
}

/// Where the Python script's `~/.claude` layout lives on this machine. Port
/// of `CLAUDE`/`SETTINGS`/`MANIFEST`/`PYBIN`.
pub struct ClaudeLayout {
    pub settings: PathBuf,
    pub manifest: PathBuf,
    pub py_bin: &'static str,
}

impl ClaudeLayout {
    /// Port of the module-level `CLAUDE = os.path.expanduser("~/.claude")`
    /// derivation, plus `PYBIN` selection by platform.
    pub fn for_home(home: &Path) -> Self {
        let claude = home.join(".claude");
        Self {
            settings: claude.join("settings.json"),
            manifest: claude.join("hooks").join("hooks-manifest.json"),
            py_bin: if cfg!(windows) { "python" } else { "python3" },
        }
    }
}

/// One `registered <id> -> <command>` line the Python script prints per hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredHook {
    pub id: String,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct InstallSummary {
    pub registered: Vec<RegisteredHook>,
    pub backup_path: PathBuf,
}

/// Port of `main()`: `hooks_dir` is the directory containing `hooks.json`
/// and the hook `.py` files (`HERE` in Python — the directory the installer
/// script itself lives in); `layout` is the target machine's `~/.claude`
/// paths. Returns the same idempotent, dedupe-by-basename /
/// dedupe-by-id behaviour as the Python script.
pub fn install(
    hooks_dir: &Path,
    layout: &ClaudeLayout,
    io: &dyn InstallIo,
) -> Result<InstallSummary, InstallError> {
    let hooks_json_path = hooks_dir.join("hooks.json");
    let hooks: Vec<Value> = read_json(io, &hooks_json_path)?
        .as_array()
        .cloned()
        .ok_or_else(|| InstallError(format!("{}: not a JSON array", hooks_json_path.display())))?;

    let mut settings = read_json(io, &layout.settings)?;
    let mut manifest = if io.exists(&layout.manifest) {
        read_json(io, &layout.manifest)?
    } else {
        json!({"hooks": []})
    };

    let backup_path = PathBuf::from(format!("{}.pre-synced-hooks.bak", layout.settings.display()));
    io.copy_file(&layout.settings, &backup_path)
        .map_err(|e| InstallError(format!("backing up {}: {e}", layout.settings.display())))?;

    if !settings.is_object() {
        return Err(InstallError(format!("{}: not a JSON object", layout.settings.display())));
    }
    let settings_obj = settings.as_object_mut().unwrap();
    settings_obj.entry("hooks").or_insert_with(|| json!({}));
    let hooks_by_event = settings_obj
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| InstallError(format!("{}: \"hooks\" is not an object", layout.settings.display())))?;

    let mut registered = Vec::new();

    for hk in &hooks {
        let file = field_str(hk, "file", &hooks_json_path)?;
        let event = field_str(hk, "event", &hooks_json_path)?;
        let matcher = field_str(hk, "matcher", &hooks_json_path)?;
        let hook_manifest_entry = hk
            .get("manifest")
            .cloned()
            .ok_or_else(|| InstallError(format!("{}: hook missing \"manifest\"", hooks_json_path.display())))?;

        let abs_path = normalize_forward_slashes(&hooks_dir.join(&file));
        let command = format!("{} {abs_path}", layout.py_bin);
        let basename = file.clone();

        // settings.json: find/create the event -> matcher entry, dedupe by basename.
        let event_list = hooks_by_event
            .entry(event.clone())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| InstallError(format!("hooks.{event} is not an array")))?;
        let entry_index = event_list.iter().position(|e| {
            e.get("matcher").and_then(Value::as_str) == Some(matcher.as_str())
        });
        let entry_index = match entry_index {
            Some(i) => i,
            None => {
                event_list.push(json!({"matcher": matcher, "hooks": []}));
                event_list.len() - 1
            }
        };
        let entry = event_list[entry_index]
            .as_object_mut()
            .ok_or_else(|| InstallError("hook entry is not an object".to_string()))?;
        let hook_list = entry
            .entry("hooks")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| InstallError("entry.hooks is not an array".to_string()))?;
        hook_list.retain(|h| {
            !h.get("command")
                .and_then(Value::as_str)
                .map(|c| c.ends_with(basename.as_str()))
                .unwrap_or(false)
        });
        hook_list.push(json!({"type": "command", "command": command}));

        // hooks-manifest.json: replace the entry by id.
        let mut man = hook_manifest_entry
            .as_object()
            .cloned()
            .ok_or_else(|| InstallError(format!("{}: hook \"manifest\" is not an object", hooks_json_path.display())))?;
        let man_id = man
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| InstallError(format!("{}: hook manifest missing \"id\"", hooks_json_path.display())))?
            .to_string();
        man.insert("command".to_string(), json!(command));

        let manifest_hooks = manifest
            .as_object_mut()
            .and_then(|m| m.entry("hooks").or_insert_with(|| json!([])).as_array_mut())
            .ok_or_else(|| InstallError("hooks-manifest.json: \"hooks\" is not an array".to_string()))?;
        manifest_hooks.retain(|h| h.get("id").and_then(Value::as_str) != Some(man_id.as_str()));
        manifest_hooks.push(Value::Object(man));

        registered.push(RegisteredHook { id: man_id, command });
    }

    io.write_string(&layout.settings, &serde_json::to_string_pretty(&settings).unwrap_or_default())
        .map_err(|e| InstallError(format!("writing {}: {e}", layout.settings.display())))?;
    if let Some(parent) = layout.manifest.parent() {
        io.create_dir_all(parent)
            .map_err(|e| InstallError(format!("creating {}: {e}", parent.display())))?;
    }
    // Python's `json.dump(..., indent=1)` for the manifest.
    io.write_string(&layout.manifest, &to_string_indent1(&manifest))
        .map_err(|e| InstallError(format!("writing {}: {e}", layout.manifest.display())))?;

    Ok(InstallSummary { registered, backup_path })
}

fn field_str(hk: &Value, key: &str, hooks_json_path: &Path) -> Result<String, InstallError> {
    hk.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| InstallError(format!("{}: hook missing \"{key}\"", hooks_json_path.display())))
}

fn normalize_forward_slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn read_json(io: &dyn InstallIo, path: &Path) -> Result<Value, InstallError> {
    let raw = io
        .read_to_string(path)
        .map_err(|e| InstallError(format!("reading {}: {e}", path.display())))?;
    serde_json::from_str(&raw).map_err(|e| InstallError(format!("parsing {}: {e}", path.display())))
}

/// `json.dump(obj, f, indent=1)`: two-space-free, one-space-per-level
/// indentation with no trailing newline (Python's `json.dump` writes none).
fn to_string_indent1(v: &Value) -> String {
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    serde::Serialize::serialize(v, &mut ser).expect("Value serialization never fails");
    String::from_utf8(buf).expect("serde_json output is always valid UTF-8")
}
