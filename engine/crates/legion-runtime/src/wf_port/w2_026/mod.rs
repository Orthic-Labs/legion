//! Port of `skills/seo/extensions/banana/scripts/setup_mcp.py` and
//! `skills/seo/extensions/banana/scripts/validate_setup.py`
//! (chunk w2_026, area `skills/seo/extensions/banana/scripts`, target crate
//! `legion-runtime`).
//!
//! Coverage check: `git grep -i "nanobanana\|banana"` and
//! `git grep "GOOGLE_AI_API_KEY"` across `engine/` turned up nothing. This is
//! a fresh, faithful port.
//!
//! The two Python scripts read/write Claude Code's `~/.claude/settings.json`
//! to add, inspect, remove, or validate a `nanobanana-mcp` MCP server entry
//! (an image-generation tool unrelated to Membrane/Blueprint, which are out
//! of scope here per product direction).
//!
//! Ported faithfully as a JSON-value-in, JSON-value-out core (this crate's
//! usual style of keeping file/env I/O at the edges):
//! - `check_setup` → [`describe_setup`] (configured status, masked key,
//!   model, matching the same `key[:8] + "..." + key[-4:] if len(key) > 12
//!   else "(not set)"` masking rule, see [`mask_key`]),
//! - `remove_mcp` → [`remove_entry`],
//! - `setup_mcp` → [`apply_entry`] (same empty/whitespace-only key error),
//! - `validate_setup.py`'s nine checks → [`check_settings_file_exists`],
//!   [`check_json_valid`], [`check_mcp_configured`],
//!   [`check_command_is_npx`], [`check_package_correct`],
//!   [`check_api_key_set`], [`check_model_set`], [`check_npx_available`],
//!   [`check_output_dir`], composed by [`run_validation`] in the same order
//!   and short-circuiting the same way (missing settings file, or invalid
//!   JSON, stops after that check; everything else always runs, matching the
//!   source, which appends checks 4-7 only `if has_mcp` but always runs
//!   checks 8-9).
//!
//! Not ported here (I/O, left to callers/binaries): reading/writing the real
//! `~/.claude/settings.json`, `input()` prompting, `shutil.which("npx")`,
//! creating the output directory on disk, and CLI argv parsing /
//! `sys.exit`. [`settings_path`] and [`output_dir`] reproduce the source's
//! path computation (`Path.home() / ".claude" / "settings.json"` and
//! `Path.home() / "Documents" / "nanobanana_generated"`) for callers that do
//! perform that I/O.

use std::path::PathBuf;

use serde_json::{json, Value};

/// The MCP server's key in `mcpServers`.
pub const MCP_NAME: &str = "nanobanana-mcp";
/// The npm package the entry launches via `npx -y <package>`.
pub const MCP_PACKAGE: &str = "@ycse/nanobanana-mcp";
/// Default value for the `NANOBANANA_MODEL` env var when none is supplied.
pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
/// Where generated images are written, relative to the home directory.
pub const OUTPUT_DIR_SUFFIX: &[&str] = &["Documents", "nanobanana_generated"];

/// Resolves `$HOME`, mirroring Python's `Path.home()`.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `~/.claude/settings.json`, matching `setup_mcp.py`'s `SETTINGS_PATH`.
pub fn settings_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".claude").join("settings.json"))
}

/// `~/Documents/nanobanana_generated`, matching `validate_setup.py`'s
/// `OUTPUT_DIR`.
pub fn output_dir() -> Option<PathBuf> {
    home_dir().map(|home| {
        let mut path = home;
        for part in OUTPUT_DIR_SUFFIX {
            path.push(part);
        }
        path
    })
}

/// Errors from [`apply_entry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// `setup_mcp.py`: `if not api_key or not api_key.strip(): ... sys.exit(1)`.
    #[error("API key cannot be empty.")]
    EmptyApiKey,
}

/// Masks an API key the same way `check_setup`/`validate_setup.py` do:
/// `key[:8] + "..." + key[-4:]` when longer than 12 characters, else a
/// placeholder. Operates on Unicode scalar values (`chars`), like Python 3
/// string slicing operates on code points.
pub fn mask_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() > 12 {
        let head: String = chars[..8].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}...{tail}")
    } else {
        "(not set)".to_string()
    }
}

/// The `mcpServers` object, or an empty object if absent — matching
/// `settings.get("mcpServers", {})`.
fn mcp_servers(settings: &Value) -> Value {
    settings
        .get("mcpServers")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

/// Result of [`describe_setup`], the data `check_setup()` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupDescription {
    pub package: String,
    pub masked_api_key: String,
    pub model: String,
}

/// Port of `check_setup()`. Returns `None` when the entry is absent
/// (`check_setup` prints "NOT configured" and returns `False`).
pub fn describe_setup(settings: &Value) -> Option<SetupDescription> {
    let servers = mcp_servers(settings);
    let entry = servers.get(MCP_NAME)?;
    let env = entry.get("env").cloned().unwrap_or_else(|| json!({}));
    let key = env
        .get("GOOGLE_AI_API_KEY")
        .and_then(Value::as_str)
        .unwrap_or("");
    let model = env
        .get("NANOBANANA_MODEL")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| DEFAULT_MODEL.to_string());
    Some(SetupDescription {
        package: MCP_PACKAGE.to_string(),
        masked_api_key: mask_key(key),
        model,
    })
}

/// Port of `remove_mcp()`'s mutation. Returns `true` if an entry was
/// present and removed, `false` if there was nothing to remove.
pub fn remove_entry(settings: &mut Value) -> bool {
    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().expect("settings coerced to object");
    let Some(servers) = obj.get_mut("mcpServers").and_then(Value::as_object_mut) else {
        return false;
    };
    servers.remove(MCP_NAME).is_some()
}

/// Port of `setup_mcp(api_key)`'s mutation. Trims the key like the source
/// (`api_key = api_key.strip()`), then writes the same shape:
/// `{"command": "npx", "args": ["-y", MCP_PACKAGE], "env": {...}}`.
pub fn apply_entry(settings: &mut Value, api_key: &str) -> Result<(), SetupError> {
    if api_key.trim().is_empty() {
        return Err(SetupError::EmptyApiKey);
    }
    let trimmed = api_key.trim();

    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().expect("settings coerced to object");
    let needs_new_servers = match obj.get("mcpServers") {
        Some(value) => !value.is_object(),
        None => true,
    };
    if needs_new_servers {
        obj.insert("mcpServers".to_string(), json!({}));
    }
    let servers = obj
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .expect("mcpServers coerced to object above");
    servers.insert(
        MCP_NAME.to_string(),
        json!({
            "command": "npx",
            "args": ["-y", MCP_PACKAGE],
            "env": {
                "GOOGLE_AI_API_KEY": trimmed,
                "NANOBANANA_MODEL": DEFAULT_MODEL,
            },
        }),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// validate_setup.py
// ---------------------------------------------------------------------

/// One `[PASS]`/`[FAIL]` line from `validate_setup.py`'s `check()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub label: String,
    pub passed: bool,
    pub detail: String,
}

impl CheckResult {
    fn new(label: &str, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            label: label.to_string(),
            passed,
            detail: detail.into(),
        }
    }

    /// Renders the same line `check()` prints: `  [PASS] label: detail`
    /// (detail omitted when empty).
    pub fn render(&self) -> String {
        let status = if self.passed { "PASS" } else { "FAIL" };
        if self.detail.is_empty() {
            format!("  [{status}] {}", self.label)
        } else {
            format!("  [{status}] {}: {}", self.label, self.detail)
        }
    }
}

/// Check 1: `SETTINGS_PATH.exists()`.
pub fn check_settings_file_exists(exists: bool, settings_path: &str) -> CheckResult {
    CheckResult::new(
        "Claude Code settings.json exists",
        exists,
        settings_path.to_string(),
    )
}

/// Check 2: the file parsed as JSON. `error_detail` is the parser's message
/// on failure (matching `str(e)` from `json.JSONDecodeError`).
pub fn check_json_valid(parsed_ok: bool, error_detail: &str) -> CheckResult {
    if parsed_ok {
        CheckResult::new("settings.json is valid JSON", true, "")
    } else {
        CheckResult::new("settings.json is valid JSON", false, error_detail)
    }
}

/// Check 3: `MCP_NAME in servers`. Returns the check plus whether checks
/// 4-7 should run (`if has_mcp:` in the source).
pub fn check_mcp_configured(settings: &Value) -> (CheckResult, bool) {
    let servers = mcp_servers(settings);
    let has_mcp = servers.get(MCP_NAME).is_some();
    (
        CheckResult::new(&format!("MCP server '{MCP_NAME}' configured"), has_mcp, ""),
        has_mcp,
    )
}

fn mcp_entry(settings: &Value) -> Value {
    mcp_servers(settings)
        .get(MCP_NAME)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Check 4: `mcp.get("command") == "npx"`.
pub fn check_command_is_npx(settings: &Value) -> CheckResult {
    let entry = mcp_entry(settings);
    let command = entry.get("command").and_then(Value::as_str);
    CheckResult::new(
        "Command is 'npx'",
        command == Some("npx"),
        command.unwrap_or("(missing)"),
    )
}

/// Check 5: `"@ycse/nanobanana-mcp" in args`.
pub fn check_package_correct(settings: &Value) -> CheckResult {
    let entry = mcp_entry(settings);
    let args: Vec<String> = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_str().map(str::to_string).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    let has_pkg = args.iter().any(|a| a == MCP_PACKAGE);
    // Python renders the list with repr-style quoting; `{:?}` on a Vec<String>
    // produces the same `["a", "b"]` shape.
    CheckResult::new("Package is @ycse/nanobanana-mcp", has_pkg, format!("{args:?}"))
}

/// Check 6: `bool(env.get("GOOGLE_AI_API_KEY", ""))`.
pub fn check_api_key_set(settings: &Value) -> CheckResult {
    let entry = mcp_entry(settings);
    let key = entry
        .get("env")
        .and_then(|e| e.get("GOOGLE_AI_API_KEY"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let detail = if key.chars().count() > 12 {
        mask_key(key)
    } else {
        "(empty or short)".to_string()
    };
    CheckResult::new("GOOGLE_AI_API_KEY is set", !key.is_empty(), detail)
}

/// Check 7: `bool(env.get("NANOBANANA_MODEL", ""))`.
pub fn check_model_set(settings: &Value) -> CheckResult {
    let entry = mcp_entry(settings);
    let model = entry
        .get("env")
        .and_then(|e| e.get("NANOBANANA_MODEL"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let detail = if model.is_empty() {
        "(not set, will use package default)".to_string()
    } else {
        model.to_string()
    };
    CheckResult::new("NANOBANANA_MODEL is set", !model.is_empty(), detail)
}

/// Check 8: `shutil.which("npx") is not None`.
pub fn check_npx_available(npx_path: Option<&str>) -> CheckResult {
    CheckResult::new(
        "npx is available in PATH",
        npx_path.is_some(),
        npx_path.unwrap_or("not found"),
    )
}

/// Outcome of checking/creating the output directory, for [`check_output_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputDirState {
    /// The directory already existed.
    AlreadyExists,
    /// The directory did not exist and was created successfully.
    Created,
    /// The directory did not exist and creation failed; `detail` is the OS
    /// error text (`str(e)` from `OSError`).
    CreateFailed { detail: String },
}

/// Check 9: `OUTPUT_DIR.exists()`, else `mkdir(parents=True, exist_ok=True)`.
pub fn check_output_dir(state: &OutputDirState, output_dir: &str) -> CheckResult {
    match state {
        OutputDirState::AlreadyExists => {
            CheckResult::new("Output directory exists", true, output_dir.to_string())
        }
        OutputDirState::Created => {
            CheckResult::new("Output directory created", true, output_dir.to_string())
        }
        OutputDirState::CreateFailed { detail } => {
            CheckResult::new("Output directory writable", false, detail.clone())
        }
    }
}

/// The full report from `validate_setup.py`'s `main()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub checks: Vec<CheckResult>,
}

impl ValidationReport {
    pub fn passed(&self) -> usize {
        self.checks.iter().filter(|c| c.passed).count()
    }

    pub fn total(&self) -> usize {
        self.checks.len()
    }

    /// `main()`'s return value: `0` if every check passed, else `1`. Also
    /// covers the two early-return paths (`return 1` when the settings file
    /// is missing or fails to parse), which callers represent by passing a
    /// `checks` list that stops at that point.
    pub fn exit_code(&self) -> i32 {
        if !self.checks.is_empty() && self.passed() == self.total() {
            0
        } else {
            1
        }
    }
}

/// Composes checks 3-9 against an already-parsed `settings.json`, matching
/// `main()`'s control flow from "MCP entry exists" onward: checks 4-7 run
/// only when check 3 (`has_mcp`) passes, checks 8-9 always run.
pub fn run_validation(
    settings: &Value,
    npx_path: Option<&str>,
    output_dir_state: &OutputDirState,
    output_dir_display: &str,
) -> Vec<CheckResult> {
    let mut checks = Vec::new();
    let (mcp_check, has_mcp) = check_mcp_configured(settings);
    checks.push(mcp_check);
    if has_mcp {
        checks.push(check_command_is_npx(settings));
        checks.push(check_package_correct(settings));
        checks.push(check_api_key_set(settings));
        checks.push(check_model_set(settings));
    }
    checks.push(check_npx_available(npx_path));
    checks.push(check_output_dir(output_dir_state, output_dir_display));
    checks
}
