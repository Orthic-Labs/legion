//! Port of `skills/seo/extensions/banana/scripts/presets.py`.
//!
//! The Python CLI persists each preset as `~/.banana/presets/<name>.json`.
//! This port keeps the pure logic — name sanitization, preset construction,
//! and listing/formatting — as filesystem-agnostic functions; callers own
//! the actual reads/writes (see `PresetStore::path_for` for the exact
//! on-disk layout Python used, reproduced verbatim for callers that do
//! their own I/O).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetError {
    /// Mirrors `_sanitize_name` exiting when nothing safe remains.
    EmptyName,
    /// Mirrors `cmd_create` refusing to overwrite an existing preset.
    AlreadyExists(String),
    /// Mirrors `_load_preset` / `cmd_delete` on a missing file.
    NotFound(String),
    /// Mirrors `cmd_delete` requiring `--confirm`.
    ConfirmRequired,
}

impl std::fmt::Display for PresetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => write!(
                f,
                "Preset name must contain only letters, numbers, hyphens, and underscores."
            ),
            Self::AlreadyExists(name) => {
                write!(f, "Preset '{name}' already exists. Use a different name.")
            }
            Self::NotFound(name) => write!(f, "Preset '{name}' not found."),
            Self::ConfirmRequired => write!(f, "Pass --confirm to delete the preset."),
        }
    }
}

impl std::error::Error for PresetError {}

/// Sanitize a preset name to prevent path traversal: strip everything
/// except `[a-zA-Z0-9_-]`, matching Python's
/// `re.sub(r'[^a-zA-Z0-9_\-]', '', name)`.
pub fn sanitize_name(name: &str) -> Result<String, PresetError> {
    let safe: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe.is_empty() {
        Err(PresetError::EmptyName)
    } else {
        Ok(safe)
    }
}

/// The on-disk filename (relative to `~/.banana/presets/`) for a preset,
/// matching `_preset_path`'s `f"{safe_name}.json"`.
pub fn preset_filename(name: &str) -> Result<String, PresetError> {
    Ok(format!("{}.json", sanitize_name(name)?))
}

/// A brand/style preset, matching the Python `preset` dict field-for-field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Preset {
    pub name: String,
    pub description: String,
    pub colors: Vec<String>,
    pub style: String,
    pub typography: String,
    pub lighting: String,
    pub mood: String,
    pub default_ratio: String,
    pub default_resolution: String,
}

/// Inputs to `cmd_create`, mirroring the argparse options (all optional
/// except `name`; empty-string inputs are treated as "not provided" for
/// `colors`, matching `[c.strip() for c in args.colors.split(",")] if
/// args.colors else []`).
#[derive(Debug, Clone, Default)]
pub struct CreatePresetInput<'a> {
    pub name: &'a str,
    pub colors: &'a str,
    pub style: &'a str,
    pub typography: &'a str,
    pub lighting: &'a str,
    pub mood: &'a str,
    pub description: &'a str,
    pub ratio: &'a str,
    pub resolution: &'a str,
}

/// Build a new [`Preset`] from CLI-style inputs, matching `cmd_create`'s
/// field construction and defaults (`description` defaults to
/// `"Custom preset: {name}"`; `ratio`/`resolution` default to `"16:9"` /
/// `"2K"`). Does not check for an existing file — callers that persist to
/// disk must check `AlreadyExists` themselves before calling this.
pub fn build_preset(input: &CreatePresetInput<'_>) -> Preset {
    let colors: Vec<String> = if input.colors.is_empty() {
        Vec::new()
    } else {
        input
            .colors
            .split(',')
            .map(|c| c.trim().to_string())
            .collect()
    };

    let description = if input.description.is_empty() {
        format!("Custom preset: {}", input.name)
    } else {
        input.description.to_string()
    };

    Preset {
        name: input.name.to_string(),
        description,
        colors,
        style: input.style.to_string(),
        typography: input.typography.to_string(),
        lighting: input.lighting.to_string(),
        mood: input.mood.to_string(),
        default_ratio: if input.ratio.is_empty() {
            "16:9".to_string()
        } else {
            input.ratio.to_string()
        },
        default_resolution: if input.resolution.is_empty() {
            "2K".to_string()
        } else {
            input.resolution.to_string()
        },
    }
}

/// One row for `cmd_list`'s formatted output: `(stem, description_or_invalid)`.
/// Matches Python printing `f"  {p.stem:20s} - {desc}"` per file, or
/// `"(invalid preset file)"` when JSON parsing fails.
pub fn format_list_row(stem: &str, parsed: Option<&Preset>) -> String {
    let desc = match parsed {
        Some(p) => p.description.clone(),
        None => "(invalid preset file)".to_string(),
    };
    format!("  {stem:<20} - {desc}")
}

/// Validate a `--confirm` delete gate, matching `cmd_delete`'s first check.
pub fn require_confirm(confirmed: bool) -> Result<(), PresetError> {
    if confirmed {
        Ok(())
    } else {
        Err(PresetError::ConfirmRequired)
    }
}
