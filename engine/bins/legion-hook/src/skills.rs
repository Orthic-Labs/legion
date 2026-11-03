//! Named-skill check: a skill Adrian names in a prompt must be called with the Skill tool before the turn ends.
//!
//! The names ride on the turn marker of the evidence ledger (`skills`), and the Skill calls are the ledger's
//! own `Skill` rows after that marker, so no second state file records them. Only the once-per-turn block
//! marker lives in `skills/<session>.blocked`. Every read or parse failure allows the stop.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{ledger, off, session_id, state_dir, write_atomic, Payload};

/// Installed skills as `plugin:name`: the installed assets, and the legion, pulse and egm plugins.
fn catalog() -> Vec<String> {
    let mut found = Vec::new();
    let mut add = |plugin: &str, skills: PathBuf| {
        for dir in fs::read_dir(skills).into_iter().flatten().flatten() {
            let text = fs::read_to_string(dir.path().join("SKILL.md")).unwrap_or_default();
            if !text.is_empty() && !text.contains("disable-model-invocation: true") {
                let name = dir.file_name().to_string_lossy().to_lowercase();
                found.push(format!("{plugin}:{name}"));
            }
        }
    };
    if let Some(assets) = crate::installed_assets_root() {
        add("legion", assets.join("skills"));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let cache = PathBuf::from(home.unwrap_or_default()).join(".claude/plugins/cache");
    for market in fs::read_dir(cache).into_iter().flatten().flatten() {
        for plugin in fs::read_dir(market.path()).into_iter().flatten().flatten() {
            let name = plugin.file_name().to_string_lossy().to_lowercase();
            if !["legion", "pulse", "egm"].contains(&name.as_str()) {
                continue;
            }
            for version in fs::read_dir(plugin.path()).into_iter().flatten().flatten() {
                add(&name, version.path().join("skills"));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Skills a prompt names: `/x`, `legion:x`, `pulse:x`, `egm:x`, or `x skill` for an installed `x`.
fn detect(prompt: &str, catalog: &[String]) -> Vec<String> {
    let edge = |c: char| !(c.is_alphanumeric() || matches!(c, '/' | ':' | '-' | '_'));
    let words: Vec<String> = prompt
        .split_whitespace()
        .map(|w| w.to_lowercase().trim_matches(edge).to_owned())
        .collect();
    let mut found: Vec<String> = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let prefixed = ["legion:", "pulse:", "egm:"]
            .iter()
            .any(|plugin| word.starts_with(plugin));
        let spec = match word.strip_prefix('/') {
            Some(rest) => rest,
            None if prefixed || words.get(index + 1).is_some_and(|next| next == "skill") => {
                word.as_str()
            }
            None => continue,
        };
        let exact = catalog.iter().find(|full| full.as_str() == spec);
        let named = catalog
            .iter()
            .filter(|full| full.ends_with(&format!(":{spec}")));
        let hit = exact.or(named.min_by_key(|full| !full.starts_with("legion:")));
        if let Some(full) = hit.filter(|full| !found.contains(*full)) {
            found.push(full.clone());
        }
        if found.len() >= 4 {
            break;
        }
    }
    found
}

/// The skills a typed prompt names, for the turn marker. A leading slash command is run by the host
/// itself (no Skill call follows), so the first word of such a prompt is not counted; Codex has no Skill tool.
pub fn named(payload: &Payload, prompt: &str) -> Vec<String> {
    let codex = payload.get("legion_host").and_then(Value::as_str) == Some("codex");
    let lower = prompt.to_lowercase();
    if codex || off("skill-named") || !(lower.contains("skill") || lower.contains(['/', ':'])) {
        return Vec::new();
    }
    let text = prompt.trim_start();
    let body = if text.starts_with(['/', '<']) {
        text.split_once(char::is_whitespace)
            .map_or("", |(_, rest)| rest)
    } else {
        text
    };
    detect(body, &catalog())
}

/// Did a successful `Skill` row call `name` (as `plugin:skill` or the bare skill)?
fn called(rows: &[Value], name: &str) -> bool {
    rows.iter().any(|row| {
        let arg = row["command"].as_str().unwrap_or("").trim();
        let arg = arg.trim_start_matches('/').to_lowercase();
        row["tool"] == "Skill"
            && row["failed"] != true
            && !arg.is_empty()
            && (arg == name || name.ends_with(&format!(":{arg}")))
    })
}

/// Stop: a skill named this turn with no `Skill` call since the prompt sends the turn back once, never on a
/// re-entered stop.
pub fn stop_check(request: &HookRequest) -> Option<HookResponse> {
    if !matches!(request.event_type.as_str(), "Stop" | "stop") || off("skill-named") {
        return None;
    }
    let payload = request.payload.as_object()?;
    if payload.get("stop_hook_active") == Some(&Value::Bool(true)) {
        return None;
    }
    let session = session_id(payload)?;
    let entries = ledger(&session);
    let start = entries
        .iter()
        .rposition(|entry| entry["marker"] == "turn")?;
    let marker = &entries[start];
    let names = marker["skills"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str);
    let missing: Vec<&str> = names
        .filter(|name| !called(&entries[start + 1..], name))
        .collect();
    if missing.is_empty() {
        return None;
    }
    let turn = format!("{}:{}", marker["t"], missing.join(","));
    let blocked = state_dir("skills")?.join(format!("{session}.blocked"));
    if fs::read_to_string(&blocked).is_ok_and(|seen| seen == turn) {
        return None;
    }
    write_atomic(&blocked, turn.as_bytes())?;
    let reason = format!(
        "You named skill {}; call it with the Skill tool before finishing.",
        missing.join(", ")
    );
    Some(HookResponse::denied(
        request.event_type.clone(),
        "ARC_SKILL_NAMED",
        reason,
        "strong",
    ))
}
