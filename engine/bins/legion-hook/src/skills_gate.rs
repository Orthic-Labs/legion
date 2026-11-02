//! Skill enforcement: a skill Adrian names is called before other work, and event skills before UI or copy edits.

use std::env::var_os;
use std::fs;
use std::path::PathBuf;

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{edit_path, now_secs, off, session_id, state_dir, str_field, tool_name};
use crate::state::{write_atomic, Payload};
use crate::transcript::{human, skill_loaded_since_compaction};

type Pending = Vec<(u64, String)>;

/// Installed skills as `plugin:name`: the installed assets, and the legion, pulse and egm plugins.
fn catalog() -> Vec<String> {
    let mut found = Vec::new();
    let mut add = |plugin: &str, skills: PathBuf| {
        for dir in fs::read_dir(skills).into_iter().flatten().flatten() {
            let text = fs::read_to_string(dir.path().join("SKILL.md")).unwrap_or_default();
            if !text.is_empty() && !text.contains("disable-model-invocation: true") {
                found.push(format!(
                    "{plugin}:{}",
                    dir.file_name().to_string_lossy().to_lowercase()
                ));
            }
        }
    };
    if let Some(assets) = crate::installed_assets_root() {
        add("legion", assets.join("skills"));
    }
    let home = var_os("HOME")
        .or_else(|| var_os("USERPROFILE"))
        .unwrap_or_default();
    let cache = PathBuf::from(home).join(".claude/plugins/cache");
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

fn pending_path(payload: &Payload) -> Option<PathBuf> {
    Some(state_dir("skills")?.join(format!("{}.pending", session_id(payload)?)))
}

/// UserPromptSubmit: record the skills Adrian named as pending and tell the agent to call them first.
pub fn on_user_prompt(request: &HookRequest) -> Option<HookResponse> {
    let event = request.event_type.as_str();
    if off("skill-named") || !matches!(event, "UserPromptSubmit" | "user-prompt-submit") {
        return None;
    }
    let payload = request.payload.as_object()?;
    let prompt =
        str_field(payload, &["prompt", "user_prompt", "userPrompt"]).filter(|text| human(text))?;
    let path = pending_path(payload)?;
    let _ = fs::remove_file(&path);
    let lower = prompt.to_lowercase();
    if !(lower.contains("skill") || lower.contains('/') || lower.contains(':')) {
        return None;
    }
    let names = detect(&prompt, &catalog());
    if names.is_empty() {
        return None;
    }
    let list = names.join(", ");
    let codex = payload.get("legion_host").and_then(|host| host.as_str()) == Some("codex");
    let context = if codex {
        format!("Adrian asked for skill {list}: read its SKILL.md first and follow it before other work.")
    } else {
        let lines: Vec<String> = names
            .iter()
            .map(|name| format!("{} {name}", now_secs()))
            .collect();
        write_atomic(&path, lines.join("\n").as_bytes());
        format!("Adrian asked for skill {list}: call the Skill tool for it before other work; an agent of the same name is not a substitute.")
    };
    Some(
        HookResponse::allowed(request.event_type.clone(), "named skill recorded")
            .with_additional_context(context),
    )
}

/// Pending skills after one tool call, and whether the call is denied. A pending skill expires after
/// 1 h, clears on its `Skill` call or when the transcript shows it loaded; reading and planning tools pass.
fn gate(
    mut pending: Pending,
    tool: &str,
    arg: &str,
    now: u64,
    loaded: &dyn Fn(&str) -> bool,
) -> (Pending, bool) {
    pending.retain(|(t, _)| now.saturating_sub(*t) <= 3600);
    let arg = arg.trim().trim_start_matches('/');
    if tool == "Skill" {
        pending.retain(|(_, skill)| !(skill == arg || skill.ends_with(&format!(":{arg}"))));
    }
    let reading = "Skill Read Grep Glob ToolSearch mcp__ccd_turn__update_plan TaskCreate TaskUpdate TaskList TaskGet TodoWrite";
    let allowed = reading.split(' ').any(|name| name == tool);
    if !allowed {
        pending.retain(|(_, skill)| !loaded(skill));
    }
    let denied = !allowed && !pending.is_empty();
    (pending, denied)
}

fn named_gate(payload: &Payload, tool: &str) -> Option<(&'static str, String)> {
    if off("skill-named") || payload.contains_key("agent_id") {
        return None;
    }
    let path = pending_path(payload)?;
    let text = fs::read_to_string(&path).ok()?;
    let parse = |line: &str| {
        Some((
            line.split_once(' ')?.0.parse::<u64>().ok()?,
            line.split_once(' ')?.1.to_owned(),
        ))
    };
    let before: Pending = text.lines().filter_map(parse).collect();
    let arg = crate::state::tool_input(payload).and_then(|input| str_field(input, &["skill"]));
    let transcript = str_field(payload, &["transcript_path"]);
    let loaded = |skill: &str| {
        transcript
            .as_deref()
            .and_then(|path| skill_loaded_since_compaction(path, skill))
            == Some(true)
    };
    let (after, denied) = gate(
        before.clone(),
        tool,
        &arg.unwrap_or_default(),
        now_secs(),
        &loaded,
    );
    if after != before {
        let lines: Vec<String> = after
            .iter()
            .map(|(t, skill)| format!("{t} {skill}"))
            .collect();
        write_atomic(&path, lines.join("\n").as_bytes());
    }
    let names: Vec<&str> = after.iter().map(|(_, skill)| skill.as_str()).collect();
    denied.then(|| {
        (
            "ARC_SKILL_FIRST",
            format!("Call Skill {} first (Adrian named it).", names.join(", ")),
        )
    })
}

/// The event skill an edit of this path needs: designer for UI files, writing for reader-facing copy.
fn required_skill(path: &str) -> Option<&'static str> {
    let path = path.replace('\\', "/").to_lowercase();
    let scratch = [
        "/volumes/d/scratch",
        "d:/scratch",
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ];
    if scratch.iter().any(|dir| path.starts_with(dir))
        || path.contains("/node_modules/")
        || path.contains("/target/")
    {
        return None;
    }
    let (dir, file) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
    let ext = file.rsplit_once('.').map_or("", |(_, ext)| ext);
    let web = ["tsx", "jsx", "css", "scss", "svelte", "vue", "html"].contains(&ext);
    if web || (ext == "swift" && (dir.ends_with("/views") || dir.ends_with("/view"))) {
        return Some("legion:designer");
    }
    let doc = ext == "md" && (dir.ends_with("/docs") || dir.contains("/docs/"));
    let copy =
        file.starts_with("readme") || ext == "strings" || (ext == "json" && file.contains("copy"));
    (doc || copy || dir.contains("/marketing")).then_some("legion:writing")
}

fn event_gate(payload: &Payload) -> Option<(&'static str, String)> {
    let codex = payload.get("legion_host").and_then(|host| host.as_str()) == Some("codex");
    if off("skill-event") || codex || payload.contains_key("agent_id") {
        return None;
    }
    let skill = required_skill(&edit_path(payload)?.to_string_lossy())?;
    let transcript = str_field(payload, &["transcript_path"])?;
    let loaded = skill_loaded_since_compaction(&transcript, skill)?;
    (!loaded).then(|| {
        (
            "ARC_SKILL_EVENT",
            format!("Load {skill} before editing this file: call Skill {skill} first."),
        )
    })
}

/// PreToolUse: deny non-reading tools while a named skill is pending, and event-skill edits without it.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let (code, message) =
        named_gate(payload, &tool_name(payload)?).or_else(|| event_gate(payload))?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        code,
        message,
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skills() -> Vec<String> {
        [
            "legion:designer",
            "legion:writing",
            "pulse:membrane",
            "egm:egm-style",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn a_named_skill_is_found_by_slash_prefix_or_the_word_skill() {
        assert_eq!(
            detect("use /designer for this", &skills()),
            ["legion:designer"]
        );
        assert_eq!(
            detect("load pulse:membrane first", &skills()),
            ["pulse:membrane"]
        );
        assert_eq!(
            detect("apply the writing skill.", &skills()),
            ["legion:writing"]
        );
        assert!(detect("use the designer, then writing", &skills()).is_empty());
        assert!(detect("open /Volumes/D/x", &skills()).is_empty());
    }

    #[test]
    fn a_pending_skill_blocks_work_until_it_is_called() {
        let pending = vec![(100, "legion:designer".to_owned())];
        let none = |_: &str| false;
        assert!(gate(pending.clone(), "Edit", "", 200, &none).1);
        assert!(!gate(pending.clone(), "Read", "", 200, &none).1);
        assert!(
            gate(pending.clone(), "Skill", "legion:designer", 200, &none)
                .0
                .is_empty()
        );
        assert!(gate(pending.clone(), "Skill", "designer", 200, &none)
            .0
            .is_empty());
        assert!(!gate(pending.clone(), "Edit", "", 200, &|_: &str| true).1);
        assert!(!gate(pending, "Edit", "", 100 + 3601, &none).1);
    }

    #[test]
    fn ui_and_copy_files_need_an_event_skill() {
        assert_eq!(required_skill("/r/app/Button.tsx"), Some("legion:designer"));
        assert_eq!(required_skill("/r/docs/guide.md"), Some("legion:writing"));
        assert_eq!(required_skill("/r/README.md"), Some("legion:writing"));
        assert_eq!(required_skill("/r/src/lib.rs"), None);
        assert_eq!(required_skill("/Volumes/D/scratch/x/a.tsx"), None);
    }
}
