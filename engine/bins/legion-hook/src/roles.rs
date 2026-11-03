//! Guard check `roles`: every subagent names a role, and the role sets its model.

use serde_json::Value;

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{off, str_field, tool_input, tool_name};
use crate::transcript::skill_loaded_since_compaction;

/// Role id, its tier in `model-tiers.json`, the fallback model, and whether opus or fable may run it.
static ROLES: [(&str, &str, &str, bool); 6] = [
    ("alchemist", "mechanical-cheap", "haiku", false),
    ("alchemist-specialist", "balanced-executor", "sonnet", false),
    ("oracle", "frontier-judgment", "opus", true),
    ("sage", "frontier-judgment", "opus", true),
    ("sentry", "mechanical-cheap", "haiku", false),
    ("council-seat", "deliberation", "fable", true),
];
/// Read-only lookup types (plus `egm:*`): haiku by default, sonnet allowed.
const LOOKUPS: [&str; 5] = [
    "Explore",
    "general-purpose",
    "claude-code-guide",
    "Plan",
    "web-fetch",
];
const NAME_A_ROLE: &str = "Name a role: subagent_type must be legion:alchemist, legion:alchemist-specialist, legion:oracle, legion:sage, legion:sentry, legion:council-seat, or a lookup type (Explore, general-purpose, claude-code-guide, Plan, web-fetch, egm:*).";

#[derive(Debug, PartialEq)]
enum Decision {
    Allow,
    Deny(&'static str, String),
    /// Run the agent on this model instead.
    Model(String),
}

/// The Claude Code alias (`opus`, `sonnet`, `haiku`, `fable`) a model name denotes.
fn alias(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    let known = ["opus", "sonnet", "haiku", "fable"];
    let found = known.iter().find(|alias| lower.contains(**alias));
    found.map_or(lower.clone(), |alias| alias.to_string())
}

/// The model `model-tiers.json` gives a tier on Claude Code.
fn tier_model(tiers: &Value, tier: &str) -> Option<String> {
    let name = tiers["tiers"][tier]["hosts"]["claude-code"].as_str()?;
    Some(alias(name))
}

/// `model-tiers.json` from the env override or the plugin root; null when unreadable.
fn load_tiers() -> Value {
    let env = |name: &str| std::env::var(name).unwrap_or_default();
    let root = env("CLAUDE_PLUGIN_ROOT");
    let file = "src/config/model-tiers.json";
    let paths = [
        env("LEGION_MODEL_TIERS"),
        format!("{root}/share/legion/{file}"),
        format!("{root}/{file}"),
    ];
    let read =
        |path: &String| serde_json::from_str::<Value>(&std::fs::read_to_string(path).ok()?).ok();
    paths.iter().find_map(read).unwrap_or(Value::Null)
}

/// A prompt line that starts `Specialist reason:`, allowing list and quote markers before it.
fn has_reason(prompt: &str) -> bool {
    let marker = |c: char| c.is_whitespace() || "-*>_#".contains(c);
    prompt
        .lines()
        .map(|line| line.trim_start_matches(marker).to_lowercase())
        .any(|line| line.starts_with("specialist reason:"))
}

fn decide(
    tiers: &Value,
    subagent: &str,
    prompt: &str,
    model: &str,
    council_loaded: &dyn Fn() -> Option<bool>,
) -> Decision {
    let bare = subagent.strip_prefix("legion:").unwrap_or(subagent);
    let role = ROLES.iter().find(|role| role.0 == bare);
    let model = alias(model);
    let frontier = |name: &str| matches!(name, "opus" | "fable");
    let Some(&(id, tier, fallback, may_use_frontier)) = role else {
        if !LOOKUPS.contains(&subagent) && !subagent.starts_with("egm:") {
            return Decision::Deny("ARC_ROLE_REQUIRED", NAME_A_ROLE.to_owned());
        }
        let ok = matches!(model.as_str(), "haiku" | "sonnet");
        return if ok {
            Decision::Allow
        } else {
            Decision::Model("haiku".to_owned())
        };
    };
    if id == "alchemist-specialist" && !has_reason(prompt) {
        let message = "Use legion:alchemist, or add a 'Specialist reason:' line (a mistake would pass checks yet be wrong, or one failed attempt).";
        return Decision::Deny("ARC_SPECIALIST_REASON", message.to_owned());
    }
    if id == "council-seat" && council_loaded() == Some(false) {
        let message =
            "legion:council-seat runs only inside /council: call Skill(legion:council) first.";
        return Decision::Deny("ARC_COUNCIL_ONLY", message.to_owned());
    }
    let from_file = tier_model(tiers, tier).filter(|name| may_use_frontier || !frontier(name));
    let want = from_file.unwrap_or_else(|| fallback.to_owned());
    if model == want || (may_use_frontier && frontier(&model)) {
        return Decision::Allow;
    }
    Decision::Model(want)
}

/// PreToolUse of `Agent`/`Task`: deny an unknown role, or rewrite a wrong model.
pub fn check_pre_tool_use(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() || off("roles") {
        return None;
    }
    let payload = request.payload.as_object()?;
    if !matches!(tool_name(payload)?.as_str(), "Agent" | "Task") {
        return None;
    }
    let input = tool_input(payload)?;
    let get = |key: &str| str_field(input, &[key]).unwrap_or_default();
    let council_loaded = || {
        let path = str_field(payload, &["transcript_path"])?;
        skill_loaded_since_compaction(&path, "legion:council")
    };
    let tiers = load_tiers();
    let decision = decide(
        &tiers,
        &get("subagent_type"),
        &get("prompt"),
        &get("model"),
        &council_loaded,
    );
    let event = request.event_type.clone();
    match decision {
        Decision::Allow => None,
        Decision::Deny(code, message) => Some(HookResponse::denied(event, code, message, "strong")),
        Decision::Model(model) => {
            let mut updated = input.clone();
            updated.insert("model".to_owned(), Value::String(model.clone()));
            let note = format!("model set to {model} (model-tiers.json)");
            Some(HookResponse::allowed(event, note).with_updated_input(Value::Object(updated)))
        }
    }
}
