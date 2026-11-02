//! Guard check `roles` (fix-plan M4b): every subagent has a role, and the role
//! sets its model.
//!
//! * `Agent` / `Task` launches must name a Legion roster role or a read-only
//!   lookup type. The model is taken from `src/config/model-tiers.json`
//!   (the `claude-code` host of the role's tier) and written back through
//!   `updatedInput`; the agent never chooses it. Opus and Fable stay with
//!   oracle, sage and council-seat.
//! * `legion:alchemist-specialist` needs a `Specialist reason:` line.
//! * `legion:council-seat` runs only after `/council` (or `Skill(legion:council)`).
//! * `Workflow` scripts get one heuristic: an `agent(...)` call that sets
//!   `model` to opus or fable without naming oracle, sage or council-seat.
//!
//! The check fails open: unreadable files, missing transcripts or a malformed
//! payload never deny. `LEGION_HOOK_OFF=roles` turns it off.

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

use serde_json::{Map, Value};

use crate::protocol::{HookRequest, HookResponse};

pub const CHECK_ID: &str = "roles";
pub const CODE_ROLE_REQUIRED: &str = "ARC_ROLE_REQUIRED";
pub const CODE_SPECIALIST_REASON: &str = "ARC_SPECIALIST_REASON";
pub const CODE_COUNCIL_ONLY: &str = "ARC_COUNCIL_ONLY";
pub const CODE_WORKFLOW_MODEL: &str = "ARC_WORKFLOW_MODEL";

const MSG_ROLE_REQUIRED: &str =
    "Name a role: subagent_type must be a Legion role or a read-only lookup type.";
const MSG_SPECIALIST_REASON: &str = "Use legion:alchemist, or add a 'Specialist reason:' line (a mistake would pass checks yet be wrong, or one failed attempt).";
const MSG_COUNCIL_ONLY: &str = "legion:council-seat runs only inside /council: call Skill(legion:council) first, or use another role.";

/// Host key inside `tiers.<tier>.hosts` of `model-tiers.json`.
const HOST: &str = "claude-code";
/// Same window `main.rs` `transcript_shows_edits` reads.
const MAX_TRANSCRIPT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;

/// Compile-time copy of the roster file. Installed customers may have no
/// `src/config` next to the plugin, so this keeps the check working; a file
/// found at run time wins over it (see `tier_file_candidates`).
const EMBEDDED_MODEL_TIERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/config/model-tiers.json"
));

struct RoleSpec {
    /// Roster id without the `legion:` prefix.
    id: &'static str,
    /// Tier name in `model-tiers.json`.
    tier: &'static str,
    /// Used when the file is missing the tier or the host.
    default_model: &'static str,
    /// May run on opus or fable.
    frontier: bool,
}

static ROLES: [RoleSpec; 6] = [
    RoleSpec {
        id: "alchemist",
        tier: "mechanical-cheap",
        default_model: "haiku",
        frontier: false,
    },
    RoleSpec {
        id: "alchemist-specialist",
        tier: "balanced-executor",
        default_model: "sonnet",
        frontier: false,
    },
    RoleSpec {
        id: "oracle",
        tier: "frontier-judgment",
        default_model: "opus",
        frontier: true,
    },
    RoleSpec {
        id: "sage",
        tier: "frontier-judgment",
        default_model: "opus",
        frontier: true,
    },
    RoleSpec {
        id: "sentry",
        tier: "mechanical-cheap",
        default_model: "haiku",
        frontier: false,
    },
    RoleSpec {
        id: "council-seat",
        tier: "deliberation",
        default_model: "fable",
        frontier: true,
    },
];

/// Read-only lookup types (plus the `egm:` prefix). `Plan` is a built-in
/// planner without write tools.
const LOOKUP_TYPES: [&str; 4] = ["Explore", "general-purpose", "claude-code-guide", "Plan"];
const LOOKUP_PREFIX: &str = "egm:";

/// Role models resolved from the roster file, as Claude Code model aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Roster {
    roles: Vec<(&'static str, String)>,
    /// Lookup types default to this (mechanical-cheap tier).
    lookup_default: String,
    /// Lookup types never exceed this (balanced-executor tier).
    lookup_cap: String,
}

impl Roster {
    fn builtin() -> Self {
        Self {
            roles: ROLES
                .iter()
                .map(|spec| (spec.id, spec.default_model.to_owned()))
                .collect(),
            lookup_default: "haiku".to_owned(),
            lookup_cap: "sonnet".to_owned(),
        }
    }

    /// Parse `model-tiers.json`. A model the file assigns to a role that may
    /// not run on opus or fable is ignored: "no opus or fable outside oracle,
    /// sage and council-seat" outranks the file.
    fn from_json(text: &str) -> Option<Self> {
        let doc: Value = serde_json::from_str(text).ok()?;
        let tiers = doc.get("tiers")?.as_object()?;
        let host_model = |tier: &str| -> Option<String> {
            tiers
                .get(tier)?
                .get("hosts")?
                .get(HOST)?
                .as_str()
                .map(model_alias)
                .filter(|alias| !alias.is_empty())
        };
        let roles = ROLES
            .iter()
            .map(|spec| {
                let model = host_model(spec.tier)
                    .filter(|alias| spec.frontier || !is_frontier_alias(alias))
                    .unwrap_or_else(|| spec.default_model.to_owned());
                (spec.id, model)
            })
            .collect();
        let lookup_default = host_model("mechanical-cheap")
            .filter(|alias| !is_frontier_alias(alias))
            .unwrap_or_else(|| "haiku".to_owned());
        let lookup_cap = host_model("balanced-executor")
            .filter(|alias| !is_frontier_alias(alias))
            .unwrap_or_else(|| "sonnet".to_owned());
        Some(Self {
            roles,
            lookup_default,
            lookup_cap,
        })
    }

    fn role_model(&self, id: &str) -> &str {
        self.roles
            .iter()
            .find(|(role, _)| *role == id)
            .map(|(_, model)| model.as_str())
            .or_else(|| {
                ROLES
                    .iter()
                    .find(|spec| spec.id == id)
                    .map(|spec| spec.default_model)
            })
            .unwrap_or("haiku")
    }
}

/// Map a model id or alias to the Claude Code alias it denotes
/// (`claude-fable-5-1` -> `fable`). Unknown strings come back lowercased.
fn model_alias(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    for alias in ["opus", "sonnet", "haiku", "fable"] {
        if lowered.contains(alias) {
            return alias.to_owned();
        }
    }
    lowered
}

fn is_frontier_alias(alias: &str) -> bool {
    matches!(alias, "opus" | "fable")
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Where a roster file may live at run time, in priority order.
fn tier_file_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = env_path("LEGION_MODEL_TIERS") {
        paths.push(explicit);
    }
    if let Some(root) = env_path("CLAUDE_PLUGIN_ROOT") {
        paths.push(root.join("share/legion/src/config/model-tiers.json"));
        paths.push(root.join("src/config/model-tiers.json"));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
    {
        paths.push(dir.join("../share/legion/src/config/model-tiers.json"));
    }
    paths
}

fn load_roster() -> Roster {
    for path in tier_file_candidates() {
        if let Some(roster) = fs::read_to_string(&path)
            .ok()
            .and_then(|text| Roster::from_json(&text))
        {
            return roster;
        }
    }
    Roster::from_json(EMBEDDED_MODEL_TIERS).unwrap_or_else(Roster::builtin)
}

fn kill_switch_on(id: &str) -> bool {
    std::env::var("LEGION_HOOK_OFF")
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(id))
        })
        .unwrap_or(false)
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
}

fn tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))
        .and_then(Value::as_object)
}

/// Read at most the last `max_bytes` of a transcript. The flag says the file
/// was longer than the window (the first, possibly partial, line is dropped).
/// Shared with `governor`.
pub(crate) fn read_transcript_tail(path: &str, max_bytes: u64) -> Option<(String, bool)> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let truncated = length > max_bytes;
    if truncated {
        file.seek(SeekFrom::Start(length - max_bytes)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(max_bytes).read_to_end(&mut bytes).ok()?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        match text.find('\n') {
            Some(newline) => text = text[newline + 1..].to_owned(),
            None => text.clear(),
        }
    }
    Some((text, truncated))
}

/// Entry point for PreToolUse. `None` means no opinion (allow). A denied
/// response blocks. An allowed response carrying `updated_input` is a rewrite
/// the caller must return to the host if nothing else denies the launch.
pub fn check_pre_tool_use(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() || kill_switch_on(CHECK_ID) {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = first_string(payload, &["tool_name", "toolName"])?;
    match tool.as_str() {
        "Agent" | "Task" => check_agent(request, payload, &load_roster()),
        "Workflow" => check_workflow(request, payload),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Present,
    Absent,
    /// Could not be established (no transcript, unreadable, or beyond the
    /// read window). Treated as allow.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentDecision {
    Allow,
    Rewrite { model: String, note: String },
    Deny { code: &'static str, message: String },
}

enum Kind {
    Role(&'static RoleSpec),
    Lookup,
    Unknown,
}

fn classify(subagent: &str) -> Kind {
    let bare = subagent.strip_prefix("legion:").unwrap_or(subagent);
    if let Some(spec) = ROLES.iter().find(|spec| spec.id == bare) {
        return Kind::Role(spec);
    }
    if LOOKUP_TYPES
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case(subagent))
        || subagent.starts_with(LOOKUP_PREFIX)
    {
        return Kind::Lookup;
    }
    Kind::Unknown
}

fn check_agent(
    request: &HookRequest,
    payload: &Map<String, Value>,
    roster: &Roster,
) -> Option<HookResponse> {
    let input = tool_input(payload)?;
    let subagent = first_string(input, &["subagent_type", "subagentType"]);
    let prompt = first_string(input, &["prompt"]).unwrap_or_default();
    let requested = first_string(input, &["model"]);
    let council = || council_evidence(payload);
    let event = request.event_type.clone();
    match decide_agent(
        roster,
        subagent.as_deref(),
        &prompt,
        requested.as_deref(),
        &council,
    ) {
        AgentDecision::Allow => None,
        AgentDecision::Deny { code, message } => {
            Some(HookResponse::denied(event, code, message, "strong"))
        }
        AgentDecision::Rewrite { model, note } => {
            let mut updated = input.clone();
            updated.insert("model".to_owned(), Value::String(model));
            Some(HookResponse::allowed(event, note).with_updated_input(Value::Object(updated)))
        }
    }
}

fn deny(code: &'static str, message: impl Into<String>) -> AgentDecision {
    AgentDecision::Deny {
        code,
        message: message.into(),
    }
}

/// Pure decision for one `Agent` launch. The council evidence is a closure so
/// the transcript is read only for council seats.
fn decide_agent(
    roster: &Roster,
    subagent: Option<&str>,
    prompt: &str,
    requested: Option<&str>,
    council: &dyn Fn() -> Evidence,
) -> AgentDecision {
    let Some(subagent) = subagent.map(str::trim).filter(|value| !value.is_empty()) else {
        return deny(CODE_ROLE_REQUIRED, MSG_ROLE_REQUIRED);
    };
    match classify(subagent) {
        Kind::Unknown => deny(
            CODE_ROLE_REQUIRED,
            format!("{MSG_ROLE_REQUIRED} '{subagent}' is neither."),
        ),
        Kind::Lookup => decide_lookup_model(roster, subagent, requested),
        Kind::Role(spec) => {
            if spec.id == "alchemist-specialist" && !has_specialist_reason(prompt) {
                return deny(CODE_SPECIALIST_REASON, MSG_SPECIALIST_REASON);
            }
            if spec.id == "council-seat" && council() == Evidence::Absent {
                return deny(CODE_COUNCIL_ONLY, MSG_COUNCIL_ONLY);
            }
            decide_role_model(roster, spec, requested)
        }
    }
}

fn requested_alias(requested: Option<&str>) -> Option<String> {
    requested.map(model_alias).filter(|alias| !alias.is_empty())
}

/// "model 'opus' replaced by" or "model unset, now", to precede the new model.
fn change_phrase(requested: Option<&str>) -> String {
    match requested.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => format!("model '{value}' replaced by"),
        None => "model unset, now".to_owned(),
    }
}

fn decide_role_model(roster: &Roster, spec: &RoleSpec, requested: Option<&str>) -> AgentDecision {
    let want = roster.role_model(spec.id);
    let alias = requested_alias(requested);
    if alias.as_deref() == Some(want) {
        return AgentDecision::Allow;
    }
    let mut note = format!(
        "legion:{} runs on {want} (model-tiers.json): {} {want}.",
        spec.id,
        change_phrase(requested)
    );
    if !spec.frontier && alias.as_deref().is_some_and(is_frontier_alias) {
        note.push_str(" Opus and fable are reserved for oracle, sage and council-seat.");
    }
    AgentDecision::Rewrite {
        model: want.to_owned(),
        note,
    }
}

fn decide_lookup_model(roster: &Roster, subagent: &str, requested: Option<&str>) -> AgentDecision {
    let alias = requested_alias(requested);
    if let Some(alias) = alias.as_deref() {
        if alias == roster.lookup_default || alias == roster.lookup_cap {
            return AgentDecision::Allow;
        }
    }
    let frontier = alias.as_deref().is_some_and(is_frontier_alias);
    let want = if frontier {
        &roster.lookup_cap
    } else {
        &roster.lookup_default
    };
    let mut note = format!(
        "{subagent} is a read-only lookup type: {} {want} (at most {}).",
        change_phrase(requested),
        roster.lookup_cap
    );
    if frontier {
        note.push_str(" Opus and fable are reserved for oracle, sage and council-seat.");
    }
    AgentDecision::Rewrite {
        model: want.clone(),
        note,
    }
}

/// A prompt line starting with `Specialist reason:` (leading blanks and
/// markdown markers allowed).
fn has_specialist_reason(prompt: &str) -> bool {
    const PREFIX: &str = "Specialist reason:";
    prompt.lines().any(|line| {
        let trimmed = line.trim_start_matches(|c: char| {
            c.is_whitespace() || matches!(c, '-' | '*' | '>' | '_' | '#')
        });
        trimmed
            .get(..PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
    })
}

fn council_evidence(payload: &Map<String, Value>) -> Evidence {
    let Some(path) = first_string(payload, &["transcript_path", "transcriptPath"]) else {
        return Evidence::Unknown;
    };
    let Some((text, truncated)) = read_transcript_tail(&path, MAX_TRANSCRIPT_BYTES) else {
        return Evidence::Unknown;
    };
    if transcript_shows_council(&text) {
        Evidence::Present
    } else if truncated {
        // The call may sit before the window; absence is not proven.
        Evidence::Unknown
    } else {
        Evidence::Absent
    }
}

fn is_council_name(name: &str) -> bool {
    let name = name.trim().trim_start_matches('/').to_ascii_lowercase();
    name == "council" || name == "legion:council"
}

/// Text of a user message: a string, or the joined `text` blocks.
pub(crate) fn user_message_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn command_names(text: &str) -> Vec<&str> {
    const OPEN: &str = "<command-name>";
    const CLOSE: &str = "</command-name>";
    let mut names = Vec::new();
    for (start, _) in text.match_indices(OPEN) {
        let rest = &text[start + OPEN.len()..];
        if let Some(end) = rest.find(CLOSE) {
            names.push(&rest[..end]);
        }
    }
    names
}

/// One transcript record: an assistant `Skill` tool_use naming council, or a
/// user-typed `/council` command (`<command-name>` tag).
fn record_invokes_council(record: &Value) -> bool {
    let content = record.pointer("/message/content");
    match record.get("type").and_then(Value::as_str) {
        Some("assistant") => content.and_then(Value::as_array).is_some_and(|blocks| {
            blocks.iter().any(|block| {
                block.get("type").and_then(Value::as_str) == Some("tool_use")
                    && block.get("name").and_then(Value::as_str) == Some("Skill")
                    && block
                        .pointer("/input/skill")
                        .and_then(Value::as_str)
                        .is_some_and(is_council_name)
            })
        }),
        Some("user") => {
            let text = user_message_text(content);
            command_names(&text).into_iter().any(is_council_name)
        }
        _ => false,
    }
}

fn transcript_shows_council(text: &str) -> bool {
    text.lines().any(|line| {
        line.contains("ouncil")
            && serde_json::from_str::<Value>(line)
                .map(|record| record_invokes_council(&record))
                .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Workflow: one heuristic, stated plainly. The script is JavaScript text; we
// find each `agent(` call, take its balanced argument text, and look for a
// string-literal `model` option naming opus or fable. A call that also names
// `agentType` or `agent` as oracle, sage or council-seat is allowed. Options
// built elsewhere (`agent(p, OPTS)`), computed model names, and the `model`
// field of `meta.phases` are not seen. Workflow agents with no `model` inherit
// the lead's model; that is not checked here.
// ---------------------------------------------------------------------------

fn check_workflow(request: &HookRequest, payload: &Map<String, Value>) -> Option<HookResponse> {
    let input = tool_input(payload)?;
    let mut script = first_string(input, &["script"]).unwrap_or_default();
    if script.is_empty() {
        if let Some(path) = first_string(input, &["scriptPath", "script_path"]) {
            script = read_small_file(&path).unwrap_or_default();
        }
    }
    if script.is_empty() {
        return None;
    }
    let model = workflow_frontier_model(&script)?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        CODE_WORKFLOW_MODEL,
        format!(
            "Workflow agent() sets model '{model}', which is reserved for oracle, sage and council-seat. \
             Set agentType to legion:oracle, legion:sage or legion:council-seat, or drop the model so the role sets it."
        ),
        "strong",
    ))
}

fn read_small_file(path: &str) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(MAX_SCRIPT_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// Index of the `)` closing a call whose argument text starts at `from`, or the
/// end of the script when it never closes. Skips strings and comments.
fn matching_paren_end(script: &str, from: usize) -> usize {
    let bytes = script.as_bytes();
    let mut depth = 1usize;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            quote @ (b'"' | b'\'' | b'`') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Argument text of every `agent(` call.
fn agent_calls(script: &str) -> Vec<&str> {
    const CALL: &str = "agent(";
    let bytes = script.as_bytes();
    let mut calls = Vec::new();
    let mut from = 0usize;
    while let Some(relative) = script[from..].find(CALL) {
        let start = from + relative;
        from = start + CALL.len();
        if start > 0 && is_ident_byte(bytes[start - 1]) {
            continue;
        }
        let end = matching_paren_end(script, from).min(script.len());
        calls.push(&script[from..end]);
    }
    calls
}

fn skip_blanks(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Value of a string-literal option `key: 'value'` (key bare or quoted) in
/// object-literal text. First match wins.
fn string_option(text: &str, key: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(relative) = text[from..].find(key) {
        let start = from + relative;
        let end = start + key.len();
        from = end;
        if (start > 0 && is_ident_byte(bytes[start - 1]))
            || (end < bytes.len() && is_ident_byte(bytes[end]))
        {
            continue;
        }
        let mut i = end;
        if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            i += 1;
        }
        i = skip_blanks(bytes, i);
        if i >= bytes.len() || bytes[i] != b':' {
            continue;
        }
        i = skip_blanks(bytes, i + 1);
        if i >= bytes.len() || !matches!(bytes[i], b'"' | b'\'' | b'`') {
            continue;
        }
        let quote = bytes[i] as char;
        let value_start = i + 1;
        if let Some(length) = text[value_start..].find(quote) {
            return Some(text[value_start..value_start + length].to_owned());
        }
    }
    None
}

fn is_frontier_role_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    let bare = name.strip_prefix("legion:").unwrap_or(&name);
    matches!(bare, "oracle" | "sage" | "council-seat")
}

/// The first opus or fable `model` option in a call that names no frontier role.
fn workflow_frontier_model(script: &str) -> Option<String> {
    for call in agent_calls(script) {
        let Some(model) = string_option(call, "model") else {
            continue;
        };
        if !is_frontier_alias(&model_alias(&model)) {
            continue;
        }
        let role = string_option(call, "agentType").or_else(|| string_option(call, "agent"));
        if role.as_deref().is_some_and(is_frontier_role_name) {
            continue;
        }
        return Some(model);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roster() -> Roster {
        Roster::from_json(EMBEDDED_MODEL_TIERS).expect("embedded roster parses")
    }

    fn unknown() -> Evidence {
        Evidence::Unknown
    }

    fn decide(subagent: Option<&str>, prompt: &str, model: Option<&str>) -> AgentDecision {
        decide_agent(&roster(), subagent, prompt, model, &unknown)
    }

    fn rewrite_model(decision: AgentDecision) -> String {
        match decision {
            AgentDecision::Rewrite { model, .. } => model,
            other => panic!("expected a rewrite, got {other:?}"),
        }
    }

    fn deny_code(decision: AgentDecision) -> &'static str {
        match decision {
            AgentDecision::Deny { code, .. } => code,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn embedded_roster_matches_the_role_table() {
        let roster = roster();
        assert_eq!(roster.role_model("alchemist"), "haiku");
        assert_eq!(roster.role_model("alchemist-specialist"), "sonnet");
        assert_eq!(roster.role_model("oracle"), "opus");
        assert_eq!(roster.role_model("sage"), "opus");
        assert_eq!(roster.role_model("sentry"), "haiku");
        assert_eq!(roster.role_model("council-seat"), "fable");
        assert_eq!(roster.lookup_default, "haiku");
        assert_eq!(roster.lookup_cap, "sonnet");
    }

    #[test]
    fn roster_file_wins_but_never_gives_opus_to_a_cheap_role() {
        let text = r#"{"tiers":{
            "mechanical-cheap":{"hosts":{"claude-code":"opus"}},
            "balanced-executor":{"hosts":{"claude-code":"claude-haiku-4-5"}},
            "frontier-judgment":{"hosts":{"claude-code":"claude-opus-5-5"}}
        }}"#;
        let roster = Roster::from_json(text).expect("parses");
        assert_eq!(roster.role_model("alchemist"), "haiku");
        assert_eq!(roster.role_model("sentry"), "haiku");
        assert_eq!(roster.role_model("alchemist-specialist"), "haiku");
        assert_eq!(roster.role_model("oracle"), "opus");
        assert_eq!(roster.lookup_default, "haiku");
        assert_eq!(roster.lookup_cap, "haiku");
        // A tier the file lacks falls back to the table.
        assert_eq!(roster.role_model("council-seat"), "fable");
        assert!(Roster::from_json("not json").is_none());
    }

    #[test]
    fn model_alias_normalizes_ids() {
        assert_eq!(model_alias("claude-fable-5-1"), "fable");
        assert_eq!(model_alias(" Claude-Haiku-4-5 "), "haiku");
        assert_eq!(model_alias("opus[1m]"), "opus");
        assert_eq!(model_alias("inherit"), "inherit");
    }

    #[test]
    fn missing_or_unknown_role_is_denied() {
        assert_eq!(deny_code(decide(None, "x", None)), CODE_ROLE_REQUIRED);
        assert_eq!(deny_code(decide(Some("  "), "x", None)), CODE_ROLE_REQUIRED);
        assert_eq!(
            deny_code(decide(Some("fork"), "x", None)),
            CODE_ROLE_REQUIRED
        );
        match decide(None, "x", Some("opus")) {
            AgentDecision::Deny { message, .. } => assert_eq!(message, MSG_ROLE_REQUIRED),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_model_is_filled_from_the_role() {
        assert_eq!(
            rewrite_model(decide(Some("legion:alchemist"), "x", None)),
            "haiku"
        );
        assert_eq!(
            rewrite_model(decide(Some("legion:sentry"), "x", None)),
            "haiku"
        );
        assert_eq!(
            rewrite_model(decide(Some("legion:oracle"), "x", None)),
            "opus"
        );
        assert_eq!(
            rewrite_model(decide(Some("legion:sage"), "x", Some(""))),
            "opus"
        );
        assert_eq!(
            rewrite_model(decide(Some("oracle"), "x", Some("haiku"))),
            "opus"
        );
    }

    #[test]
    fn matching_model_is_left_alone() {
        assert_eq!(
            decide(Some("legion:alchemist"), "x", Some("haiku")),
            AgentDecision::Allow
        );
        assert_eq!(
            decide(Some("legion:alchemist"), "x", Some("claude-haiku-4-5")),
            AgentDecision::Allow
        );
        assert_eq!(
            decide(Some("legion:oracle"), "x", Some("opus")),
            AgentDecision::Allow
        );
    }

    #[test]
    fn opus_for_a_cheap_role_is_rewritten_and_explained() {
        match decide(Some("legion:alchemist"), "x", Some("opus")) {
            AgentDecision::Rewrite { model, note } => {
                assert_eq!(model, "haiku");
                assert!(note.contains("reserved for oracle, sage and council-seat"));
                assert!(note.contains("'opus'"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            rewrite_model(decide(Some("legion:alchemist"), "x", Some("fable"))),
            "haiku"
        );
        assert_eq!(
            rewrite_model(decide(Some("legion:alchemist"), "x", Some("inherit"))),
            "haiku"
        );
    }

    #[test]
    fn specialist_needs_a_reason_line() {
        let code = deny_code(decide(Some("legion:alchemist-specialist"), "do it", None));
        assert_eq!(code, CODE_SPECIALIST_REASON);
        let prompt = "Specialist reason: Guard gating logic.\nRead the rules.";
        assert_eq!(
            rewrite_model(decide(Some("legion:alchemist-specialist"), prompt, None)),
            "sonnet"
        );
        let indented = "Brief.\n  **Specialist reason:** signing code";
        assert!(has_specialist_reason(indented));
        assert!(!has_specialist_reason(
            "The specialist reason: is inline, not a line start"
        ));
        assert!(!has_specialist_reason("Specialist"));
    }

    #[test]
    fn council_seat_needs_council_evidence() {
        let absent = || Evidence::Absent;
        let present = || Evidence::Present;
        let roster = roster();
        assert_eq!(
            deny_code(decide_agent(
                &roster,
                Some("legion:council-seat"),
                "x",
                None,
                &absent
            )),
            CODE_COUNCIL_ONLY
        );
        assert_eq!(
            rewrite_model(decide_agent(
                &roster,
                Some("legion:council-seat"),
                "x",
                None,
                &present
            )),
            "fable"
        );
        assert_eq!(
            rewrite_model(decide_agent(
                &roster,
                Some("legion:council-seat"),
                "x",
                None,
                &unknown
            )),
            "fable"
        );
    }

    #[test]
    fn lookup_types_default_to_haiku_and_cap_at_sonnet() {
        for kind in [
            "Explore",
            "general-purpose",
            "claude-code-guide",
            "egm:egm-style",
            "Plan",
        ] {
            assert_eq!(
                rewrite_model(decide(Some(kind), "x", None)),
                "haiku",
                "{kind}"
            );
            assert_eq!(
                rewrite_model(decide(Some(kind), "x", Some("opus"))),
                "sonnet",
                "{kind}"
            );
            assert_eq!(
                rewrite_model(decide(Some(kind), "x", Some("fable"))),
                "sonnet",
                "{kind}"
            );
            assert_eq!(
                rewrite_model(decide(Some(kind), "x", Some("inherit"))),
                "haiku",
                "{kind}"
            );
            assert_eq!(
                decide(Some(kind), "x", Some("sonnet")),
                AgentDecision::Allow,
                "{kind}"
            );
            assert_eq!(
                decide(Some(kind), "x", Some("haiku")),
                AgentDecision::Allow,
                "{kind}"
            );
        }
    }

    #[test]
    fn transcript_evidence_covers_skill_calls_and_slash_commands() {
        let skill = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"legion:council","args":"x"}}]}}"#;
        let bare = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"council"}}]}}"#;
        let slash = r#"{"type":"user","message":{"role":"user","content":"<command-message>council</command-message>\n<command-name>/council</command-name>"}}"#;
        let other = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"legion:debugger","args":"council"}}]}}"#;
        let mention =
            r#"{"type":"user","message":{"role":"user","content":"please convene the council"}}"#;
        assert!(transcript_shows_council(skill));
        assert!(transcript_shows_council(bare));
        assert!(transcript_shows_council(slash));
        assert!(transcript_shows_council(&format!("{other}\n{skill}")));
        assert!(!transcript_shows_council(other));
        assert!(!transcript_shows_council(mention));
        assert!(!transcript_shows_council("not json council"));
    }

    #[test]
    fn rewrite_response_keeps_the_original_input() {
        let request = HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload: json!({
                "tool_name": "Agent",
                "tool_input": {
                    "description": "d",
                    "subagent_type": "legion:alchemist",
                    "model": "opus",
                    "prompt": "edit the file"
                }
            }),
        };
        let payload = request.payload.as_object().expect("object");
        let response = check_agent(&request, payload, &roster()).expect("rewrite");
        assert!(response.allowed);
        let updated = response.updated_input.clone().expect("updated input");
        assert_eq!(updated["model"], "haiku");
        assert_eq!(updated["prompt"], "edit the file");
        assert_eq!(updated["subagent_type"], "legion:alchemist");
        assert_eq!(updated["description"], "d");
        let value = response.to_value();
        assert_eq!(
            value["hookSpecificOutput"]["updatedInput"]["model"],
            "haiku"
        );

        let denied = HookRequest {
            payload: json!({"tool_name": "Agent", "tool_input": {"prompt": "x"}}),
            ..request.clone()
        };
        let payload = denied.payload.as_object().expect("object");
        let response = check_agent(&denied, payload, &roster()).expect("denial");
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some(CODE_ROLE_REQUIRED));
    }

    #[test]
    fn workflow_denies_opus_without_a_frontier_role() {
        let bad = "phase('x')\nconst r = await agent('review it', {model: 'opus', schema: S})";
        assert_eq!(workflow_frontier_model(bad).as_deref(), Some("opus"));
        let quoted = r#"await agent("p", { "model": "claude-fable-5-1" })"#;
        assert_eq!(
            workflow_frontier_model(quoted).as_deref(),
            Some("claude-fable-5-1")
        );
        let oracle = "await agent('p', {model: 'opus', agentType: 'legion:oracle'})";
        assert_eq!(workflow_frontier_model(oracle), None);
        let seat = "await agent('p', {agent: 'council-seat', model: 'fable'})";
        assert_eq!(workflow_frontier_model(seat), None);
        let cheap = "await agent('p', {model: 'haiku'})\nawait agent('q', {})";
        assert_eq!(workflow_frontier_model(cheap), None);
    }

    #[test]
    fn workflow_scan_is_per_call_and_ignores_lookalikes() {
        // The oracle call does not excuse a later bare opus call.
        let mixed = "await agent('a', {agentType: 'oracle', model: 'opus'})\nawait agent('b', {model: 'opus'})";
        assert_eq!(workflow_frontier_model(mixed).as_deref(), Some("opus"));
        // `modelTier` and `subagent(` are not `model` / `agent(`.
        let lookalike = "subagent('p', {modelTier: 'opus'})";
        assert_eq!(workflow_frontier_model(lookalike), None);
        // A comment apostrophe does not swallow the call.
        let comment = "await agent('a', {\n // don't\n model: 'opus'})";
        assert_eq!(workflow_frontier_model(comment).as_deref(), Some("opus"));
    }

    #[test]
    fn workflow_response_is_a_denial() {
        let request = HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload: json!({
                "tool_name": "Workflow",
                "tool_input": {"script": "await agent('x', {model: 'fable'})"}
            }),
        };
        let payload = request.payload.as_object().expect("object");
        let response = check_workflow(&request, payload).expect("denial");
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some(CODE_WORKFLOW_MODEL));
    }
}
