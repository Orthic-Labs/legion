//! Skill enforcement (fix plan M5).
//!
//! Two deterministic checks live here, each with its own `LEGION_HOOK_OFF`
//! id:
//!
//! - `skill-named`: when Adrian's prompt names an installed skill (`/x`,
//!   `legion:x`, `pulse:x`, `egm:x`, or "x skill"), the prompt hook injects
//!   "call Skill x first" and records the skill as pending. Until the `Skill`
//!   tool is called for it, every tool except a short read/plan allowlist is
//!   denied (`ARC_SKILL_FIRST`). The next user prompt clears the pending list.
//! - `skill-event`: before a `Write`/`Edit`/`MultiEdit` of a UI file the
//!   transcript must show `legion:designer` loaded since the last compaction;
//!   before one of reader-facing copy it must show `legion:writing`
//!   (`ARC_SKILL_EVENT`).
//!
//! Every check fails open: an unreadable file, a missing field or an I/O error
//! allows the call. A pending skill also expires after one hour, and subagent
//! tool calls are never gated by the lead's named skill.
//!
//! This module also hosts the small helpers the sibling `locks` and
//! `issue_gate` checks share (kill switch, state directory, atomic write,
//! payload field access).

use std::{
    fs,
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Map, Value};

use crate::protocol::{HookRequest, HookResponse};

pub const CHECK_NAMED: &str = "skill-named";
pub const CHECK_EVENT: &str = "skill-event";

const STATE_FOLDER: &str = "skills";
const PENDING_TTL_SECS: u64 = 3600;
const AGENT_LOAD_RETAIN_SECS: u64 = 24 * 3600;
const MAX_AGENT_LOADS: usize = 256;
const MAX_NAMED: usize = 4;
const MAX_TRANSCRIPT_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const PLUGIN_PREFIXES: [&str; 3] = ["legion", "pulse", "egm"];
const DESIGNER_SKILL: &str = "legion:designer";
const WRITING_SKILL: &str = "legion:writing";

/// Tools that stay available while a named skill is still pending.
const ALLOWED_WHILE_PENDING: [&str; 11] = [
    "Skill",
    "Read",
    "Grep",
    "Glob",
    "ToolSearch",
    "mcp__ccd_turn__update_plan",
    "TaskCreate",
    "TaskUpdate",
    "TaskList",
    "TaskGet",
    "TodoWrite",
];

// ---------------------------------------------------------------------------
// Shared helpers (also used by `locks` and `issue_gate`)
// ---------------------------------------------------------------------------

/// True when `LEGION_HOOK_OFF` (a comma list) names `id`.
pub(crate) fn check_disabled(id: &str) -> bool {
    kill_switch_names(std::env::var("LEGION_HOOK_OFF").ok().as_deref(), id)
}

pub(crate) fn kill_switch_names(list: Option<&str>, id: &str) -> bool {
    list.map(|list| {
        list.split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(id))
    })
    .unwrap_or(false)
}

/// `$LEGION_STATE_DIR`, else `~/.legion`.
pub(crate) fn state_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("LEGION_STATE_DIR").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    Some(home_dir()?.join(".legion"))
}

/// One state folder per check, e.g. `~/.legion/skills`.
pub(crate) fn state_dir(folder: &str) -> Option<PathBuf> {
    Some(state_root()?.join(folder))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Write a temp file beside `path`, then rename it into place.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "tmp{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp, bytes)?;
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

pub(crate) fn str_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn session_id(object: &Map<String, Value>) -> Option<String> {
    str_field(object, &["session_id", "sessionId", "conversation_id"])
}

pub(crate) fn tool_name(object: &Map<String, Value>) -> Option<String> {
    str_field(object, &["tool_name", "toolName"])
}

pub(crate) fn tool_input(object: &Map<String, Value>) -> Option<&Map<String, Value>> {
    ["tool_input", "toolInput"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_object))
}

/// Present only when the tool call comes from a subagent.
pub(crate) fn agent_id(object: &Map<String, Value>) -> Option<String> {
    str_field(object, &["agent_id", "agentId"])
}

fn is_user_prompt_event(event_type: &str) -> bool {
    matches!(event_type, "UserPromptSubmit" | "user-prompt-submit")
}

// ---------------------------------------------------------------------------
// Skill catalog and prompt detection (pure)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CatalogSkill {
    pub plugin: String,
    pub name: String,
}

impl CatalogSkill {
    fn full(&self) -> String {
        format!("{}:{}", self.plugin, self.name)
    }
}

/// Prompts that are not Adrian typing: relayed chat messages and host
/// notifications never name a skill for enforcement.
fn prompt_is_ignored(prompt: &str) -> bool {
    let trimmed = prompt.trim_start();
    [
        "[Pulse Chat",
        "<task-notification",
        "<system-reminder",
        "<command-name",
        "<local-command",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn clean_word(raw: &str) -> String {
    raw.to_lowercase()
        .trim_start_matches(|c: char| {
            matches!(c, '(' | '[' | '{' | '<' | '"' | '\'' | '`' | '*' | '_')
        })
        .trim_end_matches(|c: char| {
            matches!(
                c,
                '.' | ','
                    | ';'
                    | ':'
                    | '!'
                    | '?'
                    | ')'
                    | ']'
                    | '}'
                    | '>'
                    | '"'
                    | '\''
                    | '`'
                    | '*'
                    | '_'
            )
        })
        .to_owned()
}

fn resolve_skill(spec: &str, catalog: &[CatalogSkill]) -> Option<String> {
    if let Some((plugin, name)) = spec.split_once(':') {
        return catalog
            .iter()
            .find(|skill| skill.plugin == plugin && skill.name == name)
            .map(CatalogSkill::full);
    }
    catalog
        .iter()
        .filter(|skill| skill.name == spec)
        .min_by_key(|skill| skill.plugin != "legion")
        .map(CatalogSkill::full)
}

/// Full skill names (`plugin:name`) that Adrian's prompt names.
///
/// A skill counts when a whole word is `/x`, `/plugin:x`, `plugin:x`
/// (plugin in legion/pulse/egm), or a bare installed `x` followed by the word
/// `skill`. Plain "use x" or "run x" never matches, and an unknown name never
/// matches.
pub(crate) fn detect_named(prompt: &str, catalog: &[CatalogSkill]) -> Vec<String> {
    if prompt_is_ignored(prompt) || catalog.is_empty() {
        return Vec::new();
    }
    let words: Vec<String> = prompt.split_whitespace().map(clean_word).collect();
    let mut found: Vec<String> = Vec::new();
    for (index, word) in words.iter().enumerate() {
        if word.is_empty() {
            continue;
        }
        let hit = if let Some(rest) = word.strip_prefix('/') {
            resolve_skill(rest, catalog)
        } else if let Some((plugin, _)) = word.split_once(':') {
            if PLUGIN_PREFIXES.contains(&plugin) {
                resolve_skill(word, catalog)
            } else {
                None
            }
        } else if words.get(index + 1).map(String::as_str) == Some("skill") {
            resolve_skill(word, catalog)
        } else {
            None
        };
        if let Some(full) = hit {
            if !found.contains(&full) {
                found.push(full);
            }
        }
        if found.len() >= MAX_NAMED {
            break;
        }
    }
    found
}

/// Does a `Skill` tool argument or a `<command-name>` value name `full`
/// (`plugin:name`)? A bare `name` matches too.
pub(crate) fn skill_arg_matches(full: &str, arg: &str) -> bool {
    let normalized = arg.trim().trim_start_matches('/').to_lowercase();
    if normalized.is_empty() {
        return false;
    }
    normalized == full || full.split_once(':').map(|(_, name)| name) == Some(normalized.as_str())
}

fn named_context(names: &[String], codex: bool) -> String {
    let list = names.join(", ");
    if codex {
        return format!(
            "The user asked for skill {list}: read its SKILL.md first and follow it before other work."
        );
    }
    if names.len() == 1 {
        format!(
            "The user asked for skill {list}: call the Skill tool for {list} before other work; an agent of the same name is not a substitute."
        )
    } else {
        format!(
            "The user asked for skills {list}: call the Skill tool for each of them before other work; an agent of the same name is not a substitute."
        )
    }
}

// ---------------------------------------------------------------------------
// Catalog loading (I/O)
// ---------------------------------------------------------------------------

/// Installed skills: the installed assets `skills/` folder and registry, plus
/// the `skills/` folder of each legion/pulse/egm plugin in the Claude plugin
/// cache. A skill with `disable-model-invocation: true` cannot be called by
/// the `Skill` tool, so it is left out (never lock a session on it).
fn load_catalog() -> Vec<CatalogSkill> {
    let mut out: Vec<CatalogSkill> = Vec::new();
    if let Some(assets) = crate::installed_assets_root() {
        add_skill_dirs(&mut out, "legion", &assets.join("skills"));
        add_registry_ids(
            &mut out,
            "legion",
            &assets.join("registry").join("index.json"),
        );
    }
    if let Some(home) = home_dir() {
        add_plugin_cache(
            &mut out,
            &home.join(".claude").join("plugins").join("cache"),
        );
    }
    out.sort();
    out.dedup();
    out
}

fn add_skill_dirs(out: &mut Vec<CatalogSkill>, plugin: &str, dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.starts_with('_') || name.starts_with('.') {
            continue;
        }
        let skill_md = entry.path().join("SKILL.md");
        if skill_md.is_file() && model_invocable(&skill_md) {
            out.push(CatalogSkill {
                plugin: plugin.to_owned(),
                name,
            });
        }
    }
}

fn add_registry_ids(out: &mut Vec<CatalogSkill>, plugin: &str, index: &Path) {
    let Ok(bytes) = fs::read(index) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    let Some(bundles) = value.get("bundles").and_then(Value::as_array) else {
        return;
    };
    for bundle in bundles {
        if let Some(id) = bundle.get("id").and_then(Value::as_str) {
            let id = id.trim().to_lowercase();
            if !id.is_empty() && !id.starts_with('_') {
                out.push(CatalogSkill {
                    plugin: plugin.to_owned(),
                    name: id,
                });
            }
        }
    }
}

fn add_plugin_cache(out: &mut Vec<CatalogSkill>, cache: &Path) {
    let Ok(markets) = fs::read_dir(cache) else {
        return;
    };
    for market in markets.flatten() {
        let Ok(plugins) = fs::read_dir(market.path()) else {
            continue;
        };
        for plugin_dir in plugins.flatten() {
            let plugin = plugin_dir.file_name().to_string_lossy().to_lowercase();
            if !PLUGIN_PREFIXES.contains(&plugin.as_str()) {
                continue;
            }
            let Ok(versions) = fs::read_dir(plugin_dir.path()) else {
                continue;
            };
            for version in versions.flatten() {
                let root = version.path();
                if root.join(".orphaned_at").exists() {
                    continue;
                }
                add_skill_dirs(out, &plugin, &root.join("skills"));
            }
        }
    }
}

/// False when the SKILL.md frontmatter says `disable-model-invocation: true`
/// or the file cannot be read.
fn model_invocable(skill_md: &Path) -> bool {
    let Ok(file) = fs::File::open(skill_md) else {
        return false;
    };
    let mut head = Vec::new();
    if file.take(4096).read_to_end(&mut head).is_err() {
        return false;
    }
    frontmatter_allows_model_invocation(&String::from_utf8_lossy(&head))
}

fn frontmatter_allows_model_invocation(head: &str) -> bool {
    let mut lines = head.lines();
    if lines.next().map(str::trim) != Some("---") {
        return true;
    }
    for line in lines {
        let line = line.trim();
        if line == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("disable-model-invocation:") {
            if value.trim().eq_ignore_ascii_case("true") {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Per-session state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingSkill {
    skill: String,
    t: u64,
}

/// A `Skill` call made by a subagent. A subagent's own transcript is not the
/// lead's, so its loads are remembered here, keyed by agent id.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentLoad {
    agent: String,
    skill: String,
    t: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    pending: Vec<PendingSkill>,
    loads: Vec<AgentLoad>,
}

impl State {
    fn parse(bytes: &[u8]) -> State {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            return State::default();
        };
        let pending = value
            .get("pending")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(PendingSkill {
                            skill: item.get("skill")?.as_str()?.to_owned(),
                            t: item.get("t").and_then(Value::as_u64).unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let loads = value
            .get("loads")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(AgentLoad {
                            agent: item.get("agent")?.as_str()?.to_owned(),
                            skill: item.get("skill")?.as_str()?.to_owned(),
                            t: item.get("t").and_then(Value::as_u64).unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        State { pending, loads }
    }

    fn render(&self) -> Vec<u8> {
        let value = json!({
            "pending": self
                .pending
                .iter()
                .map(|p| json!({"skill": p.skill, "t": p.t}))
                .collect::<Vec<Value>>(),
            "loads": self
                .loads
                .iter()
                .map(|l| json!({"agent": l.agent, "skill": l.skill, "t": l.t}))
                .collect::<Vec<Value>>(),
        });
        let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.loads.is_empty()
    }

    fn record_agent_load(&mut self, agent: &str, skill_arg: &str, now: u64) {
        self.loads
            .retain(|load| now.saturating_sub(load.t) <= AGENT_LOAD_RETAIN_SECS);
        self.loads.push(AgentLoad {
            agent: agent.to_owned(),
            skill: skill_arg.trim().trim_start_matches('/').to_lowercase(),
            t: now,
        });
        if self.loads.len() > MAX_AGENT_LOADS {
            let excess = self.loads.len() - MAX_AGENT_LOADS;
            self.loads.drain(..excess);
        }
    }

    fn agent_loaded(&self, agent: &str, skill_full: &str) -> bool {
        self.loads
            .iter()
            .any(|load| load.agent == agent && skill_arg_matches(skill_full, &load.skill))
    }
}

fn sanitize_session(session: &str) -> String {
    session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect()
}

fn state_file(dir: &Path, session: &str) -> PathBuf {
    dir.join(format!("{}.json", sanitize_session(session)))
}

fn read_state(path: &Path) -> State {
    fs::read(path)
        .map(|bytes| State::parse(&bytes))
        .unwrap_or_default()
}

fn write_state(path: &Path, state: &State) -> io::Result<()> {
    if state.is_empty() {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    write_atomic(path, &state.render())
}

// ---------------------------------------------------------------------------
// skill-named: UserPromptSubmit
// ---------------------------------------------------------------------------

/// UserPromptSubmit: detect skills the prompt names, record them as pending
/// and tell the model to call `Skill` first. Always clears the previous
/// pending list. Returns `None` when nothing is named.
pub fn on_user_prompt(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK_NAMED) || !is_user_prompt_event(&request.event_type) {
        return None;
    }
    let dir = state_dir(STATE_FOLDER)?;
    on_user_prompt_in(request, &load_catalog(), &dir)
}

fn on_user_prompt_in(
    request: &HookRequest,
    catalog: &[CatalogSkill],
    dir: &Path,
) -> Option<HookResponse> {
    let payload = request.payload.as_object()?;
    let prompt = str_field(payload, &["prompt", "user_prompt", "userPrompt"])?;
    if prompt_is_ignored(&prompt) {
        return None;
    }
    let session = session_id(payload)?;
    let names = detect_named(&prompt, catalog);
    // Codex has no Skill tool: it gets the instruction only, never a lock.
    let codex = payload.contains_key("turn_id");
    let path = state_file(dir, &session);
    let mut state = read_state(&path);
    let before = state.clone();
    state.pending.clear();
    if !codex {
        let now = now_secs();
        state.pending = names
            .iter()
            .map(|skill| PendingSkill {
                skill: skill.clone(),
                t: now,
            })
            .collect();
    }
    if state != before {
        let _ = write_state(&path, &state);
    }
    if names.is_empty() {
        return None;
    }
    Some(
        HookResponse::allowed(request.event_type.clone(), "named skill recorded")
            .with_additional_context(named_context(&names, codex)),
    )
}

// ---------------------------------------------------------------------------
// PreToolUse (skill-named + skill-event)
// ---------------------------------------------------------------------------

/// PreToolUse: enforce the pending named skill, then the event skills.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    named_gate(request, payload, &tool).or_else(|| event_gate(request, payload, &tool))
}

#[derive(Debug, PartialEq, Eq)]
enum Named {
    Allow,
    Deny(Vec<String>),
}

/// Pure decision for the named-skill gate. Returns the outcome and whether
/// `state` changed (so the caller can persist it).
fn named_decision(
    state: &mut State,
    tool: &str,
    skill_arg: Option<&str>,
    now: u64,
) -> (Named, bool) {
    let before = state.pending.len();
    state
        .pending
        .retain(|pending| now.saturating_sub(pending.t) <= PENDING_TTL_SECS);
    let mut changed = state.pending.len() != before;
    if state.pending.is_empty() {
        return (Named::Allow, changed);
    }
    if tool == "Skill" {
        if let Some(arg) = skill_arg {
            let before = state.pending.len();
            state
                .pending
                .retain(|pending| !skill_arg_matches(&pending.skill, arg));
            changed |= state.pending.len() != before;
        }
        return (Named::Allow, changed);
    }
    if ALLOWED_WHILE_PENDING.contains(&tool) {
        return (Named::Allow, changed);
    }
    (
        Named::Deny(state.pending.iter().map(|p| p.skill.clone()).collect()),
        changed,
    )
}

fn named_gate(
    request: &HookRequest,
    payload: &Map<String, Value>,
    tool: &str,
) -> Option<HookResponse> {
    if check_disabled(CHECK_NAMED) {
        return None;
    }
    let session = session_id(payload)?;
    let path = state_file(&state_dir(STATE_FOLDER)?, &session);
    named_gate_in(request, payload, tool, &path, now_secs())
}

fn named_gate_in(
    request: &HookRequest,
    payload: &Map<String, Value>,
    tool: &str,
    path: &Path,
    now: u64,
) -> Option<HookResponse> {
    let skill_arg = if tool == "Skill" {
        tool_input(payload).and_then(|input| str_field(input, &["skill"]))
    } else {
        None
    };
    if let Some(agent) = agent_id(payload) {
        // The lead's named skill never blocks a subagent. Remember the
        // subagent's own Skill calls for the event-skill gate.
        if let Some(arg) = skill_arg {
            let mut state = read_state(path);
            state.record_agent_load(&agent, &arg, now);
            let _ = write_state(path, &state);
        }
        return None;
    }
    let mut state = read_state(path);
    let (outcome, changed) = named_decision(&mut state, tool, skill_arg.as_deref(), now);
    if changed {
        let _ = write_state(path, &state);
    }
    match outcome {
        Named::Allow => None,
        Named::Deny(names) => Some(HookResponse::denied(
            request.event_type.clone(),
            "ARC_SKILL_FIRST",
            format!("Call Skill {} first (the user named it).", names.join(", ")),
            "strong",
        )),
    }
}

// ---------------------------------------------------------------------------
// skill-event
// ---------------------------------------------------------------------------

fn is_scratch_path(normalized: &str) -> bool {
    normalized.starts_with("/volumes/d/scratch")
        || normalized.starts_with("d:/scratch")
        || normalized == "/tmp"
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/private/var/folders/")
}

/// Which event skill an edit of `path` requires, if any.
///
/// UI files (`*.tsx|jsx|css|scss|svelte|vue|html`, and `*.swift` under a
/// `Views`/`View` folder) need `legion:designer`; reader-facing copy
/// (`README*`, `docs/**/*.md`, `*.strings`, `*copy*.json`, `marketing/**`)
/// needs `legion:writing`. Scratch paths and generated folders are exempt.
pub(crate) fn required_skill(path: &str) -> Option<&'static str> {
    let normalized = path.replace('\\', "/").to_lowercase();
    if is_scratch_path(&normalized) {
        return None;
    }
    let components: Vec<&str> = normalized
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    let (file, dirs) = components.split_last()?;
    if dirs
        .iter()
        .any(|dir| matches!(*dir, "node_modules" | "target" | ".git" | "dist"))
    {
        return None;
    }
    let extension = file.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    if matches!(
        extension,
        "tsx" | "jsx" | "css" | "scss" | "svelte" | "vue" | "html"
    ) {
        return Some(DESIGNER_SKILL);
    }
    if extension == "swift" && dirs.iter().any(|dir| matches!(*dir, "views" | "view")) {
        return Some(DESIGNER_SKILL);
    }
    if file.starts_with("readme")
        || extension == "strings"
        || (extension == "json" && file.contains("copy"))
        || (extension == "md" && dirs.contains(&"docs"))
        || dirs.contains(&"marketing")
    {
        return Some(WRITING_SKILL);
    }
    None
}

enum LineEffect {
    Nothing,
    Reset,
    Loaded,
}

fn is_compact_marker(value: &Value) -> bool {
    let system_boundary = value.get("type").and_then(Value::as_str) == Some("system")
        && value.get("subtype").and_then(Value::as_str) == Some("compact_boundary");
    system_boundary || value.get("isCompactSummary").and_then(Value::as_bool) == Some(true)
}

fn command_name_matches(text: &str, skill: &str) -> bool {
    const OPEN: &str = "<command-name>";
    const CLOSE: &str = "</command-name>";
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else {
            break;
        };
        if skill_arg_matches(skill, &after[..end]) {
            return true;
        }
        rest = &after[end..];
    }
    false
}

fn item_loads_skill(item: &Value, skill: &str) -> bool {
    match item.get("type").and_then(Value::as_str) {
        Some("tool_use") => {
            item.get("name").and_then(Value::as_str) == Some("Skill")
                && item
                    .get("input")
                    .and_then(|input| input.get("skill"))
                    .and_then(Value::as_str)
                    .is_some_and(|arg| skill_arg_matches(skill, arg))
        }
        Some("text") => item
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(|text| command_name_matches(text, skill)),
        _ => false,
    }
}

fn line_loads_skill(value: &Value, skill: &str) -> bool {
    match value
        .get("message")
        .and_then(|message| message.get("content"))
    {
        Some(Value::Array(items)) => items.iter().any(|item| item_loads_skill(item, skill)),
        Some(Value::String(text)) => command_name_matches(text, skill),
        _ => false,
    }
}

/// What one transcript line means for "is `skill` loaded": a compaction
/// resets the set, a `Skill` call or a typed slash command loads it. The
/// cheap substring tests run first; only a candidate line is parsed.
fn line_effect(line: &str, skill: &str) -> LineEffect {
    let may_compact = line.contains("compact_boundary") || line.contains("isCompactSummary");
    let may_load = line.contains("\"Skill\"") || line.contains("<command-name>");
    if !may_compact && !may_load {
        return LineEffect::Nothing;
    }
    let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
        return LineEffect::Nothing;
    };
    if may_compact && is_compact_marker(&value) {
        return LineEffect::Reset;
    }
    if may_load && line_loads_skill(&value, skill) {
        return LineEffect::Loaded;
    }
    LineEffect::Nothing
}

/// Is `skill` loaded in the transcript since the last compaction (or session
/// start)? `None` means the transcript could not be read or is too large to
/// scan: the caller allows.
pub(crate) fn transcript_has_skill(path: &Path, skill: &str) -> Option<bool> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_TRANSCRIPT_SCAN_BYTES {
        return None;
    }
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut buffer: Vec<u8> = Vec::new();
    let mut loaded = false;
    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer).ok()? == 0 {
            break;
        }
        match line_effect(&String::from_utf8_lossy(&buffer), skill) {
            LineEffect::Nothing => {}
            LineEffect::Reset => loaded = false,
            LineEffect::Loaded => loaded = true,
        }
    }
    Some(loaded)
}

fn event_denial(event_type: &str, skill: &str) -> HookResponse {
    let what = if skill == DESIGNER_SKILL {
        "UI"
    } else {
        "text a reader gets"
    };
    HookResponse::denied(
        event_type.to_owned(),
        "ARC_SKILL_EVENT",
        format!("Load {skill} ({what}) before editing this file: call Skill {skill} first."),
        "strong",
    )
}

fn event_gate(
    request: &HookRequest,
    payload: &Map<String, Value>,
    tool: &str,
) -> Option<HookResponse> {
    if check_disabled(CHECK_EVENT) || !matches!(tool, "Write" | "Edit" | "MultiEdit") {
        return None;
    }
    let file = str_field(tool_input(payload)?, &["file_path", "path"])?;
    let skill = required_skill(&file)?;
    let transcript = str_field(payload, &["transcript_path", "transcriptPath"])?;
    // Unreadable or oversized transcript: allow.
    if transcript_has_skill(Path::new(&transcript), skill)? {
        return None;
    }
    // A subagent's own Skill call is not in the lead's transcript.
    if let (Some(agent), Some(session), Some(dir)) = (
        agent_id(payload),
        session_id(payload),
        state_dir(STATE_FOLDER),
    ) {
        if read_state(&state_file(&dir, &session)).agent_loaded(&agent, skill) {
            return None;
        }
    }
    Some(event_denial(&request.event_type, skill))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(event: &str, payload: Value) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: event.to_owned(),
            payload,
        }
    }

    fn catalog() -> Vec<CatalogSkill> {
        let skill = |plugin: &str, name: &str| CatalogSkill {
            plugin: plugin.to_owned(),
            name: name.to_owned(),
        };
        vec![
            skill("legion", "designer"),
            skill("legion", "writing"),
            skill("legion", "commit"),
            skill("legion", "audit-fix"),
            skill("pulse", "membrane"),
            skill("egm", "egm-review"),
        ]
    }

    #[test]
    fn kill_switch_reads_a_comma_list() {
        assert!(kill_switch_names(Some("locks, skill-named"), "skill-named"));
        assert!(kill_switch_names(Some("SKILL-NAMED"), "skill-named"));
        assert!(!kill_switch_names(Some("locks"), "skill-named"));
        assert!(!kill_switch_names(Some("skill-named-x"), "skill-named"));
        assert!(!kill_switch_names(None, "skill-named"));
    }

    #[test]
    fn detects_slash_prefixed_and_skill_word_forms() {
        let catalog = catalog();
        assert_eq!(
            detect_named("please run /designer on the page", &catalog),
            vec!["legion:designer"]
        );
        assert_eq!(
            detect_named("Use legion:writing for this.", &catalog),
            vec!["legion:writing"]
        );
        assert_eq!(
            detect_named("check pulse:membrane, then egm:egm-review.", &catalog),
            vec!["pulse:membrane", "egm:egm-review"]
        );
        assert_eq!(
            detect_named("load the commit skill first", &catalog),
            vec!["legion:commit"]
        );
        assert_eq!(
            detect_named("try /legion:audit-fix now", &catalog),
            vec!["legion:audit-fix"]
        );
        assert_eq!(
            detect_named("/designer /designer designer skill", &catalog),
            vec!["legion:designer"]
        );
    }

    #[test]
    fn plain_use_run_and_unknown_names_do_not_match() {
        let catalog = catalog();
        assert!(detect_named("use designer for this", &catalog).is_empty());
        assert!(detect_named("run commit and writing", &catalog).is_empty());
        assert!(detect_named("the /Volumes/D/claude/legion/designer folder", &catalog).is_empty());
        assert!(detect_named("legion:unknown and /nothing and zzz skill", &catalog).is_empty());
        assert!(detect_named("social skills matter", &catalog).is_empty());
        assert!(detect_named("anything", &[]).is_empty());
    }

    #[test]
    fn relayed_and_host_prompts_are_ignored() {
        let catalog = catalog();
        assert!(detect_named("[Pulse Chat from dell] use /designer", &catalog).is_empty());
        assert!(detect_named("<task-notification> /designer", &catalog).is_empty());
    }

    #[test]
    fn skill_arg_matching_accepts_full_bare_and_slash_forms() {
        assert!(skill_arg_matches("legion:designer", "legion:designer"));
        assert!(skill_arg_matches("legion:designer", "designer"));
        assert!(skill_arg_matches("legion:designer", "/Legion:Designer"));
        assert!(!skill_arg_matches("legion:designer", "legion:writing"));
        assert!(!skill_arg_matches("legion:designer", ""));
    }

    #[test]
    fn named_decision_denies_everything_but_the_allowlist() {
        let mut state = State {
            pending: vec![PendingSkill {
                skill: "legion:designer".into(),
                t: 100,
            }],
            loads: Vec::new(),
        };
        let (outcome, changed) = named_decision(&mut state, "Bash", None, 200);
        assert_eq!(outcome, Named::Deny(vec!["legion:designer".to_owned()]));
        assert!(!changed);
        for tool in [
            "Read",
            "Grep",
            "Glob",
            "ToolSearch",
            "TaskCreate",
            "mcp__ccd_turn__update_plan",
        ] {
            assert_eq!(named_decision(&mut state, tool, None, 200).0, Named::Allow);
        }
        assert!(matches!(
            named_decision(&mut state, "Write", None, 200).0,
            Named::Deny(_)
        ));
        // A Skill call for another skill neither clears nor blocks.
        let (outcome, changed) = named_decision(&mut state, "Skill", Some("legion:writing"), 200);
        assert_eq!((outcome, changed), (Named::Allow, false));
        assert_eq!(state.pending.len(), 1);
        // The named skill clears it.
        let (outcome, changed) = named_decision(&mut state, "Skill", Some("legion:designer"), 200);
        assert_eq!((outcome, changed), (Named::Allow, true));
        assert!(state.pending.is_empty());
        assert_eq!(
            named_decision(&mut state, "Bash", None, 200).0,
            Named::Allow
        );
    }

    #[test]
    fn pending_expires_after_the_ttl() {
        let mut state = State {
            pending: vec![PendingSkill {
                skill: "legion:designer".into(),
                t: 100,
            }],
            loads: Vec::new(),
        };
        let (outcome, changed) =
            named_decision(&mut state, "Bash", None, 100 + PENDING_TTL_SECS + 1);
        assert_eq!((outcome, changed), (Named::Allow, true));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn prompt_records_pending_and_the_next_prompt_clears_it() {
        let dir = TestDir::new("prompt");
        let catalog = catalog();
        let payload = |prompt: &str| json!({"session_id": "s1", "prompt": prompt, "hook_event_name": "UserPromptSubmit"});
        let named = request("UserPromptSubmit", payload("start with /designer please"));
        let response = on_user_prompt_in(&named, &catalog, dir.path()).expect("context");
        assert!(response.allowed);
        let context = response.additional_context.expect("additional context");
        assert!(context.contains("legion:designer"));
        assert!(context.contains("an agent of the same name is not a substitute"));
        let path = state_file(dir.path(), "s1");
        assert_eq!(read_state(&path).pending.len(), 1);

        let plain = request("UserPromptSubmit", payload("thanks, now do the next thing"));
        assert!(on_user_prompt_in(&plain, &catalog, dir.path()).is_none());
        assert!(read_state(&path).pending.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn pulse_chat_prompt_leaves_pending_untouched() {
        let dir = TestDir::new("pulse");
        let catalog = catalog();
        let named = request(
            "UserPromptSubmit",
            json!({"session_id": "s1", "prompt": "/commit now"}),
        );
        assert!(on_user_prompt_in(&named, &catalog, dir.path()).is_some());
        let relayed = request(
            "UserPromptSubmit",
            json!({"session_id": "s1", "prompt": "[Pulse Chat from mac] hello"}),
        );
        assert!(on_user_prompt_in(&relayed, &catalog, dir.path()).is_none());
        assert_eq!(read_state(&state_file(dir.path(), "s1")).pending.len(), 1);
    }

    #[test]
    fn codex_prompt_is_told_but_never_locked() {
        let dir = TestDir::new("codex");
        let catalog = catalog();
        let named = request(
            "UserPromptSubmit",
            json!({"session_id": "s1", "turn_id": "t1", "prompt": "/designer"}),
        );
        let response = on_user_prompt_in(&named, &catalog, dir.path()).expect("context");
        assert!(response
            .additional_context
            .expect("context")
            .contains("SKILL.md"));
        assert!(read_state(&state_file(dir.path(), "s1")).pending.is_empty());
    }

    #[test]
    fn gate_denies_then_clears_on_the_named_skill_call() {
        let dir = TestDir::new("gate");
        let path = state_file(dir.path(), "s1");
        write_state(
            &path,
            &State {
                pending: vec![PendingSkill {
                    skill: "legion:designer".into(),
                    t: 1000,
                }],
                loads: Vec::new(),
            },
        )
        .expect("write state");
        let bash = request(
            "PreToolUse",
            json!({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}}),
        );
        let bash_payload = bash.payload.as_object().expect("payload");
        let denied = named_gate_in(&bash, bash_payload, "Bash", &path, 1001).expect("denied");
        assert!(!denied.allowed);
        assert_eq!(denied.code.as_deref(), Some("ARC_SKILL_FIRST"));
        assert_eq!(
            denied.reason,
            "Call Skill legion:designer first (the user named it)."
        );

        let skill = request(
            "PreToolUse",
            json!({"session_id": "s1", "tool_name": "Skill", "tool_input": {"skill": "legion:designer"}}),
        );
        let skill_payload = skill.payload.as_object().expect("payload");
        assert!(named_gate_in(&skill, skill_payload, "Skill", &path, 1002).is_none());
        assert!(named_gate_in(&bash, bash_payload, "Bash", &path, 1003).is_none());
    }

    #[test]
    fn subagent_calls_are_not_blocked_and_their_skill_loads_are_remembered() {
        let dir = TestDir::new("agent");
        let path = state_file(dir.path(), "s1");
        write_state(
            &path,
            &State {
                pending: vec![PendingSkill {
                    skill: "legion:commit".into(),
                    t: 1000,
                }],
                loads: Vec::new(),
            },
        )
        .expect("write state");
        let bash = request(
            "PreToolUse",
            json!({"session_id": "s1", "agent_id": "a1", "tool_name": "Bash"}),
        );
        let payload = bash.payload.as_object().expect("payload");
        assert!(named_gate_in(&bash, payload, "Bash", &path, 1001).is_none());

        let skill = request(
            "PreToolUse",
            json!({"session_id": "s1", "agent_id": "a1", "tool_name": "Skill", "tool_input": {"skill": "legion:designer"}}),
        );
        let payload = skill.payload.as_object().expect("payload");
        assert!(named_gate_in(&skill, payload, "Skill", &path, 1002).is_none());
        let state = read_state(&path);
        assert!(state.agent_loaded("a1", "legion:designer"));
        assert!(!state.agent_loaded("a2", "legion:designer"));
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn classifies_ui_copy_and_exempt_paths() {
        for ui in [
            "/repo/src/App.tsx",
            "/repo/src/App.jsx",
            "/repo/src/app.css",
            "/repo/src/app.scss",
            "/repo/src/A.svelte",
            "/repo/src/A.vue",
            "/repo/public/index.html",
            "/repo/App/Views/Home.swift",
            "C:\\repo\\App\\View\\Home.swift",
        ] {
            assert_eq!(required_skill(ui), Some(DESIGNER_SKILL), "{ui}");
        }
        for copy in [
            "/repo/README.md",
            "/repo/readme.txt",
            "/repo/docs/rules/x.md",
            "/repo/App/en.lproj/Localizable.strings",
            "/repo/content/site-copy.json",
            "/repo/marketing/landing.txt",
        ] {
            assert_eq!(required_skill(copy), Some(WRITING_SKILL), "{copy}");
        }
        for other in [
            "/repo/src/main.rs",
            "/repo/App/Model/Home.swift",
            "/repo/notes.md",
            "/repo/package.json",
            "/Volumes/D/scratch/x/index.html",
            "D:\\scratch\\x\\README.md",
            "/tmp/page.html",
            "/private/tmp/claude-501/x/README.md",
            "/repo/node_modules/a/index.html",
        ] {
            assert_eq!(required_skill(other), None, "{other}");
        }
    }

    fn write_transcript(dir: &TestDir, lines: &[&str]) -> PathBuf {
        let path = dir.path().join("transcript.jsonl");
        fs::write(&path, lines.join("\n") + "\n").expect("write transcript");
        path
    }

    const SKILL_CALL: &str = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Skill","input":{"skill":"legion:designer"}}]}}"#;
    const COMPACT: &str =
        r#"{"type":"system","subtype":"compact_boundary","content":"Conversation compacted"}"#;
    const OTHER: &str =
        r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hello"}]}}"#;

    #[test]
    fn transcript_scan_sees_skill_calls_and_compaction() {
        let dir = TestDir::new("transcript");
        let loaded = write_transcript(&dir, &[OTHER, SKILL_CALL, OTHER]);
        assert_eq!(transcript_has_skill(&loaded, DESIGNER_SKILL), Some(true));
        assert_eq!(transcript_has_skill(&loaded, WRITING_SKILL), Some(false));

        let compacted = write_transcript(&dir, &[SKILL_CALL, COMPACT, OTHER]);
        assert_eq!(
            transcript_has_skill(&compacted, DESIGNER_SKILL),
            Some(false)
        );

        let reloaded = write_transcript(&dir, &[SKILL_CALL, COMPACT, SKILL_CALL]);
        assert_eq!(transcript_has_skill(&reloaded, DESIGNER_SKILL), Some(true));

        assert_eq!(
            transcript_has_skill(&dir.path().join("missing.jsonl"), DESIGNER_SKILL),
            None
        );
    }

    #[test]
    fn typed_slash_command_counts_as_loaded() {
        let dir = TestDir::new("slash");
        let line = r#"{"type":"user","message":{"role":"user","content":"<command-message>designer</command-message>\n<command-name>/legion:designer</command-name>"}}"#;
        let path = write_transcript(&dir, &[line]);
        assert_eq!(transcript_has_skill(&path, DESIGNER_SKILL), Some(true));
        assert_eq!(transcript_has_skill(&path, WRITING_SKILL), Some(false));
    }

    #[test]
    fn a_line_that_only_mentions_compaction_does_not_reset() {
        let dir = TestDir::new("mention");
        let mention =
            r#"{"type":"user","message":{"content":"grep compact_boundary in the transcript"}}"#;
        let path = write_transcript(&dir, &[SKILL_CALL, mention]);
        assert_eq!(transcript_has_skill(&path, DESIGNER_SKILL), Some(true));
    }

    #[test]
    fn edit_of_a_ui_file_is_denied_until_the_skill_is_in_the_transcript() {
        let dir = TestDir::new("event");
        let bare = write_transcript(&dir, &[OTHER]);
        let edit = |transcript: &Path| {
            request(
                "PreToolUse",
                json!({
                    "session_id": "s1",
                    "tool_name": "Edit",
                    "transcript_path": transcript.to_string_lossy(),
                    "tool_input": {"file_path": "/repo/src/App.tsx"}
                }),
            )
        };
        let req = edit(&bare);
        let payload = req.payload.as_object().expect("payload");
        let denied = event_gate(&req, payload, "Edit").expect("denied");
        assert_eq!(denied.code.as_deref(), Some("ARC_SKILL_EVENT"));
        assert!(denied
            .reason
            .starts_with("Load legion:designer (UI) before editing this file"));

        let loaded = write_transcript(&dir, &[SKILL_CALL]);
        let req = edit(&loaded);
        let payload = req.payload.as_object().expect("payload");
        assert!(event_gate(&req, payload, "Edit").is_none());

        // Unreadable transcript: allow.
        let req = edit(&dir.path().join("nope.jsonl"));
        let payload = req.payload.as_object().expect("payload");
        assert!(event_gate(&req, payload, "Edit").is_none());
    }

    #[test]
    fn frontmatter_with_disabled_model_invocation_is_skipped() {
        assert!(!frontmatter_allows_model_invocation(
            "---\nname: egm-draft\ndisable-model-invocation: true\n---\nbody"
        ));
        assert!(frontmatter_allows_model_invocation(
            "---\nname: designer\ndescription: x\n---\ndisable-model-invocation: true"
        ));
        assert!(frontmatter_allows_model_invocation("no frontmatter"));
    }

    #[test]
    fn state_round_trips() {
        let state = State {
            pending: vec![PendingSkill {
                skill: "legion:commit".into(),
                t: 5,
            }],
            loads: vec![AgentLoad {
                agent: "a1".into(),
                skill: "legion:designer".into(),
                t: 6,
            }],
        };
        assert_eq!(State::parse(&state.render()), state);
        assert_eq!(State::parse(b"not json"), State::default());
    }
}
