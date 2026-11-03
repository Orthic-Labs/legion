//! Port of the pure logic in `skills/designer/engine/scripts/live-poll.mjs`.
//!
//! See [`crate::wf_port::w2_019`] for what is and isn't ported from this
//! file.

use serde_json::{json, Value};

/// Mirrors `EVENT_TYPES_NEEDING_AGENT_REPLY` in `live-poll.mjs`: event
/// types for which stream mode blocks on a `--reply` before continuing.
const EVENT_TYPES_NEEDING_AGENT_REPLY: [&str; 3] = ["generate", "steer", "manual_edit_apply"];

/// Port of `requiresAgentReply(event)`.
pub fn requires_agent_reply(event_type: &str) -> bool {
    EVENT_TYPES_NEEDING_AGENT_REPLY.contains(&event_type)
}

/// Port of `buildPollReplyPayload(token, { id, type, message, file, data })`.
/// Fields that were `undefined` in JS (and so dropped from the JSON body)
/// are omitted here as `null`, matching `JSON.stringify`'s behavior for an
/// object literal with `undefined`-valued keys being sent through
/// `fetch`'s `JSON.stringify(body)` — JS drops `undefined` keys entirely,
/// so we mirror that by only inserting present fields.
pub fn build_poll_reply_payload(token: &str, reply: &PollReply) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("token".to_string(), json!(token));
    obj.insert("id".to_string(), json!(reply.id));
    obj.insert("type".to_string(), json!(reply.reply_type));
    if let Some(message) = &reply.message {
        obj.insert("message".to_string(), json!(message));
    }
    if let Some(file) = &reply.file {
        obj.insert("file".to_string(), json!(file));
    }
    if let Some(data) = &reply.data {
        obj.insert("data".to_string(), data.clone());
    }
    Value::Object(obj)
}

/// A parsed `--reply <id> <status> [--file path] [--data '<json>'] [message]`
/// invocation. Mirrors the object literal `parseReplyArgs` returns.
#[derive(Debug, Clone, PartialEq)]
pub struct PollReply {
    pub id: String,
    pub reply_type: String,
    pub message: Option<String>,
    pub file: Option<String>,
    pub data: Option<Value>,
}

/// Mirrors the `code`-tagged `Error`s `parseReplyArgs`/`validateReplyArgs`
/// throw.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyArgsError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for ReplyArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ReplyArgsError {}

const USAGE: &str =
    "Usage: legion script designer/live-poll --reply <id> <status> [--file path] [--data '<json>'] [message]";

/// Port of `validateReplyArgs({ id, status })`.
fn validate_reply_args(id: Option<&str>, status: Option<&str>) -> Result<(), ReplyArgsError> {
    let missing_id = match id {
        None => true,
        Some(v) => v.starts_with("--"),
    };
    if missing_id {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!("{USAGE}\nMissing event id after --reply."),
        });
    }
    let id = id.unwrap();
    if ["done", "error", "complete", "discard", "discarded"].contains(&id) {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!(
                "{USAGE}\nThe value after --reply must be the event id, not the status \"{id}\". Use --reply EVENT_ID {id}."
            ),
        });
    }
    let missing_status = match status {
        None => true,
        Some(v) => v.starts_with("--"),
    };
    if missing_status {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!("{USAGE}\nMissing reply status after event id \"{id}\"."),
        });
    }
    Ok(())
}

/// Port of `parseReplyArgs(args)`. Returns `Ok(None)` when `--reply` is
/// absent (JS returns `null`), mirroring the "not a reply invocation" case.
pub fn parse_reply_args(args: &[String]) -> Result<Option<PollReply>, ReplyArgsError> {
    let Some(reply_idx) = args.iter().position(|a| a == "--reply") else {
        return Ok(None);
    };
    let id = args.get(reply_idx + 1).map(String::as_str);
    let status = args.get(reply_idx + 2).map(String::as_str);
    validate_reply_args(id, status)?;
    let id = id.unwrap().to_string();
    let reply_type = status.unwrap().to_string();

    let file_idx = args.iter().position(|a| a == "--file");
    let file = file_idx
        .filter(|&i| i + 1 < args.len())
        .map(|i| args[i + 1].clone());

    let data_idx = args.iter().position(|a| a == "--data");
    let data = if let Some(i) = data_idx.filter(|&i| i + 1 < args.len()) {
        Some(
            serde_json::from_str::<Value>(&args[i + 1]).map_err(|err| ReplyArgsError {
                code: "INVALID_DATA_JSON",
                message: format!("--data must be valid JSON: {err}"),
            })?,
        )
    } else {
        None
    };

    // Port of: args.find((a, i) => i > replyIdx + 2 && !a.startsWith('--')
    //   && i !== fileIdx + 1 && i !== dataIdx + 1)
    let file_value_idx = file_idx.map(|i| i + 1);
    let data_value_idx = data_idx.map(|i| i + 1);
    let message = args.iter().enumerate().find_map(|(i, a)| {
        if i > reply_idx + 2
            && !a.starts_with("--")
            && Some(i) != file_value_idx
            && Some(i) != data_value_idx
        {
            Some(a.clone())
        } else {
            None
        }
    });

    Ok(Some(PollReply {
        id,
        reply_type,
        message,
        file,
        data,
    }))
}

/// Port of `manualApplyPollBanner(event = {})`.
pub fn manual_apply_poll_banner(event_id: Option<&str>) -> String {
    let id = event_id.unwrap_or("EVENT_ID");
    format!(
        "Manual Apply action required: edit source, then reply with `legion script designer/live-poll --reply {id} done --data '<json>'`.\n\
         The JSON data must include status, appliedEntryIds, failed, files, and notes; summary counters are only a recovery fallback.\n\
         Do not run legion script designer/live-commit-manual-edits for this leased event.\n\
         Do not poll again before replying.\n"
    )
}

/// Port of `isEventPending(status, eventId)`: does `pendingEvents` (an
/// array of `{ id, ... }` entries, taken here as a slice of ids for
/// simplicity) contain `eventId`?
pub fn is_event_pending(pending_event_ids: &[String], event_id: &str) -> bool {
    pending_event_ids.iter().any(|id| id == event_id)
}

/// Minimal accept/discard event shape needed by
/// [`build_accept_script_args`]; mirrors the fields `buildAcceptScriptArgs`
/// reads off `event`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AcceptEvent {
    pub event_type: String, // "accept" | "discard"
    pub id: String,
    pub variant_id: Option<String>,
    pub page_url: Option<String>,
    pub param_values: Option<Value>,
}

/// Port of `buildAcceptScriptArgs(event)`.
pub fn build_accept_script_args(event: &AcceptEvent) -> Vec<String> {
    let mut args = if event.event_type == "discard" {
        vec![
            "--id".to_string(),
            event.id.clone(),
            "--discard".to_string(),
        ]
    } else {
        vec![
            "--id".to_string(),
            event.id.clone(),
            "--variant".to_string(),
            event.variant_id.clone().unwrap_or_default(),
        ]
    };
    if let Some(page_url) = &event.page_url {
        args.push("--page-url".to_string());
        args.push(page_url.clone());
    }
    if event.event_type == "accept" {
        if let Some(Value::Object(map)) = &event.param_values {
            if !map.is_empty() {
                args.push("--param-values".to_string());
                args.push(Value::Object(map.clone()).to_string());
            }
        }
    }
    args
}
