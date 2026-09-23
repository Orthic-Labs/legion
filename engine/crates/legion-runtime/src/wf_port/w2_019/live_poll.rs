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
    "Usage: node \"live-poll.mjs\" --reply <id> <status> [--file path] [--data '<json>'] [message]";

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
        "Manual Apply action required: edit source, then reply with `live-poll.mjs --reply {id} done --data '<json>'`.\n\
         The JSON data must include status, appliedEntryIds, failed, files, and notes; summary counters are only a recovery fallback.\n\
         Do not run live-commit-manual-edits.mjs for this leased event.\n\
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
        vec!["--id".to_string(), event.id.clone(), "--discard".to_string()]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_agent_reply_matches_js_set() {
        assert!(requires_agent_reply("generate"));
        assert!(requires_agent_reply("steer"));
        assert!(requires_agent_reply("manual_edit_apply"));
        assert!(!requires_agent_reply("accept"));
        assert!(!requires_agent_reply("discard"));
        assert!(!requires_agent_reply("exit"));
    }

    #[test]
    fn build_poll_reply_payload_omits_absent_optional_fields() {
        let reply = PollReply {
            id: "ev1".into(),
            reply_type: "done".into(),
            message: None,
            file: None,
            data: None,
        };
        let payload = build_poll_reply_payload("tok", &reply);
        let obj = payload.as_object().unwrap();
        assert_eq!(obj.get("token").unwrap(), "tok");
        assert_eq!(obj.get("id").unwrap(), "ev1");
        assert_eq!(obj.get("type").unwrap(), "done");
        assert!(!obj.contains_key("message"));
        assert!(!obj.contains_key("file"));
        assert!(!obj.contains_key("data"));
    }

    #[test]
    fn build_poll_reply_payload_includes_present_optional_fields() {
        let reply = PollReply {
            id: "ev1".into(),
            reply_type: "done".into(),
            message: Some("ok".into()),
            file: Some("src/App.svelte".into()),
            data: Some(json!({"carbonize": true})),
        };
        let payload = build_poll_reply_payload("tok", &reply);
        assert_eq!(payload["message"], "ok");
        assert_eq!(payload["file"], "src/App.svelte");
        assert_eq!(payload["data"]["carbonize"], true);
    }

    #[test]
    fn parse_reply_args_returns_none_without_flag() {
        let args = vec!["--stream".to_string()];
        assert_eq!(parse_reply_args(&args).unwrap(), None);
    }

    #[test]
    fn parse_reply_args_missing_id_errors() {
        let args = vec!["--reply".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
        assert!(err.message.contains("Missing event id after --reply."));
    }

    #[test]
    fn parse_reply_args_rejects_status_in_id_position() {
        let args = vec!["--reply".to_string(), "done".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert!(err.message.contains("must be the event id, not the status"));
    }

    #[test]
    fn parse_reply_args_missing_status_errors() {
        let args = vec!["--reply".to_string(), "ev1".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert!(err.message.contains("Missing reply status after event id"));
    }

    #[test]
    fn parse_reply_args_happy_path_with_file_data_and_message() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "done".to_string(),
            "--file".to_string(),
            "src/App.svelte".to_string(),
            "--data".to_string(),
            r#"{"a":1}"#.to_string(),
            "trailing message".to_string(),
        ];
        let reply = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(reply.id, "ev1");
        assert_eq!(reply.reply_type, "done");
        assert_eq!(reply.file.as_deref(), Some("src/App.svelte"));
        assert_eq!(reply.data.unwrap(), json!({"a": 1}));
        assert_eq!(reply.message.as_deref(), Some("trailing message"));
    }

    #[test]
    fn parse_reply_args_invalid_data_json_errors() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "error".to_string(),
            "--data".to_string(),
            "not json".to_string(),
        ];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_DATA_JSON");
        assert!(err.message.starts_with("--data must be valid JSON:"));
    }

    #[test]
    fn parse_reply_args_message_excludes_file_and_data_values() {
        // A plain-text message that happens to come right after --file's
        // value or --data's value must not be picked up as that flag's
        // value's neighbor being mistaken for the message; only the actual
        // free-standing token becomes `message`.
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "error".to_string(),
            "--file".to_string(),
            "a.txt".to_string(),
            "--data".to_string(),
            "{}".to_string(),
            "boom".to_string(),
        ];
        let reply = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(reply.message.as_deref(), Some("boom"));
    }

    #[test]
    fn manual_apply_poll_banner_defaults_event_id() {
        let banner = manual_apply_poll_banner(None);
        assert!(banner.contains("--reply EVENT_ID done"));
        let banner2 = manual_apply_poll_banner(Some("ev42"));
        assert!(banner2.contains("--reply ev42 done"));
    }

    #[test]
    fn is_event_pending_checks_membership() {
        let ids = vec!["a".to_string(), "b".to_string()];
        assert!(is_event_pending(&ids, "a"));
        assert!(!is_event_pending(&ids, "c"));
    }

    #[test]
    fn build_accept_script_args_for_discard() {
        let event = AcceptEvent {
            event_type: "discard".into(),
            id: "ev1".into(),
            page_url: Some("https://x/y".into()),
            ..Default::default()
        };
        let args = build_accept_script_args(&event);
        assert_eq!(
            args,
            vec!["--id", "ev1", "--discard", "--page-url", "https://x/y"]
        );
    }

    #[test]
    fn build_accept_script_args_for_accept_with_param_values() {
        let event = AcceptEvent {
            event_type: "accept".into(),
            id: "ev2".into(),
            variant_id: Some("v3".into()),
            page_url: None,
            param_values: Some(json!({"color": "blue"})),
        };
        let args = build_accept_script_args(&event);
        assert_eq!(args[0..4], ["--id", "ev2", "--variant", "v3"]);
        assert_eq!(args[4], "--param-values");
        assert_eq!(
            serde_json::from_str::<Value>(&args[5]).unwrap(),
            json!({"color": "blue"})
        );
    }

    #[test]
    fn build_accept_script_args_for_accept_with_empty_param_values_omits_flag() {
        let event = AcceptEvent {
            event_type: "accept".into(),
            id: "ev2".into(),
            variant_id: Some("v3".into()),
            param_values: Some(json!({})),
            ..Default::default()
        };
        let args = build_accept_script_args(&event);
        assert_eq!(args, vec!["--id", "ev2", "--variant", "v3"]);
    }
}
