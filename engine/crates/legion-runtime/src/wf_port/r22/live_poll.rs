//! Port of the pure/testable functions from
//! `skills/designer/engine/scripts/live-poll.mjs`: the two timeout
//! constants, `buildPollReplyPayload`, `parseReplyArgs` (+ its
//! `validateReplyArgs` helper), `requiresAgentReply`, `isEventPending`,
//! `buildAcceptScriptArgs`, and `manualApplyPollBanner`.
//!
//! NOT ported (needs network I/O, `readLiveServerInfo` from
//! `lib/impeccable-paths.mjs` — only partially ported outside this packet
//! in chunk `q_q1` — and/or `execFileSync` on the unported
//! `live-accept.mjs`, all outside this packet's files): `readServerInfo`,
//! `postReply`, `fetchServerStatus`, `waitForEventAck`, `fetchNextEvent`,
//! `augmentEventWithAcceptHandling`, `writeCarbonizeBanner`,
//! `printPollEvent`, `runPollOnce`, `runPollStream`, `handlePollError`,
//! `pollCli`.

use serde_json::{json, Value};

/// Mirrors `PER_REQUEST_TIMEOUT_MS`.
pub const PER_REQUEST_TIMEOUT_MS: u64 = 270_000;
/// Mirrors `DEFAULT_EVENT_LEASE_MS`.
pub const DEFAULT_EVENT_LEASE_MS: u64 = 600_000;

/// Mirrors `EVENT_TYPES_NEEDING_AGENT_REPLY`.
const EVENT_TYPES_NEEDING_AGENT_REPLY: [&str; 3] = ["generate", "steer", "manual_edit_apply"];

/// Mirrors `requiresAgentReply(event)`. `event_type` is `event?.type`
/// (absent/non-string types never require a reply, same as the source's
/// `Set.has(undefined)` being `false`).
pub fn requires_agent_reply(event_type: Option<&str>) -> bool {
    match event_type {
        Some(t) => EVENT_TYPES_NEEDING_AGENT_REPLY.contains(&t),
        None => false,
    }
}

/// Mirrors `buildPollReplyPayload(token, { id, type, message, file, data })`.
/// Fields absent in the source's optional destructure serialize as JSON
/// `null`, matching `JSON.stringify` on an object with `undefined` fields
/// dropped... note: the JS object literal keeps `undefined` keys out of
/// `JSON.stringify` output entirely (they are omitted, not `null`). This is
/// reproduced by omitting `None` fields from the emitted object.
pub fn build_poll_reply_payload(
    token: &str,
    id: &str,
    reply_type: &str,
    message: Option<&str>,
    file: Option<&str>,
    data: Option<Value>,
) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("token".to_string(), json!(token));
    obj.insert("id".to_string(), json!(id));
    obj.insert("type".to_string(), json!(reply_type));
    if let Some(m) = message {
        obj.insert("message".to_string(), json!(m));
    }
    if let Some(f) = file {
        obj.insert("file".to_string(), json!(f));
    }
    if let Some(d) = data {
        obj.insert("data".to_string(), d);
    }
    Value::Object(obj)
}

/// Mirrors `isEventPending(status, eventId)`:
/// `(status.pendingEvents || []).some((entry) => entry.id === eventId)`.
pub fn is_event_pending(status: &Value, event_id: &str) -> bool {
    status
        .get("pendingEvents")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .any(|entry| entry.get("id").and_then(Value::as_str) == Some(event_id))
        })
        .unwrap_or(false)
}

/// Error shape mirroring the JS `Error` objects thrown by
/// `validateReplyArgs`/`parseReplyArgs`, which callers inspect via `.code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyArgsError {
    pub code: &'static str,
    pub message: String,
}

const REPLY_USAGE: &str =
    "Usage: node live-poll.mjs --reply <id> <status> [--file path] [--data '<json>'] [message]";

/// Mirrors `validateReplyArgs({ id, status })`.
fn validate_reply_args(id: Option<&str>, status: Option<&str>) -> Result<(), ReplyArgsError> {
    let id_missing_or_flag = id.map(|v| v.starts_with("--")).unwrap_or(true);
    if id_missing_or_flag {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!("{REPLY_USAGE}\nMissing event id after --reply."),
        });
    }
    let id = id.unwrap();
    if matches!(id, "done" | "error" | "complete" | "discard" | "discarded") {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!(
                "{REPLY_USAGE}\nThe value after --reply must be the event id, not the status {:?}. Use --reply EVENT_ID {id}.",
                id
            ),
        });
    }
    let status_missing_or_flag = status.map(|v| v.starts_with("--")).unwrap_or(true);
    if status_missing_or_flag {
        return Err(ReplyArgsError {
            code: "INVALID_REPLY_ARGS",
            message: format!(
                "{REPLY_USAGE}\nMissing reply status after event id {:?}.",
                id
            ),
        });
    }
    Ok(())
}

/// A parsed `--reply` invocation, mirroring the object returned by
/// `parseReplyArgs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReply {
    pub id: String,
    pub reply_type: String,
    pub message: Option<String>,
    pub file: Option<String>,
    pub data: Option<Value>,
}

/// Mirrors `parseReplyArgs(args)`. Returns `Ok(None)` when `--reply` is
/// absent (source returns `null`), `Ok(Some(parsed))` on success, and
/// `Err` for `INVALID_REPLY_ARGS` / `INVALID_DATA_JSON`, exactly matching
/// the source's thrown-`Error.code` values.
pub fn parse_reply_args(args: &[String]) -> Result<Option<ParsedReply>, ReplyArgsError> {
    let Some(reply_idx) = args.iter().position(|a| a == "--reply") else {
        return Ok(None);
    };

    let id = args.get(reply_idx + 1).map(|s| s.as_str());
    let status = args.get(reply_idx + 2).map(|s| s.as_str());
    validate_reply_args(id, status)?;
    let id = id.unwrap().to_string();
    let status = status.unwrap().to_string();

    let file_idx = args.iter().position(|a| a == "--file");
    let file = file_idx
        .filter(|&i| i + 1 < args.len())
        .map(|i| args[i + 1].clone());

    let data_idx = args.iter().position(|a| a == "--data");
    let data = match data_idx.filter(|&i| i + 1 < args.len()) {
        Some(i) => {
            let raw = &args[i + 1];
            match serde_json::from_str::<Value>(raw) {
                Ok(v) => Some(v),
                Err(err) => {
                    return Err(ReplyArgsError {
                        code: "INVALID_DATA_JSON",
                        message: format!("--data must be valid JSON: {err}"),
                    })
                }
            }
        }
        None => None,
    };

    // message = args.find((a, i) => i > replyIdx + 2 && !a.startsWith('--')
    //   && i !== fileIdx + 1 && i !== dataIdx + 1)
    // Note: when fileIdx/dataIdx are -1 (absent), `fileIdx + 1 === 0` /
    // `dataIdx + 1 === 0` in JS, which can only ever collide with index 0 —
    // impossible here since the predicate already requires `i > replyIdx + 2
    // >= 2`. Reproduced with Option-based index comparison, which has the
    // same effective behavior.
    let file_next = file_idx.map(|i| i + 1);
    let data_next = data_idx.map(|i| i + 1);
    let message = args.iter().enumerate().find_map(|(i, a)| {
        if i > reply_idx + 2
            && !a.starts_with("--")
            && Some(i) != file_next
            && Some(i) != data_next
        {
            Some(a.clone())
        } else {
            None
        }
    });

    Ok(Some(ParsedReply {
        id,
        reply_type: status,
        message,
        file,
        data,
    }))
}

/// The subset of a poll event's fields `buildAcceptScriptArgs` reads.
#[derive(Debug, Clone, Default)]
pub struct AcceptEvent {
    pub event_type: String,
    pub id: String,
    pub variant_id: Option<String>,
    pub page_url: Option<String>,
    pub param_values: Option<serde_json::Map<String, Value>>,
}

/// Mirrors `buildAcceptScriptArgs(event)`.
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
        if let Some(pv) = &event.param_values {
            if !pv.is_empty() {
                args.push("--param-values".to_string());
                args.push(Value::Object(pv.clone()).to_string());
            }
        }
    }
    args
}

/// Mirrors `manualApplyPollBanner(event = {})`; `event_id` is `event.id ||
/// 'EVENT_ID'`.
pub fn manual_apply_poll_banner(event_id: Option<&str>) -> String {
    let id = event_id.filter(|s| !s.is_empty()).unwrap_or("EVENT_ID");
    let lines = [
        format!(
            "Manual Apply action required: edit source, then reply with `live-poll.mjs --reply {id} done --data '<json>'`."
        ),
        "The JSON data must include status, appliedEntryIds, failed, files, and notes; summary counters are only a recovery fallback.".to_string(),
        "Do not run live-commit-manual-edits.mjs for this leased event.".to_string(),
        "Do not poll again before replying.".to_string(),
    ];
    format!("{}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_agent_reply_matches_set() {
        assert!(requires_agent_reply(Some("generate")));
        assert!(requires_agent_reply(Some("steer")));
        assert!(requires_agent_reply(Some("manual_edit_apply")));
        assert!(!requires_agent_reply(Some("accept")));
        assert!(!requires_agent_reply(None));
    }

    #[test]
    fn build_poll_reply_payload_omits_absent_optionals() {
        let payload = build_poll_reply_payload("tok", "ev1", "done", None, None, None);
        assert_eq!(
            payload,
            json!({ "token": "tok", "id": "ev1", "type": "done" })
        );
    }

    #[test]
    fn build_poll_reply_payload_includes_present_optionals() {
        let payload = build_poll_reply_payload(
            "tok",
            "ev1",
            "error",
            Some("oops"),
            Some("a.txt"),
            Some(json!({"carbonize": true})),
        );
        assert_eq!(
            payload,
            json!({
                "token": "tok",
                "id": "ev1",
                "type": "error",
                "message": "oops",
                "file": "a.txt",
                "data": {"carbonize": true}
            })
        );
    }

    #[test]
    fn is_event_pending_true_when_id_present() {
        let status = json!({ "pendingEvents": [{"id": "a"}, {"id": "b"}] });
        assert!(is_event_pending(&status, "b"));
        assert!(!is_event_pending(&status, "c"));
    }

    #[test]
    fn is_event_pending_defaults_to_false_when_missing() {
        let status = json!({});
        assert!(!is_event_pending(&status, "b"));
    }

    #[test]
    fn parse_reply_args_absent_flag_returns_none() {
        let args = vec!["--stream".to_string()];
        assert_eq!(parse_reply_args(&args), Ok(None));
    }

    #[test]
    fn parse_reply_args_missing_id_errors() {
        let args = vec!["--reply".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
    }

    #[test]
    fn parse_reply_args_status_looking_id_errors() {
        let args = vec!["--reply".to_string(), "done".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
        assert!(err.message.contains("not the status"));
    }

    #[test]
    fn parse_reply_args_missing_status_errors() {
        let args = vec!["--reply".to_string(), "ev1".to_string()];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_REPLY_ARGS");
    }

    #[test]
    fn parse_reply_args_basic_done() {
        let args = vec!["--reply".to_string(), "ev1".to_string(), "done".to_string()];
        let parsed = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(parsed.id, "ev1");
        assert_eq!(parsed.reply_type, "done");
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.file, None);
        assert_eq!(parsed.data, None);
    }

    #[test]
    fn parse_reply_args_with_message_file_and_data() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "error".to_string(),
            "--file".to_string(),
            "a.txt".to_string(),
            "--data".to_string(),
            "{\"k\":1}".to_string(),
            "boom".to_string(),
        ];
        let parsed = parse_reply_args(&args).unwrap().unwrap();
        assert_eq!(parsed.file.as_deref(), Some("a.txt"));
        assert_eq!(parsed.data, Some(json!({"k": 1})));
        assert_eq!(parsed.message.as_deref(), Some("boom"));
    }

    #[test]
    fn parse_reply_args_invalid_data_json_errors() {
        let args = vec![
            "--reply".to_string(),
            "ev1".to_string(),
            "done".to_string(),
            "--data".to_string(),
            "{not json".to_string(),
        ];
        let err = parse_reply_args(&args).unwrap_err();
        assert_eq!(err.code, "INVALID_DATA_JSON");
    }

    #[test]
    fn build_accept_script_args_discard() {
        let event = AcceptEvent {
            event_type: "discard".to_string(),
            id: "ev1".to_string(),
            ..Default::default()
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec!["--id", "ev1", "--discard"]
        );
    }

    #[test]
    fn build_accept_script_args_accept_with_variant_and_params() {
        let mut pv = serde_json::Map::new();
        pv.insert("color".to_string(), json!("blue"));
        let event = AcceptEvent {
            event_type: "accept".to_string(),
            id: "ev1".to_string(),
            variant_id: Some("2".to_string()),
            page_url: Some("http://x/y".to_string()),
            param_values: Some(pv),
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec![
                "--id",
                "ev1",
                "--variant",
                "2",
                "--page-url",
                "http://x/y",
                "--param-values",
                "{\"color\":\"blue\"}",
            ]
        );
    }

    #[test]
    fn build_accept_script_args_accept_empty_params_omitted() {
        let event = AcceptEvent {
            event_type: "accept".to_string(),
            id: "ev1".to_string(),
            variant_id: Some("1".to_string()),
            param_values: Some(serde_json::Map::new()),
            ..Default::default()
        };
        assert_eq!(
            build_accept_script_args(&event),
            vec!["--id", "ev1", "--variant", "1"]
        );
    }

    #[test]
    fn manual_apply_poll_banner_default_id() {
        let banner = manual_apply_poll_banner(None);
        assert!(banner.contains("--reply EVENT_ID done"));
        assert!(banner.ends_with('\n'));
    }

    #[test]
    fn manual_apply_poll_banner_with_id() {
        let banner = manual_apply_poll_banner(Some("ev42"));
        assert!(banner.contains("--reply ev42 done"));
    }

    #[test]
    fn timeout_constants_match_source() {
        assert_eq!(PER_REQUEST_TIMEOUT_MS, 270_000);
        assert_eq!(DEFAULT_EVENT_LEASE_MS, 600_000);
    }
}
