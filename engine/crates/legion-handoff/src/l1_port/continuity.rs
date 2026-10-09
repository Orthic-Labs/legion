//! Native, deterministic transcript continuity for the handoff CLI.
//!
//! This module intentionally owns only the portable file-side reducer that
//! the old Membrane command supplied.  It never executes transcript content,
//! asks a model to interpret it, or treats system/tool/runtime material as a
//! user obligation.  The source prefix is verified before rows are adapted.

// Adapted from CodeRight Membrane Transcript at commit
// 543859ccba421e88e144d961a20bb3c21aad3e0a: adapters, classifier, redaction,
// evidence, and event contracts under context/engine/crates/membrane-transcript/src.
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::pointer::Platform;

pub const CONTINUITY_SCHEMA: &str = "legion.handoff.continuity.v1";
pub const RECEIPT_SCHEMA: &str = "legion.handoff.continuity-receipt.v1";
pub const PARSER_VERSION: &str = "legion.transcript-event.v1";
const MAX_TEXT_CHARS: usize = 6_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceBinding {
    pub platform: String,
    pub session_id: String,
    pub workspace: String,
    pub source_path: String,
    pub cutoff_bytes: u64,
    pub sha256: String,
    pub prefix_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityEvent {
    pub id: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub kind: String,
    pub role: String,
    pub text: String,
    pub source_ref: String,
    pub source_hash: String,
    pub provenance: String,
    /// Transcript text is evidence, never an instruction to the receiver.
    pub authority: String,
    pub trusted: bool,
    pub row_index: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub block_index: u64,
    pub sequence: u64,
    pub timestamp: Option<String>,
    pub tool: Option<String>,
    pub call_id: Option<String>,
    pub redacted: bool,
    pub classification: String,
    #[serde(rename = "class")]
    pub class_alias: String,
    pub projection: String,
    pub host: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "transcriptId")]
    pub transcript_id: String,
    #[serde(rename = "parserDigest")]
    pub parser_digest: String,
    pub synthetic: bool,
    pub meta: bool,
    #[serde(rename = "privateReasoningOmitted")]
    pub private_reasoning_omitted: bool,
    pub flags: ContinuityFlags,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityFlags {
    pub synthetic: bool,
    pub meta: bool,
    pub private_reasoning_omitted: bool,
    pub redacted: bool,
    pub is_error: bool,
    pub is_sidechain: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityOmission {
    pub id: String,
    pub reason: String,
    pub source_ref: String,
    pub source_hash: String,
    pub provenance: String,
    pub recoverable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityGap {
    pub id: String,
    pub kind: String,
    pub reason: String,
    pub source_ref: String,
    pub recoverable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityReceipt {
    pub schema: String,
    pub host: String,
    pub platform: String,
    pub session_id: String,
    pub transcript_id: String,
    pub workspace: String,
    pub source_path: String,
    pub cutoff_bytes: u64,
    pub prefix_length: u64,
    pub prefix_digest: String,
    pub source_sha256: String,
    pub context_sha256: String,
    pub event_count: usize,
    pub omission_count: usize,
    pub events_observed: usize,
    pub parser_version: String,
    pub parser_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuityContext {
    pub schema: String,
    pub parser_version: String,
    pub source: SourceBinding,
    pub events: Vec<ContinuityEvent>,
    pub user_requests: Vec<ContinuityEvent>,
    pub omissions: Vec<ContinuityOmission>,
    pub gaps: Vec<ContinuityGap>,
    pub provenance: Vec<String>,
    pub receipt: ContinuityReceipt,
}

#[derive(Clone, Debug)]
pub struct ContinuityInput {
    pub path: PathBuf,
    pub platform: Platform,
    pub session_id: String,
    pub workspace: String,
    pub cutoff_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawEvent {
    kind: &'static str,
    role: &'static str,
    text: String,
    timestamp: Option<String>,
    tool: Option<String>,
    call_id: Option<String>,
    redacted: bool,
    is_error: bool,
}

impl ContinuityInput {
    pub fn new(
        path: impl Into<PathBuf>,
        platform: Platform,
        session_id: impl Into<String>,
        workspace: impl Into<String>,
        cutoff_bytes: u64,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            platform,
            session_id: session_id.into(),
            workspace: workspace.into(),
            cutoff_bytes,
            sha256: sha256.into(),
        }
    }
}

/// Verify the immutable prefix and produce a typed context packet.
pub fn normalize(input: &ContinuityInput) -> Result<ContinuityContext, String> {
    let file =
        fs::File::open(&input.path).map_err(|error| format!("cannot read transcript: {error}"))?;
    let file_len = file
        .metadata()
        .map_err(|error| format!("cannot stat transcript: {error}"))?
        .len();
    if input.cutoff_bytes == 0 {
        return Err("cutoff_bytes must be positive".into());
    }
    let cutoff = usize::try_from(input.cutoff_bytes)
        .map_err(|_| "cutoff_bytes is too large for this platform".to_string())?;
    if input.cutoff_bytes > file_len {
        return Err(format!(
            "pointer cutoff {} exceeds transcript length {}",
            input.cutoff_bytes, file_len
        ));
    }
    let mut prefix_bytes = Vec::with_capacity(cutoff);
    file.take(input.cutoff_bytes)
        .read_to_end(&mut prefix_bytes)
        .map_err(|error| format!("cannot read transcript prefix: {error}"))?;
    if prefix_bytes.len() != cutoff {
        return Err("transcript ended before pointer cutoff".into());
    }
    let prefix = prefix_bytes.as_slice();
    if !prefix.ends_with(b"\n") {
        return Err("pointer cutoff does not end at a complete JSONL row".into());
    }
    let expected = normalize_hash(&input.sha256)?;
    let actual = hex::encode(Sha256::digest(prefix));
    if expected != actual {
        return Err(format!(
            "source prefix sha256 mismatch: expected {expected}, got {actual}"
        ));
    }

    let mut rows = Vec::new();
    let mut start = 0usize;
    for (index, chunk) in prefix.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let end = start + chunk.len();
        let source_ref = source_ref(&input.path, index as u64 + 1, start as u64, end as u64);
        match serde_json::from_slice::<Value>(chunk) {
            Ok(value) if value.is_object() => rows.push((
                index as u64 + 1,
                start as u64,
                end as u64,
                source_ref,
                value,
            )),
            Ok(_) => rows.push((
                index as u64 + 1,
                start as u64,
                end as u64,
                source_ref,
                Value::Null,
            )),
            Err(_) => rows.push((
                index as u64 + 1,
                start as u64,
                end as u64,
                source_ref,
                Value::Null,
            )),
        }
        start = end;
    }
    if rows.is_empty() {
        return Err("transcript contains no complete JSONL row".into());
    }

    verify_identity(input, &rows)?;
    let source_hash = format!("sha256:{actual}");
    let binding = SourceBinding {
        platform: input.platform.as_str().to_string(),
        session_id: input.session_id.clone(),
        workspace: input.workspace.clone(),
        source_path: input.path.display().to_string(),
        cutoff_bytes: input.cutoff_bytes,
        sha256: actual.clone(),
        prefix_verified: true,
    };

    let mut events = Vec::new();
    let mut omissions = Vec::new();
    let mut sequence = 0u64;
    for (row_index, start, end, source_ref, value) in rows {
        if value.is_null() {
            let reason = if prefix[(start as usize)..(end as usize)]
                .iter()
                .all(|byte| byte.is_ascii_whitespace())
            {
                "empty_or_malformed_row"
            } else {
                "malformed_or_non_object_row"
            };
            omissions.push(omission(
                &input.path,
                row_index,
                start,
                end,
                &source_hash,
                reason,
                true,
            ));
            continue;
        }
        let adapted = adapt_row(input.platform, &value);
        if adapted.is_empty() {
            omissions.push(omission(
                &input.path,
                row_index,
                start,
                end,
                &source_hash,
                omission_reason(input.platform, &value),
                false,
            ));
            continue;
        }
        for (block_index, event) in adapted.into_iter().enumerate() {
            if event.kind == "omission" {
                omissions.push(omission(
                    &input.path,
                    row_index,
                    start,
                    end,
                    &source_hash,
                    &event.text,
                    true,
                ));
                continue;
            }
            let (text, was_truncated) = if event.kind == "user_message" {
                // User requests are retained verbatim apart from mandatory
                // secret replacement; whitespace is part of user intent.
                (redact(&event.text), false)
            } else {
                let redacted = redact(&event.text);
                let truncated = redacted.chars().count() > MAX_TEXT_CHARS;
                (compact_text(&redacted), truncated)
            };
            if text.is_empty() {
                omissions.push(omission(
                    &input.path,
                    row_index,
                    start,
                    end,
                    &source_hash,
                    "empty_event_text",
                    true,
                ));
                continue;
            }
            sequence += 1;
            let classification = classify(event.kind, event.tool.as_deref(), &text, event.is_error);
            if was_truncated {
                omissions.push(omission(
                    &input.path,
                    row_index,
                    start,
                    end,
                    &source_hash,
                    "event_text_truncated",
                    true,
                ));
            }
            let id = event_id(
                &source_hash,
                row_index,
                block_index as u64,
                sequence,
                event.kind,
                &text,
            );
            let source_ref = source_ref.clone();
            events.push(ContinuityEvent {
                id: id.clone(),
                event_id: id,
                kind: event.kind.to_string(),
                role: event.role.to_string(),
                text: text.clone(),
                source_ref: source_ref.clone(),
                source_hash: source_hash.clone(),
                provenance: format!(
                    "legion.continuity:{}:{}",
                    input.platform.as_str(),
                    source_ref
                ),
                authority: "untrusted_transcript_data".into(),
                trusted: false,
                row_index,
                byte_start: start,
                byte_end: end,
                block_index: block_index as u64,
                sequence,
                timestamp: event.timestamp,
                tool: event.tool,
                call_id: event.call_id,
                redacted: event.redacted
                    || text.contains("[REDACTED]")
                    || text.contains("[BINARY_BLOB_REMOVED]"),
                classification: classification.clone(),
                class_alias: classification,
                projection: "default".into(),
                host: input.platform.as_str().into(),
                session_id: input.session_id.clone(),
                transcript_id: input
                    .path
                    .file_stem()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                parser_digest: parser_digest(),
                synthetic: false,
                meta: false,
                private_reasoning_omitted: false,
                flags: ContinuityFlags {
                    synthetic: false,
                    meta: false,
                    private_reasoning_omitted: false,
                    redacted: event.redacted
                        || text.contains("[REDACTED]")
                        || text.contains("[BINARY_BLOB_REMOVED]"),
                    is_error: event.is_error,
                    is_sidechain: false,
                },
            });
        }
    }

    let user_requests = events
        .iter()
        .filter(|event| event.kind == "user_message")
        .cloned()
        .collect::<Vec<_>>();
    let mut gaps = omissions
        .iter()
        .map(|omission| ContinuityGap {
            id: format!("gap_{}", omission.id),
            kind: "source_omission".into(),
            reason: omission.reason.clone(),
            source_ref: omission.source_ref.clone(),
            recoverable: omission.recoverable,
        })
        .collect::<Vec<_>>();
    if user_requests.is_empty() {
        gaps.push(ContinuityGap {
            id: format!("gap_no_user_request_{}", short_hash(&source_hash)),
            kind: "missing_user_request".into(),
            reason: "no admissible user request found in verified prefix".into(),
            source_ref: format!("{}#prefix=0..{}", input.path.display(), input.cutoff_bytes),
            recoverable: true,
        });
    }
    let provenance = {
        let mut values = vec![
            format!("source:{source_hash}"),
            format!("path:{}", input.path.display()),
        ];
        values.extend(events.iter().map(|event| event.provenance.clone()));
        values.extend(omissions.iter().map(|item| item.provenance.clone()));
        values.sort();
        values.dedup();
        values
    };
    let mut context = ContinuityContext {
        schema: CONTINUITY_SCHEMA.into(),
        parser_version: PARSER_VERSION.into(),
        source: binding,
        events,
        user_requests,
        omissions,
        gaps,
        provenance,
        receipt: ContinuityReceipt {
            schema: RECEIPT_SCHEMA.into(),
            host: input.platform.as_str().into(),
            platform: input.platform.as_str().into(),
            session_id: input.session_id.clone(),
            transcript_id: input
                .path
                .file_stem()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_default(),
            workspace: input.workspace.clone(),
            source_path: input.path.display().to_string(),
            cutoff_bytes: input.cutoff_bytes,
            prefix_length: input.cutoff_bytes,
            prefix_digest: format!("sha256:{actual}"),
            source_sha256: source_hash,
            context_sha256: String::new(),
            event_count: 0,
            omission_count: 0,
            events_observed: 0,
            parser_version: PARSER_VERSION.into(),
            parser_digest: parser_digest(),
        },
    };
    context.receipt.event_count = context.events.len();
    context.receipt.omission_count = context.omissions.len();
    context.receipt.events_observed = context.events.len();
    context.receipt.context_sha256 = context_digest(&context)?;
    Ok(context)
}

/// Verify a generated context's receipt binding.  This is read-only and does
/// not read or reparse source transcript content.
pub fn verify_context_receipt(context: &ContinuityContext) -> Result<(), String> {
    if context.schema != CONTINUITY_SCHEMA || context.receipt.schema != RECEIPT_SCHEMA {
        return Err("unsupported continuity receipt schema".into());
    }
    if !context.source.prefix_verified {
        return Err("source prefix is not verified".into());
    }
    if context.receipt.event_count != context.events.len()
        || context.receipt.omission_count != context.omissions.len()
    {
        return Err("continuity receipt counts do not match context".into());
    }
    let expected = context.receipt.context_sha256.clone();
    let actual = context_digest(context)?;
    if expected != actual {
        return Err(format!(
            "context sha256 mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn context_digest(context: &ContinuityContext) -> Result<String, String> {
    let mut clone = context.clone();
    clone.receipt.context_sha256.clear();
    let bytes = serde_json::to_vec(&clone).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn parser_digest() -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(include_bytes!("continuity.rs")))
    )
}

fn verify_identity(
    input: &ContinuityInput,
    rows: &[(u64, u64, u64, String, Value)],
) -> Result<(), String> {
    let mut seen_session = false;
    let mut seen_workspace = false;
    for (_, _, _, _, value) in rows {
        let Some(object) = value.as_object() else {
            continue;
        };
        let row_type = object.get("type").and_then(Value::as_str).unwrap_or("");
        if (input.platform == Platform::Claude
            && matches!(row_type, "response_item" | "session_meta"))
            || (input.platform == Platform::Codex && matches!(row_type, "user" | "assistant"))
        {
            return Err(format!(
                "platform mismatch: {} row in {} transcript",
                row_type,
                input.platform.as_str()
            ));
        }
        let (session, workspace) = match input.platform {
            Platform::Claude => (
                first_string(object, &["sessionId", "session_id"]),
                first_string(object, &["cwd", "workspace"]),
            ),
            Platform::Codex => {
                let payload = object
                    .get("payload")
                    .and_then(Value::as_object)
                    .unwrap_or(object);
                let session_keys = if row_type == "session_meta" {
                    &["id", "sessionId", "session_id"][..]
                } else {
                    &["sessionId", "session_id"][..]
                };
                (
                    first_string(payload, session_keys),
                    first_string(payload, &["cwd", "workspace"]),
                )
            }
        };
        if let Some(value) = session {
            seen_session = true;
            if value != input.session_id {
                return Err(format!(
                    "session ID mismatch: pointer {}, transcript {}",
                    input.session_id, value
                ));
            }
        }
        if let Some(value) = workspace {
            seen_workspace = true;
            // Agents `cd` into subfolders during a run, so a row may come from
            // the workspace or any folder inside it, compared by whole path
            // components (`/repo-other` is not inside `/repo`).
            if !path_within(&value, &input.workspace) {
                return Err(format!(
                    "workspace mismatch: pointer {}, transcript {}",
                    input.workspace, value
                ));
            }
        }
    }
    if !seen_session {
        return Err("transcript has no session identity to bind".into());
    }
    if !seen_workspace {
        return Err("transcript has no workspace identity to bind".into());
    }
    Ok(())
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match object.get(*key) {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(value) if value.is_number() || value.is_boolean() => Some(value.to_string()),
        _ => None,
    })
}

fn adapt_row(platform: Platform, object: &Value) -> Vec<RawEvent> {
    match platform {
        Platform::Claude => adapt_claude(object),
        Platform::Codex => adapt_codex(object),
    }
}

fn adapt_claude(object: &Value) -> Vec<RawEvent> {
    let Some(map) = object.as_object() else {
        return Vec::new();
    };
    let row_type = map.get("type").and_then(Value::as_str).unwrap_or("");
    if row_type != "user" && row_type != "assistant" {
        return Vec::new();
    }
    if map
        .get("isSidechain")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || map.get("isMeta").and_then(Value::as_bool).unwrap_or(false)
        || map
            .get("isCompactSummary")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return vec![RawEvent::omission("system_or_sidechain_material")];
    }
    let timestamp = map
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(message) = map.get("message").and_then(Value::as_object) else {
        if let Some(result) = map.get("toolUseResult") {
            return vec![RawEvent {
                kind: "tool_result",
                role: "user",
                text: json_text(result),
                timestamp,
                tool: None,
                call_id: first_string(map, &["tool_use_id", "toolUseId", "call_id"]),
                redacted: false,
                is_error: false,
            }];
        }
        return vec![RawEvent::omission("missing_message_object")];
    };
    if let Some(role) = message.get("role").and_then(Value::as_str) {
        if role != row_type {
            return vec![RawEvent::omission("message_role_mismatch")];
        }
    }
    let Some(content) = message.get("content") else {
        return vec![RawEvent::omission("missing_message_content")];
    };
    if let Some(text) = content.as_str() {
        if row_type == "user" && injected_context(text) {
            return vec![RawEvent::omission("runtime_or_system_context")];
        }
        return vec![RawEvent {
            kind: if row_type == "user" {
                "user_message"
            } else {
                "assistant_message"
            },
            role: if row_type == "user" {
                "user"
            } else {
                "assistant"
            },
            text: text.into(),
            timestamp,
            tool: None,
            call_id: None,
            redacted: false,
            is_error: false,
        }];
    }
    let Some(blocks) = content.as_array() else {
        return vec![RawEvent::omission("unsupported_message_content")];
    };
    let mut result = Vec::new();
    for block in blocks {
        let Some(block) = block.as_object() else {
            continue;
        };
        match block.get("type").and_then(Value::as_str).unwrap_or("") {
            "text" => {
                let text = block.get("text").and_then(Value::as_str).unwrap_or("");
                if row_type != "user" || !injected_context(text) {
                    result.push(RawEvent {
                        kind: if row_type == "user" {
                            "user_message"
                        } else {
                            "assistant_message"
                        },
                        role: if row_type == "user" {
                            "user"
                        } else {
                            "assistant"
                        },
                        text: text.into(),
                        timestamp: timestamp.clone(),
                        tool: None,
                        call_id: None,
                        redacted: false,
                        is_error: false,
                    });
                } else {
                    result.push(RawEvent::omission("runtime_or_system_context"));
                }
            }
            "thinking" | "reasoning" => {
                result.push(RawEvent::omission("private_reasoning_omitted"))
            }
            "tool_use" if row_type == "assistant" => result.push(RawEvent {
                kind: "tool_call",
                role: "assistant",
                text: block
                    .get("input")
                    .map(json_text)
                    .unwrap_or_else(|| "{}".into()),
                timestamp: timestamp.clone(),
                tool: Some(
                    block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .into(),
                ),
                call_id: first_string(block, &["id", "callId", "call_id"]),
                redacted: false,
                is_error: false,
            }),
            "tool_result" if row_type == "user" => result.push(RawEvent {
                kind: "tool_result",
                role: "user",
                text: block.get("content").map(json_text).unwrap_or_default(),
                timestamp: timestamp.clone(),
                tool: None,
                call_id: first_string(block, &["tool_use_id", "toolCallId", "call_id"]),
                redacted: false,
                is_error: block
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
            _ => result.push(RawEvent::omission("unsupported_message_block")),
        }
    }
    if result.is_empty() {
        result.push(RawEvent::omission("empty_message_blocks"));
    }
    result
}

fn adapt_codex(object: &Value) -> Vec<RawEvent> {
    let Some(map) = object.as_object() else {
        return Vec::new();
    };
    if map.get("type").and_then(Value::as_str) != Some("response_item") {
        return Vec::new();
    }
    let Some(payload) = map.get("payload").and_then(Value::as_object) else {
        return vec![RawEvent::omission("missing_codex_payload")];
    };
    let timestamp = map
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_string);
    match payload.get("type").and_then(Value::as_str).unwrap_or("") {
        "message" => {
            let role = payload.get("role").and_then(Value::as_str).unwrap_or("");
            if role != "user" && role != "assistant" {
                return vec![RawEvent::omission("system_or_runtime_message")];
            }
            if payload.get("channel").and_then(Value::as_str) == Some("analysis")
                || payload.get("phase").and_then(Value::as_str) == Some("analysis")
            {
                return vec![RawEvent::omission("private_reasoning_omitted")];
            }
            let text = codex_text(payload.get("content").unwrap_or(&Value::Null));
            if role == "user" && injected_context(&text) {
                return vec![RawEvent::omission("runtime_or_system_context")];
            }
            vec![RawEvent {
                kind: if role == "user" {
                    "user_message"
                } else {
                    "assistant_message"
                },
                role: if role == "user" { "user" } else { "assistant" },
                text,
                timestamp,
                tool: None,
                call_id: None,
                redacted: false,
                is_error: false,
            }]
        }
        "function_call" | "custom_tool_call" => vec![RawEvent {
            kind: "tool_call",
            role: "assistant",
            text: payload
                .get("arguments")
                .or_else(|| payload.get("input"))
                .map(json_text)
                .unwrap_or_default(),
            timestamp,
            tool: Some(
                payload
                    .get("name")
                    .or_else(|| payload.get("tool_name"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .into(),
            ),
            call_id: first_string(payload, &["call_id", "callId"]),
            redacted: false,
            is_error: false,
        }],
        "function_call_output" | "custom_tool_call_output" => vec![RawEvent {
            kind: "tool_result",
            role: "user",
            text: payload
                .get("output")
                .or_else(|| payload.get("content"))
                .map(json_text)
                .unwrap_or_default(),
            timestamp,
            tool: None,
            call_id: first_string(payload, &["call_id", "callId"]),
            redacted: false,
            is_error: payload
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }],
        "reasoning" => vec![RawEvent::omission("private_reasoning_omitted")],
        "event_msg" => vec![RawEvent::omission("runtime_event_omitted")],
        _ => vec![RawEvent::omission("unsupported_codex_payload")],
    }
}

impl RawEvent {
    fn omission(reason: &'static str) -> Self {
        Self {
            kind: "omission",
            role: "system",
            text: reason.into(),
            timestamp: None,
            tool: None,
            call_id: None,
            redacted: false,
            is_error: false,
        }
    }
}

fn json_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn codex_text(value: &Value) -> String {
    match value {
        Value::String(text) => strip_codex_control(text),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                let object = item.as_object()?;
                match object.get("type").and_then(Value::as_str) {
                    Some("input_text") | Some("output_text") | Some("text") => object
                        .get("text")
                        .and_then(Value::as_str)
                        .map(strip_codex_control),
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn strip_codex_control(text: &str) -> String {
    static CONTROL: OnceLock<Regex> = OnceLock::new();
    static IMAGE: OnceLock<Regex> = OnceLock::new();
    let control = CONTROL.get_or_init(|| {
        Regex::new(r"(?s)<(?:subagent_notification|codex_internal_context|codex_delegation|turn_aborted|heartbeat)(?:\s[^>]*)?>.*?</(?:subagent_notification|codex_internal_context|codex_delegation|turn_aborted|heartbeat)>").unwrap()
    });
    let image = IMAGE.get_or_init(|| Regex::new(r"</?image\b[^>]*>?").unwrap());
    image
        .replace_all(&control.replace_all(text, ""), "")
        .into_owned()
}

fn injected_context(text: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "# AGENTS.md instructions",
        "# CLAUDE.md instructions",
        "# Context from my IDE setup:",
        "# Files mentioned by the user",
        "<environment_context",
        "<permissions instructions",
        "<recommended_plugins",
        "<summary>",
        "<command-name",
        "<command-message",
        "<local-command-stdout",
        "<task-notification",
        "[Request interrupted",
    ];
    let value = text.trim_start();
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

fn classify(kind: &str, tool: Option<&str>, text: &str, is_error: bool) -> String {
    let folded_tool = tool.unwrap_or_default().to_ascii_lowercase();
    let folded_text = text.to_ascii_lowercase();
    if kind == "tool_result"
        && (is_error
            || folded_text.contains("error")
            || folded_text.contains("enoent")
            || folded_text.contains("failed"))
    {
        return "unresolved_failure".into();
    }
    if kind == "tool_call" {
        if [
            "todowrite",
            "updateplan",
            "creategoal",
            "create_thread",
            "send_message",
            "apply_patch",
        ]
        .iter()
        .any(|token| folded_tool.contains(token))
        {
            return "decision_or_constraint".into();
        }
        if [
            "write", "edit", "create", "delete", "remove", "patch", "move", "rename", "deploy",
            "publish", "install", "commit", "push", "merge",
        ]
        .iter()
        .any(|token| folded_tool.contains(token))
        {
            return "mutation".into();
        }
    }
    if kind == "user_message"
        && [
            "fix ",
            "implement ",
            "add ",
            "build ",
            "create ",
            "ensure ",
            "can you",
        ]
        .iter()
        .any(|prefix| folded_text.starts_with(prefix))
    {
        return "open_user_request".into();
    }
    if (kind == "user_message" || kind == "assistant_message")
        && (folded_text.starts_with("decision:")
            || folded_text.starts_with("constraint:")
            || folded_text.starts_with("invariant:")
            || folded_text.contains("never use ")
            || folded_text.contains("always use "))
    {
        return "decision_or_constraint".into();
    }
    "successful_readonly".into()
}

fn compact_text(value: &str) -> String {
    let mut text = redact(&value.replace('\0', ""));
    text = text.trim().to_string();
    if text.chars().count() > MAX_TEXT_CHARS {
        text = text.chars().take(MAX_TEXT_CHARS).collect::<String>() + "\n[TRUNCATED]";
    }
    text
}

fn redact(value: &str) -> String {
    static PATTERNS: OnceLock<Vec<(Regex, bool)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b").unwrap(), false),
            (
                Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").unwrap(),
                false,
            ),
            (
                Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").unwrap(),
                false,
            ),
            (Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(), false),
            (
                Regex::new(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b").unwrap(),
                false,
            ),
            (
                Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
                false,
            ),
            (
                Regex::new(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
                    .unwrap(),
                false,
            ),
            (
                Regex::new(r"(?i)\b(password|passphrase|api[_-]?key|secret|token)\s*[:=]\s*\S{6,}")
                    .unwrap(),
                false,
            ),
            (
                Regex::new(
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                )
                .unwrap(),
                true,
            ),
        ]
    });
    let mut result = value.to_string();
    for (pattern, binary) in patterns {
        result = pattern
            .replace_all(
                &result,
                if *binary {
                    "[BINARY_BLOB_REMOVED]"
                } else {
                    "[REDACTED]"
                },
            )
            .into_owned();
    }
    // Donor redaction also removes unlabelled base64-like blobs. Preserve
    // their non-base64 anchor so surrounding prose remains intact.
    static BASE64_BLOB: OnceLock<Regex> = OnceLock::new();
    let pattern = BASE64_BLOB
        .get_or_init(|| Regex::new(r#"(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{512,}={0,2})"#).unwrap());
    result = pattern
        .replace_all(&result, "${1}[BINARY_BLOB_REMOVED]")
        .into_owned();
    result
}

fn source_ref(path: &Path, row: u64, start: u64, end: u64) -> String {
    format!("{}#row={row};bytes={start}..{end}", path.display())
}

fn omission(
    path: &Path,
    row: u64,
    start: u64,
    end: u64,
    source_hash: &str,
    reason: &str,
    recoverable: bool,
) -> ContinuityOmission {
    let source_ref = source_ref(path, row, start, end);
    let id = format!(
        "omit_{}",
        short_hash(&format!("{source_hash}:{source_ref}:{reason}"))
    );
    ContinuityOmission {
        id,
        reason: reason.into(),
        source_ref: source_ref.clone(),
        source_hash: source_hash.into(),
        provenance: format!("legion.continuity:omission:{source_ref}"),
        recoverable,
    }
}

fn omission_reason(platform: Platform, value: &Value) -> &'static str {
    let row_type = value.get("type").and_then(Value::as_str).unwrap_or("");
    match platform {
        Platform::Claude if row_type == "user" || row_type == "assistant" => "unsupported_row",
        Platform::Codex if row_type == "response_item" => "unsupported_row",
        _ => "unsupported_row",
    }
}

fn event_id(
    source_hash: &str,
    row: u64,
    block: u64,
    sequence: u64,
    kind: &str,
    text: &str,
) -> String {
    let hash = short_hash(&format!(
        "{source_hash}:{row}:{block}:{sequence}:{kind}:{text}"
    ));
    format!("evt_{hash}")
}

fn short_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..32].to_string()
}

fn normalize_hash(value: &str) -> Result<String, String> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("sha256 must be 64 hexadecimal characters".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn path_within(candidate: &str, root: &str) -> bool {
    let candidate = normalized_path(candidate);
    let root = normalized_path(root);
    if root.is_empty() {
        return false;
    }
    candidate == root
        || candidate
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn normalized_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_lowercase()
}
