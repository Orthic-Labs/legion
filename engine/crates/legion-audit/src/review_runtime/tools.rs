//! Snapshot-only context tools behind RightKit's allowlist. No shell or live FS.
use crate::{
    native_providers::reasoning::excerpts::redact_lines,
    native_providers::reasoning::ReasoningInvocation,
    snapshot::{FrozenSnapshot, SnapshotSide},
};
use rightkit_agent_tools::{CallCtx, Caller, Effect, Tool, ToolError, ToolSpec, Toolbox};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_REPLY_BYTES: usize = 32 * 1024;
const MAX_LINES: usize = 256;
const MAX_SCAN_FILES: usize = 128;
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const CALLER: &str = "legion-audit-review";
const MAX_EAGER_FILES: usize = 4;
const MAX_EAGER_SOURCE_BYTES: usize = 8 * 1024;
const NAMES: &[&str] = &[
    "audit.read_file",
    "audit.search_code",
    "audit.list_files",
    "audit.read_diff",
    "audit.find_callers",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextRequest {
    pub tool: String,
    pub arguments: Value,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Args {
    path: Option<String>,
    side: Option<String>,
    start_line: Option<usize>,
    end_line: Option<usize>,
    query: Option<String>,
    prefix: Option<String>,
    offset: Option<usize>,
}

pub struct ContextTools {
    toolbox: Toolbox,
}
fn specifications() -> Vec<ToolSpec> {
    let mut specs = NAMES.iter().map(|name| ToolSpec::new(*name, "Bounded secret-redacted immutable source context; find_callers is lexical evidence, not a semantic call graph", Effect::Observe, json!({"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"side":{"type":"string","enum":["selected","base"]},"startLine":{"type":"integer"},"endLine":{"type":"integer"},"query":{"type":"string"},"prefix":{"type":"string"},"offset":{"type":"integer"}}}))).collect::<Vec<_>>();
    // Match RightKit Toolbox's BTreeMap registry order.
    specs.sort_by(|left, right| left.name.cmp(&right.name));
    specs
}
pub(super) fn specs() -> Value {
    let registered = specifications();
    let mut common = json!(&registered[0]);
    common.as_object_mut().unwrap().remove("name");
    let names = registered
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<Vec<_>>();
    // Each listed name inherits this exact descriptor. Registration still
    // receives full ToolSpecs; only model-visible duplicate text is shared.
    json!({"common":common,"names":names})
}
fn skeleton_targets<'a>(packet: &'a Value, denominator: &[String]) -> BTreeSet<(&'a str, &'a str)> {
    let selected: BTreeSet<_> = denominator.iter().map(String::as_str).collect();
    packet["excerpts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|excerpt| {
            if excerpt["mode"] != "skeleton" {
                return None;
            }
            let path = excerpt["path"]
                .as_str()
                .filter(|path| selected.contains(path))?;
            let side = excerpt["sourceSide"].as_str().unwrap_or("selected");
            matches!(side, "selected" | "base").then_some((path, side))
        })
        .collect()
}
impl ContextTools {
    pub fn new(snapshot: FrozenSnapshot) -> Result<Self, String> {
        let snapshot = Arc::new(snapshot);
        let mut toolbox = Toolbox::new();
        for spec in specifications() {
            toolbox
                .register(Arc::new(SnapshotTool {
                    snapshot: snapshot.clone(),
                    spec,
                }))
                .map_err(|error| error.to_string())?;
        }
        toolbox.allow(CALLER, NAMES.iter().copied());
        Ok(Self { toolbox })
    }
    pub fn call(&self, request: ContextRequest) -> Value {
        self.call_within(request, MAX_REPLY_BYTES)
    }

    /// Like `call`, but the whole serialized reply is also held to `max_bytes`
    /// (the caller's remaining physical request envelope). Whole records are
    /// dropped and the reply is marked truncated, so the shortfall stays a
    /// visible coverage gap; `resumeStartLine` says where paging can continue.
    pub fn call_within(&self, request: ContextRequest, max_bytes: usize) -> Value {
        bounded_reply_within(
            match self
                .toolbox
                .call(&Caller::new(CALLER), &request.tool, request.arguments)
            {
                Ok(value) => value,
                Err(error) => json!({"denied":true,"error":error.to_value(),"truncated":false}),
            },
            max_bytes,
        )
    }

    /// Front-load only small, already-selected skeleton files through the
    /// same redacting read tool available to the reviewer. This is optional
    /// context, never a replacement for the signed packet or its denominator.
    pub(super) fn eager_skeleton_context(
        &self,
        request: &ReasoningInvocation,
        snapshot: &FrozenSnapshot,
    ) -> Value {
        let wanted = skeleton_targets(&request.packet, &request.denominator_paths);
        let mut source_bytes = 0usize;
        let mut deliveries = Vec::new();
        for (path, side) in wanted {
            if deliveries.len() >= MAX_EAGER_FILES {
                break;
            }
            let files = if side == "base" {
                &snapshot.manifest.base_files
            } else {
                &snapshot.manifest.files
            };
            let Some(file) = files.get(path) else {
                continue;
            };
            if source_bytes.saturating_add(file.bytes) > MAX_EAGER_SOURCE_BYTES {
                continue;
            }
            let call = json!({"tool":"audit.read_file","arguments":{"path":path,"side":side,"startLine":1,"endLine":MAX_LINES}});
            let reply = self.call(ContextRequest {
                tool: "audit.read_file".into(),
                arguments: call["arguments"].clone(),
            });
            let row = json!({"toolRequest":call,"hostToolReply":reply});
            deliveries.push(row);
            // Bound the whole context envelope, preserving whole tool replies.
            if json!({"deliveries":&deliveries}).to_string().len() > MAX_REPLY_BYTES - 1024 {
                deliveries.pop();
                break;
            }
            source_bytes += file.bytes;
        }
        json!({"source":"host-eager-snapshot-context","sourceBytes":source_bytes,"deliveries":deliveries})
    }
}

struct SnapshotTool {
    snapshot: Arc<FrozenSnapshot>,
    spec: ToolSpec,
}
fn denied(message: impl Into<String>) -> ToolError {
    ToolError::new("audit_context_denied", message)
}
fn side(args: &Args) -> Result<SnapshotSide, ToolError> {
    match args.side.as_deref().unwrap_or("selected") {
        "selected" => Ok(SnapshotSide::Selected),
        "base" => Ok(SnapshotSide::Base),
        _ => Err(denied("invalid snapshot side")),
    }
}
fn redacted(
    snapshot: &FrozenSnapshot,
    path: &str,
    selected: SnapshotSide,
) -> Result<Vec<Value>, ToolError> {
    let bytes = snapshot
        .read(path, selected, MAX_FILE_BYTES)
        .map_err(|error| denied(error.to_string()))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| denied("binary/non-UTF8 source unavailable"))?;
    Ok(redact_lines(text)
        .into_iter()
        .map(|line| json!({"startLine":line.start,"endLine":line.end,"text":line.text}))
        .collect())
}
fn append_bounded(rows: &mut Vec<Value>, row: Value, used: &mut usize) -> bool {
    let bytes = row.to_string().len();
    if used.saturating_add(bytes) > MAX_REPLY_BYTES - 2048 || rows.len() >= MAX_LINES {
        return false;
    }
    *used += bytes;
    rows.push(row);
    true
}
// Bound the complete serialized envelope, including metadata & unavailable-path
// diagnostics. Whole records are removed; no source line is silently sliced.
/// Smallest reply cap the physical-envelope clamp will request; below it the
/// caller must stop instead of receiving a metadata-only reply.
pub(super) const MIN_CLAMPED_REPLY_BYTES: usize = 1024;
pub(super) fn bounded_reply_within(mut reply: Value, max_bytes: usize) -> Value {
    let cap = max_bytes.min(MAX_REPLY_BYTES);
    reply
        .as_object_mut()
        .map(|object| object.remove("replyDigest"));
    // 100 bytes: digest; 48 more: resume hint added after trimming.
    while reply.to_string().len() + 148 > cap {
        reply["truncated"] = json!(true);
        reply["envelopeTruncated"] = json!(true);
        let removed = reply
            .get_mut("gaps")
            .and_then(Value::as_array_mut)
            .and_then(Vec::pop)
            .is_some()
            || reply
                .get_mut("rows")
                .and_then(Value::as_array_mut)
                .and_then(Vec::pop)
                .is_some();
        if !removed {
            reply = json!({"denied":true,"truncated":true,"envelopeTruncated":true,"gaps":["context reply metadata exceeds byte cap"]});
            break;
        }
    }
    if reply["envelopeTruncated"] == true {
        let resume = reply["rows"]
            .as_array()
            .and_then(|rows| rows.last())
            .and_then(|row| row.pointer("/source/endLine"))
            .and_then(Value::as_u64)
            .filter(|_| {
                matches!(
                    reply["tool"].as_str(),
                    Some("audit.read_file" | "audit.read_diff")
                )
            });
        if let Some(line) = resume {
            reply["resumeStartLine"] = json!(line + 1);
        }
    }
    if let Ok(digest) = legion_contracts::canonical_digest(&reply) {
        reply["replyDigest"] = json!(digest);
    }
    reply
}
impl Tool for SnapshotTool {
    fn spec(&self) -> &ToolSpec {
        &self.spec
    }
    fn call(&self, ctx: &CallCtx, value: Value) -> Result<Value, ToolError> {
        let args: Args =
            serde_json::from_value(value).map_err(|error| denied(error.to_string()))?;
        let selected = side(&args)?;
        let files = match selected {
            SnapshotSide::Selected => &self.snapshot.manifest.files,
            SnapshotSide::Base => &self.snapshot.manifest.base_files,
        };
        let started = Instant::now();
        let mut rows = Vec::new();
        let mut used = 0;
        let mut truncated = false;
        let mut next_offset = None;
        let mut gaps = BTreeSet::new();
        match self.spec.name.as_str() {
            "audit.read_file" | "audit.read_diff" => {
                let path = args
                    .path
                    .as_deref()
                    .ok_or_else(|| denied("path required"))?;
                let start = args.start_line.unwrap_or(1);
                let end = args.end_line.unwrap_or(start.saturating_add(MAX_LINES - 1));
                if start == 0 || end < start || end - start >= MAX_LINES {
                    return Err(denied("request at most256 source lines"));
                }
                let sides = if self.spec.name == "audit.read_diff" {
                    vec![
                        ("base", SnapshotSide::Base),
                        ("selected", SnapshotSide::Selected),
                    ]
                } else {
                    vec![(args.side.as_deref().unwrap_or("selected"), selected)]
                };
                for (label, selected) in sides {
                    match redacted(&self.snapshot, path, selected) {
                        Ok(lines) => {
                            let total = lines
                                .last()
                                .and_then(|line| line["endLine"].as_u64())
                                .unwrap_or(0);
                            for line in lines.into_iter().filter(|line| {
                                line["endLine"].as_u64().unwrap_or(0) >= start as u64
                                    && line["startLine"].as_u64().unwrap_or(u64::MAX) <= end as u64
                            }) {
                                if !append_bounded(
                                    &mut rows,
                                    json!({"path":path,"side":label,"source":line}),
                                    &mut used,
                                ) {
                                    truncated = true;
                                    break;
                                }
                            }
                            truncated |= total > end as u64;
                        }
                        Err(error) if self.spec.name == "audit.read_diff" => {
                            gaps.insert(format!("{label}:{}", error.code));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            "audit.list_files" | "audit.search_code" | "audit.find_callers" => {
                let offset = args.offset.unwrap_or(0);
                let prefix = args.prefix.as_deref().unwrap_or("");
                if prefix.len() > 1024 {
                    return Err(denied("prefix too long"));
                }
                let query = args.query.as_deref().unwrap_or("");
                if self.spec.name != "audit.list_files" && (query.is_empty() || query.len() > 256) {
                    return Err(denied("literal query requires1..256 bytes"));
                }
                let mut scanned_bytes = 0usize;
                let paths: Vec<_> = files
                    .iter()
                    .filter(|(path, _)| path.starts_with(prefix))
                    .collect();
                for (index, (path, metadata)) in paths.iter().enumerate().skip(offset) {
                    if ctx.cancel.is_cancelled() {
                        return Err(denied("context call cancelled"));
                    }
                    if index - offset >= MAX_SCAN_FILES
                        || scanned_bytes.saturating_add(metadata.bytes) > MAX_SCAN_BYTES
                        || started.elapsed() > Duration::from_secs(2)
                    {
                        truncated = true;
                        next_offset = Some(index);
                        break;
                    }
                    if self.spec.name == "audit.list_files" {
                        if !append_bounded(
                            &mut rows,
                            json!({"path":path,"digest":metadata.digest,"bytes":metadata.bytes}),
                            &mut used,
                        ) {
                            truncated = true;
                            next_offset = Some(index);
                            break;
                        }
                        continue;
                    }
                    scanned_bytes += metadata.bytes;
                    match redacted(&self.snapshot, path, selected) {
                        Ok(lines) => {
                            for line in lines.into_iter().filter(|line| {
                                line["text"]
                                    .as_str()
                                    .is_some_and(|text| text.contains(query))
                            }) {
                                if !append_bounded(
                                    &mut rows,
                                    json!({"path":path,"side":args.side.as_deref().unwrap_or("selected"),"source":line}),
                                    &mut used,
                                ) {
                                    truncated = true;
                                    next_offset = Some(index);
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            gaps.insert(format!("unavailable:{path}"));
                        }
                    }
                    if truncated {
                        break;
                    }
                }
            }
            _ => return Err(denied("tool outside context allowlist")),
        }
        let mut reply = json!({"snapshotKey":self.snapshot.manifest.key,"tool":self.spec.name,"rows":rows,"truncated":truncated,"nextOffset":next_offset,"gaps":gaps,"semanticCallGraph":false});
        let digest = legion_contracts::canonical_digest(&reply)
            .map_err(|error| denied(error.to_string()))?;
        reply["replyDigest"] = json!(digest);
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_model_specs_reconstruct_every_registered_tool_exactly() {
        let encoded = specs();
        let names = encoded["names"].as_array().unwrap();
        let common = encoded["common"].as_object().unwrap();
        assert!(!common.contains_key("name"));
        let reconstructed = names
            .iter()
            .map(|name| {
                let mut descriptor = common.clone();
                descriptor.insert("name".into(), name.clone());
                Value::Object(descriptor)
            })
            .collect::<Vec<_>>();
        // Full serialized equality verifies every name's description, effect
        // & input schema, including registration order & all schema fields.
        let registered = json!(specifications());
        assert_eq!(Value::Array(reconstructed), registered);
        assert_eq!(names.len(), 5);
        assert!(encoded.to_string().len() < registered.to_string().len());
    }
    #[test]
    fn eager_source_never_expands_selected_paths_or_source_side_authority() {
        let packet = json!({"excerpts":[
            {"path":"selected.py","mode":"skeleton","sourceSide":"selected"},
            {"path":"deleted.py","mode":"skeleton","sourceSide":"base"},
            {"path":"unselected.py","mode":"skeleton"},
            {"path":"raw.py","mode":"raw"},
            {"path":"invalid.py","mode":"skeleton","sourceSide":"live"}
        ]});
        let denominator = ["selected.py", "deleted.py", "raw.py", "invalid.py"].map(str::to_owned);
        assert_eq!(
            skeleton_targets(&packet, &denominator),
            BTreeSet::from([("selected.py", "selected"), ("deleted.py", "base")])
        );
    }
    #[test]
    fn strict_arguments_reject_unadvertised_authority() {
        assert!(serde_json::from_value::<Args>(json!({"path":"x","shell":"cat x"})).is_err());
        assert!(serde_json::from_value::<ContextRequest>(
            json!({"tool":"audit.read_file","arguments":{},"command":"x"})
        )
        .is_err());
    }
    #[test]
    fn reply_bound_keeps_whole_source_rows() {
        let mut rows = Vec::new();
        let mut bytes = 0;
        assert!(!append_bounded(
            &mut rows,
            json!({"text":"x".repeat(MAX_REPLY_BYTES)}),
            &mut bytes
        ));
        assert!(rows.is_empty());
        assert_eq!(bytes, 0);
    }
    #[test]
    fn reply_bound_includes_long_unavailable_paths_and_metadata() {
        let reply = bounded_reply_within(
            json!({"rows":[],"gaps":(0..128).map(|index| format!("unavailable:{index}:{}", "x".repeat(1024))).collect::<Vec<_>>(),"snapshotKey":"s","truncated":false}),
            MAX_REPLY_BYTES,
        );
        assert!(reply.to_string().len() <= MAX_REPLY_BYTES);
        assert_eq!(reply["truncated"], true);
        assert_eq!(reply["envelopeTruncated"], true);
        assert!(reply["replyDigest"].is_string());
        let metadata =
            bounded_reply_within(json!({"snapshotKey":"x".repeat(MAX_REPLY_BYTES),"rows":[],"gaps":[]}), MAX_REPLY_BYTES);
        assert!(metadata.to_string().len() <= MAX_REPLY_BYTES);
    }
}
