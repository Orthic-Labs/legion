//! Snapshot-only context tools behind RightKit's allowlist. No shell or live FS.
use crate::{
    native_providers::reasoning::excerpts::redact_lines,
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
impl ContextTools {
    pub fn new(snapshot: FrozenSnapshot) -> Result<Self, String> {
        let snapshot = Arc::new(snapshot);
        let mut toolbox = Toolbox::new();
        for name in NAMES {
            toolbox.register(Arc::new(SnapshotTool { snapshot: snapshot.clone(), spec: ToolSpec::new(*name, "Bounded secret-redacted immutable source context; find_callers is lexical evidence, not a semantic call graph", Effect::Observe, json!({"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"side":{"type":"string","enum":["selected","base"]},"startLine":{"type":"integer"},"endLine":{"type":"integer"},"query":{"type":"string"},"prefix":{"type":"string"},"offset":{"type":"integer"}}})) })).map_err(|error| error.to_string())?;
        }
        toolbox.allow(CALLER, NAMES.iter().copied());
        Ok(Self { toolbox })
    }
    pub fn specs(&self) -> Value {
        serde_json::to_value(self.toolbox.list_for(CALLER)).unwrap_or(Value::Null)
    }
    pub fn call(&self, request: ContextRequest) -> Value {
        bounded_reply(
            match self
                .toolbox
                .call(&Caller::new(CALLER), &request.tool, request.arguments)
            {
                Ok(value) => value,
                Err(error) => json!({"denied":true,"error":error.to_value(),"truncated":false}),
            },
        )
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
fn bounded_reply(mut reply: Value) -> Value {
    reply
        .as_object_mut()
        .map(|object| object.remove("replyDigest"));
    while reply.to_string().len() + 100 > MAX_REPLY_BYTES {
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
        let reply = bounded_reply(
            json!({"rows":[],"gaps":(0..128).map(|index| format!("unavailable:{index}:{}", "x".repeat(1024))).collect::<Vec<_>>(),"snapshotKey":"s","truncated":false}),
        );
        assert!(reply.to_string().len() <= MAX_REPLY_BYTES);
        assert_eq!(reply["truncated"], true);
        assert_eq!(reply["envelopeTruncated"], true);
        assert!(reply["replyDigest"].is_string());
        let metadata =
            bounded_reply(json!({"snapshotKey":"x".repeat(MAX_REPLY_BYTES),"rows":[],"gaps":[]}));
        assert!(metadata.to_string().len() <= MAX_REPLY_BYTES);
    }
}
