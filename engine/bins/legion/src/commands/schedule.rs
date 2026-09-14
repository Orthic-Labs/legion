use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct ScheduleArgs {
    #[arg(long = "trigger-id")]
    pub trigger_id: Option<String>,
    #[arg(long)]
    pub workflow: Option<String>,
    #[arg(long, default_value = ".legion/triggers")]
    pub state_root: PathBuf,
    #[arg(long, default_value = "schedule")]
    pub source: String,
    #[arg(long)]
    pub payload_digest: Option<String>,
    #[arg(long)]
    pub plan: Option<PathBuf>,
    #[arg(long)]
    pub run: Option<PathBuf>,
    #[arg(long)]
    pub trigger: Option<PathBuf>,
    #[arg(long, default_value = "json")]
    pub format: String,
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: ScheduleArgs) -> CommandResult {
    if let Some(path) = args.trigger.clone() {
        return enqueue_artifact(path);
    }
    if args.plan.is_some() && args.run.is_some() {
        return Err(CommandError::usage("schedule accepts one canonical plan or run artifact"));
    }
    if let Some(path) = args.plan.as_ref().or(args.run.as_ref()) {
        let artifact: Value = serde_json::from_slice(&std::fs::read(&path).map_err(|e| CommandError::usage(format!("invalid schedule artifact: {e}")))?)
            .map_err(|e| CommandError::usage(format!("invalid schedule artifact: {e}")))?;
        let schedule = artifact.get("scheduleReceipt").or_else(|| artifact.get("execution").and_then(|v| v.get("scheduleReceipt"))).or_else(|| artifact.get("schedule"))
            .ok_or_else(|| CommandError::usage("artifact has no canonical schedule receipt"))?;
        if !schedule.get("waves").is_some_and(Value::is_array) { return Err(CommandError::usage("artifact has no canonical schedule receipt")); }
        return Ok(json!({"__raw": render_schedule(schedule, &args.format)?}));
    }
    let (Some(trigger_id), Some(workflow)) = (args.trigger_id, args.workflow) else {
        return Err(CommandError::usage("schedule requires --plan, --run or --trigger"));
    };
    if trigger_id.trim().is_empty() || workflow.trim().is_empty() { return Err(CommandError::usage("schedule requires non-empty --trigger-id and --workflow")); }
    let state = persist_legacy(&args.state_root, &trigger_id, &workflow, &args.source, args.payload_digest.as_deref())?;
    Ok(json!({"schemaVersion":1,"kind":"legion-trigger-enqueue","status":"complete","triggerId":trigger_id,"workflow":workflow,"source":args.source,"deduplicated":state.0,"queueReceipt":state.1,"workflowState":if state.0 {"already-started"} else {"started"},"json":args.json}))
}

fn render_schedule(input: &Value, format: &str) -> Result<String, CommandError> {
    let mut value = input.clone();
    let waves = value.get_mut("waves").and_then(Value::as_array_mut).ok_or_else(|| CommandError::usage("artifact has no canonical schedule receipt"))?;
    for wave in waves.iter_mut() { if let Some(items) = wave.as_array_mut() { items.sort_by(|a,b| a.as_str().cmp(&b.as_str())); } }
    match format {
        "json" => Ok(format!("{}\n", serde_json::to_string(&value).map_err(|e| CommandError::internal(e.to_string()))?)),
        "mermaid" => { let mut out = String::from("flowchart LR\n"); for (i,w) in waves.iter().enumerate() { for id in w.as_array().into_iter().flatten().filter_map(Value::as_str) { out.push_str(&format!("  W{i} --> {id}\n")); } } Ok(out) }
        "text" => Ok(waves.iter().enumerate().map(|(i,w)| format!("wave {i}: {}", w.as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))).collect::<Vec<_>>().join("\n") + "\n"),
        _ => Err(CommandError::usage("unknown schedule format")),
    }
}

fn enqueue_artifact(path: PathBuf) -> CommandResult {
    let trigger: Value = serde_json::from_slice(&std::fs::read(&path).map_err(|e| CommandError::usage(format!("invalid trigger artifact: {e}")))?)
        .map_err(|e| CommandError::usage(format!("invalid trigger artifact: {e}")))?;
    let required = ["triggerId", "type", "source", "target", "idempotencyKey"];
    for key in required { if !trigger.get(key).is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty())) { return Err(CommandError::usage(format!("invalid trigger artifact: trigger {key} is required"))); } }
    if !trigger.get("runArgs").is_some_and(Value::is_array) { return Err(CommandError::usage("invalid trigger artifact: trigger runArgs are required to start target workflow")); }
    let root = Path::new(".audit").join("arcane").join("triggers"); std::fs::create_dir_all(&root).map_err(super::io_error)?;
    let file = root.join("triggers.json");
    let mut state: Value = if file.is_file() { serde_json::from_slice(&std::fs::read(&file).map_err(super::io_error)?).map_err(|e| CommandError::usage(e.to_string()))? } else { json!({"schemaVersion":1,"triggers":[]}) };
    if let Some(existing) = state["triggers"].as_array().and_then(|xs| xs.iter().find(|x| x.get("idempotencyKey") == trigger.get("idempotencyKey"))) { let mut out = existing.clone(); out["deduplicated"] = json!(true); return Ok(out); }
    let mut receipt = trigger; receipt["schemaVersion"] = json!(1); receipt["kind"] = json!("legion-trigger-receipt"); receipt["state"] = json!("ENQUEUED"); receipt["deduplicated"] = json!(false);
    receipt["receivedAt"] = json!(format!("{}Z", unix_seconds()));
    state["triggers"].as_array_mut().unwrap().push(receipt.clone());
    let temp = file.with_extension("json.tmp"); std::fs::write(&temp, serde_json::to_vec(&state).unwrap()).map_err(super::io_error)?; std::fs::rename(&temp, &file).map_err(super::io_error)?; Ok(receipt)
}

fn unix_seconds() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn persist_legacy(root: &Path, id: &str, workflow: &str, source: &str, digest: Option<&str>) -> Result<(bool, PathBuf), CommandError> {
    std::fs::create_dir_all(root).map_err(super::io_error)?; let safe = id.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-'|'_') { c } else { '_' }).collect::<String>(); let path = root.join(format!("{safe}.json"));
    if path.exists() { return Ok((true, path)); }
    let value = json!({"schemaVersion":1,"kind":"legion-trigger-receipt","triggerId":id,"workflow":workflow,"source":source,"payloadDigest":digest,"state":"started"}); std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).map_err(super::io_error)?; Ok((false,path))
}
