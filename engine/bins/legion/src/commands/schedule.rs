use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct ScheduleArgs {
    #[arg(long)]
    pub plan: Option<PathBuf>,
    #[arg(long)]
    pub run: Option<PathBuf>,
    #[arg(long)]
    pub trigger: Option<PathBuf>,
    #[arg(long, default_value = "json")]
    pub format: String,
}

pub fn run(args: ScheduleArgs) -> CommandResult {
    if let Some(path) = args.trigger { return enqueue_artifact(path); }
    if args.plan.is_some() && args.run.is_some() { return Err(CommandError::usage("schedule accepts one canonical plan or run artifact")); }
    let Some(path) = args.plan.as_ref().or(args.run.as_ref()) else { return Err(CommandError::usage("schedule requires --plan, --run or --trigger")); };
    let artifact: Value = serde_json::from_slice(&read_schedule_artifact(path)?)
        .map_err(|error| CommandError::usage(format!("invalid schedule artifact: {error}")))?;
    let schedule = artifact.get("scheduleReceipt")
        .or_else(|| artifact.get("execution").and_then(|value| value.get("scheduleReceipt")))
        .or_else(|| artifact.get("schedule"))
        .filter(|value| value.get("waves").is_some_and(Value::is_array))
        .ok_or_else(|| CommandError::usage("artifact has no canonical schedule receipt"))?;
    Ok(json!({"__raw": render_schedule(schedule, &args.format)?}))
}

fn read_schedule_artifact(path: &Path) -> Result<Vec<u8>, CommandError> {
    std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            let absolute = std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf());
            return CommandError::usage(format!(
                "invalid schedule artifact: ENOENT: no such file or directory, open '{}'",
                absolute.display()
            ));
        }
        CommandError::usage(format!("invalid schedule artifact: {error}"))
    })
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries { sorted.insert(key, canonicalize(value)); }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

fn render_schedule(input: &Value, format: &str) -> Result<String, CommandError> {
    if !matches!(format, "json" | "text" | "mermaid") { return Err(CommandError::usage("unknown schedule option: --format")); }
    let mut value = input.clone();
    let waves = value.get_mut("waves").and_then(Value::as_array_mut).ok_or_else(|| CommandError::usage("artifact has no canonical schedule receipt"))?;
    for wave in waves.iter_mut() { if let Some(items) = wave.as_array_mut() { items.sort_by(|left, right| left.as_str().cmp(&right.as_str())); } }
    match format {
        "json" => Ok(format!("{}\n", serde_json::to_string(&canonicalize(value)).map_err(|error| CommandError::internal(error.to_string()))?)),
        "mermaid" => {
            let mut out = String::from("flowchart LR\n");
            for (index, wave) in waves.iter().enumerate() { for id in wave.as_array().into_iter().flatten().filter_map(Value::as_str) { out.push_str(&format!("  W{index} --> {id}\n")); } }
            out.push('\n'); Ok(out)
        }
        "text" => Ok(waves.iter().enumerate().map(|(index, wave)| format!("wave {index}: {}", wave.as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))).collect::<Vec<_>>().join("\n") + "\n"),
        _ => unreachable!(),
    }
}

fn enqueue_artifact(path: PathBuf) -> CommandResult {
    let trigger: Value = serde_json::from_slice(&std::fs::read(&path).map_err(|error| CommandError::usage(format!("invalid trigger artifact: {error}")))?)
        .map_err(|error| CommandError::usage(format!("invalid trigger artifact: {error}")))?;
    for key in ["triggerId", "type", "source", "target", "idempotencyKey"] {
        if !trigger.get(key).is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty())) { return Err(CommandError::usage(format!("invalid trigger artifact: trigger {key} is required"))); }
    }
    let root = Path::new(".audit").join("arcane").join("triggers");
    let mut store = TriggerStore::load(root)?;
    let idempotency = trigger["idempotencyKey"].as_str().unwrap();
    if let Some(existing) = store.state.get("triggers").and_then(Value::as_array).and_then(|entries| entries.iter().find(|entry| entry.get("idempotencyKey").and_then(Value::as_str) == Some(idempotency))) {
        let mut output = existing.clone(); output["deduplicated"] = json!(true); return Ok(output);
    }
    if !trigger.get("runArgs").is_some_and(Value::is_array) { return Err(CommandError::usage("invalid trigger artifact: trigger runArgs are required to start target workflow")); }
    let mut receipt = trigger;
    receipt["schemaVersion"] = json!(1); receipt["kind"] = json!("legion-trigger-receipt");
    receipt["receivedAt"] = receipt.get("receivedAt").filter(|value| !value.is_null()).cloned().unwrap_or_else(|| json!(iso_now()));
    receipt["state"] = json!("STARTED"); receipt["deduplicated"] = json!(false); receipt["startedAt"] = json!(iso_now()); receipt["startResult"] = json!({"exitCode": null});
    store.state.get_mut("triggers").and_then(Value::as_array_mut).expect("trigger store has triggers array").push(receipt.clone());
    store.write()?; Ok(receipt)
}

struct TriggerStore { root: PathBuf, state: Value }
impl TriggerStore {
    fn load(root: PathBuf) -> Result<Self, CommandError> {
        let path = root.join("triggers.json");
        let state = if path.is_file() { serde_json::from_slice(&std::fs::read(&path).map_err(super::io_error)?).map_err(|error| CommandError::usage(format!("invalid trigger artifact: {error}")))? } else { json!({"schemaVersion":1,"triggers":[]}) };
        if !state.get("triggers").is_some_and(Value::is_array) { return Err(CommandError::usage("invalid trigger artifact: trigger store has no triggers array")); }
        Ok(Self { root, state })
    }
    fn write(&self) -> Result<(), CommandError> {
        std::fs::create_dir_all(&self.root).map_err(super::io_error)?;
        let path = self.root.join("triggers.json"); let temporary = self.root.join(format!(".triggers-{}.tmp", std::process::id()));
        std::fs::write(&temporary, serde_json::to_vec(&self.state).map_err(super::io_error)?).map_err(super::io_error)?;
        std::fs::rename(&temporary, path).map_err(super::io_error)
    }
}

fn iso_now() -> String {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let seconds = elapsed.as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let year = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month + 2).div_euclid(5) + 1;
    let month = month + if month < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", day_seconds / 3_600, day_seconds % 3_600 / 60, day_seconds % 60, elapsed.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renderer_is_pure_and_canonicalizes_wave_members() {
        let input = json!({"z":1,"waves":[["b","a"]]});
        assert_eq!(render_schedule(&input, "json").unwrap(), "{\"waves\":[[\"a\",\"b\"]],\"z\":1}\n");
        assert_eq!(input["waves"][0], json!(["b","a"]));
    }
}
