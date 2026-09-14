use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = common_argv(&args);
    let mut run_dir: Option<PathBuf> = None;
    let mut id: Option<String> = None;
    let mut index = 0;
    while index < argv.len() {
        match argv[index].as_str() {
            "--run" => {
                index += 1;
                run_dir = argv
                    .get(index)
                    .map(|value| PathBuf::from(value))
                    .filter(|path| !path.as_os_str().is_empty());
                if run_dir.is_none() {
                    return Err(CommandError::usage("explain --run requires a directory"));
                }
            }
            value if !value.starts_with('-') && id.is_none() => id = Some(value.to_owned()),
            _ => {}
        }
        index += 1;
    }
    let id = id.ok_or_else(|| {
        CommandError::usage("explain requires a finding or gap id")
    })?;
    let source = run_dir.as_deref().and_then(load_run_source);
    let findings = source
        .as_ref()
        .and_then(|value| value.get("findings"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let gaps = source
        .as_ref()
        .and_then(|value| value.get("coverage_gaps"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let finding = findings.iter().find(|item| matches_id(item, &id));
    let gap = gaps.iter().find(|item| matches_gap(item, &id));
    let found = finding.is_some() || gap.is_some();
    let detail = if let Some(finding) = finding {
        let title = finding
            .get("title")
            .or_else(|| finding.get("ruleId"))
            .and_then(Value::as_str)
            .unwrap_or("finding");
        let body = finding
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        format!("{title} — {body} (severity {severity})")
    } else if let Some(gap) = gap {
        let kind = gap.get("kind").and_then(Value::as_str).unwrap_or("gap");
        format!(
            "coverage gap {kind}: {}",
            gap.get("detail")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "{}".into())
        )
    } else {
        format!(
            "no finding or gap with id {id} in {}",
            run_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "no run supplied".into())
        )
    };
    let explanation = json!({
        "schemaVersion": 1,
        "kind": "legion-explain",
        "id": id,
        "found": found,
        "finding": finding.cloned().unwrap_or(Value::Null),
        "gap": gap.cloned().unwrap_or(Value::Null),
        "detail": detail,
    });
    Ok(explanation)
}

fn load_run_source(run_dir: &Path) -> Option<Value> {
    let report = run_dir.join("report.json");
    if let Ok(bytes) = std::fs::read(&report) {
        return serde_json::from_slice(&bytes).ok();
    }
    let facts = run_dir.join("facts.json");
    std::fs::read(&facts)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn matches_id(item: &Value, id: &str) -> bool {
    item.get("id").and_then(Value::as_str) == Some(id)
        || item.get("ruleId").and_then(Value::as_str) == Some(id)
}

fn matches_gap(item: &Value, id: &str) -> bool {
    item.get("kind").and_then(Value::as_str) == Some(id)
}

fn common_argv(args: &CommonArgs) -> Vec<String> {
    args.args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect()
}
