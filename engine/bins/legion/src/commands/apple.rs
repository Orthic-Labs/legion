use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::{fs::File, io::Read, path::PathBuf};
use tokio_util::sync::CancellationToken;

/// `legion apple catalog` describes operations. Both CLI & MCP use the same
/// Rust operation contracts; input never becomes a shell command.
#[derive(Debug, Args)]
pub struct AppleArgs {
    #[arg(default_value = "catalog")]
    pub operation: String,
    /// JSON arguments for the selected operation.
    #[arg(long, conflicts_with = "input_file")]
    pub input: Option<String>,
    /// Read JSON arguments from a bounded UTF-8 file.
    #[arg(long)]
    pub input_file: Option<PathBuf>,
    /// Execute a planned process/API operation within host-authorized scope.
    #[arg(long)]
    pub execute: bool,
    /// Host policy context; never an independent authorization grant.
    #[arg(long)]
    pub policy_context: Option<String>,
}

fn parse_input(args: &AppleArgs) -> Result<Value, CommandError> {
    const LIMIT: u64 = 1024 * 1024;
    let raw = match (&args.input, &args.input_file) {
        (Some(raw), None) if raw.len() <= LIMIT as usize => raw.clone(),
        (None, Some(path)) => {
            let file =
                File::open(path).map_err(|e| CommandError::usage(format!("Apple input: {e}")))?;
            if !file
                .metadata()
                .map_err(|e| CommandError::usage(e.to_string()))?
                .is_file()
            {
                return Err(CommandError::usage("Apple input must be a regular file"));
            }
            let mut text = String::new();
            file.take(LIMIT + 1)
                .read_to_string(&mut text)
                .map_err(|e| CommandError::usage(format!("Apple input: {e}")))?;
            if text.len() > LIMIT as usize {
                return Err(CommandError::usage("Apple input exceeds 1 MiB"));
            }
            text
        }
        (None, None) => "{}".into(),
        _ => {
            return Err(CommandError::usage(
                "provide at most 1 MiB through --input or --input-file",
            ))
        }
    };
    let mut value: Value = serde_json::from_str(&raw)
        .map_err(|e| CommandError::usage(format!("invalid Apple JSON input: {e}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| CommandError::usage("Apple input must be a JSON object"))?;
    if args.execute {
        object.insert("execute".into(), Value::Bool(true));
    }
    Ok(value)
}

pub async fn run(args: AppleArgs, cancellation: CancellationToken) -> CommandResult {
    let arguments = parse_input(&args)?;
    let policy_context = args
        .policy_context
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()
        .map_err(|e| CommandError::usage(format!("invalid Apple policy context: {e}")))?;
    // Host effect validation is shared with the MCP entrypoint.
    let request = json!({
        "operation": args.operation,
        "arguments": arguments,
        "policyContext": policy_context
    });
    let result = tokio::select! {
        _ = cancellation.cancelled() => return Err(CommandError::cancelled()),
        result = crate::apple_mcp::invoke(&request) => result,
    };
    let mut value = result.map_err(|e| CommandError::incomplete(e.to_string()))?;
    if value.get("success").and_then(Value::as_bool) == Some(false)
        || value.get("ok").and_then(Value::as_bool) == Some(false)
    {
        value["valid"] = Value::Bool(false);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(input: &str) -> AppleArgs {
        AppleArgs {
            operation: "catalog".into(),
            input: Some(input.into()),
            input_file: None,
            execute: false,
            policy_context: None,
        }
    }
    #[test]
    fn input_is_structured_and_explicit_execution_is_preserved() {
        assert!(parse_input(&args("[]")).is_err());
        assert!(parse_input(&args("{broken")).is_err());
        let mut input = args(r#"{"execute":false}"#);
        input.execute = true;
        assert_eq!(parse_input(&input).unwrap()["execute"], true);
    }
}
