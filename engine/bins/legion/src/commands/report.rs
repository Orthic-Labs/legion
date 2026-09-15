use super::{CommandError, CommandResult};
use clap::Args;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Args)]
pub struct ReportArgs {
    pub report: PathBuf,
    #[arg(long, default_value = "json")]
    pub format: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub async fn run(args: ReportArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let report_path = if args.report.is_absolute() {
        args.report.clone()
    } else {
        std::env::current_dir().map_err(super::io_error)?.join(&args.report)
    };
    let bytes = std::fs::read(&report_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CommandError::internal(format!(
                "Error: ENOENT: no such file or directory, open '{}'",
                report_path.display()
            ))
        } else {
            super::io_error(error)
        }
    })?;
    let report: legion_contracts::ReportV1 = serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
    report
        .validate()
        .map_err(|error| CommandError::policy(error.to_string()))?;
    let rendered = match args.format.as_str() {
        "json" => legion_report::render_json(&report),
        "sarif" => legion_report::render_sarif(&report),
        "markdown" | "md" => legion_report::render_markdown(&report),
        "html" => legion_report::render_html(&report),
        format => {
            return Err(CommandError::usage(format!(
                "unsupported report format: {format}"
            )))
        }
    }
    .map_err(super::io_error)?;
    if let Some(path) = &args.out {
        std::fs::write(path, rendered.as_bytes()).map_err(super::io_error)?;
        Ok(
            serde_json::json!({"schemaVersion":1,"kind":"legion-report","format":args.format,"path":args.report,"out":path,"status":"complete","__silent":true}),
        )
    } else {
        Ok(serde_json::json!({"__raw": rendered}))
    }
}
