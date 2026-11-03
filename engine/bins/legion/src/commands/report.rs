use super::{CommandError, CommandResult};
use clap::Args;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[arg(value_name = "REPORT")]
    pub report_path: PathBuf,
    #[arg(long = "report", default_value = "audit")]
    pub report_kind: String,
    #[arg(long, default_value = "json")]
    pub format: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub async fn run(args: ReportArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    if matches!(args.report_kind.as_str(), "trend" | "debt") {
        let format = projection_format(&args)?;
        let root = super::audit_assurance::store_root(&absolute(&args.report_path)?)?;
        let rendered = if args.report_kind == "trend" {
            super::audit_assurance::trend_projection(&root, format)?
        } else {
            super::audit_assurance::debt_projection(&root, format)?
        };
        return emit(&args, rendered);
    }
    let report_path = if args.report_path.is_absolute() {
        args.report_path.clone()
    } else {
        std::env::current_dir()
            .map_err(super::io_error)?
            .join(&args.report_path)
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
    // Any supported schema (ADR-8): v1 reads as a v2 view with legacy-unknown
    // confidence. JSON keeps the schema the file was written in; the other
    // renderers consume the v1 core of the view.
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
    let view = rightkit_evidence_contracts::Report::read_any(&value)
        .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
    let report = view.v1_core();
    report
        .validate()
        .map_err(|error| CommandError::policy(error.to_string()))?;
    let source_schema = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let rendered = match (args.report_kind.as_str(), args.format.as_str()) {
        ("audit", "json") if source_schema == 2 => rightkit_evidence_report::render_json_schema(&view, 2),
        ("audit", "json") => {
            let original: rightkit_evidence_contracts::ReportV1 = serde_json::from_value(value.clone())
                .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
            rightkit_evidence_report::render_json(&original)
        }
        ("audit", "sarif") => rightkit_evidence_report::render_sarif(&report),
        ("audit", "markdown" | "md") => rightkit_evidence_report::render_markdown(&report),
        ("audit", "html") => rightkit_evidence_report::render_html(&report),
        ("review", "markdown" | "md") => rightkit_evidence_report::render_review(&view),
        ("review", "github-review") if args.out.is_some() => {
            rightkit_evidence_report::render_github_review(&view)
        }
        ("review", "github-review") => {
            return Err(CommandError::usage(
                "--format github-review requires --out; output is a file only",
            ));
        }
        ("ponytail", "markdown" | "md") => rightkit_evidence_report::render_ponytail(&view),
        ("assurance", _) => {
            let format = projection_format(&args)?;
            return emit(
                &args,
                super::audit_assurance::assurance_projection(&view, format)?,
            );
        }
        ("audit" | "review" | "ponytail", format) => {
            return Err(CommandError::usage(format!(
                "unsupported report/format combination: --report {} --format {format}",
                args.report_kind
            )));
        }
        (kind, _) => {
            return Err(CommandError::usage(format!(
                "unsupported report type: {kind}; expected audit, review, ponytail, assurance, trend, or debt"
            )));
        }
    }
    .map_err(super::io_error)?;
    emit(&args, rendered)
}

fn absolute(path: &std::path::Path) -> Result<PathBuf, CommandError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().map_err(super::io_error)?.join(path))
    }
}

/// Projections accept only json and markdown.
fn projection_format(args: &ReportArgs) -> Result<&'static str, CommandError> {
    match args.format.as_str() {
        "json" => Ok("json"),
        "markdown" | "md" => Ok("markdown"),
        format => Err(CommandError::usage(format!(
            "unsupported report/format combination: --report {} --format {format}",
            args.report_kind
        ))),
    }
}

fn emit(args: &ReportArgs, rendered: String) -> CommandResult {
    if let Some(path) = &args.out {
        std::fs::write(path, rendered.as_bytes()).map_err(super::io_error)?;
        Ok(
            serde_json::json!({"schemaVersion":1,"kind":"legion-report","report":args.report_kind,"format":args.format,"path":args.report_path,"out":path,"status":"complete","__silent":true}),
        )
    } else {
        Ok(serde_json::json!({"__raw": rendered}))
    }
}
