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
    let view = legion_contracts::Report::read_any(&value)
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
        ("audit", "json") if source_schema == 2 => legion_report::render_json_schema(&view, 2),
        ("audit", "json") => {
            let original: legion_contracts::ReportV1 = serde_json::from_value(value.clone())
                .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
            legion_report::render_json(&original)
        }
        ("audit", "sarif") => legion_report::render_sarif(&report),
        ("audit", "markdown" | "md") => legion_report::render_markdown(&report),
        ("audit", "html") => legion_report::render_html(&report),
        ("review", "markdown" | "md") => legion_report::render_review(&view),
        ("review", "github-review") if args.out.is_some() => {
            legion_report::render_github_review(&view)
        }
        ("review", "github-review") => {
            return Err(CommandError::usage(
                "--format github-review requires --out; output is a file only",
            ));
        }
        ("ponytail", "markdown" | "md") => legion_report::render_ponytail(&view),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn github_review_writes_json_file_without_stdout_payload() {
        let unique = format!(
            "legion-report-github-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let temp_root = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = temp_root.join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("report.json");
        let output = root.join("review.json");
        std::fs::write(
            &input,
            r#"{"schema_version":2,"report_id":"review-1","status":"incomplete","findings":[{"id":"minimize-1","severity":"medium","title":"inline sole implementation","message":"wrapper only delegates","provider":"reasoning.minimize","locations":["src/lib.rs:2"],"evidence":{"lens":"minimize","ponytailTag":"yagni","action":"inline sole implementation","failureScenario":"wrapper only delegates","verifyStatus":"unverified"},"confidence":"likely","confidenceBasis":"anchored-tool-hit","anchor":{"path":"src/lib.rs","range":{"start":2,"end":2},"lineHash":"sha256:line","state":"in-diff"},"attribution":"unresolved","disposition":"executed"}],"gaps":["coverage:partial"],"claims":{},"targets":[],"scope":{"spec":"legacy-v1","head":"unknown"},"unresolvedPossible":0,"reasoningBudgetUsed":{"judgment":0,"specialist":0,"mechanical":0,"seats":0}}"#,
        )
        .unwrap();
        let result = run(
            ReportArgs {
                report_path: input,
                report_kind: "review".into(),
                format: "github-review".into(),
                out: Some(output.clone()),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(result["__silent"], true);
        let payload: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(payload["event"], "COMMENT");
        assert_eq!(payload["comments"].as_array().unwrap().len(), 1);
        assert_eq!(payload["comments"][0]["path"], "src/lib.rs");
        assert_eq!(payload["comments"][0]["line"], 2);
        let body = payload["comments"][0]["body"].as_str().unwrap();
        assert!(body.contains("Supplied fix: inline sole implementation"));
        assert!(body.contains("Case: wrapper only delegates"));
        assert!(body.contains("Confidence: `likely`"));
        assert!(!body.contains("proven"));
        assert!(!result.as_object().unwrap().contains_key("__raw"));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn args(kind: &str, format: &str, path: PathBuf) -> ReportArgs {
        ReportArgs {
            report_path: path,
            report_kind: kind.into(),
            format: format.into(),
            out: None,
        }
    }

    fn temp(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-report-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn assurance_projection_refuses_legacy_report_and_bad_format() {
        let root = temp("assurance");
        let input = root.join("report.json");
        std::fs::write(
            &input,
            r#"{"schema_version":1,"report_id":"legacy-1","status":"clean","findings":[],"gaps":[],"claims":{},"targets":[]}"#,
        )
        .unwrap();
        let error = run(
            args("assurance", "json", input.clone()),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, 2);
        assert!(error.message.contains("no auditAssuranceV1"));
        let error = run(
            args("assurance", "sarif", input.clone()),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, 4);
        // Legacy v1 round trip is unchanged.
        let value = run(args("audit", "json", input), CancellationToken::new())
            .await
            .unwrap();
        assert!(value["__raw"].as_str().unwrap().contains("legacy-1"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unknown_kind_lists_projection_kinds() {
        let root = temp("kind");
        let input = root.join("report.json");
        std::fs::write(
            &input,
            r#"{"schema_version":1,"report_id":"k-1","status":"clean","findings":[],"gaps":[],"claims":{},"targets":[]}"#,
        )
        .unwrap();
        let error = run(args("bogus", "json", input), CancellationToken::new())
            .await
            .unwrap_err();
        assert!(error.message.contains("assurance, trend, or debt"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn debt_projection_reports_markers_from_a_directory() {
        let root = temp("debt");
        std::fs::write(root.join("a.rs"), "// TODO: remove\nfn main() {}\n").unwrap();
        let value = run(args("debt", "json", root.clone()), CancellationToken::new())
            .await
            .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(value["__raw"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["kind"], "audit-debt-projection");
        std::fs::remove_dir_all(root).unwrap();
    }
}
