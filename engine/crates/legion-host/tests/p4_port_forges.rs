use legion_host::p4_port::{
    action_summary, azure_devops_adapter, bitbucket_adapter, gitlab_ci_adapter, install_preview,
    mcp_install_config, sarif_upload_command,
};
use serde_json::json;

#[test]
fn gitlab_ci_adapter_defaults() {
    let a = gitlab_ci_adapter(None, None, None);
    assert_eq!(a.job_name, "legion-audit");
    assert_eq!(
        a.script,
        vec!["legion audit . --profile standard --out .audit".to_string()]
    );
    assert!(a.canonical_cli);
}

#[test]
fn gitlab_ci_adapter_with_baseline() {
    let a = gitlab_ci_adapter(Some("custom-job"), Some("deep"), Some("main"));
    assert_eq!(a.job_name, "custom-job");
    assert_eq!(
        a.script,
        vec!["legion audit . --profile deep --baseline main --out .audit".to_string()]
    );
}

#[test]
fn bitbucket_adapter_defaults() {
    let a = bitbucket_adapter(None, None);
    assert_eq!(a.pipeline_name, "legion-audit");
    assert_eq!(a.kind, "legion-bitbucket-adapter");
}

#[test]
fn azure_devops_adapter_defaults() {
    let a = azure_devops_adapter(None, None);
    assert_eq!(a.pipeline_name, "legion-audit");
    assert_eq!(a.kind, "legion-azure-devops-adapter");
}

#[test]
fn action_summary_matches_js_shape() {
    let report = json!({
        "audit_status": "pass",
        "quality_gate": "ok",
        "coverage_gaps": [1, 2],
    });
    let scoped = json!({
        "introduced": [{"fingerprint": "fp1"}, {"id": "id2"}],
        "existing": [{}, {}, {}],
    });
    let out = action_summary(&report, &scoped, "/tmp/run");
    assert_eq!(out["schemaVersion"], 1);
    assert_eq!(out["kind"], "legion-github-action-summary");
    assert_eq!(out["runDir"], "/tmp/run");
    assert_eq!(out["auditStatus"], "pass");
    assert_eq!(out["qualityGate"], "ok");
    assert_eq!(out["introducedCount"], 2);
    assert_eq!(out["existingCount"], 3);
    assert_eq!(out["coverageGaps"], 2);
    assert_eq!(out["commentIds"], json!(["fp1", "id2"]));
}

#[test]
fn action_summary_handles_missing_fields() {
    let out = action_summary(&json!({}), &json!({}), "run");
    assert_eq!(out["auditStatus"], json!(null));
    assert_eq!(out["introducedCount"], 0);
    assert_eq!(out["existingCount"], 0);
    assert_eq!(out["coverageGaps"], 0);
    assert_eq!(out["commentIds"], json!([]));
}

#[test]
fn sarif_upload_command_with_token() {
    let out = sarif_upload_command("out.sarif", Some("tok"));
    assert_eq!(out["executable"], "gh");
    assert_eq!(
        out["args"],
        json!(["api", "repos/{owner}/{repo}/code-scanning/sarifs", "-f", "sarif=@out.sarif"])
    );
    assert_eq!(out["env"], json!({"GH_TOKEN": "tok"}));
}

#[test]
fn sarif_upload_command_without_token() {
    let out = sarif_upload_command("out.sarif", None);
    assert_eq!(out["env"], json!({}));
}

#[test]
fn mcp_install_config_defaults() {
    let out = mcp_install_config(None, None);
    assert_eq!(
        out,
        json!({"mcpServers": {"legion": {"command": "legion", "args": ["serve", "--stdio"]}}})
    );
}

#[test]
fn install_preview_shape() {
    let cfg = mcp_install_config(None, None);
    let out = install_preview("claude-desktop", cfg.clone());
    assert_eq!(out["schemaVersion"], 1);
    assert_eq!(out["kind"], "legion-mcp-install-preview");
    assert_eq!(out["host"], "claude-desktop");
    assert_eq!(out["wouldWrite"], "claude-desktop MCP client config");
    assert_eq!(out["config"], cfg);
    assert_eq!(out["dryRun"], true);
}
