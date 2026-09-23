//! Port of `src/integrations/forges.mjs`, `src/integrations/{azure-devops,bitbucket,gitlab}/index.mjs`,
//! `src/integrations/github-action/index.mjs`, and `src/integrations/mcp/install.mjs`.
//!
//! Forge CI adapters invoke a preinstalled native Legion command and only
//! translate each forge provider's job/artifact shape. Provisioning, policy,
//! routing, capability, workflow, receipt, and report semantics belong to
//! Legion core.

use serde::Serialize;
use serde_json::{json, Value};

/// Mirrors `gitlabCiAdapter({ jobName, profile, baseline })`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GitlabCiAdapter {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "jobName")]
    pub job_name: String,
    pub script: Vec<String>,
    pub artifacts: Value,
    #[serde(rename = "canonicalCli")]
    pub canonical_cli: bool,
}

pub fn gitlab_ci_adapter(job_name: Option<&str>, profile: Option<&str>, baseline: Option<&str>) -> GitlabCiAdapter {
    let job_name = job_name.unwrap_or("legion-audit").to_string();
    let profile = profile.unwrap_or("standard");
    let baseline_flag = baseline
        .map(|b| format!(" --baseline {b}"))
        .unwrap_or_default();
    GitlabCiAdapter {
        schema_version: 1,
        kind: "legion-gitlab-ci-adapter".to_string(),
        job_name,
        script: vec![format!(
            "legion audit . --profile {profile}{baseline_flag} --out .audit"
        )],
        artifacts: json!({ "reports": { "sarif": ".audit/report.sarif" }, "paths": [".audit/"] }),
        canonical_cli: true,
    }
}

/// Mirrors `bitbucketAdapter({ pipelineName, profile })`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BitbucketAdapter {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "pipelineName")]
    pub pipeline_name: String,
    pub steps: Value,
    pub artifacts: Value,
    #[serde(rename = "canonicalCli")]
    pub canonical_cli: bool,
}

pub fn bitbucket_adapter(pipeline_name: Option<&str>, profile: Option<&str>) -> BitbucketAdapter {
    let pipeline_name = pipeline_name.unwrap_or("legion-audit").to_string();
    let profile = profile.unwrap_or("standard");
    BitbucketAdapter {
        schema_version: 1,
        kind: "legion-bitbucket-adapter".to_string(),
        pipeline_name,
        steps: json!([
            { "step": { "name": "Legion audit", "script": [format!("legion audit . --profile {profile} --out .audit")] } }
        ]),
        artifacts: json!({ "downloads": [".audit/report.sarif"] }),
        canonical_cli: true,
    }
}

/// Mirrors `azureDevopsAdapter({ pipelineName, profile })`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AzureDevopsAdapter {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    #[serde(rename = "pipelineName")]
    pub pipeline_name: String,
    pub steps: Value,
    #[serde(rename = "canonicalCli")]
    pub canonical_cli: bool,
}

pub fn azure_devops_adapter(pipeline_name: Option<&str>, profile: Option<&str>) -> AzureDevopsAdapter {
    let pipeline_name = pipeline_name.unwrap_or("legion-audit").to_string();
    let profile = profile.unwrap_or("standard");
    AzureDevopsAdapter {
        schema_version: 1,
        kind: "legion-azure-devops-adapter".to_string(),
        pipeline_name,
        steps: json!([
            { "script": format!("legion audit . --profile {profile} --out .audit"), "displayName": "Run legion audit" },
            { "task": "PublishPipelineArtifact@1", "inputs": { "path": ".audit", "artifact": "legion" } }
        ]),
        canonical_cli: true,
    }
}

/// Mirrors `actionSummary({ report, scoped, runDir })` from
/// `src/integrations/github-action/index.mjs`.
pub fn action_summary(report: &Value, scoped: &Value, run_dir: &str) -> Value {
    let empty = json!([]);
    let introduced = scoped.get("introduced").unwrap_or(&empty).as_array().cloned().unwrap_or_default();
    let existing_count = scoped
        .get("existing")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let coverage_gaps = report
        .get("coverage_gaps")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let comment_ids: Vec<Value> = introduced
        .iter()
        .map(|finding| {
            finding
                .get("fingerprint")
                .cloned()
                .or_else(|| finding.get("id").cloned())
                .unwrap_or(Value::Null)
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-github-action-summary",
        "runDir": run_dir,
        "auditStatus": report.get("audit_status").cloned().unwrap_or(Value::Null),
        "qualityGate": report.get("quality_gate").cloned().unwrap_or(Value::Null),
        "introducedCount": introduced.len(),
        "existingCount": existing_count,
        "coverageGaps": coverage_gaps,
        "commentIds": comment_ids,
    })
}

/// Mirrors `sarifUploadCommand({ sarifPath, githubToken })`.
pub fn sarif_upload_command(sarif_path: &str, github_token: Option<&str>) -> Value {
    let env = match github_token {
        Some(token) if !token.is_empty() => json!({ "GH_TOKEN": token }),
        _ => json!({}),
    };
    json!({
        "executable": "gh",
        "args": ["api", "repos/{owner}/{repo}/code-scanning/sarifs", "-f", format!("sarif=@{sarif_path}")],
        "env": env,
    })
}

/// Mirrors `mcpInstallConfig({ command, args })` from
/// `src/integrations/mcp/install.mjs`.
pub fn mcp_install_config(command: Option<&str>, args: Option<&[&str]>) -> Value {
    let command = command.unwrap_or("legion");
    let args: Vec<&str> = args.map(|a| a.to_vec()).unwrap_or_else(|| vec!["serve", "--stdio"]);
    json!({
        "mcpServers": {
            "legion": { "command": command, "args": args }
        }
    })
}

/// Mirrors `installPreview({ host, config })`.
pub fn install_preview(host: &str, config: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-mcp-install-preview",
        "host": host,
        "wouldWrite": format!("{host} MCP client config"),
        "config": config,
        "dryRun": true,
    })
}
