use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::EffectError;

pub const REQUEST_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ToolOrigin {
    System,
    TargetProject,
    LegionOwned,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Sensitivity {
    Public,
    Internal,
    Restricted,
    Secret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReceipt {
    pub id: String,
    pub network: bool,
    pub filesystem_scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedRequest {
    pub executable: String,
    pub args: Vec<String>,
    pub environment_names: Vec<String>,
    pub redacted_argument_indexes: BTreeSet<usize>,
    pub redacted_environment_names: BTreeSet<String>,
}

/// Typed request submitted by providers. It intentionally contains no shell command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalToolRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub provider_id: String,
    pub plan_id: String,
    pub policy_id: String,
    pub task_id: Option<String>,
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub origin: ToolOrigin,
    pub shell: bool,
    pub expected_digest: Option<String>,
    pub version_args: Vec<String>,
    pub version_requirement: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub environment_allowlist: BTreeSet<String>,
    pub sensitive_argument_indexes: BTreeSet<usize>,
    pub sensitive_environment_names: BTreeSet<String>,
    pub requires_network_sandbox: bool,
    pub sandbox: Option<SandboxReceipt>,
    pub timeout_ms: u64,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}

impl Default for ExternalToolRequest {
    fn default() -> Self {
        Self {
            schema_version: REQUEST_SCHEMA_VERSION,
            request_id: String::new(),
            provider_id: String::new(),
            plan_id: String::new(),
            policy_id: String::new(),
            task_id: None,
            executable: String::new(),
            args: Vec::new(),
            cwd: String::new(),
            origin: ToolOrigin::TargetProject,
            shell: false,
            expected_digest: None,
            version_args: vec!["--version".into()],
            version_requirement: None,
            environment: BTreeMap::new(),
            environment_allowlist: BTreeSet::new(),
            sensitive_argument_indexes: BTreeSet::new(),
            sensitive_environment_names: BTreeSet::new(),
            requires_network_sandbox: false,
            sandbox: None,
            timeout_ms: 120_000,
            stdout_limit: 8 * 1024 * 1024,
            stderr_limit: 8 * 1024 * 1024,
        }
    }
}

impl ExternalToolRequest {
    pub fn validate(&self) -> Result<(), EffectError> {
        if self.schema_version != REQUEST_SCHEMA_VERSION {
            return Err(EffectError::InvalidRequest(
                "unsupported schema version".into(),
            ));
        }
        for (name, value) in [
            ("request_id", &self.request_id),
            ("provider_id", &self.provider_id),
            ("plan_id", &self.plan_id),
            ("policy_id", &self.policy_id),
            ("executable", &self.executable),
            ("cwd", &self.cwd),
        ] {
            if value.trim().is_empty() {
                return Err(EffectError::InvalidRequest(format!(
                    "{name} must be non-empty"
                )));
            }
        }
        if self.shell {
            return Err(EffectError::UnauthorizedEffect(
                "shell execution is forbidden".into(),
            ));
        }
        if self
            .args
            .iter()
            .chain(self.version_args.iter())
            .any(|arg| arg.contains('\0'))
        {
            return Err(EffectError::InvalidRequest(
                "arguments may not contain NUL".into(),
            ));
        }
        if self.timeout_ms == 0 || self.stdout_limit == 0 || self.stderr_limit == 0 {
            return Err(EffectError::InvalidRequest(
                "limits must be positive".into(),
            ));
        }
        if !Path::new(&self.cwd).is_absolute() {
            return Err(EffectError::InvalidRequest(
                "cwd must be absolute before execution".into(),
            ));
        }
        if self.origin == ToolOrigin::LegionOwned && Self::is_runtime_tool(&self.executable) {
            return Err(EffectError::UnauthorizedEffect(
                "Legion-owned runtime execution is forbidden".into(),
            ));
        }
        Ok(())
    }

    fn is_runtime_tool(value: &str) -> bool {
        let name = Path::new(value)
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or(value)
            .to_ascii_lowercase();
        [
            "node",
            "nodejs",
            "python",
            "python3",
            "sh",
            "bash",
            "zsh",
            "pwsh",
            "powershell",
            "npm",
            "npx",
            "pip",
            "pip3",
        ]
        .iter()
        .any(|item| name == *item || name.starts_with(&format!("{item}.")))
    }

    pub fn redacted(&self) -> RedactedRequest {
        let args = self
            .args
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if self.sensitive_argument_indexes.contains(&index) {
                    "[REDACTED]".into()
                } else {
                    value.clone()
                }
            })
            .collect();
        let environment_names = self.environment.keys().cloned().collect::<Vec<_>>();
        RedactedRequest {
            executable: self.executable.clone(),
            args,
            environment_names,
            redacted_argument_indexes: self.sensitive_argument_indexes.clone(),
            redacted_environment_names: self.sensitive_environment_names.clone(),
        }
    }
}
