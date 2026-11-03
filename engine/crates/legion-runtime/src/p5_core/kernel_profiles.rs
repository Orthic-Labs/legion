//! Ported from src/packages/kernel/lib/profiles.mjs (packet P5d).

use legion_catalog::json::{self, Value};

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

const ORDER: &[&str] = &["strict", "standard", "advanced"];
const WORKER_PROFILES: &[&str] = &["strict", "standard", "advanced"];

fn policy_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("policy".to_string()),
            ..Default::default()
        },
    )
}

/// Port of `ProfileLimits` shape carried by `DEFAULT_PROFILE_POLICY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileLimits {
    pub max_packet_tasks: u32,
    pub max_concurrency: u32,
    pub max_mutation_concurrency: u32,
    pub allow_read_only_parallel: bool,
    pub allow_worker_spawn: bool,
}

/// Port of `DEFAULT_PROFILE_POLICY`.
pub fn default_profile_policy(name: &str) -> Option<ProfileLimits> {
    Some(match name {
        "strict" => ProfileLimits {
            max_packet_tasks: 1,
            max_concurrency: 1,
            max_mutation_concurrency: 1,
            allow_read_only_parallel: false,
            allow_worker_spawn: false,
        },
        "standard" => ProfileLimits {
            max_packet_tasks: 4,
            max_concurrency: 2,
            max_mutation_concurrency: 1,
            allow_read_only_parallel: true,
            allow_worker_spawn: false,
        },
        "advanced" => ProfileLimits {
            max_packet_tasks: 8,
            max_concurrency: 4,
            max_mutation_concurrency: 4,
            allow_read_only_parallel: true,
            allow_worker_spawn: true,
        },
        _ => return None,
    })
}

#[allow(clippy::result_large_err)]
fn validate_limits(
    name: &str,
    limits: Option<ProfileLimits>,
) -> Result<ProfileLimits, KernelError> {
    let limits =
        limits.ok_or_else(|| policy_error(format!("profile limits missing for {name}")))?;
    if limits.max_packet_tasks < 1 {
        return Err(policy_error(format!(
            "{name}.maxPacketTasks must be a positive integer"
        )));
    }
    if limits.max_concurrency < 1 {
        return Err(policy_error(format!(
            "{name}.maxConcurrency must be a positive integer"
        )));
    }
    if limits.max_mutation_concurrency < 1 {
        return Err(policy_error(format!(
            "{name}.maxMutationConcurrency must be a positive integer"
        )));
    }
    if limits.max_mutation_concurrency > limits.max_concurrency {
        return Err(policy_error(
            "mutation concurrency cannot exceed total concurrency",
        ));
    }
    Ok(limits)
}

#[derive(Debug, Clone)]
pub struct ModelProfile {
    pub name: String,
    pub limits: ProfileLimits,
    pub assigned_by: String,
    pub downgrade: Option<Value>,
}

/// Port of `loadModelProfile(name, policy = DEFAULT_PROFILE_POLICY)`.
#[allow(clippy::result_large_err)]
pub fn load_model_profile(
    name: &str,
    policy: impl Fn(&str) -> Option<ProfileLimits>,
) -> Result<ModelProfile, KernelError> {
    if !WORKER_PROFILES.contains(&name) {
        return Err(policy_error(format!("unknown worker profile: {name}")));
    }
    let limits = validate_limits(name, policy(name))?;
    Ok(ModelProfile {
        name: name.to_string(),
        limits,
        assigned_by: "qualification-policy".to_string(),
        downgrade: None,
    })
}

/// Port of `downgradeModelProfile(profile, reason, options)`.
#[allow(clippy::result_large_err)]
pub fn downgrade_model_profile(
    profile: &ModelProfile,
    reason: &str,
    requested_by: Option<&str>,
    policy: impl Fn(&str) -> Option<ProfileLimits>,
) -> Result<ModelProfile, KernelError> {
    if reason.trim().is_empty() {
        return Err(KernelError::new(
            "INVALID_ARGUMENT",
            "profile downgrade reason is required",
            KernelErrorOptions {
                category: Some("usage".to_string()),
                ..Default::default()
            },
        ));
    }
    if requested_by
        .map(|r| r.eq_ignore_ascii_case("model"))
        .unwrap_or(false)
    {
        return Err(KernelError::new(
            "AUTHORITY_DENIED",
            "model-requested profile changes are forbidden",
            KernelErrorOptions {
                category: Some("authority".to_string()),
                ..Default::default()
            },
        ));
    }
    let current = load_model_profile(&profile.name, &policy)?;
    let index = ORDER.iter().position(|n| *n == current.name).unwrap_or(0);
    let downgraded_name = ORDER[index.saturating_sub(1)];
    let mut downgraded = load_model_profile(downgraded_name, &policy)?;
    downgraded.downgrade = Some(json::json!({
        "from": current.name,
        "reason": reason,
        "source": requested_by.unwrap_or("qualification-policy"),
    }));
    Ok(downgraded)
}
