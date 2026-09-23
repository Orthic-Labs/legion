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

fn validate_limits(name: &str, limits: Option<ProfileLimits>) -> Result<ProfileLimits, KernelError> {
    let limits = limits.ok_or_else(|| policy_error(format!("profile limits missing for {name}")))?;
    if limits.max_packet_tasks < 1 {
        return Err(policy_error(format!("{name}.maxPacketTasks must be a positive integer")));
    }
    if limits.max_concurrency < 1 {
        return Err(policy_error(format!("{name}.maxConcurrency must be a positive integer")));
    }
    if limits.max_mutation_concurrency < 1 {
        return Err(policy_error(format!("{name}.maxMutationConcurrency must be a positive integer")));
    }
    if limits.max_mutation_concurrency > limits.max_concurrency {
        return Err(policy_error("mutation concurrency cannot exceed total concurrency"));
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
pub fn load_model_profile(name: &str, policy: impl Fn(&str) -> Option<ProfileLimits>) -> Result<ModelProfile, KernelError> {
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
    if requested_by.map(|r| r.eq_ignore_ascii_case("model")).unwrap_or(false) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_model_profile_returns_default_limits() {
        let profile = load_model_profile("standard", default_profile_policy).unwrap();
        assert_eq!(profile.limits.max_concurrency, 2);
        assert_eq!(profile.assigned_by, "qualification-policy");
    }

    #[test]
    fn load_model_profile_rejects_unknown_name() {
        let error = load_model_profile("bogus", default_profile_policy).unwrap_err();
        assert_eq!(error.category, "policy");
    }

    #[test]
    fn validate_limits_rejects_mutation_concurrency_over_total() {
        let bad_policy = |name: &str| {
            if name == "strict" {
                Some(ProfileLimits {
                    max_packet_tasks: 1,
                    max_concurrency: 1,
                    max_mutation_concurrency: 2,
                    allow_read_only_parallel: false,
                    allow_worker_spawn: false,
                })
            } else {
                default_profile_policy(name)
            }
        };
        let error = load_model_profile("strict", bad_policy).unwrap_err();
        assert_eq!(error.category, "policy");
    }

    #[test]
    fn downgrade_model_profile_steps_down_one_tier() {
        let profile = load_model_profile("advanced", default_profile_policy).unwrap();
        let downgraded = downgrade_model_profile(&profile, "budget exceeded", None, default_profile_policy).unwrap();
        assert_eq!(downgraded.name, "standard");
        assert_eq!(downgraded.downgrade.unwrap()["from"], "advanced");
    }

    #[test]
    fn downgrade_model_profile_floors_at_strict() {
        let profile = load_model_profile("strict", default_profile_policy).unwrap();
        let downgraded = downgrade_model_profile(&profile, "budget exceeded", None, default_profile_policy).unwrap();
        assert_eq!(downgraded.name, "strict");
    }

    #[test]
    fn downgrade_model_profile_rejects_model_requested_change() {
        let profile = load_model_profile("advanced", default_profile_policy).unwrap();
        let error = downgrade_model_profile(&profile, "reason", Some("model"), default_profile_policy).unwrap_err();
        assert_eq!(error.code, "AUTHORITY_DENIED");
    }

    #[test]
    fn downgrade_model_profile_rejects_empty_reason() {
        let profile = load_model_profile("advanced", default_profile_policy).unwrap();
        let error = downgrade_model_profile(&profile, "   ", None, default_profile_policy).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
    }
}
