use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    canonical_digest,
    id::{AgentId, RequestId, TaskId},
    require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum EffectClass {
    FILE_WRITE,
    FILE_DELETE,
    FILE_MOVE,
    COMMAND_EXEC,
    NETWORK_EGRESS,
    PROCESS_SPAWN,
    CREDENTIAL_ACCESS,
    DEPENDENCY_INSTALL,
    VCS_COMMIT,
    VCS_PUSH,
    PUBLISH,
    /// A write, send, or delete *positively identified* through an MCP
    /// tool's name or operation. This is intentionally distinct from
    /// ordinary filesystem/network classes so the Guard can keep the newly
    /// covered external-tool surface denied by the canonical default policy.
    EXTERNAL_SIDE_EFFECT,
    /// MCP tool lacking a positive classification signal. Kept distinct from
    /// `EXTERNAL_SIDE_EFFECT` so receipts report observed uncertainty truthfully.
    /// Canonical policy denies this class by default: unknown tools fail closed
    /// until an operator supplies a narrower policy rule or classification.
    /// Only hook fallback logic assigns this class; caller-supplied class strings
    /// cannot claim unclassified treatment.
    MCP_UNCLASSIFIED_OBSERVATION,
    /// An MCP tool the Guard positively recognises as read-only.
    ///
    /// Distinct from `MCP_UNCLASSIFIED_OBSERVATION`, which means "we do not
    /// know what this does" and must stay denied. A named tool that only
    /// reads is ordinary work, and denying it stopped that work with no way
    /// to proceed. The allowlist lives in the hook and is deliberately tiny:
    /// membership is a claim the Guard makes about a specific tool, never a
    /// verb pattern a third-party server can match by naming itself well.
    MCP_KNOWN_OBSERVATION,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalRequirement {
    None,
    User,
    Authority,
}

fn default_operations() -> Vec<String> {
    vec!["*".into()]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub id: String,
    pub effect_class: EffectClass,
    pub allowed: bool,
    pub approval: ApprovalRequirement,
    pub targets: Vec<String>,
    /// Operation-level discrimination within one effect class (e.g. bounded
    /// vs. destructive FILE_DELETE). Matched the same way as `targets`:
    /// exact string or "*". Defaults to `["*"]` so existing rules and
    /// fixtures written before this field existed keep matching every
    /// operation, unchanged.
    #[serde(default = "default_operations")]
    pub operations: Vec<String>,
    pub required_trust: Option<String>,
    pub required_enforcement: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyPack {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub id: String,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl PolicyPack {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        let mut ids = std::collections::BTreeSet::new();
        if self.id.trim().is_empty() {
            return Err(ContractError::InvalidContract {
                path: "id".into(),
                reason: "must be non-empty".into(),
            });
        }
        if self.version == 0 {
            return Err(ContractError::InvalidContract {
                path: "version".into(),
                reason: "must be positive".into(),
            });
        }
        for rule in &self.rules {
            require_version(rule.schema_version, 1)?;
            if !ids.insert(&rule.id) {
                return Err(ContractError::InvalidContract {
                    path: "rules.id".into(),
                    reason: "duplicate rule id".into(),
                });
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

fn rule(
    id: &str,
    effect_class: EffectClass,
    allowed: bool,
    operations: &[&str],
) -> PolicyRule {
    PolicyRule {
        schema_version: 1,
        id: id.into(),
        effect_class,
        allowed,
        approval: ApprovalRequirement::None,
        targets: vec!["*".into()],
        operations: operations.iter().map(|value| value.to_string()).collect(),
        required_trust: None,
        required_enforcement: Vec::new(),
    }
}

/// The Guard's built-in default policy. This pack is always present in the
/// normal installed state — ambient permission is an explicit policy
/// decision here, never the absence of policy.
///
/// The line this pack draws is destruction, not caution. A push, a publish, a
/// dependency install, an outbound request, a spawned process: none of them
/// destroy anything, and all of them are ordinary work in this workspace.
/// Denying them by default did not make the operator safer — it stopped the
/// work and offered no way to proceed, which is how a guard stops being one.
/// What stays denied is what cannot be undone or what leaks: a destructive
/// delete, a history-rewriting push, credential material, and an MCP effect
/// the Guard cannot classify. Those are refusals rather than prompts on
/// purpose: an approval an operator grants without reading is not a control,
/// and the rare legitimate rewrite is better done by hand.
///
/// `FILE_DELETE` gets two rules instead of one class-level decision:
/// ordinary/bounded deletes (`operations: ["*"]`) stay ambient-allowed so a
/// normal source-file removal in a refactor needs no approval, while a
/// second rule reserves specific destructive-delete operation tags for
/// denial once the hook adapter can distinguish them. Today the adapter
/// (`legion-hook`'s `default_operation`) always tags `FILE_DELETE` as
/// `"delete"` unless a caller supplies an explicit operation, and raw-shell
/// recursive/broad deletes are already hard-gated earlier in dispatch — so
/// no request currently reaches this pack carrying one of the reserved
/// operation tags below. Wiring the adapter to emit them for a genuinely
/// destructive delete path is future work; this ships the schema capability
/// (the `operations` field plus the two-rule shape) now.
///
/// `MCP_UNCLASSIFIED_OBSERVATION` receives its own deny-by-default rule. This
/// preserves truthful receipts without silently granting unknown MCP behavior.
/// Projects may permit a narrow target or operation through an explicit rule.
pub fn canonical_default_policy_pack() -> PolicyPack {
    PolicyPack {
        schema_version: 1,
        id: "canonical-default".into(),
        version: 1,
        rules: vec![
            rule("default-file-write-allow", EffectClass::FILE_WRITE, true, &["*"]),
            rule("default-file-move-allow", EffectClass::FILE_MOVE, true, &["*"]),
            rule("default-vcs-commit-allow", EffectClass::VCS_COMMIT, true, &["*"]),
            rule("default-command-exec-allow", EffectClass::COMMAND_EXEC, true, &["*"]),
            rule("default-file-delete-ordinary-allow", EffectClass::FILE_DELETE, true, &["*"]),
            rule(
                "default-file-delete-destructive-deny",
                EffectClass::FILE_DELETE,
                false,
                &["delete-recursive", "delete-force", "delete-broad"],
            ),
            rule("default-mcp-known-observation-allow", EffectClass::MCP_KNOWN_OBSERVATION, true, &["*"]),
            rule("default-credential-access-deny", EffectClass::CREDENTIAL_ACCESS, false, &["*"]),
            rule("default-publish-allow", EffectClass::PUBLISH, true, &["*"]),
            // A push adds commits to a remote. It destroys nothing, and it is
            // ordinary work in every repository here; denying it stopped that
            // work with no way to proceed.
            rule("default-vcs-push-allow", EffectClass::VCS_PUSH, true, &["*"]),
            rule("default-dependency-install-allow", EffectClass::DEPENDENCY_INSTALL, true, &["*"]),
            rule("default-network-egress-allow", EffectClass::NETWORK_EGRESS, true, &["*"]),
            rule("default-process-spawn-allow", EffectClass::PROCESS_SPAWN, true, &["*"]),
            rule(
                "default-external-side-effect-deny",
                EffectClass::EXTERNAL_SIDE_EFFECT,
                false,
                &["*"],
            ),
            // Unclassified MCP tools fail closed. Callers must positively classify
            // observations before canonical policy can allow them.
            rule(
                "default-mcp-unclassified-observation-deny",
                EffectClass::MCP_UNCLASSIFIED_OBSERVATION,
                false,
                &["*"],
            ),
        ],
        extensions: BTreeMap::new(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub requested_by: AgentId,
    pub effect_class: EffectClass,
    pub target: String,
    pub operation: String,
    pub preview: Option<String>,
    pub source_revision: String,
    pub approval_required: bool,
}

impl EffectRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        for (path, value) in [
            ("target", &self.target),
            ("operation", &self.operation),
            ("source_revision", &self.source_revision),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must be non-empty".into(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_default_pack_is_valid_and_has_no_duplicate_rule_ids() {
        canonical_default_policy_pack()
            .validate()
            .expect("canonical default policy pack validates");
    }

    #[test]
    fn canonical_default_pack_allows_ordinary_classes_and_denies_reserved_classes() {
        let pack = canonical_default_policy_pack();
        let allowed_classes = [
            EffectClass::FILE_WRITE,
            EffectClass::FILE_MOVE,
            EffectClass::VCS_COMMIT,
            EffectClass::COMMAND_EXEC,
            // A push, a dependency install, an outbound request and a spawned
            // process all destroy nothing. Denying them stopped ordinary work
            // with no way to proceed, which is not what the guard is for.
            EffectClass::PUBLISH,
            EffectClass::VCS_PUSH,
            EffectClass::DEPENDENCY_INSTALL,
            EffectClass::NETWORK_EGRESS,
            EffectClass::PROCESS_SPAWN,
        ];
        for effect_class in allowed_classes {
            let rule = pack
                .rules
                .iter()
                .find(|rule| rule.effect_class == effect_class)
                .unwrap_or_else(|| panic!("{effect_class:?} has a default rule"));
            assert!(rule.allowed, "{effect_class:?} should be ambient-allowed");
        }
        let reserved_classes = [
            EffectClass::CREDENTIAL_ACCESS,
            EffectClass::EXTERNAL_SIDE_EFFECT,
        ];
        for effect_class in reserved_classes {
            let rule = pack
                .rules
                .iter()
                .find(|rule| rule.effect_class == effect_class)
                .unwrap_or_else(|| panic!("{effect_class:?} has a default rule"));
            assert!(!rule.allowed, "{effect_class:?} should deny by default");
        }
    }

    /// Destructive deletes stay denied while an ordinary delete does not.
    #[test]
    fn destructive_delete_stays_denied() {
        let pack = canonical_default_policy_pack();
        let destructive = pack
            .rules
            .iter()
            .find(|rule| rule.effect_class == EffectClass::FILE_DELETE && !rule.allowed)
            .expect("a destructive FILE_DELETE rule is present");
        for operation in ["delete-recursive", "delete-force", "delete-broad"] {
            assert!(
                destructive.operations.iter().any(|value| value == operation),
                "{operation} must stay denied"
            );
        }
    }

    /// Both classes fail closed while preserving truthful receipt classification.
    #[test]
    fn external_side_effect_and_mcp_unclassified_observation_both_fail_closed() {
        let pack = canonical_default_policy_pack();
        let external_side_effect = pack
            .rules
            .iter()
            .find(|rule| rule.effect_class == EffectClass::EXTERNAL_SIDE_EFFECT)
            .expect("EXTERNAL_SIDE_EFFECT has a default rule");
        let unclassified_observation = pack
            .rules
            .iter()
            .find(|rule| rule.effect_class == EffectClass::MCP_UNCLASSIFIED_OBSERVATION)
            .expect("MCP_UNCLASSIFIED_OBSERVATION has a default rule");
        assert!(
            !external_side_effect.allowed,
            "a positively classified MCP write/send/delete must stay denied by default"
        );
        assert!(
            !unclassified_observation.allowed,
            "an unclassified MCP tool must fail closed by default"
        );
    }

    #[test]
    fn canonical_default_pack_gives_file_delete_two_operation_scoped_rules() {
        let pack = canonical_default_policy_pack();
        let file_delete_rules: Vec<_> = pack
            .rules
            .iter()
            .filter(|rule| rule.effect_class == EffectClass::FILE_DELETE)
            .collect();
        assert_eq!(file_delete_rules.len(), 2);
        let ordinary = file_delete_rules
            .iter()
            .find(|rule| rule.allowed)
            .expect("one FILE_DELETE rule ambient-allows");
        assert_eq!(ordinary.operations, vec!["*".to_string()]);
        let destructive = file_delete_rules
            .iter()
            .find(|rule| !rule.allowed)
            .expect("one FILE_DELETE rule denies destructive operations");
        assert!(!destructive.operations.contains(&"*".to_string()));
    }

    #[test]
    fn operations_field_defaults_to_wildcard_when_absent_from_input() {
        let json = serde_json::json!({
            "schema_version": 1,
            "id": "legacy-rule",
            "effect_class": "FILE_WRITE",
            "allowed": true,
            "approval": "NONE",
            "targets": ["*"],
            "required_trust": null,
            "required_enforcement": []
        });
        let rule: PolicyRule =
            serde_json::from_value(json).expect("a rule with no operations field still parses");
        assert_eq!(rule.operations, vec!["*".to_string()]);
    }

    #[test]
    fn operations_field_round_trips_through_json() {
        let mut rule = canonical_default_policy_pack().rules.remove(0);
        rule.operations = vec!["delete-recursive".into(), "delete-force".into()];
        let serialized = serde_json::to_value(&rule).expect("rule serializes");
        let restored: PolicyRule =
            serde_json::from_value(serialized).expect("rule round-trips through json");
        assert_eq!(restored.operations, rule.operations);
    }
}
