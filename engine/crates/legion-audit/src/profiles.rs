//! Frozen audit profiles and the audit-owned runtime closure.
//!
//! Profiles `pre-pr`, `repository` and `release` are strength-ordered.
//! A faster profile may legitimately omit release-only obligations, but
//! a pass under a weaker profile never projects to a stronger one: a
//! release run cannot inherit a `pre-pr` completeness claim. Legacy CLI
//! profile strings (e.g. `standard`) are untouched here — callers opt in
//! by selecting one of these profiles explicitly (root CLI wiring).
//!
//! The `no-node-python` constraint governs Audit-owned execution only:
//! Node/Python launchers, plugins, TS-loaded configs and child
//! interpreters are excluded from the launch closure, while evidence
//! merely *produced* by Node/Python in application CI and imported with
//! authenticated provenance is not rejected.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assurance::EvidenceKind;
use crate::error::AuditError;

/// Strength-ordered audit profile, frozen into the plan before solving.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditProfile {
    PrePr,
    Repository,
    Release,
}

impl AuditProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrePr => "pre-pr",
            Self::Repository => "repository",
            Self::Release => "release",
        }
    }

    /// Strict parse: unknown/legacy names return `None` so existing
    /// commands retain legacy semantics unless a new profile is chosen.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pre-pr" => Some(Self::PrePr),
            "repository" => Some(Self::Repository),
            "release" => Some(Self::Release),
            _ => None,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::PrePr => 1,
            Self::Repository => 2,
            Self::Release => 3,
        }
    }

    /// A completed run may be claimed for `claimed` only when it ran at
    /// equal-or-stronger strength (pre-pr never projects to release).
    pub fn can_project_to(self, claimed: AuditProfile) -> bool {
        self.rank() >= claimed.rank()
    }

    /// Evidence kinds this profile mandates when a candidate obligation
    /// exists for the declared product (see `FrozenProfile`).
    pub fn mandatory_evidence_kinds(self) -> Vec<EvidenceKind> {
        match self {
            Self::PrePr => vec![EvidenceKind::ProviderExecution],
            Self::Repository => vec![
                EvidenceKind::ProviderExecution,
                EvidenceKind::Test,
                EvidenceKind::Build,
            ],
            Self::Release => vec![
                EvidenceKind::ProviderExecution,
                EvidenceKind::Test,
                EvidenceKind::Build,
                EvidenceKind::Runtime,
                EvidenceKind::Artifact,
                EvidenceKind::Review,
            ],
        }
    }
}

/// Runtime constraint frozen with the profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeConstraint {
    /// No Node/Python anywhere in Audit-owned execution. Imported,
    /// authenticated evidence produced by them stays admissible.
    NoNodePython,
    Unrestricted,
}

impl RuntimeConstraint {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "no-node-python" => Some(Self::NoNodePython),
            "unrestricted" => Some(Self::Unrestricted),
            _ => None,
        }
    }
}

/// A frozen profile selection: profile + rule/profile revision +
/// runtime constraint + mandated evidence kinds, stored in plan bounds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenProfile {
    pub profile: AuditProfile,
    /// Rule/profile revision; part of every obligation identity.
    pub revision: String,
    pub runtime_constraint: RuntimeConstraint,
    pub mandatory_evidence_kinds: Vec<EvidenceKind>,
}

impl FrozenProfile {
    pub fn freeze(
        profile: AuditProfile,
        revision: impl Into<String>,
        runtime_constraint: RuntimeConstraint,
    ) -> Result<Self, AuditError> {
        let frozen = Self {
            profile,
            revision: revision.into(),
            runtime_constraint,
            mandatory_evidence_kinds: profile.mandatory_evidence_kinds(),
        };
        frozen.validate("profile")?;
        Ok(frozen)
    }

    pub fn validate(&self, path: &str) -> Result<(), AuditError> {
        if self.revision.trim().is_empty() {
            return Err(AuditError::Invalid(format!(
                "{path}.revision: must be non-empty"
            )));
        }
        if self.mandatory_evidence_kinds != self.profile.mandatory_evidence_kinds() {
            return Err(AuditError::Invalid(format!(
                "{path}.mandatoryEvidenceKinds: disagree with profile {}",
                self.profile.as_str()
            )));
        }
        Ok(())
    }

    pub fn to_bound_value(&self) -> Result<Value, AuditError> {
        serde_json::to_value(self).map_err(|e| AuditError::Invalid(format!("profile: {e}")))
    }

    pub fn from_bound_value(value: &Value) -> Result<Self, AuditError> {
        let parsed: Self = serde_json::from_value(value.clone())
            .map_err(|e| AuditError::Invalid(format!("profile: {e}")))?;
        parsed.validate("profile")?;
        Ok(parsed)
    }
}

/// Runtime class of one step in a launch closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeClass {
    Native,
    Jvm,
    Swift,
    Node,
    Python,
    /// Unclassified runtime: under `NoNodePython` it is reported for
    /// review, never silently admitted as native.
    Unknown,
}

/// How a step participates in Audit-owned execution. Imported evidence
/// is *consumed*, not launched by Audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchStepKind {
    Launcher,
    Plugin,
    /// A config file loaded/executed by a runtime (e.g. TS config).
    Config,
    ChildInterpreter,
    Tool,
    ImportedEvidence,
}

/// One step of the frozen launch closure for a provider/run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchStep {
    pub name: String,
    pub runtime: RuntimeClass,
    pub kind: LaunchStepKind,
    /// True when Audit itself launches this step. Application CI steps
    /// that produced imported evidence are `false`.
    pub audit_owned: bool,
}

/// Frozen launch closure: every launcher, plugin, executed config and
/// child interpreter reachable from Audit-owned execution.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeClosure {
    #[serde(default)]
    pub steps: Vec<LaunchStep>,
}

/// One closure violation under the frozen constraint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeViolation {
    pub step: String,
    pub reason: String,
}

/// Validate a launch closure against the constraint. Under
/// `NoNodePython`, audit-owned Node/Python steps of any launch kind
/// (launcher/plugin/config/child-interpreter/tool) violate; imported
/// evidence and non-audit-owned producer steps do not. Unknown audit-
/// owned runtimes are flagged, never assumed native. A non-empty result
/// keeps dependent obligations `unmet` (see `assurance::apply_evidence`)
/// unless satisfied by a qualified native check or an authenticated
/// upstream CI receipt.
pub fn validate_runtime_closure(
    constraint: RuntimeConstraint,
    closure: &RuntimeClosure,
) -> Vec<RuntimeViolation> {
    if constraint == RuntimeConstraint::Unrestricted {
        return Vec::new();
    }
    let mut violations = Vec::new();
    for step in &closure.steps {
        if !step.audit_owned || step.kind == LaunchStepKind::ImportedEvidence {
            continue;
        }
        let reason = match step.runtime {
            RuntimeClass::Node => Some("node-runtime-in-audit-owned-execution"),
            RuntimeClass::Python => Some("python-runtime-in-audit-owned-execution"),
            RuntimeClass::Unknown => Some("unclassified-runtime-in-audit-owned-execution"),
            RuntimeClass::Native | RuntimeClass::Jvm | RuntimeClass::Swift => None,
        };
        if let Some(reason) = reason {
            violations.push(RuntimeViolation {
                step: step.name.clone(),
                reason: reason.to_owned(),
            });
        }
    }
    violations
}

/// Convenience for registries describing a runner as free-form strings:
/// map a runner kind/module string to a runtime class conservatively.
/// Recognizes common Node/Python spellings; anything unrecognized is
/// `Unknown`, never `Native`.
pub fn classify_runtime(runner_kind: &str) -> RuntimeClass {
    let normalized = runner_kind.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "native" | "rust" | "rust-algorithm" | "binary" => RuntimeClass::Native,
        "jvm" | "java" | "kotlin" | "gradle" | "detekt" => RuntimeClass::Jvm,
        "swift" | "swiftpm" | "xcode" => RuntimeClass::Swift,
        "node" | "nodejs" | "node.js" | "npm" | "npx" | "pnpm" | "yarn" | "bun" | "deno"
        | "runtime-script" | "javascript" | "typescript" => RuntimeClass::Node,
        "python" | "python3" | "pip" | "uv" => RuntimeClass::Python,
        _ => RuntimeClass::Unknown,
    }
}
