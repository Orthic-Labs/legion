use serde::{Deserialize, Serialize};

/// Version of the host-neutral Arcane vocabulary.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    FileWrite,
    FileDelete,
    FileMove,
    CommandExec,
    NetworkEgress,
    ProcessSpawn,
    CredentialAccess,
    DependencyInstall,
    VcsCommit,
    VcsPush,
    Publish,
    ExternalSideEffect,
}

impl EffectClass {
    pub const ALL: [Self; 12] = [
        Self::FileWrite,
        Self::FileDelete,
        Self::FileMove,
        Self::CommandExec,
        Self::NetworkEgress,
        Self::ProcessSpawn,
        Self::CredentialAccess,
        Self::DependencyInstall,
        Self::VcsCommit,
        Self::VcsPush,
        Self::Publish,
        Self::ExternalSideEffect,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    Unauthenticated,
    HostConnectionTrust,
    CapabilitySignature,
}

impl TrustLevel {
    pub fn satisfies(self, minimum: Self) -> bool {
        self >= minimum
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    Unsupported,
    ReadOnly,
    Observed,
    Strong,
}

impl EnforcementLevel {
    pub fn satisfies(self, minimum: Self) -> bool {
        self >= minimum
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    None,
    User,
    Authority,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractVersion {
    pub name: String,
    pub major: u32,
    pub minor: u32,
}

impl ContractVersion {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("contract version name must be non-empty".into());
        }
        if self.major == 0 {
            return Err("contract version major must be positive".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Read,
    Write,
    Delete,
    Move,
    Execute,
    Connect,
    Spawn,
    Commit,
    Push,
    Publish,
}
