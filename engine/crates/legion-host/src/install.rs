use crate::{
    descriptor::HostDescriptor,
    error::HostError,
    ownership::{digest_bytes, verify_owned_block},
    projection::{CollisionPolicy, ProjectionItem},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Write,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub path: String,
    pub kind: MutationKind,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub bytes: Option<Vec<u8>>,
    pub owner: String,
    pub generation: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationPlan {
    pub mutations: Vec<Mutation>,
}

impl MutationPlan {
    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }
    pub fn validate(&self) -> Result<(), HostError> {
        let mut paths = std::collections::BTreeSet::new();
        for mutation in &self.mutations {
            if !paths.insert(&mutation.path) {
                return Err(HostError::OwnershipCollision {
                    path: mutation.path.clone(),
                    reason: "duplicate mutation target".into(),
                });
            }
        }
        Ok(())
    }
}

pub trait FileEffects {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, HostError>;
    fn atomic_write(&mut self, path: &str, bytes: &[u8]) -> Result<(), HostError>;
    fn atomic_delete(&mut self, path: &str) -> Result<(), HostError>;
}

/// Captured pre-operation contents.  The host always captures before applying
/// so callers can restore an integration after any failed verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransactionPreimage {
    pub entries: BTreeMap<String, Option<Vec<u8>>>,
}

pub fn capture_preimage<E: FileEffects>(
    effects: &E,
    plan: &MutationPlan,
) -> Result<TransactionPreimage, HostError> {
    plan.validate()?;
    let mut entries = BTreeMap::new();
    for mutation in &plan.mutations {
        entries.insert(mutation.path.clone(), effects.read(&mutation.path)?);
    }
    Ok(TransactionPreimage { entries })
}

pub fn rollback<E: FileEffects>(
    effects: &mut E,
    preimage: &TransactionPreimage,
) -> Result<(), HostError> {
    for (path, before) in &preimage.entries {
        match before {
            Some(bytes) => effects.atomic_write(path, bytes)?,
            None => effects.atomic_delete(path)?,
        }
    }
    Ok(())
}

pub fn apply_transaction<E, V>(
    effects: &mut E,
    plan: &MutationPlan,
    verify: V,
) -> Result<TransactionPreimage, HostError>
where
    E: FileEffects,
    V: FnOnce(&E) -> Result<bool, HostError>,
{
    let preimage = capture_preimage(effects, plan)?;
    let outcome = apply(effects, plan).and_then(|_| {
        verify(effects).and_then(|ok| {
            ok.then_some(()).ok_or_else(|| HostError::Verification {
                reason: "post-apply verification did not pass".into(),
            })
        })
    });
    if let Err(error) = outcome {
        rollback(effects, &preimage).map_err(|rollback_error| HostError::Rollback {
            reason: format!("{error}; recovery failed: {rollback_error}"),
        })?;
        return Err(error);
    }
    Ok(preimage)
}

pub fn install_transactional<E, V>(
    effects: &mut E,
    descriptor: &HostDescriptor,
    existing: &BTreeMap<String, Vec<u8>>,
    projections: impl IntoIterator<Item = ProjectionItem>,
    verify: V,
) -> Result<MutationPlan, HostError>
where
    E: FileEffects,
    V: FnOnce(&E) -> Result<bool, HostError>,
{
    descriptor.validate()?;
    let plan = plan(existing, projections)?;
    apply_transaction(effects, &plan, verify)?;
    Ok(plan)
}

pub fn plan(
    existing: &BTreeMap<String, Vec<u8>>,
    projections: impl IntoIterator<Item = ProjectionItem>,
) -> Result<MutationPlan, HostError> {
    let mut mutations = Vec::new();
    for item in projections {
        let before = existing.get(&item.path);
        if before.is_some_and(|bytes| bytes == &item.bytes) {
            continue;
        }
        if let Some(before) = before {
            if matches!(item.collision, CollisionPolicy::CreateOnly) {
                return Err(HostError::HarnessConflict {
                    path: item.path,
                    reason: "existing projection is not byte-identical to canonical content".into(),
                });
            }
            let digest_matches = item
                .before_digest
                .as_ref()
                .is_some_and(|expected| expected == &digest_bytes(before));
            let marker_matches =
                verify_owned_block(std::str::from_utf8(before).unwrap_or_default(), &item.owner);
            if !digest_matches && !marker_matches {
                return Err(HostError::HarnessConflict {
                    path: item.path,
                    reason: "existing content is foreign or changed outside Legion ownership"
                        .into(),
                });
            }
        }
        mutations.push(Mutation {
            path: item.path,
            kind: MutationKind::Write,
            before_digest: before.map(|bytes| digest(bytes)),
            after_digest: Some(digest(&item.bytes)),
            bytes: Some(item.bytes),
            owner: item.owner,
            generation: item.generation,
        });
    }
    let result = MutationPlan { mutations };
    result.validate()?;
    Ok(result)
}

pub fn apply<E: FileEffects>(effects: &mut E, plan: &MutationPlan) -> Result<(), HostError> {
    plan.validate()?;
    for mutation in &plan.mutations {
        match mutation.kind {
            MutationKind::Write => effects.atomic_write(
                &mutation.path,
                mutation
                    .bytes
                    .as_deref()
                    .ok_or_else(|| HostError::SemanticBlocker {
                        reason: "write mutation has no bytes".into(),
                    })?,
            )?,
            MutationKind::Delete => effects.atomic_delete(&mutation.path)?,
        }
    }
    Ok(())
}

pub fn install<E: FileEffects>(
    effects: &mut E,
    descriptor: &HostDescriptor,
    existing: &BTreeMap<String, Vec<u8>>,
    projections: impl IntoIterator<Item = ProjectionItem>,
) -> Result<MutationPlan, HostError> {
    descriptor.validate()?;
    let plan = plan(existing, projections)?;
    apply(effects, &plan)?;
    Ok(plan)
}

pub fn digest(bytes: &[u8]) -> String {
    digest_bytes(bytes)
}
