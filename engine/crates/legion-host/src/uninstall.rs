use crate::{
    error::HostError,
    install::{digest, FileEffects, Mutation, MutationKind, MutationPlan},
    ownership::{parse_marker, remove_owned_block, OwnershipMark},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedTarget {
    pub path: String,
    pub expected_digest: Option<String>,
    pub owner: String,
    #[serde(default)]
    pub json_key: Option<String>,
    #[serde(default)]
    pub toml_table: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallResult {
    pub removed: Vec<String>,
    pub kept: Vec<String>,
    pub plan: MutationPlan,
}

pub fn plan_uninstall<E: FileEffects>(
    effects: &E,
    targets: &[OwnedTarget],
) -> Result<UninstallResult, HostError> {
    let mut result = UninstallResult::default();
    for target in targets {
        let Some(bytes) = effects.read(&target.path)? else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        if let Some(key) = &target.json_key {
            let mut value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| HostError::HarnessConflict {
                    path: target.path.clone(),
                    reason: "existing JSON does not parse".into(),
                })?;
            let Some(object) = value
                .get_mut(key)
                .and_then(serde_json::Value::as_object_mut)
            else {
                result.kept.push(target.path.clone());
                continue;
            };
            let Some(current) = object.get("legion").cloned() else {
                result.kept.push(target.path.clone());
                continue;
            };
            let Some(current_object) = current.as_object() else {
                result.kept.push(target.path.clone());
                continue;
            };
            let Some(metadata) = current_object.get("_legionOwnership") else {
                result.kept.push(target.path.clone());
                continue;
            };
            let mark: OwnershipMark = match serde_json::from_value(metadata.clone()) {
                Ok(mark) => mark,
                Err(_) => {
                    result.kept.push(target.path.clone());
                    continue;
                }
            };
            let mut payload = current.clone();
            payload.as_object_mut().unwrap().remove("_legionOwnership");
            let payload_bytes = serde_json::to_vec(&payload)?;
            if mark.owner != target.owner || !mark.owns(&payload_bytes) {
                result.kept.push(target.path.clone());
                continue;
            }
            object.remove("legion");
            let mut after = serde_json::to_vec_pretty(&value)?;
            after.push(b'\n');
            result.plan.mutations.push(Mutation {
                path: target.path.clone(),
                kind: MutationKind::Write,
                before_digest: Some(digest(&bytes)),
                after_digest: Some(digest(&after)),
                bytes: Some(after),
                owner: target.owner.clone(),
                generation: "uninstall".into(),
            });
            result.removed.push(target.path.clone());
            continue;
        }
        if let Some(table) = &target.toml_table {
            if !text.trim().is_empty() && toml::from_str::<toml::Value>(text).is_err() {
                return Err(HostError::HarnessConflict {
                    path: target.path.clone(),
                    reason: "existing TOML does not parse".into(),
                });
            }
            let lines = text.lines().collect::<Vec<_>>();
            let header = format!("[{table}.legion]");
            let Some(start) = lines.iter().position(|line| line.trim() == header) else {
                result.kept.push(target.path.clone());
                continue;
            };
            let marker_index = start
                .checked_sub(1)
                .filter(|index| lines[*index].trim_start().starts_with("# legion-owned "));
            let Some(marker_index) = marker_index else {
                result.kept.push(target.path.clone());
                continue;
            };
            let marker_text = lines[marker_index]
                .trim_start()
                .trim_start_matches('#')
                .trim();
            let mark = match parse_comment_marker(marker_text) {
                Some(mark) => mark,
                None => {
                    result.kept.push(target.path.clone());
                    continue;
                }
            };
            let end = (start + 1..lines.len())
                .find(|index| lines[*index].trim_start().starts_with('['))
                .unwrap_or(lines.len());
            let payload = lines[start..end]
                .iter()
                .copied()
                .filter(|line| !line.trim().eq("# /legion-owned"))
                .collect::<Vec<_>>()
                .join("\n");
            if mark.owner != target.owner || !mark.owns(payload.as_bytes()) {
                result.kept.push(target.path.clone());
                continue;
            }
            let mut kept_lines = lines[..marker_index].to_vec();
            kept_lines.extend_from_slice(&lines[end..]);
            let after = format!("{}\n", kept_lines.join("\n")).into_bytes();
            result.plan.mutations.push(Mutation {
                path: target.path.clone(),
                kind: MutationKind::Write,
                before_digest: Some(digest(&bytes)),
                after_digest: Some(digest(&after)),
                bytes: Some(after),
                owner: target.owner.clone(),
                generation: "uninstall".into(),
            });
            result.removed.push(target.path.clone());
            continue;
        }
        let marker_owned = parse_marker(&text).is_some_and(|mark| mark.owner == target.owner);
        let expected = target
            .expected_digest
            .as_ref()
            .is_some_and(|value| value == &digest(&bytes));
        if marker_owned && target.expected_digest.is_none() {
            let (after, changed) = remove_owned_block(&text, &target.owner);
            if changed {
                result.plan.mutations.push(Mutation {
                    path: target.path.clone(),
                    kind: if after.trim().is_empty() {
                        MutationKind::Delete
                    } else {
                        MutationKind::Write
                    },
                    before_digest: Some(digest(&bytes)),
                    after_digest: if after.trim().is_empty() {
                        None
                    } else {
                        Some(digest(after.as_bytes()))
                    },
                    bytes: if after.trim().is_empty() {
                        None
                    } else {
                        Some(after.into_bytes())
                    },
                    owner: target.owner.clone(),
                    generation: "uninstall".into(),
                });
                result.removed.push(target.path.clone());
                continue;
            }
        }
        let structured_config = target.path.ends_with(".json") || target.path.ends_with(".toml");
        if expected && !structured_config {
            result.plan.mutations.push(Mutation {
                path: target.path.clone(),
                kind: MutationKind::Delete,
                before_digest: Some(digest(&bytes)),
                after_digest: None,
                bytes: None,
                owner: target.owner.clone(),
                generation: "uninstall".into(),
            });
            result.removed.push(target.path.clone());
        } else {
            result.kept.push(target.path.clone());
        }
    }
    result.plan.validate()?;
    result.removed.sort();
    result.kept.sort();
    Ok(result)
}

fn parse_comment_marker(text: &str) -> Option<OwnershipMark> {
    let fields = text
        .strip_prefix("legion-owned ")?
        .split_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    Some(OwnershipMark {
        owner: fields.get("owner")?.to_string(),
        generation: fields.get("generation")?.to_string(),
        digest: fields.get("digest")?.to_string(),
    })
}

pub fn uninstall<E: FileEffects>(
    effects: &mut E,
    targets: &[OwnedTarget],
) -> Result<UninstallResult, HostError> {
    let result = plan_uninstall(effects, targets)?;
    crate::install::apply(effects, &result.plan)?;
    Ok(result)
}

pub fn uninstall_transactional<E: FileEffects>(
    effects: &mut E,
    targets: &[OwnedTarget],
) -> Result<UninstallResult, HostError> {
    let result = plan_uninstall(effects, targets)?;
    crate::install::apply_transaction(effects, &result.plan, |_| Ok(true))?;
    Ok(result)
}
