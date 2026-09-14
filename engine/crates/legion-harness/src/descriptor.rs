use crate::error::HarnessError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionRule {
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mechanism {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceDescriptor {
    pub fidelity: String,
    pub mechanism: Mechanism,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessDescriptor {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "installOwner", default = "default_install_owner")]
    pub install_owner: String,
    #[serde(default)]
    pub detect: DetectionRule,
    #[serde(default)]
    pub surfaces: BTreeMap<String, SurfaceDescriptor>,
    #[serde(skip)]
    pub generic: bool,
}

fn default_install_owner() -> String {
    "adapter".into()
}

pub fn builtin_adapters() -> Result<Vec<HarnessDescriptor>, HarnessError> {
    let raw = include_str!("descriptors.json");
    let mut adapters = serde_json::from_str::<Vec<HarnessDescriptor>>(raw)
        .map_err(|error| HarnessError::internal(error.to_string()))?;
    for adapter in &mut adapters {
        adapter.generic = false;
    }
    adapters.push(generic_default());
    Ok(adapters)
}

pub fn adapter_ids(adapters: &[HarnessDescriptor]) -> Vec<String> {
    adapters.iter().map(|adapter| adapter.id.clone()).collect()
}

pub fn adapter_by_id<'a>(
    adapters: &'a [HarnessDescriptor],
    id: &str,
) -> Result<&'a HarnessDescriptor, HarnessError> {
    adapters
        .iter()
        .find(|adapter| adapter.id == id)
        .ok_or_else(|| {
            HarnessError::usage(format!(
                "unknown harness: {id} (known: {})",
                adapter_ids(adapters).join(", ")
            ))
        })
}

pub fn resolve_descriptor(
    adapters: &[HarnessDescriptor],
    id: &str,
    root: &Path,
) -> Result<HarnessDescriptor, HarnessError> {
    let base = adapter_by_id(adapters, id)?;
    if id != "generic" {
        return Ok(base.clone());
    }
    Ok(resolve_generic_descriptor(root, base)?)
}

fn generic_default() -> HarnessDescriptor {
    HarnessDescriptor {
        id: "generic".into(),
        display_name: "Generic / custom harness".into(),
        install_owner: "adapter".into(),
        detect: DetectionRule {
            any_of: Vec::new(),
            env: vec!["LEGION_HARNESS".into(), "LEGION_HARNESS_DESCRIPTOR".into()],
        },
        surfaces: BTreeMap::from([
            (
                "instructions".into(),
                SurfaceDescriptor {
                    fidelity: "strong".into(),
                    mechanism: Mechanism {
                        kind: "agents-md".into(),
                        path: Some("AGENTS.md".into()),
                        table: None,
                        key: None,
                    },
                    note: None,
                },
            ),
            (
                "skills".into(),
                SurfaceDescriptor {
                    fidelity: "degraded".into(),
                    mechanism: Mechanism {
                        kind: "skills-dir".into(),
                        path: Some(".agents/skills".into()),
                        table: None,
                        key: None,
                    },
                    note: Some(
                        "canonical packages projected to .agents/skills and referenced from the instructions block"
                            .into(),
                    ),
                },
            ),
            (
                "agents".into(),
                SurfaceDescriptor {
                    fidelity: "unsupported".into(),
                    mechanism: Mechanism {
                        kind: "none".into(),
                        path: None,
                        table: None,
                        key: None,
                    },
                    note: None,
                },
            ),
            (
                "mcp".into(),
                SurfaceDescriptor {
                    fidelity: "unsupported".into(),
                    mechanism: Mechanism {
                        kind: "none".into(),
                        path: None,
                        table: None,
                        key: None,
                    },
                    note: None,
                },
            ),
            (
                "hooks".into(),
                SurfaceDescriptor {
                    fidelity: "unsupported".into(),
                    mechanism: Mechanism {
                        kind: "none".into(),
                        path: None,
                        table: None,
                        key: None,
                    },
                    note: None,
                },
            ),
        ]),
        generic: true,
    }
}

pub fn resolve_generic_descriptor(
    root: &Path,
    default: &HarnessDescriptor,
) -> Result<HarnessDescriptor, HarnessError> {
    let candidates = generic_descriptor_candidates(root);
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| HarnessError::descriptor_invalid(error.to_string()))?;
        let declared: Value = serde_json::from_slice(&bytes).map_err(|error| {
            HarnessError::descriptor_invalid(format!(
                "harness descriptor at {} does not parse: {}",
                path.display(),
                error
            ))
        })?;
        if !declared.is_object() {
            return Err(HarnessError::descriptor_invalid(format!(
                "harness descriptor at {} must be a JSON object",
                path.display()
            )));
        }
        let mut merged = serde_json::to_value(default)
            .map_err(|error| HarnessError::internal(error.to_string()))?;
        merge_generic_descriptor(&mut merged, &declared);
        let descriptor: HarnessDescriptor = serde_json::from_value(merged)
            .map_err(|error| HarnessError::internal(error.to_string()))?;
        return Ok(descriptor);
    }
    Ok(default.clone())
}

fn generic_descriptor_candidates(root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(from_env) = std::env::var("LEGION_HARNESS_DESCRIPTOR") {
        let path = PathBuf::from(from_env);
        candidates.push(if path.is_absolute() {
            path
        } else {
            root.join(path)
        });
    }
    candidates.push(root.join(".agents").join("legion-harness.json"));
    candidates
}

fn merge_generic_descriptor(target: &mut Value, declared: &Value) {
    if let Some(object) = declared.as_object() {
        for (key, value) in object {
            if key == "surfaces" {
                let surfaces = target
                    .as_object_mut()
                    .and_then(|map| map.get_mut("surfaces"))
                    .and_then(Value::as_object_mut);
                if let Some(surfaces) = surfaces {
                    if let Some(declared_surfaces) = value.as_object() {
                        for (surface, surface_value) in declared_surfaces {
                            surfaces.insert(surface.clone(), surface_value.clone());
                        }
                    }
                }
            } else {
                target
                    .as_object_mut()
                    .expect("generic default is object")
                    .insert(key.clone(), value.clone());
            }
        }
    }
}

pub fn capabilities_value(descriptor: &HarnessDescriptor) -> Result<Value, HarnessError> {
    let mut surfaces = BTreeMap::new();
    for surface in crate::surfaces::SURFACES {
            let declared = descriptor.surfaces.get(surface);
            let mechanism = declared
                .map(|value| value.mechanism.clone())
                .unwrap_or_else(|| Mechanism {
                    kind: "none".into(),
                    path: None,
                    table: None,
                    key: None,
                });
            let fidelity = if surface == "hooks" {
                declared
                    .map(|value| value.fidelity.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| crate::surfaces::enforcement_fidelity(&mechanism))
            } else {
                declared
                    .map(|value| value.fidelity.clone())
                    .unwrap_or_else(|| "unsupported".into())
            };
            let note = declared.and_then(|value| value.note.clone());
        let mechanism_value = serde_json::to_value(&mechanism)
            .map_err(|error| HarnessError::internal(error.to_string()))?;
        surfaces.insert(
            surface.to_string(),
            json!({
                "fidelity": fidelity,
                "mechanism": mechanism_value,
                "note": note,
            }),
        );
    }
    Ok(json!({
        "id": descriptor.id,
        "displayName": descriptor.display_name,
        "installOwner": descriptor.install_owner,
        "surfaces": surfaces,
    }))
}
