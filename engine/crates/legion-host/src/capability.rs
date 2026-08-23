use crate::{descriptor::HostDescriptor, error::HostError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SURFACES: [&str; 5] = ["instructions", "skills", "agents", "mcp", "hooks"];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fidelity {
    Strong,
    Degraded,
    Unsupported,
}

impl Fidelity {
    pub fn parse(value: &str) -> Result<Self, HostError> {
        match value {
            "strong" => Ok(Self::Strong),
            "degraded" => Ok(Self::Degraded),
            "unsupported" => Ok(Self::Unsupported),
            _ => Err(HostError::InvalidDescriptor {
                path: "fidelity".into(),
                reason: format!("unknown fidelity {value}"),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub surface: String,
    pub fidelity: Fidelity,
    pub mechanism: String,
    pub path: Option<String>,
    pub note: Option<String>,
}

pub fn capabilities(
    descriptor: &HostDescriptor,
) -> Result<BTreeMap<String, Capability>, HostError> {
    descriptor.validate()?;
    let mut output = BTreeMap::new();
    for surface in SURFACES {
        let declared = descriptor.surfaces.get(surface);
        let fidelity = declared
            .map(|value| Fidelity::parse(&value.fidelity))
            .transpose()?
            .unwrap_or(Fidelity::Unsupported);
        let mechanism = declared
            .map(|value| value.mechanism.kind.clone())
            .unwrap_or_else(|| "none".into());
        let path = declared.and_then(|value| value.mechanism.path.clone());
        let note = declared.and_then(|value| value.note.clone());
        output.insert(
            surface.into(),
            Capability {
                surface: surface.into(),
                fidelity,
                mechanism,
                path,
                note,
            },
        );
    }
    Ok(output)
}

pub fn capability(descriptor: &HostDescriptor, surface: &str) -> Result<Capability, HostError> {
    capabilities(descriptor)?
        .remove(surface)
        .ok_or_else(|| HostError::SourceDrift {
            path: format!("surface:{surface}"),
            reason: "unknown host surface".into(),
        })
}
