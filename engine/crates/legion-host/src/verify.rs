use crate::{error::HostError, install::digest, install::FileEffects, projection::ProjectionItem};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub ok: bool,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub foreign: Vec<String>,
}

pub fn verify<E: FileEffects>(
    effects: &E,
    projections: &[ProjectionItem],
) -> Result<Verification, HostError> {
    let mut result = Verification {
        ok: true,
        ..Verification::default()
    };
    for projection in projections {
        let Some(bytes) = effects.read(&projection.path)? else {
            result.missing.push(projection.path.clone());
            continue;
        };
        if digest(&bytes) != digest(&projection.bytes) {
            result.mismatched.push(projection.path.clone());
        }
    }
    result.missing.sort();
    result.mismatched.sort();
    result.foreign.sort();
    result.ok =
        result.missing.is_empty() && result.mismatched.is_empty() && result.foreign.is_empty();
    Ok(result)
}
