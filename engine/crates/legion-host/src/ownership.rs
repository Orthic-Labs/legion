use crate::error::HostError;
use legion_contracts::canonical_digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipMark {
    pub owner: String,
    pub generation: String,
    pub digest: String,
}

impl OwnershipMark {
    pub fn new(
        owner: impl Into<String>,
        generation: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, HostError> {
        let owner = owner.into();
        let generation = generation.into();
        if owner.trim().is_empty() || generation.trim().is_empty() {
            return Err(HostError::InvalidDescriptor {
                path: "ownership".into(),
                reason: "owner and generation must be non-empty".into(),
            });
        }
        let digest =
            canonical_digest(&bytes.to_vec()).map_err(|error| HostError::SemanticBlocker {
                reason: error.to_string(),
            })?;
        Ok(Self {
            owner,
            generation,
            digest,
        })
    }
    pub fn owns(&self, bytes: &[u8]) -> bool {
        canonical_digest(&bytes.to_vec())
            .map(|digest| digest == self.digest)
            .unwrap_or(false)
    }
    pub fn marker(&self) -> String {
        format!(
            "<!-- legion-owned owner={} generation={} digest={} -->",
            self.owner, self.generation, self.digest
        )
    }
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    canonical_digest(&bytes.to_vec()).unwrap_or_else(|_| "sha256:invalid".into())
}

pub fn marker_for(owner: &str, generation: &str, bytes: &[u8]) -> Result<String, HostError> {
    Ok(OwnershipMark::new(owner, generation, bytes)?.marker())
}

pub fn owned_block(owner: &str, generation: &str, payload: &[u8]) -> Result<Vec<u8>, HostError> {
    let mark = OwnershipMark::new(owner, generation, payload)?;
    let mut output = mark.marker().into_bytes();
    output.push(b'\n');
    output.extend_from_slice(payload);
    if !payload.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(b"<!-- /legion-owned -->\n");
    Ok(output)
}

pub fn parse_marker(text: &str) -> Option<OwnershipMark> {
    let start = text.find("<!-- legion-owned ")?;
    let end = text[start..].find(" -->")? + start;
    let fields = text[start + 18..end]
        .split_whitespace()
        .filter_map(|item| item.split_once('='))
        .collect::<BTreeMap<_, _>>();
    Some(OwnershipMark {
        owner: fields.get("owner")?.to_string(),
        generation: fields.get("generation")?.to_string(),
        digest: fields.get("digest")?.to_string(),
    })
}

pub fn replace_owned_block(
    existing: &str,
    block: &str,
    mark: &OwnershipMark,
) -> Result<String, HostError> {
    if let Some(existing_mark) = parse_marker(existing) {
        let payload = marker_payload(existing).unwrap_or_default();
        if existing_mark.owner != mark.owner || !existing_mark.owns(payload.as_bytes()) {
            return Err(HostError::HarnessConflict {
                path: "config".into(),
                reason: "existing marker is not an owned generation".into(),
            });
        }
    }
    Ok(format!("{}{}\n", existing.trim_end(), block))
}

pub fn remove_owned_block(existing: &str, owner: &str) -> (String, bool) {
    let Some(mark) = parse_marker(existing) else {
        return (existing.to_owned(), false);
    };
    let payload = marker_payload(existing).unwrap_or_default();
    if mark.owner != owner || !mark.owns(payload.as_bytes()) {
        return (existing.to_owned(), false);
    }
    let start = existing.find("<!-- legion-owned ").unwrap();
    let end = existing[start..]
        .find(" -->")
        .map(|offset| start + offset + 4)
        .unwrap_or(start);
    (
        format!("{}{}", &existing[..start], &existing[end..])
            .trim()
            .to_owned()
            + "\n",
        true,
    )
}

pub fn verify_owned_block(existing: &str, owner: &str) -> bool {
    parse_marker(existing).is_some_and(|mark| {
        mark.owner == owner
            && marker_payload(existing).is_some_and(|payload| mark.owns(payload.as_bytes()))
    })
}

fn marker_payload(text: &str) -> Option<String> {
    let start = text.find("<!-- legion-owned ")?;
    let header_end = text[start..].find(" -->")? + start + 4;
    let end = text[header_end..].find("<!-- /legion-owned -->")? + header_end;
    Some(text[header_end..end].trim_matches('\n').to_owned())
}
