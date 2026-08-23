use std::collections::BTreeMap;

use serde::Serialize;

use crate::{catalog::CatalogEntry, error::CatalogError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    pub host_id: String,
    pub accepts_canonical: bool,
    pub format: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostProjection {
    pub host_id: String,
    pub source_path: String,
    pub source_hash: String,
    pub format: String,
    pub lossy: bool,
    pub provenance: String,
    pub bytes: Vec<u8>,
}

#[derive(Serialize)]
struct DeclaredProjection<'a> {
    canonical_id: &'a str,
    kind: &'a crate::catalog::CatalogKind,
    package_identity: &'a str,
    source_path: &'a str,
    source_hash: &'a str,
    body: &'a [u8],
    frontmatter: &'a serde_json::Value,
}

pub fn project(
    entry: &CatalogEntry,
    request: &ProjectionRequest,
) -> Result<HostProjection, CatalogError> {
    if request.host_id.trim().is_empty() {
        return Err(CatalogError::InvalidCatalog {
            path: "host_id".into(),
            reason: "must be non-empty".into(),
        });
    }
    let canonical_format = entry
        .source_path
        .rsplit_once('.')
        .map(|(_, value)| value)
        .unwrap_or("markdown");
    let canonical_format = if canonical_format.eq_ignore_ascii_case("md") {
        "markdown"
    } else {
        canonical_format
    };
    if request.accepts_canonical && request.format.eq_ignore_ascii_case(canonical_format) {
        return Ok(HostProjection {
            host_id: request.host_id.clone(),
            source_path: entry.source_path.clone(),
            source_hash: entry.source_hash.clone(),
            format: request.format.clone(),
            lossy: false,
            provenance: "canonical-source".into(),
            bytes: entry.source_bytes.clone(),
        });
    }
    let declared = DeclaredProjection {
        canonical_id: &entry.canonical_id,
        kind: &entry.kind,
        package_identity: &entry.package_identity,
        source_path: &entry.source_path,
        source_hash: &entry.source_hash,
        body: &entry.body,
        frontmatter: &entry.frontmatter,
    };
    let bytes = match request.format.to_ascii_lowercase().as_str() {
        "json" => serde_json::to_vec(&declared)?,
        "yaml" | "yml" => serde_yaml::to_string(&declared).map(|value| value.into_bytes())?,
        value => return Err(CatalogError::UnsupportedFormat(value.into())),
    };
    Ok(HostProjection {
        host_id: request.host_id.clone(),
        source_path: entry.source_path.clone(),
        source_hash: entry.source_hash.clone(),
        format: request.format.clone(),
        lossy: true,
        provenance: format!("declared-projection:{}:{}", request.host_id, request.format),
        bytes,
    })
}

pub fn canonical_bytes(entry: &CatalogEntry) -> &[u8] {
    &entry.source_bytes
}

pub fn projection_metadata(projection: &HostProjection) -> BTreeMap<String, String> {
    [
        ("host_id".into(), projection.host_id.clone()),
        ("source_path".into(), projection.source_path.clone()),
        ("source_hash".into(), projection.source_hash.clone()),
        ("format".into(), projection.format.clone()),
        ("provenance".into(), projection.provenance.clone()),
        ("lossy".into(), projection.lossy.to_string()),
    ]
    .into_iter()
    .collect()
}
