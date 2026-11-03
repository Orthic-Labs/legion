//! Ported from src/lib/controls/sources/{deduplicate,ingest}.mjs
//! (packet P5b-controls-config).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SourceRecord {
    pub digest: String,
    /// Canonical text of the whole source record, used the way the JS port
    /// uses `JSON.stringify(source)` to detect drift between two records
    /// sharing a digest.
    pub canonical: String,
}

/// Port of `deduplicateSources(sources)`.
pub fn deduplicate_sources(sources: Vec<SourceRecord>) -> Result<Vec<SourceRecord>, String> {
    let mut seen: BTreeMap<String, SourceRecord> = BTreeMap::new();
    for source in sources {
        if let Some(existing) = seen.get(&source.digest) {
            if existing.canonical != source.canonical {
                return Err(format!("source digest drift: {}", source.digest));
            }
        }
        seen.insert(source.digest.clone(), source);
    }
    Ok(seen.into_values().collect())
}

const TERMINAL: &[&str] = &[
    "mapped",
    "merged-as-duplicate",
    "partially-mapped",
    "recommendation-only",
    "product-decision",
    "policy-dependent",
    "rejected-as-non-universal",
    "not-applicable-to-audit",
];

#[derive(Debug, Clone)]
pub struct IngestSource {
    pub digest: String,
    pub rights_status: String,
}

#[derive(Debug, Clone)]
pub struct IngestItem {
    pub disposition: String,
    pub rights_status: Option<String>,
    pub control_ids: Vec<String>,
    pub derived_content: bool,
}

#[derive(Debug, Clone)]
pub struct IngestedItem {
    pub id: String,
    pub disposition: String,
    pub rights_status: Option<String>,
    pub control_ids: Vec<String>,
    pub derived_content: bool,
    pub execution_authority: bool,
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

/// Port of `ingestSource({ source, items })`. Returns the source (with
/// `executionAuthority: false` forced) and the numbered items.
pub fn ingest_source(
    source: &IngestSource,
    items: &[IngestItem],
) -> Result<(IngestSource, Vec<IngestedItem>), String> {
    if !is_sha256(&source.digest) || source.rights_status.is_empty() {
        return Err("source requires valid sha256 digest and rights status".to_string());
    }

    for item in items {
        if !TERMINAL.contains(&item.disposition.as_str()) {
            return Err("source item requires terminal disposition".to_string());
        }
        let rights = item
            .rights_status
            .clone()
            .unwrap_or_else(|| source.rights_status.clone());
        let has_derived = !item.control_ids.is_empty() || item.derived_content;
        if (source.rights_status != "cleared" || rights != "cleared") && has_derived {
            return Err("source item rights do not permit derived controls".to_string());
        }
    }

    let out_source = IngestSource {
        digest: source.digest.clone(),
        rights_status: source.rights_status.clone(),
    };
    let out_items = items
        .iter()
        .enumerate()
        .map(|(index, item)| IngestedItem {
            id: format!("{}:{}", source.digest, index + 1),
            disposition: item.disposition.clone(),
            rights_status: item.rights_status.clone(),
            control_ids: item.control_ids.clone(),
            derived_content: item.derived_content,
            execution_authority: false,
        })
        .collect();

    Ok((out_source, out_items))
}
