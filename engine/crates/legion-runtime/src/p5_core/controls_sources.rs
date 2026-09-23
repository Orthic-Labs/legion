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
        hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
        let rights = item.rights_status.clone().unwrap_or_else(|| source.rights_status.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_identical_duplicate() {
        let a = SourceRecord { digest: "d1".into(), canonical: "{}".into() };
        let b = a.clone();
        let result = deduplicate_sources(vec![a, b]).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn dedup_rejects_drifted_duplicate() {
        let a = SourceRecord { digest: "d1".into(), canonical: "{\"a\":1}".into() };
        let b = SourceRecord { digest: "d1".into(), canonical: "{\"a\":2}".into() };
        let err = deduplicate_sources(vec![a, b]).unwrap_err();
        assert_eq!(err, "source digest drift: d1");
    }

    fn valid_source() -> IngestSource {
        IngestSource { digest: format!("sha256:{}", "a".repeat(64)), rights_status: "cleared".into() }
    }

    #[test]
    fn ingest_requires_valid_digest() {
        let bad = IngestSource { digest: "not-a-digest".into(), rights_status: "cleared".into() };
        let err = ingest_source(&bad, &[]).unwrap_err();
        assert_eq!(err, "source requires valid sha256 digest and rights status");
    }

    #[test]
    fn ingest_requires_terminal_disposition() {
        let item = IngestItem { disposition: "pending".into(), rights_status: None, control_ids: vec![], derived_content: false };
        let err = ingest_source(&valid_source(), &[item]).unwrap_err();
        assert_eq!(err, "source item requires terminal disposition");
    }

    #[test]
    fn ingest_blocks_derived_controls_without_cleared_rights() {
        let source = IngestSource { digest: format!("sha256:{}", "a".repeat(64)), rights_status: "restricted".into() };
        let item = IngestItem { disposition: "mapped".into(), rights_status: None, control_ids: vec!["c1".into()], derived_content: false };
        let err = ingest_source(&source, &[item]).unwrap_err();
        assert_eq!(err, "source item rights do not permit derived controls");
    }

    #[test]
    fn ingest_numbers_items_and_clears_execution_authority() {
        let item = IngestItem { disposition: "mapped".into(), rights_status: None, control_ids: vec!["c1".into()], derived_content: false };
        let (out_source, items) = ingest_source(&valid_source(), &[item]).unwrap();
        assert!(!out_source.digest.is_empty());
        assert_eq!(items[0].id, format!("{}:1", valid_source().digest));
        assert!(!items[0].execution_authority);
    }
}
