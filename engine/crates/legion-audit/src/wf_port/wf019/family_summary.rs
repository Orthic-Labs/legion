//! Port of `buildFamilySummary` from `src/lib/report/families/shared.mjs`.
//!
//! `architecture.mjs`, `code.mjs`, `compatibility.mjs`, and
//! `data-integrity.mjs` (this chunk's owned families) each have no body of
//! their own beyond `export {buildFamilySummary} from './shared.mjs';`, so
//! there is exactly one behaviour to port here.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A provider's expected/examined counters, matching the JS
/// `{expected, examined}` denominator shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Denominator {
    pub expected: f64,
    pub examined: f64,
}

/// One provider result as fed into `buildFamilySummary`, matching the JS
/// destructured `{id, provider, family, complete, status, denominator,
/// tool, rawArtifacts, componentIds, limitations}` (JS reads `result.id`,
/// `result.provider`, and `result.family` directly, and destructures the
/// rest with `[]` defaults on output only).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FamilyResult {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub complete: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub denominator: Option<Denominator>,
    #[serde(default)]
    pub tool: Option<serde_json::Value>,
    #[serde(default, rename = "rawArtifacts")]
    pub raw_artifacts: Vec<serde_json::Value>,
    #[serde(default, rename = "componentIds")]
    pub component_ids: Vec<serde_json::Value>,
    #[serde(default)]
    pub limitations: Vec<serde_json::Value>,
}

/// `result.id ?? result.provider`, used everywhere JS resolves a provider's
/// identity.
fn resolve_id(result: &FamilyResult) -> Option<String> {
    result.id.clone().or_else(|| result.provider.clone())
}

/// The projected provider shape on the summary's `providers` array, matching
/// JS's `{id: id??provider, status, complete, denominator, tool,
/// rawArtifacts, componentIds, limitations}` map, with the `[]` defaults
/// JS gives `rawArtifacts`/`componentIds`/`limitations`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderSummary {
    pub id: Option<String>,
    pub status: Option<String>,
    pub complete: Option<bool>,
    pub denominator: Option<Denominator>,
    pub tool: Option<serde_json::Value>,
    #[serde(rename = "rawArtifacts")]
    pub raw_artifacts: Vec<serde_json::Value>,
    #[serde(rename = "componentIds")]
    pub component_ids: Vec<serde_json::Value>,
    pub limitations: Vec<serde_json::Value>,
}

/// One summary gap. The three JS gap shapes (`family-denominator-zero`
/// carries `family`; `required-provider-missing` /
/// `selected-provider-result-missing` / `provider-result-incomplete` carry
/// `providerId`) are unified here with both fields optional and omitted
/// from JSON when absent, matching which JS object literal actually has
/// which key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryGap {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "providerId")]
    pub provider_id: Option<String>,
}

/// Faithful port of the `buildFamilySummary` return shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FamilySummary {
    pub family: Option<String>,
    pub status: String,
    pub providers: Vec<ProviderSummary>,
    #[serde(rename = "incompleteProviders")]
    pub incomplete_providers: Vec<String>,
    pub gaps: Vec<SummaryGap>,
    pub clean: bool,
}

/// Faithful port of `buildFamilySummary(results, family, {requiredProviderIds,
/// selectedProviderIds})`.
///
/// - `family: None` matches every result (JS `!family` — the JS callers
///   used by `architecture.mjs`/`code.mjs`/`compatibility.mjs`/
///   `data-integrity.mjs` always pass a concrete family name, so `None`
///   only mirrors the falsy branch for completeness).
/// - `expected` is `selectedProviderIds` when non-empty, else
///   `requiredProviderIds` (JS `selectedProviderIds.length ? ... : ...`).
/// - `selected` = results matching family AND (expected empty, or the
///   result's `id ?? provider` is in `expected`).
/// - `missing` = the union of `requiredProviderIds` then `selectedProviderIds`
///   (deduped, first-occurrence order — JS `new Set([...req, ...sel])`
///   preserves insertion order), filtered to ids not present among selected.
/// - `gaps`: a `family-denominator-zero` gap first when `selected` is empty,
///   then one gap per missing id (`selected-provider-result-missing` if it
///   was requested via `selectedProviderIds`, else
///   `required-provider-missing`), then one `provider-result-incomplete`
///   gap per incomplete selected result, in that order — matching the JS
///   push order exactly.
/// - a selected result is "incomplete" when `complete !== true`, or
///   `status !== 'pass'`, or its `denominator` is absent, `expected < 1`,
///   or `examined !== expected`.
/// - `clean` is `incomplete.is_empty() && gaps.is_empty()`; `status` is
///   `"complete"` when clean, else `"incomplete"`.
pub fn build_family_summary(
    results: &[FamilyResult],
    family: Option<&str>,
    required_provider_ids: &[String],
    selected_provider_ids: &[String],
) -> FamilySummary {
    let expected: HashSet<&str> = if !selected_provider_ids.is_empty() {
        selected_provider_ids.iter().map(String::as_str).collect()
    } else {
        required_provider_ids.iter().map(String::as_str).collect()
    };

    let selected: Vec<&FamilyResult> = results
        .iter()
        .filter(|result| {
            let family_match = family.is_none() || result.family.as_deref() == family;
            let id_match = if expected.is_empty() {
                true
            } else {
                resolve_id(result)
                    .map(|id| expected.contains(id.as_str()))
                    .unwrap_or(false)
            };
            family_match && id_match
        })
        .collect();

    let selected_ids: HashSet<String> = selected.iter().filter_map(|r| resolve_id(r)).collect();

    // `new Set([...requiredProviderIds, ...selectedProviderIds])`: dedup,
    // first-occurrence order, required ids checked before selected ids.
    let mut seen: HashSet<&str> = HashSet::new();
    let mut combined_ordered: Vec<&str> = Vec::new();
    for id in required_provider_ids
        .iter()
        .chain(selected_provider_ids.iter())
    {
        if seen.insert(id.as_str()) {
            combined_ordered.push(id.as_str());
        }
    }
    let missing: Vec<String> = combined_ordered
        .into_iter()
        .filter(|id| !selected_ids.contains(*id))
        .map(str::to_string)
        .collect();

    let mut gaps: Vec<SummaryGap> = Vec::new();
    if selected.is_empty() {
        gaps.push(SummaryGap {
            kind: "family-denominator-zero".to_string(),
            family: family.map(str::to_string),
            provider_id: None,
        });
    }
    for id in &missing {
        let kind = if selected_provider_ids.iter().any(|s| s == id) {
            "selected-provider-result-missing"
        } else {
            "required-provider-missing"
        };
        gaps.push(SummaryGap {
            kind: kind.to_string(),
            family: None,
            provider_id: Some(id.clone()),
        });
    }

    let incomplete: Vec<&FamilyResult> = selected
        .iter()
        .copied()
        .filter(|result| {
            result.complete != Some(true)
                || result.status.as_deref() != Some("pass")
                || match &result.denominator {
                    None => true,
                    Some(denominator) => {
                        denominator.expected < 1.0 || denominator.examined != denominator.expected
                    }
                }
        })
        .collect();

    for result in &incomplete {
        gaps.push(SummaryGap {
            kind: "provider-result-incomplete".to_string(),
            family: None,
            provider_id: resolve_id(result),
        });
    }

    let clean = incomplete.is_empty() && gaps.is_empty();

    let providers: Vec<ProviderSummary> = selected
        .iter()
        .map(|result| ProviderSummary {
            id: resolve_id(result),
            status: result.status.clone(),
            complete: result.complete,
            denominator: result.denominator,
            tool: result.tool.clone(),
            raw_artifacts: result.raw_artifacts.clone(),
            component_ids: result.component_ids.clone(),
            limitations: result.limitations.clone(),
        })
        .collect();

    let mut incomplete_providers: Vec<String> =
        incomplete.iter().filter_map(|r| resolve_id(r)).collect();
    incomplete_providers.extend(missing.iter().cloned());

    FamilySummary {
        family: family.map(str::to_string),
        status: if clean { "complete" } else { "incomplete" }.to_string(),
        providers,
        incomplete_providers,
        gaps,
        clean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, family: &str, status: &str, complete: bool, exp: f64, exam: f64) -> FamilyResult {
        FamilyResult {
            id: Some(id.to_string()),
            provider: None,
            family: Some(family.to_string()),
            complete: Some(complete),
            status: Some(status.to_string()),
            denominator: Some(Denominator {
                expected: exp,
                examined: exam,
            }),
            tool: None,
            raw_artifacts: vec![],
            component_ids: vec![],
            limitations: vec![],
        }
    }

    #[test]
    fn clean_when_all_selected_pass_and_no_missing() {
        let results = vec![result("a", "architecture", "pass", true, 3.0, 3.0)];
        let summary = build_family_summary(&results, Some("architecture"), &["a".to_string()], &[]);
        assert!(summary.clean);
        assert_eq!(summary.status, "complete");
        assert!(summary.gaps.is_empty());
        assert_eq!(summary.providers.len(), 1);
        assert_eq!(summary.providers[0].id.as_deref(), Some("a"));
        assert!(summary.incomplete_providers.is_empty());
    }

    #[test]
    fn empty_selection_emits_family_denominator_zero() {
        let results: Vec<FamilyResult> = vec![];
        let summary = build_family_summary(&results, Some("code"), &[], &[]);
        assert!(!summary.clean);
        assert_eq!(summary.status, "incomplete");
        assert_eq!(summary.gaps.len(), 1);
        assert_eq!(summary.gaps[0].kind, "family-denominator-zero");
        assert_eq!(summary.gaps[0].family.as_deref(), Some("code"));
    }

    #[test]
    fn required_provider_missing_is_reported() {
        let results = vec![result("a", "code", "pass", true, 1.0, 1.0)];
        let summary = build_family_summary(
            &results,
            Some("code"),
            &["a".to_string(), "b".to_string()],
            &[],
        );
        assert!(!summary.clean);
        let missing_gap = summary
            .gaps
            .iter()
            .find(|g| g.provider_id.as_deref() == Some("b"))
            .expect("missing gap for b");
        assert_eq!(missing_gap.kind, "required-provider-missing");
        assert_eq!(summary.incomplete_providers, vec!["b".to_string()]);
    }

    #[test]
    fn selected_provider_missing_uses_distinct_kind() {
        let results: Vec<FamilyResult> = vec![];
        let summary = build_family_summary(
            &results,
            Some("compatibility"),
            &[],
            &["only-selected".to_string()],
        );
        let missing_gap = summary
            .gaps
            .iter()
            .find(|g| g.provider_id.as_deref() == Some("only-selected"))
            .expect("missing gap");
        assert_eq!(missing_gap.kind, "selected-provider-result-missing");
    }

    #[test]
    fn incomplete_denominator_is_flagged() {
        let results = vec![result("a", "data-integrity", "pass", true, 4.0, 2.0)];
        let summary = build_family_summary(&results, Some("data-integrity"), &["a".to_string()], &[]);
        assert!(!summary.clean);
        assert_eq!(summary.status, "incomplete");
        let gap = summary
            .gaps
            .iter()
            .find(|g| g.kind == "provider-result-incomplete")
            .expect("incomplete gap");
        assert_eq!(gap.provider_id.as_deref(), Some("a"));
        assert_eq!(summary.incomplete_providers, vec!["a".to_string()]);
    }

    #[test]
    fn missing_denominator_counts_as_incomplete() {
        let mut result = result("a", "architecture", "pass", true, 1.0, 1.0);
        result.denominator = None;
        let summary = build_family_summary(&[result], Some("architecture"), &["a".to_string()], &[]);
        assert!(!summary.clean);
    }

    #[test]
    fn provider_falls_back_to_provider_field_when_id_absent() {
        let mut result = result("unused", "code", "pass", true, 1.0, 1.0);
        result.id = None;
        result.provider = Some("prov-x".to_string());
        let summary = build_family_summary(&[result], Some("code"), &["prov-x".to_string()], &[]);
        assert_eq!(summary.providers[0].id.as_deref(), Some("prov-x"));
        assert!(summary.clean);
    }

    #[test]
    fn required_and_selected_dedupe_first_occurrence_order() {
        let results: Vec<FamilyResult> = vec![];
        let summary = build_family_summary(
            &results,
            Some("code"),
            &["dup".to_string(), "r2".to_string()],
            &["dup".to_string(), "s2".to_string()],
        );
        // "dup" appears once (from required list position), then s2 (selected list adds it).
        let ids: Vec<&str> = summary
            .gaps
            .iter()
            .filter_map(|g| g.provider_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["dup", "r2", "s2"]);
        // "dup" is in selectedProviderIds too, so its kind is the selected variant.
        let dup_gap = summary.gaps.iter().find(|g| g.provider_id.as_deref() == Some("dup")).unwrap();
        assert_eq!(dup_gap.kind, "selected-provider-result-missing");
    }
}
