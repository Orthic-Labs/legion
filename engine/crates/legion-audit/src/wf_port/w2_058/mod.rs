//! wf_port w2_058 — port of `src/providers/accessibility/contrast.mjs`.
//!
//! The JS source is a thin wrapper:
//!
//! ```js
//! import { analyzeColorPairs } from '../visual/color.mjs';
//! export function analyzeContrast(pairs) {
//!   const result = analyzeColorPairs(pairs);
//!   return { ...result, provider: 'accessibility.contrast' };
//! }
//! ```
//!
//! `analyzeColorPairs` itself (from `src/providers/visual/color.mjs`) is
//! already ported, byte-for-byte in behaviour, as
//! [`crate::native_providers::p11c_experience::visual::analyze_color_pairs`]
//! (chunk w2_014 / `p11c_experience::visual`). This module only reproduces
//! the `accessibility.contrast` wrapper: it delegates to that existing
//! port and overrides the `provider` field, exactly as the JS spread does.

use crate::native_providers::p11c_experience::visual::analyze_color_pairs;
use serde_json::Value;

/// Mirrors `analyzeContrast(pairs)` from `accessibility/contrast.mjs`.
///
/// Delegates to the already-ported `analyze_color_pairs` and overwrites
/// `provider` with `"accessibility.contrast"`, matching the JS object
/// spread `{ ...result, provider: 'accessibility.contrast' }`.
pub fn analyze_contrast(pairs: &[Value]) -> Value {
    let mut result = analyze_color_pairs(pairs);
    if let Value::Object(map) = &mut result {
        map.insert("provider".to_string(), Value::String("accessibility.contrast".to_string()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn provider_is_overridden_to_accessibility_contrast() {
        let out = analyze_contrast(&[]);
        assert_eq!(out["provider"], json!("accessibility.contrast"));
    }

    #[test]
    fn empty_pairs_pass_with_zero_denominator() {
        let out = analyze_contrast(&[]);
        assert_eq!(out["status"], json!("pass"));
        assert_eq!(out["complete"], json!(false));
        assert_eq!(out["denominator"]["expected"], json!(0));
        assert_eq!(out["denominator"]["examined"], json!(0));
        assert!(out["findings"].as_array().unwrap().is_empty());
        assert!(out["coverageGaps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn passing_pair_is_complete_with_no_findings() {
        // Black on white: ratio 21, well above the default 4.5 minimum.
        let pairs = [json!({ "foreground": "#000000", "background": "#ffffff" })];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["provider"], json!("accessibility.contrast"));
        assert_eq!(out["status"], json!("pass"));
        assert_eq!(out["complete"], json!(true));
        assert_eq!(out["denominator"]["expected"], json!(1));
        assert_eq!(out["denominator"]["examined"], json!(1));
        assert!(out["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn failing_pair_is_reported_as_candidate_with_ratio() {
        // Light gray on white: ratio well under 4.5.
        let pairs = [json!({ "foreground": "#cccccc", "background": "#ffffff" })];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["status"], json!("candidates"));
        assert_eq!(out["complete"], json!(true));
        let findings = out["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["foreground"], json!("#cccccc"));
        assert_eq!(findings[0]["background"], json!("#ffffff"));
        assert!(findings[0]["ratio"].as_f64().unwrap() < 4.5);
    }

    #[test]
    fn custom_minimum_is_respected() {
        // Ratio for #777777 on #ffffff is ~4.47; passes a lowered minimum.
        let pairs = [json!({ "foreground": "#777777", "background": "#ffffff", "minimum": 3.0 })];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["status"], json!("pass"));
        assert!(out["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn unresolved_pair_is_a_coverage_gap_and_status_unproven() {
        let pairs = [json!({ "foreground": "not-a-color", "background": "#ffffff" })];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["status"], json!("unproven"));
        assert_eq!(out["complete"], json!(false));
        assert_eq!(out["denominator"]["expected"], json!(1));
        assert_eq!(out["denominator"]["examined"], json!(0));
        assert!(out["findings"].as_array().unwrap().is_empty());
        let gaps = out["coverageGaps"].as_array().unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], json!("color-pair-unresolved"));
    }

    #[test]
    fn missing_foreground_or_background_is_unresolved() {
        let pairs = [json!({ "background": "#ffffff" }), json!({ "foreground": "#000000" }), json!({})];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["status"], json!("unproven"));
        assert_eq!(out["denominator"]["expected"], json!(3));
        assert_eq!(out["denominator"]["examined"], json!(0));
        assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn mixed_resolved_and_unresolved_pairs() {
        let pairs = [
            json!({ "foreground": "#000000", "background": "#ffffff" }), // pass
            json!({ "foreground": "#cccccc", "background": "#ffffff" }), // finding
            json!({ "foreground": "bogus", "background": "#ffffff" }),   // gap
        ];
        let out = analyze_contrast(&pairs);
        assert_eq!(out["status"], json!("candidates")); // findings take priority over gaps
        assert_eq!(out["complete"], json!(false)); // coverage gap present
        assert_eq!(out["denominator"]["expected"], json!(3));
        assert_eq!(out["denominator"]["examined"], json!(2));
        assert_eq!(out["findings"].as_array().unwrap().len(), 1);
        assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 1);
    }
}
