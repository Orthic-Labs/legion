//! Integration tests for the ported `wf_port::w2_027` module (production
//! entry points), mirroring `skills/seo/hooks/pre-commit-seo-check.sh` and
//! `skills/seo/hooks/validate-schema.py`.

use legion_runtime::wf_port::w2_027::{
    check_html_file, hook_exit_code, is_critical_finding, is_schema_checked_extension,
    is_seo_checked_extension, partition_findings, schema_exit_code, should_run_pre_commit_checks,
    validate_jsonld, validate_schema_object, HookTotals, Severity,
};
use std::fs;
use std::path::Path;

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wf_w2_027")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
}

// ---------------------------------------------------------------------
// pre-commit-seo-check.sh: extension filter
// ---------------------------------------------------------------------

#[test]
fn seo_extension_filter_matches_shell_grep_set() {
    for ok in ["a.html", "a.htm", "a.php", "a.jsx", "a.tsx", "a.vue", "a.svelte"] {
        assert!(is_seo_checked_extension(ok), "{ok} should match");
    }
    for bad in ["a.md", "a.css", "a.js", "a.HTML", "html", ".html"] {
        assert!(!is_seo_checked_extension(bad), "{bad} should not match");
    }
}

#[test]
fn schema_extension_filter_matches_python_valid_extensions() {
    for ok in [
        "a.html", "a.htm", "a.jsx", "a.tsx", "a.vue", "a.svelte", "a.php", "a.ejs",
    ] {
        assert!(is_schema_checked_extension(ok), "{ok} should match");
    }
    assert!(!is_schema_checked_extension("a.md"));
}

// ---------------------------------------------------------------------
// pre-commit-seo-check.sh: check_html_file
// ---------------------------------------------------------------------

#[test]
fn clean_html_file_has_no_findings() {
    let content = fixture("clean.html");
    let findings = check_html_file(&content);
    assert!(findings.is_empty(), "expected no findings, got {findings:?}");
}

#[test]
fn placeholder_text_is_a_blocking_error() {
    let content = fixture("placeholder.html");
    let findings = check_html_file(&content);
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Error
            && f.message == "Contains placeholder text in schema markup"));
}

#[test]
fn title_length_outside_30_60_is_a_warning() {
    let short = "<html><head><title>Hi</title></head></html>";
    let findings = check_html_file(short);
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Warning && f.message.starts_with("Title tag length")));

    let ok_title = format!(
        "<html><head><title>{}</title></head></html>",
        "x".repeat(45)
    );
    assert!(check_html_file(&ok_title).is_empty());
}

#[test]
fn image_missing_alt_is_a_warning() {
    let with_alt = r#"<img src="a.png" alt="a cat">"#;
    assert!(check_html_file(with_alt).is_empty());

    let without_alt = r#"<img src="a.png">"#;
    let findings = check_html_file(without_alt);
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Warning && f.message == "Images found without alt text"));
}

#[test]
fn deprecated_schema_type_in_raw_text_is_a_blocking_error() {
    let content = r#"<script type="application/ld+json">{"@type": "HowTo"}</script>"#;
    let findings = check_html_file(content);
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Error && f.message == "Contains deprecated schema type"));
}

#[test]
fn fid_reference_is_a_warning_case_insensitive() {
    for text in ["First Input Delay", "the \"FID\" metric", "first input delay"] {
        let findings = check_html_file(text);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Warning
                && f.message.contains("should use INP")),
            "expected FID warning for {text:?}, got {findings:?}"
        );
    }
}

#[test]
fn meta_description_length_outside_120_160_is_a_warning() {
    let short = r#"<meta name="description" content="too short">"#;
    let findings = check_html_file(short);
    assert!(findings
        .iter()
        .any(|f| f.severity == Severity::Warning
            && f.message.starts_with("Meta description length")));

    let ok_desc = format!(
        r#"<meta name="description" content="{}">"#,
        "x".repeat(140)
    );
    assert!(check_html_file(&ok_desc).is_empty());
}

#[test]
fn multiple_findings_accumulate_in_file_and_across_files() {
    let content = fixture("multi_issue.html");
    let findings = check_html_file(&content);
    // placeholder (error) + img alt (warning) + deprecated type (error)
    // + FID (warning) in the fixture.
    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    assert!(errors >= 2, "expected >=2 errors, got {findings:?}");
    assert!(warnings >= 2, "expected >=2 warnings, got {findings:?}");

    let clean = fixture("clean.html");
    let mut totals = HookTotals::default();
    totals.add(&check_html_file(&content));
    totals.add(&check_html_file(&clean));
    assert_eq!(totals.errors, errors as u32);
    assert_eq!(totals.warnings, warnings as u32);
}

// ---------------------------------------------------------------------
// pre-commit-seo-check.sh: exit code / staged-changes gate
// ---------------------------------------------------------------------

#[test]
fn hook_exit_code_blocks_only_on_errors() {
    assert_eq!(hook_exit_code(HookTotals { errors: 0, warnings: 0 }), 0);
    assert_eq!(hook_exit_code(HookTotals { errors: 0, warnings: 5 }), 0);
    assert_eq!(hook_exit_code(HookTotals { errors: 1, warnings: 0 }), 2);
    assert_eq!(hook_exit_code(HookTotals { errors: 2, warnings: 3 }), 2);
}

#[test]
fn should_run_pre_commit_checks_mirrors_git_diff_cached_quiet_gate() {
    assert!(should_run_pre_commit_checks(true));
    assert!(!should_run_pre_commit_checks(false));
}

// ---------------------------------------------------------------------
// validate-schema.py: validate_jsonld
// ---------------------------------------------------------------------

#[test]
fn no_jsonld_blocks_is_not_an_error() {
    assert!(validate_jsonld("<html><body>no schema here</body></html>").is_empty());
}

#[test]
fn valid_jsonld_block_has_no_findings() {
    let content = fixture("valid_schema.html");
    assert!(validate_jsonld(&content).is_empty());
}

#[test]
fn invalid_json_in_block_reports_one_error_and_skips_object_checks() {
    let content = r#"<script type="application/ld+json">{not valid json</script>"#;
    let errors = validate_jsonld(content);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("Block 1: Invalid JSON;"));
}

#[test]
fn missing_context_and_type_are_reported() {
    let content = r#"<script type="application/ld+json">{"name": "x"}</script>"#;
    let errors = validate_jsonld(content);
    assert!(errors.contains(&"Block 1: Missing @context".to_string()));
    assert!(errors.contains(&"Block 1: Missing @type".to_string()));
}

#[test]
fn wrong_context_value_is_reported() {
    let content = r#"<script type="application/ld+json">
        {"@context": "https://example.com", "@type": "Organization"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors.contains(&"Block 1: @context should be 'https://schema.org'".to_string()));
}

#[test]
fn http_schema_org_context_is_accepted() {
    let content = r#"<script type="application/ld+json">
        {"@context": "http://schema.org", "@type": "Organization"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(!errors.iter().any(|e| e.contains("@context")));
}

#[test]
fn placeholder_text_in_schema_is_reported_case_insensitively() {
    let content = r#"<script type="application/ld+json">
        {"@context": "https://schema.org", "@type": "Organization", "name": "[Business Name]"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors
        .iter()
        .any(|e| e.contains("Contains placeholder text: [Business Name]")));
}

#[test]
fn deprecated_type_is_reported_with_reason() {
    let content = r#"<script type="application/ld+json">
        {"@context": "https://schema.org", "@type": "HowTo"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors
        .iter()
        .any(|e| e == "Block 1: @type 'HowTo' is deprecated September 2023"));
}

#[test]
fn retired_type_message_matches_python_text() {
    let content = r#"<script type="application/ld+json">
        {"@context": "https://schema.org", "@type": "ClaimReview"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors.iter().any(|e| e
        == "Block 1: @type 'ClaimReview' is retired June 2025; fact-check rich results discontinued"));
}

#[test]
fn restricted_faqpage_type_is_reported() {
    let content = r#"<script type="application/ld+json">
        {"@context": "https://schema.org", "@type": "FAQPage"}
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors.iter().any(|e| e
        == "Block 1: @type 'FAQPage' is restricted to government and healthcare sites only (Aug 2023); verify site qualifies"));
}

#[test]
fn array_of_schema_objects_validates_each_item() {
    let content = r#"<script type="application/ld+json">
        [{"@context": "https://schema.org", "@type": "HowTo"},
         {"@type": "Organization"}]
    </script>"#;
    let errors = validate_jsonld(content);
    assert!(errors.iter().any(|e| e.contains("HowTo")));
    assert!(errors.iter().any(|e| e.contains("Missing @context")));
}

#[test]
fn multiple_blocks_are_numbered_in_order() {
    let content = r#"
        <script type="application/ld+json">{"@type": "HowTo", "@context": "https://schema.org"}</script>
        <script type="application/ld+json">{"@type": "Organization"}</script>
    "#;
    let errors = validate_jsonld(content);
    assert!(errors.iter().any(|e| e.starts_with("Block 1:")));
    assert!(errors.iter().any(|e| e.starts_with("Block 2: Missing @context")));
}

#[test]
fn script_tag_matching_is_case_insensitive_and_allows_attribute_order() {
    let content = r#"<SCRIPT TYPE='APPLICATION/LD+JSON'>{"@context": "https://schema.org", "@type": "Organization"}</SCRIPT>"#;
    // Python's regex is case-insensitive on the tag/type literal text too.
    let errors = validate_jsonld(content);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn validate_schema_object_direct_call_matches_validate_jsonld_wrapper() {
    let mut obj = serde_json::Map::new();
    obj.insert("@type".to_string(), serde_json::json!("SpecialAnnouncement"));
    let errors = validate_schema_object(&obj, 7);
    assert!(errors.iter().any(|e| e.starts_with("Block 7:")));
    assert!(errors
        .iter()
        .any(|e| e == "Block 7: @type 'SpecialAnnouncement' is deprecated July 31, 2025"));
}

// ---------------------------------------------------------------------
// validate-schema.py: exit code / critical-warning split
// ---------------------------------------------------------------------

#[test]
fn is_critical_finding_matches_placeholder_deprecated_retired_keywords() {
    assert!(is_critical_finding("Block 1: Contains placeholder text: [City]"));
    assert!(is_critical_finding("Block 1: @type 'HowTo' is deprecated September 2023"));
    assert!(is_critical_finding("Block 1: @type 'ClaimReview' is retired June 2025"));
    assert!(!is_critical_finding("Block 1: Missing @context"));
    assert!(!is_critical_finding("Block 1: Missing @type"));
    assert!(!is_critical_finding(
        "Block 1: @type 'FAQPage' is restricted to government and healthcare sites only (Aug 2023); verify site qualifies"
    ));
}

#[test]
fn schema_exit_code_matches_python_main_branches() {
    assert_eq!(schema_exit_code(&[]), 0);
    assert_eq!(
        schema_exit_code(&["Block 1: Missing @context".to_string()]),
        1
    );
    assert_eq!(
        schema_exit_code(&["Block 1: Contains placeholder text: [City]".to_string()]),
        2
    );
    assert_eq!(
        schema_exit_code(&[
            "Block 1: Missing @context".to_string(),
            "Block 1: @type 'HowTo' is deprecated September 2023".to_string(),
        ]),
        2
    );
}

#[test]
fn partition_findings_splits_critical_from_warnings_preserving_order() {
    let errors = vec![
        "Block 1: Missing @context".to_string(),
        "Block 1: Contains placeholder text: [City]".to_string(),
        "Block 1: Missing @type".to_string(),
    ];
    let (critical, warnings) = partition_findings(&errors);
    assert_eq!(critical, vec!["Block 1: Contains placeholder text: [City]".to_string()]);
    assert_eq!(
        warnings,
        vec![
            "Block 1: Missing @context".to_string(),
            "Block 1: Missing @type".to_string(),
        ]
    );
}
