//! Integration coverage for wf_port chunk w2_031
//! (`skills/seo/scripts/{indexing_notify,indexnow,keyword_planner,
//! nlp_analyze,page_engine}.py`).
//!
//! `page_engine`'s assertions are ported directly from
//! `skills/seo/tests/test_page_engine.py` (the only test file found for
//! this chunk's five scripts). The other four scripts have no existing
//! Python test file; their tests here exercise the pure logic ported from
//! each script's documented behaviour (docstrings + branch bodies).

use legion_runtime::wf_port::w2_031::{indexing_notify, indexnow, keyword_planner, nlp_analyze, page_engine};
use serde_json::json;

fn page_engine_config() -> page_engine::PageEngineConfig {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wf_w2_031/page-engine.json"
    ))
    .expect("fixture page-engine.json present");
    serde_json::from_str(&text).expect("valid page-engine.json")
}

fn valid_contract() -> serde_json::Value {
    json!({
        "page_type": "INFORMATIONAL",
        "primary_intent": "learn how to use the viewer",
        "required_information": ["supported formats", "steps"],
        "proof_evidence": ["product docs"],
        "internal_link_role": "documentation spoke",
    })
}

// ---------------------------------------------------------------------
// page_engine — ported from skills/seo/tests/test_page_engine.py
// ---------------------------------------------------------------------

#[test]
fn test_structural_blocker_precedes_copy() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {
            "url": "https://e/guide",
            "page_type": "INFORMATIONAL",
            "canonical_expected": "https://e/guide",
            "canonical_observed": "https://e/other",
            "intended_indexable": true,
            "observed_indexable": false,
        },
        "page_contract": valid_contract(),
        "query_ownership": [{"query": "how to use", "classification": "ownership switching"}],
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    let kinds: Vec<&str> = result["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["type"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"canonical_mismatch"));
    assert!(kinds.contains(&"wrong_indexability"));
    assert!(kinds.contains(&"multiple_owners_one_intent"));
}

#[test]
fn test_expand_requires_real_information_gain() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/guide"},
        "page_contract": valid_contract(),
        "verdict": "EXPAND",
        "information_gain": [{"type": "better_synthesis"}],
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "fail");
    let errors: Vec<&str> = result["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
    assert!(errors.contains(&"EXPAND requires demonstrated information gain"));
}

#[test]
fn test_verified_information_gain_allows_expand() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/guide"},
        "page_contract": valid_contract(),
        "verdict": "EXPAND",
        "information_gain": [{"type": "first_party_data", "evidence": "support-ticket analysis"}],
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["verdict"], "EXPAND");
}

#[test]
fn test_unverified_claim_cannot_ship() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/guide"},
        "page_contract": valid_contract(),
        "claims": [{"claim": "Used by one million customers", "state": "requires_verification", "use_in_output": true}],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "fail");
}

#[test]
fn test_destructive_verdict_requires_justification() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/legacy"},
        "page_contract": valid_contract(),
        "verdict": "REDIRECT",
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "fail");
}

#[test]
fn page_engine_no_verdict_no_blockers_recommends_keep() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/guide"},
        "page_contract": valid_contract(),
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["verdict"], "KEEP");
}

#[test]
fn page_engine_missing_contract_field_is_investigate() {
    let cfg = page_engine_config();
    let bundle = json!({
        "page": {"url": "https://e/guide"},
        "page_contract": {"page_type": "INFORMATIONAL"},
        "claims": [],
    });
    let result = page_engine::assess(&cfg, &bundle);
    assert_eq!(result["status"], "fail");
    assert_eq!(result["verdict"], "INVESTIGATE");
}

// ---------------------------------------------------------------------
// indexnow.py
// ---------------------------------------------------------------------

#[test]
fn indexnow_genkey_is_32_lowercase_hex_chars() {
    let key = indexnow::genkey();
    assert_eq!(key.len(), 32);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Two calls should not collide.
    assert_ne!(key, indexnow::genkey());
}

#[test]
fn indexnow_default_key_location_matches_python_fstring() {
    assert_eq!(
        indexnow::default_key_location("example.com", "abc123"),
        "https://example.com/abc123.txt"
    );
}

#[test]
fn indexnow_build_submit_body_includes_key_location_when_given() {
    let urls = vec!["https://example.com/a".to_string()];
    let body = indexnow::build_submit_body("example.com", &urls, "thekey", Some("https://example.com/thekey.txt"));
    assert_eq!(body["host"], "example.com");
    assert_eq!(body["key"], "thekey");
    assert_eq!(body["urlList"][0], "https://example.com/a");
    assert_eq!(body["keyLocation"], "https://example.com/thekey.txt");
}

#[test]
fn indexnow_build_submit_body_omits_key_location_when_none() {
    let urls = vec!["https://example.com/a".to_string()];
    let body = indexnow::build_submit_body("example.com", &urls, "thekey", None);
    assert!(body.get("keyLocation").is_none());
}

#[test]
fn indexnow_parse_urls_file_skips_blank_lines() {
    let contents = "https://a\n\n  https://b  \n\nhttps://c\n";
    assert_eq!(
        indexnow::parse_urls_file(contents),
        vec!["https://a".to_string(), "https://b".to_string(), "https://c".to_string()]
    );
}

struct FakeTransport {
    response: Result<(u16, String), String>,
}

impl indexnow::Transport for FakeTransport {
    fn post_json(&self, _url: &str, _body: &serde_json::Value) -> Result<(u16, String), String> {
        self.response.clone()
    }
}

#[test]
fn indexnow_submit_with_success_status_is_accepted() {
    let transport = FakeTransport { response: Ok((202, String::new())) };
    let urls = vec!["https://example.com/a".to_string()];
    let result = indexnow::submit_with(&transport, "example.com", &urls, "key", None);
    assert_eq!(result.status, 202);
    assert_eq!(result.submitted, 1);
    assert!(result.error.is_none());
    assert!(indexnow::is_accepted(&result));
}

#[test]
fn indexnow_submit_with_http_error_reports_zero_submitted() {
    let transport = FakeTransport { response: Ok((403, "forbidden body".to_string())) };
    let urls = vec!["https://example.com/a".to_string()];
    let result = indexnow::submit_with(&transport, "example.com", &urls, "key", None);
    assert_eq!(result.status, 403);
    assert_eq!(result.submitted, 0);
    assert!(result.error.is_some());
    assert!(!indexnow::is_accepted(&result));
}

#[test]
fn indexnow_submit_with_transport_failure_has_zero_status() {
    let transport = FakeTransport { response: Err("connection refused".to_string()) };
    let urls = vec!["https://example.com/a".to_string()];
    let result = indexnow::submit_with(&transport, "example.com", &urls, "key", None);
    assert_eq!(result.status, 0);
    assert_eq!(result.error.as_deref(), Some("connection refused"));
    assert!(!indexnow::is_accepted(&result));
}

// ---------------------------------------------------------------------
// indexing_notify.py
// ---------------------------------------------------------------------

#[test]
fn indexing_notify_action_round_trips() {
    assert_eq!(indexing_notify::NotifyAction::UrlUpdated.as_str(), "URL_UPDATED");
    assert_eq!(indexing_notify::NotifyAction::UrlDeleted.as_str(), "URL_DELETED");
    assert_eq!(indexing_notify::NotifyAction::parse("URL_UPDATED"), Some(indexing_notify::NotifyAction::UrlUpdated));
    assert_eq!(indexing_notify::NotifyAction::parse("bogus"), None);
}

#[test]
fn indexing_notify_build_body_matches_python_shape() {
    let body = indexing_notify::build_notify_body("https://example.com/jobs/1", indexing_notify::NotifyAction::UrlDeleted);
    assert_eq!(body["url"], "https://example.com/jobs/1");
    assert_eq!(body["type"], "URL_DELETED");
}

#[test]
fn indexing_notify_categorize_publish_error_403() {
    let msg = indexing_notify::categorize_publish_error("403 Forbidden: not owner");
    assert!(msg.starts_with("Permission denied."));
}

#[test]
fn indexing_notify_categorize_publish_error_429() {
    let msg = indexing_notify::categorize_publish_error("429 rate limited");
    assert!(msg.contains("Quota exceeded. Daily limit: 200 publish requests."));
}

#[test]
fn indexing_notify_categorize_publish_error_400() {
    let msg = indexing_notify::categorize_publish_error("400 bad url");
    assert_eq!(msg, "Invalid URL or request: 400 bad url");
}

#[test]
fn indexing_notify_categorize_publish_error_other() {
    let msg = indexing_notify::categorize_publish_error("timeout");
    assert_eq!(msg, "Indexing API error: timeout");
}

#[test]
fn indexing_notify_categorize_metadata_error_404_vs_other() {
    assert_eq!(
        indexing_notify::categorize_metadata_error("404 not found"),
        "No notification metadata found for this URL."
    );
    assert_eq!(indexing_notify::categorize_metadata_error("boom"), "Error fetching metadata: boom");
}

#[test]
fn indexing_notify_plan_batch_under_50_has_no_warning() {
    let urls: Vec<String> = (0..10).map(|i| format!("https://e/{i}")).collect();
    let (planned, warning) = indexing_notify::plan_batch(urls.clone());
    assert_eq!(planned, urls);
    assert!(warning.is_none());
}

#[test]
fn indexing_notify_plan_batch_over_50_warns_without_truncating() {
    let urls: Vec<String> = (0..60).map(|i| format!("https://e/{i}")).collect();
    let (planned, warning) = indexing_notify::plan_batch(urls.clone());
    assert_eq!(planned.len(), 60);
    let warning = warning.expect("warning expected");
    assert!(warning.contains("60 URLs will use 60/200"));
}

#[test]
fn indexing_notify_plan_batch_over_quota_truncates_to_200() {
    let urls: Vec<String> = (0..250).map(|i| format!("https://e/{i}")).collect();
    let (planned, warning) = indexing_notify::plan_batch(urls);
    assert_eq!(planned.len(), 200);
    // Spec (`batch_notify` in `skills/seo/scripts/indexing_notify.py`):
    // the `len(urls) > 50` check runs unconditionally after the truncation
    // check and unconditionally overwrites `quota_warning`, so after
    // truncating to 200 (> 50) the final warning is the "will use N/200"
    // message, not the "exceeds daily quota" one.
    let warning = warning.expect("warning expected");
    assert!(warning.contains("Submitting 200 URLs will use 200/200"));
}

#[test]
fn indexing_notify_estimated_remaining_quota_floors_at_zero() {
    assert_eq!(indexing_notify::estimated_remaining_quota(0), 200);
    assert_eq!(indexing_notify::estimated_remaining_quota(200), 0);
    assert_eq!(indexing_notify::estimated_remaining_quota(250), 0);
}

struct FakeIndexingClient {
    responses: std::cell::RefCell<Vec<Result<serde_json::Value, String>>>,
}

impl indexing_notify::IndexingClient for FakeIndexingClient {
    fn publish(&self, _body: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.responses.borrow_mut().remove(0)
    }
    fn get_metadata(&self, _url: &str) -> Result<serde_json::Value, String> {
        unimplemented!()
    }
}

#[test]
fn indexing_notify_url_with_success_extracts_notify_time() {
    let client = FakeIndexingClient {
        responses: std::cell::RefCell::new(vec![Ok(json!({
            "urlNotificationMetadata": {"latestUpdate": {"url": "https://e/1", "type": "URL_UPDATED", "notifyTime": "2026-01-01T00:00:00Z"}}
        }))]),
    };
    let result = indexing_notify::notify_url_with(&client, "https://e/1", indexing_notify::NotifyAction::UrlUpdated);
    assert_eq!(result.notify_time.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert!(result.error.is_none());
}

#[test]
fn indexing_notify_batch_notify_does_not_actually_stop_on_quota_error() {
    // Spec (`batch_notify` in `skills/seo/scripts/indexing_notify.py`):
    // the stop check is `if "429" in str(notification.get("error", ""))`,
    // but `notification["error"]` is already the *categorized* message
    // from `notify_url`'s `except` block — which for a 429 renders as
    // "Quota exceeded. Daily limit: ..." and never contains the literal
    // substring "429". So this stop-on-quota branch is dead code in the
    // original Python too; batch_notify runs every URL regardless. Ported
    // faithfully, bug included.
    let client = FakeIndexingClient {
        responses: std::cell::RefCell::new(vec![
            Ok(json!({"urlNotificationMetadata": {"latestUpdate": {"notifyTime": "t1"}}})),
            Err("429 quota".to_string()),
            Ok(json!({"urlNotificationMetadata": {"latestUpdate": {"notifyTime": "t3"}}})),
        ]),
    };
    let urls = vec!["https://e/1".to_string(), "https://e/2".to_string(), "https://e/3".to_string()];
    let (results, summary, _warning, stop_error) =
        indexing_notify::batch_notify_with(&client, &urls, indexing_notify::NotifyAction::UrlUpdated);
    assert_eq!(results.len(), 3);
    assert_eq!(summary.success, 2);
    assert_eq!(summary.error, 1);
    assert_eq!(stop_error, None);
}

// ---------------------------------------------------------------------
// keyword_planner.py
// ---------------------------------------------------------------------

#[test]
fn keyword_planner_normalize_customer_id_strips_dashes() {
    assert_eq!(keyword_planner::normalize_customer_id("123-456-7890"), "1234567890");
}

#[test]
fn keyword_planner_split_keywords_trims_each() {
    assert_eq!(
        keyword_planner::split_keywords(" seo tools , seo audit ,seo checker"),
        vec!["seo tools".to_string(), "seo audit".to_string(), "seo checker".to_string()]
    );
}

#[test]
fn keyword_planner_micros_to_currency() {
    assert_eq!(keyword_planner::micros_to_currency(Some(2_500_000)), Some(2.5));
    assert_eq!(keyword_planner::micros_to_currency(Some(0)), None);
    assert_eq!(keyword_planner::micros_to_currency(None), None);
}

fn idea(keyword: &str, avg: Option<i64>) -> keyword_planner::KeywordIdea {
    keyword_planner::KeywordIdea {
        keyword: keyword.to_string(),
        avg_monthly_searches: avg,
        competition: "LOW".to_string(),
        competition_index: None,
        low_top_of_page_bid: None,
        high_top_of_page_bid: None,
        monthly_volumes: vec![],
    }
}

#[test]
fn keyword_planner_sort_ideas_desc_treats_none_as_zero() {
    let mut ideas = vec![idea("a", Some(10)), idea("b", None), idea("c", Some(50))];
    keyword_planner::sort_ideas_desc(&mut ideas);
    let order: Vec<&str> = ideas.iter().map(|i| i.keyword.as_str()).collect();
    assert_eq!(order, vec!["c", "a", "b"]);
}

#[test]
fn keyword_planner_last_12_months_keeps_tail() {
    let volumes: Vec<_> = (1..=15)
        .map(|m| keyword_planner::MonthlyVolume { year: 2026, month: m, volume: m as i64 * 10 })
        .collect();
    let kept = keyword_planner::last_12_months(volumes);
    assert_eq!(kept.len(), 12);
    assert_eq!(kept.first().unwrap().month, 4);
    assert_eq!(kept.last().unwrap().month, 15);
}

#[test]
fn keyword_planner_format_bid_str() {
    assert_eq!(keyword_planner::format_bid_str(Some(1.5), Some(3.25)), "$1.50-$3.25");
    assert_eq!(keyword_planner::format_bid_str(None, Some(3.25)), "N/A");
    assert_eq!(keyword_planner::format_bid_str(Some(0.0), Some(3.25)), "N/A");
}

#[test]
fn keyword_planner_join_ads_error_messages() {
    let msgs = vec!["invalid customer id".to_string(), "quota exceeded".to_string()];
    assert_eq!(
        keyword_planner::join_ads_error_messages(&msgs),
        "Google Ads API error: invalid customer id; quota exceeded"
    );
}

// ---------------------------------------------------------------------
// nlp_analyze.py
// ---------------------------------------------------------------------

#[test]
fn nlp_analyze_feature_api_name_maps_classify_and_categories_together() {
    assert_eq!(nlp_analyze::feature_api_name("entities"), Some("extractEntities"));
    assert_eq!(nlp_analyze::feature_api_name("classify"), Some("classifyText"));
    assert_eq!(nlp_analyze::feature_api_name("categories"), Some("classifyText"));
    assert_eq!(nlp_analyze::feature_api_name("bogus"), None);
}

#[test]
fn nlp_analyze_build_feature_map_dedupes_classify_categories() {
    let features = vec!["classify".to_string(), "categories".to_string(), "sentiment".to_string()];
    let map = nlp_analyze::build_feature_map(&features);
    assert_eq!(map.len(), 2);
    assert!(map.contains(&("classifyText".to_string(), true)));
    assert!(map.contains(&("extractDocumentSentiment".to_string(), true)));
}

#[test]
fn nlp_analyze_categorize_http_status() {
    assert!(nlp_analyze::categorize_http_status(403).unwrap().starts_with("Cloud Natural Language API access denied."));
    assert_eq!(nlp_analyze::categorize_http_status(429).unwrap(), "NLP API quota exceeded. Free tier: 5,000 units/month.");
    assert_eq!(nlp_analyze::categorize_http_status(200), None);
}

#[test]
fn nlp_analyze_sentiment_tone_thresholds() {
    assert_eq!(nlp_analyze::sentiment_tone(0.3), "positive");
    assert_eq!(nlp_analyze::sentiment_tone(-0.3), "negative");
    assert_eq!(nlp_analyze::sentiment_tone(0.1), "neutral");
    assert_eq!(nlp_analyze::sentiment_tone(0.25), "neutral");
}

#[test]
fn nlp_analyze_sentiment_interpretation_format() {
    let text = nlp_analyze::sentiment_interpretation(0.42, 3.1);
    assert_eq!(text, "Positive (score: 0.42) with high emotional content (magnitude: 3.10)");
}

#[test]
fn nlp_analyze_build_sentiment_none_when_empty() {
    assert!(nlp_analyze::build_sentiment(&json!({}), &[]).is_none());
}

#[test]
fn nlp_analyze_build_sentiment_computes_sentence_extremes() {
    let sentiment = nlp_analyze::build_sentiment(
        &json!({"score": 0.5, "magnitude": 1.2}),
        &[json!({"sentiment": {"score": 0.9}}), json!({"sentiment": {"score": -0.3}})],
    )
    .unwrap();
    assert_eq!(sentiment.tone, "positive");
    assert_eq!(sentiment.sentence_count, Some(2));
    assert_eq!(sentiment.most_positive, Some(0.9));
    assert_eq!(sentiment.most_negative, Some(-0.3));
}

#[test]
fn nlp_analyze_parse_entity_and_sort_by_salience() {
    let mut entities = vec![
        nlp_analyze::parse_entity(&json!({"name": "low", "type": "PERSON", "salience": 0.1})),
        nlp_analyze::parse_entity(&json!({"name": "high", "type": "ORGANIZATION", "salience": 0.9})),
    ];
    nlp_analyze::sort_entities_by_salience(&mut entities);
    assert_eq!(entities[0].name, "high");
    assert_eq!(entities[1].name, "low");
}

#[test]
fn nlp_analyze_parse_moderation_filters_low_confidence() {
    let raw = vec![json!({"name": "Violence", "confidence": 0.9}), json!({"name": "Mild", "confidence": 0.4})];
    let mods = nlp_analyze::parse_moderation(&raw);
    assert_eq!(mods.len(), 1);
    assert_eq!(mods[0].name, "Violence");
}

#[test]
fn nlp_analyze_extract_text_fallback_strips_script_style_and_tags() {
    let html = "<html><head><style>.a{color:red}</style></head><body><script>alert(1)</script><p>Hello  world</p></body></html>";
    let text = nlp_analyze::extract_text_fallback(html);
    assert_eq!(text, "Hello world");
}

#[test]
fn nlp_analyze_text_too_short() {
    assert!(nlp_analyze::text_too_short(""));
    assert!(nlp_analyze::text_too_short("short"));
    assert!(!nlp_analyze::text_too_short(&"a".repeat(50)));
}

#[test]
fn nlp_analyze_build_result_from_response_end_to_end() {
    let data = json!({
        "entities": [
            {"name": "Acme", "type": "ORGANIZATION", "salience": 0.8, "mentions": [{}, {}]},
            {"name": "Widget", "type": "CONSUMER_GOOD", "salience": 0.9, "mentions": [{}]},
        ],
        "documentSentiment": {"score": 0.6, "magnitude": 1.5},
        "sentences": [{"sentiment": {"score": 0.6}}],
        "categories": [{"name": "/Business", "confidence": 0.8}],
        "moderationCategories": [{"name": "Profanity", "confidence": 0.7}],
    });
    let result = nlp_analyze::build_result_from_response(120, "en", &data);
    assert_eq!(result.text_length, 120);
    assert_eq!(result.entities[0].name, "Widget");
    assert_eq!(result.entities[1].name, "Acme");
    assert_eq!(result.entities[1].mention_count, 2);
    assert_eq!(result.sentiment.unwrap().tone, "positive");
    assert_eq!(result.categories[0].name, "/Business");
    assert_eq!(result.moderation[0].name, "Profanity");
    assert!(result.error.is_none());
}
