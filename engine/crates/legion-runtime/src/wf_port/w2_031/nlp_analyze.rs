//! Port of `skills/seo/scripts/nlp_analyze.py`.
//!
//! Google Cloud Natural Language API — entity, sentiment, and content
//! analysis, enhancing E-E-A-T scoring with NLP entity coverage, sentiment
//! analysis, and Google's own content classification taxonomy.
//!
//! This module ports the pure logic: feature-name mapping, request-body
//! shaping, sentiment tone/interpretation classification, entity sorting,
//! moderation filtering, and HTTP-status error categorization. The actual
//! network call (`requests.post` to
//! `https://language.googleapis.com/v2/documents:annotateText`, and the
//! URL-fetch + HTML-text-extraction in `analyze_url`) needs an HTTP client
//! this crate does not currently depend on (see the w2_031 report for the
//! `reqwest` `Cargo.toml` addition). Callers supply the API response via
//! [`build_result_from_response`] after making the call themselves (or
//! behind a small transport of their own), and get back the exact same
//! result shape Python's `analyze_text` builds.

use serde_json::{json, Value};

pub const NLP_ENDPOINT: &str = "https://language.googleapis.com/v2/documents:annotateText";

/// `FEATURES` dict in Python: CLI feature name -> API feature flag name.
/// `classify` and `categories` are aliases that both map to
/// `classifyText`.
pub fn feature_api_name(feature: &str) -> Option<&'static str> {
    match feature {
        "entities" => Some("extractEntities"),
        "sentiment" => Some("extractDocumentSentiment"),
        "classify" | "categories" => Some("classifyText"),
        "moderate" => Some("moderateText"),
        _ => None,
    }
}

/// `feature_map = {}` build loop in `analyze_text`: unknown feature names
/// are silently skipped, and duplicate API feature names collapse (a
/// Python dict, so insertion order of first-seen key is kept — here we use
/// a small ordered vec-of-pairs to mirror that instead of `BTreeMap`,
/// which would reorder).
pub fn build_feature_map(features: &[String]) -> Vec<(String, bool)> {
    let mut map: Vec<(String, bool)> = Vec::new();
    for f in features {
        if let Some(api_feature) = feature_api_name(f) {
            if !map.iter().any(|(k, _)| k == api_feature) {
                map.push((api_feature.to_string(), true));
            }
        }
    }
    map
}

/// `body = {"document": {...}, "features": feature_map, "encodingType": "UTF8"}`.
/// `text[:100000]` truncation matches the API's documented limit.
pub fn build_request_body(text: &str, features: &[String], language: &str) -> Value {
    let truncated: String = text.chars().take(100_000).collect();
    let feature_map: serde_json::Map<String, Value> = build_feature_map(features)
        .into_iter()
        .map(|(k, v)| (k, Value::Bool(v)))
        .collect();
    json!({
        "document": {
            "type": "PLAIN_TEXT",
            "content": truncated,
            "languageCode": language,
        },
        "features": feature_map,
        "encodingType": "UTF8",
    })
}

/// HTTP-status error branches at the top of `analyze_text`, checked before
/// `resp.raise_for_status()`.
pub fn categorize_http_status(status: u16) -> Option<String> {
    match status {
        403 => Some(
            "Cloud Natural Language API access denied. Enable it in GCP Console: \
APIs & Services > Library > Cloud Natural Language API. Billing must be enabled on the project."
                .to_string(),
        ),
        429 => Some("NLP API quota exceeded. Free tier: 5,000 units/month.".to_string()),
        _ => None,
    }
}

/// `except requests.exceptions.RequestException as e: f"NLP API request failed: {e}"`.
pub fn request_failed_message(e: &str) -> String {
    format!("NLP API request failed: {e}")
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    pub name: String,
    pub r#type: String,
    pub salience: f64,
    pub sentiment_score: Option<f64>,
    pub sentiment_magnitude: Option<f64>,
    pub mention_count: usize,
    pub metadata: Value,
}

/// Rounds like Python's `round(x, ndigits)` (half-to-even is Python 3's
/// actual behaviour, but for the salience/score/magnitude values coming
/// from a JSON float API response, ties at exactly `.5` at the 3rd/4th
/// decimal are astronomically unlikely; this uses ordinary round-half-away
/// -from-zero, matching typical float display expectations and Rust's
/// `f64::round` after scaling).
fn round_to(value: f64, ndigits: i32) -> f64 {
    let factor = 10f64.powi(ndigits);
    (value * factor).round() / factor
}

/// Builds one `Entity` from a raw API entity JSON object, mirroring the
/// `for entity in data.get("entities", [])` loop body.
pub fn parse_entity(entity: &Value) -> Entity {
    let mentions = entity.get("mentions").and_then(Value::as_array);
    let sentiment = entity.get("sentiment");
    Entity {
        name: entity.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
        r#type: entity.get("type").and_then(Value::as_str).unwrap_or("UNKNOWN").to_string(),
        salience: round_to(entity.get("salience").and_then(Value::as_f64).unwrap_or(0.0), 4),
        sentiment_score: sentiment.and_then(|s| s.get("score")).and_then(Value::as_f64),
        sentiment_magnitude: sentiment.and_then(|s| s.get("magnitude")).and_then(Value::as_f64),
        mention_count: mentions.map(|m| m.len()).unwrap_or(0),
        metadata: entity.get("metadata").cloned().unwrap_or(json!({})),
    }
}

/// `result["entities"].sort(key=lambda e: e["salience"], reverse=True)`.
/// Stable descending sort — Python's `list.sort` is stable, and Rust's
/// `sort_by` is too.
pub fn sort_entities_by_salience(entities: &mut [Entity]) {
    entities.sort_by(|a, b| b.salience.partial_cmp(&a.salience).unwrap_or(std::cmp::Ordering::Equal));
}

/// `score > 0.25` positive / `score < -0.25` negative / else neutral.
pub fn sentiment_tone(score: f64) -> &'static str {
    if score > 0.25 {
        "positive"
    } else if score < -0.25 {
        "negative"
    } else {
        "neutral"
    }
}

/// `result["sentiment"]["interpretation"]` f-string, built from the same
/// three-way branches Python uses independently for the polarity word and
/// the magnitude word.
pub fn sentiment_interpretation(score: f64, magnitude: f64) -> String {
    let polarity = if score > 0.0 {
        "Positive"
    } else if score < 0.0 {
        "Negative"
    } else {
        "Neutral"
    };
    let strength = if magnitude > 2.0 {
        "high"
    } else if magnitude > 0.5 {
        "moderate"
    } else {
        "low"
    };
    format!(
        "{polarity} (score: {score:.2}) with {strength} emotional content (magnitude: {magnitude:.2})"
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct SentimentResult {
    pub score: f64,
    pub magnitude: f64,
    pub tone: &'static str,
    pub interpretation: String,
    pub sentence_count: Option<usize>,
    pub most_positive: Option<f64>,
    pub most_negative: Option<f64>,
}

/// Builds the `result["sentiment"]` block from `data["documentSentiment"]`
/// and `data["sentences"]`, mirroring the `if doc_sentiment:` branch
/// (returns `None` when the API returned no document sentiment at all,
/// matching `if doc_sentiment:` being falsy for `{}`).
pub fn build_sentiment(doc_sentiment: &Value, sentences: &[Value]) -> Option<SentimentResult> {
    if doc_sentiment.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return None;
    }
    let score = round_to(doc_sentiment.get("score").and_then(Value::as_f64).unwrap_or(0.0), 3);
    let magnitude = round_to(doc_sentiment.get("magnitude").and_then(Value::as_f64).unwrap_or(0.0), 3);
    let tone = sentiment_tone(score);
    let interpretation = sentiment_interpretation(score, magnitude);

    let (sentence_count, most_positive, most_negative) = if sentences.is_empty() {
        (None, None, None)
    } else {
        let scores: Vec<f64> = sentences
            .iter()
            .map(|s| s.get("sentiment").and_then(|se| se.get("score")).and_then(Value::as_f64).unwrap_or(0.0))
            .collect();
        let max = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min = scores.iter().cloned().fold(f64::INFINITY, f64::min);
        (Some(sentences.len()), Some(max), Some(min))
    };

    Some(SentimentResult { score, magnitude, tone, interpretation, sentence_count, most_positive, most_negative })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Category {
    pub name: String,
    pub confidence: f64,
}

/// `for cat in data.get("categories", [])`.
pub fn parse_categories(categories: &[Value]) -> Vec<Category> {
    categories
        .iter()
        .map(|c| Category {
            name: c.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
            confidence: round_to(c.get("confidence").and_then(Value::as_f64).unwrap_or(0.0), 4),
        })
        .collect()
}

/// `for mod in data.get("moderationCategories", []): if mod.get("confidence", 0) > 0.5`.
pub fn parse_moderation(moderation_categories: &[Value]) -> Vec<Category> {
    moderation_categories
        .iter()
        .filter(|m| m.get("confidence").and_then(Value::as_f64).unwrap_or(0.0) > 0.5)
        .map(|m| Category {
            name: m.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
            confidence: round_to(m.get("confidence").and_then(Value::as_f64).unwrap_or(0.0), 4),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct NlpResult {
    pub text_length: usize,
    pub language: String,
    pub entities: Vec<Entity>,
    pub sentiment: Option<SentimentResult>,
    pub categories: Vec<Category>,
    pub moderation: Vec<Category>,
    pub error: Option<String>,
}

/// Builds the full `analyze_text` result from a successful API response
/// body, mirroring everything after the HTTP call succeeds: entity
/// parsing + descending salience sort, sentiment block, categories, and
/// moderation filtering.
pub fn build_result_from_response(text_length: usize, language: &str, data: &Value) -> NlpResult {
    let mut entities: Vec<Entity> = data
        .get("entities")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_entity).collect())
        .unwrap_or_default();
    sort_entities_by_salience(&mut entities);

    let empty = json!({});
    let sentiment = build_sentiment(
        data.get("documentSentiment").unwrap_or(&empty),
        data.get("sentences").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
    );

    let categories = data
        .get("categories")
        .and_then(Value::as_array)
        .map(|arr| parse_categories(arr))
        .unwrap_or_default();

    let moderation = data
        .get("moderationCategories")
        .and_then(Value::as_array)
        .map(|arr| parse_moderation(arr))
        .unwrap_or_default();

    NlpResult { text_length, language: language.to_string(), entities, sentiment, categories, moderation, error: None }
}

/// `analyze_url`'s HTML-text-extraction regex fallback (used when
/// `bs4`/`BeautifulSoup` is unavailable): strips `<script>`/`<style>`
/// blocks, then all remaining tags, then collapses whitespace.
pub fn extract_text_fallback(html: &str) -> String {
    let script_re = regex::Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap();
    let style_re = regex::Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap();
    let tag_re = regex::Regex::new(r"<[^>]+>").unwrap();
    let ws_re = regex::Regex::new(r"\s+").unwrap();

    let no_script = script_re.replace_all(html, "");
    let no_style = style_re.replace_all(&no_script, "");
    let no_tags = tag_re.replace_all(&no_style, " ");
    ws_re.replace_all(&no_tags, " ").trim().to_string()
}

/// `if not text or len(text) < 50: return {"error": "..."}`.
pub fn text_too_short(text: &str) -> bool {
    text.is_empty() || text.chars().count() < 50
}
