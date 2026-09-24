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
//! URL-fetch + HTML-text-extraction in `analyze_url`) is now closed by
//! [`ReqwestNlpTransport`], a real `reqwest::blocking` + `scraper`
//! implementation (packet r40), and [`run`] ports `main()`'s argv
//! handling end to end. Callers that want a fake transport for tests can
//! still implement [`NlpTransport`] directly and drive
//! [`analyze_text_with`]/[`analyze_url_with`].

use std::io::Write;
use std::time::Duration;

use serde_json::{json, Value};

use crate::wf_port::w2_030::google_auth;

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

/// `analyze_text`'s full result dict, including the `error` slot
/// [`build_result_from_response`] leaves out (it only builds the
/// success shape).
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeResult {
    pub text_length: usize,
    pub language: String,
    pub entities: Vec<Entity>,
    pub sentiment: Option<SentimentResult>,
    pub categories: Vec<Category>,
    pub moderation: Vec<Category>,
    pub error: Option<String>,
    pub source_url: Option<String>,
    pub extracted_text_length: Option<usize>,
}

impl From<NlpResult> for AnalyzeResult {
    fn from(r: NlpResult) -> Self {
        AnalyzeResult {
            text_length: r.text_length,
            language: r.language,
            entities: r.entities,
            sentiment: r.sentiment,
            categories: r.categories,
            moderation: r.moderation,
            error: r.error,
            source_url: None,
            extracted_text_length: None,
        }
    }
}

fn error_result(text_length: usize, language: &str, error: String) -> AnalyzeResult {
    AnalyzeResult {
        text_length,
        language: language.to_string(),
        entities: Vec::new(),
        sentiment: None,
        categories: Vec::new(),
        moderation: Vec::new(),
        error: Some(error),
        source_url: None,
        extracted_text_length: None,
    }
}

/// I/O boundary a caller plugs a real transport behind: the NLP API POST
/// and the raw-HTML GET used by `analyze_url`. Mirrors
/// `requests.post(...)`/`requests.get(...)`: any HTTP response (including
/// 4xx/5xx) is `Ok`, only a transport-level failure is `Err` — matching
/// Python's `requests.exceptions.RequestException` branch.
pub trait NlpTransport {
    /// `requests.post(f"{NLP_ENDPOINT}?key={key}", json=body, timeout=30)`.
    fn post_annotate(&self, key: &str, body: &Value) -> Result<(u16, Value), String>;
    /// `requests.get(url, timeout=30, headers={"User-Agent": ...})`.
    fn get_html(&self, url: &str) -> Result<String, String>;
}

/// Real `reqwest::blocking` + `scraper` implementation of [`NlpTransport`].
pub struct ReqwestNlpTransport;

impl NlpTransport for ReqwestNlpTransport {
    fn post_annotate(&self, key: &str, body: &Value) -> Result<(u16, Value), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("NLP API request failed: {e}"))?;
        let resp = client
            .post(format!("{NLP_ENDPOINT}?key={key}"))
            .json(body)
            .send()
            .map_err(|e| request_failed_message(&e.to_string()))?;
        let status = resp.status().as_u16();
        let json = resp.json::<Value>().unwrap_or(json!({}));
        Ok((status, json))
    }

    fn get_html(&self, url: &str) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Could not fetch URL: {e}"))?;
        let resp = client
            .get(url)
            .header("User-Agent", "Mozilla/5.0 (compatible; ClaudeSEO/1.7 NLP Analyzer)")
            .send()
            .map_err(|e| format!("Could not fetch URL: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(format!("Could not fetch URL: HTTP {status}"));
        }
        resp.text().map_err(|e| format!("Could not fetch URL: {e}"))
    }
}

/// `soup.get_text(separator=" ", strip=True)` after dropping
/// `script`/`style`/`nav`/`footer`/`header` tags — the `bs4` branch of
/// `analyze_url`'s text extraction, using the `scraper` crate (this
/// crate's HTML parser, already a dependency) in place of BeautifulSoup.
/// [`extract_text_fallback`] remains the regex fallback Python uses when
/// `bs4` is not installed; this is the primary path, matching what a
/// normal install (with `beautifulsoup4` present) actually runs.
pub fn extract_text_scraper(html: &str) -> String {
    use scraper::{Html, Selector};

    const DROPPED_TAGS: &[&str] = &["script", "style", "nav", "footer", "header"];

    let document = Html::parse_document(html);
    let text_sel = Selector::parse("*").unwrap();

    let mut words: Vec<String> = Vec::new();
    for el in document.select(&text_sel) {
        // Only take text from leaf-ish elements' direct text nodes, and
        // skip anything inside a dropped tag (checked via ancestors, since
        // `scraper`'s `Html::parse_document` always wraps content in
        // `html`/`body`, so `ancestors()` reliably reaches the dropped
        // tag for nested text). Matches `soup.decompose()` on those tags.
        let in_dropped = el
            .ancestors()
            .filter_map(scraper::ElementRef::wrap)
            .any(|a| DROPPED_TAGS.contains(&a.value().name()));
        if in_dropped || DROPPED_TAGS.contains(&el.value().name()) {
            continue;
        }
        for child in el.children() {
            if let Some(text) = child.value().as_text() {
                let t = text.trim();
                if !t.is_empty() {
                    words.push(t.to_string());
                }
            }
        }
    }

    let joined = words.join(" ");
    let ws_re = regex::Regex::new(r"\s+").unwrap();
    ws_re.replace_all(&joined, " ").trim().to_string()
}

/// `analyze_text(text, features, api_key, language)`, generalized over a
/// [`NlpTransport`]. Ports the HTTP-status short-circuits, the
/// `RequestException` branch, and (on success) delegates to
/// [`build_result_from_response`].
pub fn analyze_text_with(
    transport: &dyn NlpTransport,
    text: &str,
    features: &[String],
    api_key: Option<&str>,
    language: &str,
) -> AnalyzeResult {
    let text_length = text.chars().count();
    let Some(key) = api_key else {
        return error_result(
            text_length,
            language,
            "No API key. Set GOOGLE_API_KEY or add 'api_key' to config.".to_string(),
        );
    };

    let feats: Vec<String> = if features.is_empty() {
        vec!["entities".to_string(), "sentiment".to_string(), "classify".to_string()]
    } else {
        features.to_vec()
    };
    let body = build_request_body(text, &feats, language);

    match transport.post_annotate(key, &body) {
        Ok((status, _)) if status == 403 => {
            error_result(text_length, language, categorize_http_status(403).unwrap())
        }
        Ok((status, _)) if status == 429 => {
            error_result(text_length, language, categorize_http_status(429).unwrap())
        }
        Ok((status, data)) if (200..300).contains(&status) => {
            let mut result: AnalyzeResult = build_result_from_response(text_length, language, &data).into();
            result.language = language.to_string();
            result
        }
        Ok((status, _)) => error_result(text_length, language, format!("NLP API request failed: HTTP {status}")),
        Err(e) => error_result(text_length, language, e),
    }
}

/// `analyze_url(url, features, api_key)`, generalized over a
/// [`NlpTransport`]. Validates the URL, fetches it, extracts text (via
/// [`extract_text_scraper`], falling back to [`extract_text_fallback`] on
/// a parse that yields nothing), checks the 50-char floor, then delegates
/// to [`analyze_text_with`].
pub fn analyze_url_with(
    transport: &dyn NlpTransport,
    url: &str,
    features: &[String],
    api_key: Option<&str>,
) -> AnalyzeResult {
    if !google_auth::validate_url(url) {
        return error_result(
            0,
            "en",
            "Invalid URL. Only http/https URLs to public hosts are accepted.".to_string(),
        );
    }

    let html = match transport.get_html(url) {
        Ok(h) => h,
        Err(e) => return error_result(0, "en", e),
    };

    let mut text = extract_text_scraper(&html);
    if text.is_empty() {
        text = extract_text_fallback(&html);
    }

    if text_too_short(&text) {
        return error_result(0, "en", "Extracted text too short for meaningful NLP analysis.".to_string());
    }

    let mut result = analyze_text_with(transport, &text, features, api_key, "en");
    result.source_url = Some(url.to_string());
    result.extracted_text_length = Some(text.chars().count());
    result
}

/// CLI arg bundle mirroring `argparse` in `nlp_analyze.py`'s `main()`.
#[derive(Debug, Clone, Default)]
struct Args {
    text: Option<String>,
    url: Option<String>,
    features: String,
    api_key: Option<String>,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args { features: "entities,sentiment,classify".to_string(), ..Default::default() };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--text" | "-t" => {
                i += 1;
                out.text = Some(args.get(i).ok_or("--text requires a value")?.clone());
            }
            "--url" | "-u" => {
                i += 1;
                out.url = Some(args.get(i).ok_or("--url requires a value")?.clone());
            }
            "--features" | "-f" => {
                i += 1;
                out.features = args.get(i).ok_or("--features requires a value")?.clone();
            }
            "--api-key" => {
                i += 1;
                out.api_key = Some(args.get(i).ok_or("--api-key requires a value")?.clone());
            }
            "--json" | "-j" => out.json = true,
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }
    Ok(out)
}

/// Port of `nlp_analyze.py`'s `main()`, parameterized over the transport
/// and stdout/stderr sinks. Returns the process exit code.
pub fn run(
    args: &[String],
    transport: &dyn NlpTransport,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };

    if parsed.text.is_none() && parsed.url.is_none() {
        let _ = writeln!(stderr, "Error: Provide --text or --url to analyze.");
        return 1;
    }

    let features: Vec<String> = parsed.features.split(',').map(|f| f.trim().to_string()).collect();
    let api_key = parsed.api_key.clone().or_else(|| google_auth::load_config().api_key);

    let result = if let Some(url) = &parsed.url {
        analyze_url_with(transport, url, &features, api_key.as_deref())
    } else {
        analyze_text_with(transport, parsed.text.as_deref().unwrap_or(""), &features, api_key.as_deref(), "en")
    };

    if let Some(err) = &result.error {
        let _ = writeln!(stderr, "Error: {err}");
        if !parsed.json {
            return 1;
        }
    }

    if parsed.json {
        let value = json!({
            "text_length": result.text_length,
            "language": result.language,
            "entities": result.entities.iter().map(|e| json!({
                "name": e.name,
                "type": e.r#type,
                "salience": e.salience,
                "sentiment_score": e.sentiment_score,
                "sentiment_magnitude": e.sentiment_magnitude,
                "mention_count": e.mention_count,
                "metadata": e.metadata,
            })).collect::<Vec<_>>(),
            "sentiment": result.sentiment.as_ref().map(|s| json!({
                "score": s.score,
                "magnitude": s.magnitude,
                "tone": s.tone,
                "interpretation": s.interpretation,
                "sentence_count": s.sentence_count,
                "most_positive": s.most_positive,
                "most_negative": s.most_negative,
            })),
            "categories": result.categories.iter().map(|c| json!({"name": c.name, "confidence": c.confidence})).collect::<Vec<_>>(),
            "moderation": result.moderation.iter().map(|c| json!({"name": c.name, "confidence": c.confidence})).collect::<Vec<_>>(),
            "error": result.error,
            "source_url": result.source_url,
            "extracted_text_length": result.extracted_text_length,
        });
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&value).unwrap_or_default());
        return 0;
    }

    if let Some(url) = &result.source_url {
        let _ = writeln!(stdout, "=== NLP Analysis: {url} ===");
        let _ = writeln!(stdout, "Text extracted: {} chars", result.extracted_text_length.unwrap_or(0));
    } else {
        let _ = writeln!(stdout, "=== NLP Analysis ({} chars) ===", result.text_length);
    }

    if let Some(sent) = &result.sentiment {
        let _ = writeln!(stdout, "\nSentiment: {} (score: {}, magnitude: {})", sent.tone.to_uppercase(), sent.score, sent.magnitude);
        let _ = writeln!(stdout, "  {}", sent.interpretation);
    }

    if !result.entities.is_empty() {
        let _ = writeln!(stdout, "\nTop Entities ({} total):", result.entities.len());
        for e in result.entities.iter().take(15) {
            let _ = writeln!(stdout, "  [{:12}] {} (salience: {:.3})", e.r#type, e.name, e.salience);
        }
    }

    if !result.categories.is_empty() {
        let _ = writeln!(stdout, "\nContent Categories:");
        for c in &result.categories {
            let _ = writeln!(stdout, "  {} ({:.1}%)", c.name, c.confidence * 100.0);
        }
    }

    if !result.moderation.is_empty() {
        let _ = writeln!(stdout, "\nModeration Flags:");
        for m in &result.moderation {
            let _ = writeln!(stdout, "  {} ({:.1}%)", m.name, m.confidence * 100.0);
        }
    }

    0
}
