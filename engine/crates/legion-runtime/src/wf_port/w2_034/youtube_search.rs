//! Rust port of `skills/seo/scripts/youtube_search.py` (packet r44 closes the
//! remaining gap over the pure shaping functions ported earlier).
//!
//! The script is almost entirely a thin wrapper over the YouTube Data API v3 client
//! (`googleapiclient`): every code path that matters — `search_videos`,
//! `get_video_details`, `get_channel_info` — makes a live network call and returns
//! whatever the API responds with. Shaping an already-received API response
//! (`items[].snippet`/`statistics`/`contentDetails` JSON) into the same result
//! dictionaries the Python functions build, plus the `403`/`429` error-message
//! classification, was ported first (below). Packet r44 ports the remaining pieces:
//! the network call itself is modeled as the [`YouTubeApi`] trait (per the port
//! rules — host I/O behind a trait, tested with a fake; [`ReqwestYouTubeApi`] is the
//! real `reqwest::blocking` implementation), `search_videos`/`get_video_details`/
//! `get_channel_info` are now full orchestration functions generic over that trait,
//! and [`run`] ports `main()`'s argv handling and text/JSON output. The API-key
//! lookup (`google_auth.get_api_key`) reuses the already-ported
//! `legion_runtime::wf_port::w2_030::google_auth::{load_config, GoogleApiConfig}`
//! rather than re-deriving it — `get_api_key()` in Python is exactly
//! `load_config().api_key`.

use serde::Serialize;
use serde_json::Value;

fn get_str(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn get_u64(v: &Value, key: &str) -> u64 {
    v.get(key)
        .and_then(|x| x.as_str().and_then(|s| s.parse().ok()).or_else(|| x.as_u64()))
        .unwrap_or(0)
}

/// One shaped search-result video, matching the dict appended in `search_videos()`'s
/// `result["videos"].append({...})`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchVideo {
    pub video_id: String,
    pub title: String,
    pub channel: String,
    pub channel_id: String,
    pub published: String,
    pub description: String,
    pub thumbnail: String,
    pub views: u64,
    pub likes: u64,
    pub comments: u64,
    pub duration: String,
    pub url: String,
}

/// Statistics/content-details shaped for one video, matching the `stats_map[item["id"]]`
/// entries built from the batched `videos().list(part="statistics,contentDetails")` call.
#[derive(Debug, Clone, Default)]
pub struct VideoStats {
    pub views: u64,
    pub likes: u64,
    pub comments: u64,
    pub duration: String,
}

/// Builds one `VideoStats` from a single `items[]` entry of the statistics response.
pub fn video_stats_from_item(item: &Value) -> VideoStats {
    let statistics = item.get("statistics").cloned().unwrap_or(Value::Null);
    let content = item.get("contentDetails").cloned().unwrap_or(Value::Null);
    VideoStats {
        views: get_u64(&statistics, "viewCount"),
        likes: get_u64(&statistics, "likeCount"),
        comments: get_u64(&statistics, "commentCount"),
        duration: get_str(&content, "duration"),
    }
}

/// Port of the per-video shaping inside `search_videos()`'s final loop
/// (`for vid in video_ids: ... result["videos"].append({...})`), given one search
/// `items[]` snippet and its matched `VideoStats` (or `None` when the batched
/// statistics call returned nothing for that id, matching `stats_map.get(vid, {})`
/// defaulting every field to its zero value).
pub fn shape_search_video(video_id: &str, snippet: &Value, stats: Option<&VideoStats>) -> SearchVideo {
    let default_stats = VideoStats::default();
    let stats = stats.unwrap_or(&default_stats);
    let description = get_str(snippet, "description");
    let truncated: String = description.chars().take(300).collect();
    SearchVideo {
        video_id: video_id.to_string(),
        title: get_str(snippet, "title"),
        channel: get_str(snippet, "channelTitle"),
        channel_id: get_str(snippet, "channelId"),
        published: get_str(snippet, "publishedAt"),
        description: truncated,
        thumbnail: snippet
            .get("thumbnails")
            .and_then(|t| t.get("high"))
            .and_then(|h| h.get("url"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string(),
        views: stats.views,
        likes: stats.likes,
        comments: stats.comments,
        duration: stats.duration.clone(),
        url: format!("https://www.youtube.com/watch?v={video_id}"),
    }
}

/// Port of the `error_str` classification in `search_videos()`'s `except Exception as e`
/// block: maps a raw API client error message to the same three cases. `None` input (no
/// error) yields `None`, matching `result["error"]` staying `None` on success.
pub fn classify_search_error(raw_error: &str) -> String {
    if raw_error.contains("403") {
        "YouTube Data API access denied. Ensure the API is enabled in your GCP project (APIs & Services > Library > YouTube Data API v3).".to_string()
    } else if raw_error.contains("429") {
        "YouTube API quota exceeded (10,000 units/day). Search costs 100 units.".to_string()
    } else {
        format!("YouTube API error: {raw_error}")
    }
}

/// Port of the `"No API key..."` short-circuit in every function when
/// `_build_youtube_service` returns `None` (no configured key).
pub const NO_API_KEY_ERROR_SEARCH: &str = "No API key. Set GOOGLE_API_KEY or add 'api_key' to config.";
pub const NO_API_KEY_ERROR_OTHER: &str = "No API key configured.";

/// Shaped video details, matching `get_video_details()`'s `result["details"]` dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VideoDetails {
    pub title: String,
    pub channel: String,
    pub channel_id: String,
    pub published: String,
    pub description: String,
    pub tags: Vec<String>,
    pub category_id: String,
    pub duration: String,
    pub definition: String,
    pub caption: String,
    pub views: u64,
    pub likes: u64,
    pub comments_count: u64,
    pub favorites: u64,
    pub topic_categories: Vec<String>,
    pub url: String,
}

/// Port of the `result["details"] = {...}` shaping in `get_video_details()`, given one
/// `items[0]` entry of `videos().list(part="snippet,statistics,contentDetails,topicDetails")`.
pub fn shape_video_details(video_id: &str, item: &Value) -> VideoDetails {
    let snip = item.get("snippet").cloned().unwrap_or(Value::Null);
    let stats = item.get("statistics").cloned().unwrap_or(Value::Null);
    let content = item.get("contentDetails").cloned().unwrap_or(Value::Null);
    let topics = item.get("topicDetails").cloned().unwrap_or(Value::Null);

    let tags = snip
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let topic_categories = topics
        .get("topicCategories")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    VideoDetails {
        title: get_str(&snip, "title"),
        channel: get_str(&snip, "channelTitle"),
        channel_id: get_str(&snip, "channelId"),
        published: get_str(&snip, "publishedAt"),
        description: get_str(&snip, "description"),
        tags,
        category_id: get_str(&snip, "categoryId"),
        duration: get_str(&content, "duration"),
        definition: get_str(&content, "definition"),
        caption: {
            let c = get_str(&content, "caption");
            if c.is_empty() { "false".to_string() } else { c }
        },
        views: get_u64(&stats, "viewCount"),
        likes: get_u64(&stats, "likeCount"),
        comments_count: get_u64(&stats, "commentCount"),
        favorites: get_u64(&stats, "favoriteCount"),
        topic_categories,
        url: format!("https://www.youtube.com/watch?v={video_id}"),
    }
}

/// Shaped top comment, matching one entry appended to `result["comments"]`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VideoComment {
    pub author: String,
    pub text: String,
    pub likes: u64,
    pub published: String,
}

/// Port of the `result["comments"].append({...})` shaping in `get_video_details()`,
/// given one `items[]` entry of `commentThreads().list(...)`.
pub fn shape_comment(thread: &Value) -> VideoComment {
    let snippet = thread
        .get("snippet")
        .and_then(|s| s.get("topLevelComment"))
        .and_then(|c| c.get("snippet"))
        .cloned()
        .unwrap_or(Value::Null);
    let text = get_str(&snippet, "textDisplay");
    let truncated: String = text.chars().take(500).collect();
    VideoComment {
        author: get_str(&snippet, "authorDisplayName"),
        text: truncated,
        likes: get_u64(&snippet, "likeCount"),
        published: get_str(&snippet, "publishedAt"),
    }
}

/// Shaped channel info, matching `get_channel_info()`'s `result["channel"]` dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelInfo {
    pub title: String,
    pub description: String,
    pub custom_url: String,
    pub published: String,
    pub country: String,
    pub subscribers: u64,
    pub videos: u64,
    pub views: u64,
    pub thumbnail: String,
}

/// Port of the `result["channel"] = {...}` shaping in `get_channel_info()`, given one
/// `items[0]` entry of `channels().list(part="snippet,statistics,brandingSettings")`.
pub fn shape_channel_info(item: &Value) -> ChannelInfo {
    let snip = item.get("snippet").cloned().unwrap_or(Value::Null);
    let stats = item.get("statistics").cloned().unwrap_or(Value::Null);
    let description = get_str(&snip, "description");
    let truncated: String = description.chars().take(500).collect();
    ChannelInfo {
        title: get_str(&snip, "title"),
        description: truncated,
        custom_url: get_str(&snip, "customUrl"),
        published: get_str(&snip, "publishedAt"),
        country: get_str(&snip, "country"),
        subscribers: get_u64(&stats, "subscriberCount"),
        videos: get_u64(&stats, "videoCount"),
        views: get_u64(&stats, "viewCount"),
        thumbnail: snip
            .get("thumbnails")
            .and_then(|t| t.get("high"))
            .and_then(|h| h.get("url"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string(),
    }
}

/// Port of `min(max_results, 50)` clamping used when building the `search().list(...)`
/// request's `maxResults` (the request itself is host IO; the clamp is pure).
pub fn clamp_max_results(max_results: i64) -> i64 {
    max_results.min(50)
}

// ---------------------------------------------------------------------
// Network seam (r44): the three YouTube Data API v3 calls the script's
// `_build_youtube_service(...).{search,videos,channels,commentThreads}()`
// make, standing in for `googleapiclient`.
// ---------------------------------------------------------------------

/// Host HTTP seam for the YouTube Data API v3. Mirrors the four
/// `service.<resource>().list(...).execute()` calls the Python script
/// makes; `Err` mirrors Python's `except Exception as e` (any transport or
/// non-2xx failure — the caller passes the message through
/// [`classify_search_error`] or a fixed `"YouTube API error: {e}"` prefix,
/// exactly as the Python `except` blocks do), `Ok` mirrors a successful
/// `.execute()` returning the parsed JSON body.
pub trait YouTubeApi {
    /// `service.search().list(q=query, part="snippet", type="video",
    /// maxResults=min(max_results,50), order=order).execute()`.
    fn search_list(&self, query: &str, max_results: i64, order: &str) -> Result<Value, String>;
    /// `service.videos().list(id=",".join(ids), part=parts).execute()`.
    fn videos_list(&self, ids: &[String], parts: &str) -> Result<Value, String>;
    /// `service.channels().list(id=channel_id,
    /// part="snippet,statistics,brandingSettings").execute()`.
    fn channels_list(&self, channel_id: &str) -> Result<Value, String>;
    /// `service.commentThreads().list(videoId=video_id, part="snippet",
    /// maxResults=10, order="relevance", textFormat="plainText").execute()`.
    fn comment_threads_list(&self, video_id: &str) -> Result<Value, String>;
}

/// Real implementation of [`YouTubeApi`]: blocking `reqwest` GETs against
/// the YouTube Data API v3 REST surface (the same HTTP endpoints
/// `googleapiclient`'s generated client calls), with `key=<api_key>` on
/// every request as `_build_youtube_service(api_key)` does via
/// `developerKey=key`.
pub struct ReqwestYouTubeApi {
    pub api_key: String,
    pub http: reqwest::blocking::Client,
}

impl ReqwestYouTubeApi {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }

    fn get(&self, resource: &str, params: &[(&str, String)]) -> Result<Value, String> {
        let url = format!("https://www.googleapis.com/youtube/v3/{resource}");
        let mut query: Vec<(&str, String)> = params.to_vec();
        query.push(("key", self.api_key.clone()));
        let response = self
            .http
            .get(&url)
            .query(&query)
            .send()
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body: Value = response.json().unwrap_or(Value::Null);
        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| status.to_string());
            return Err(format!("{} {}", status.as_u16(), message));
        }
        Ok(body)
    }
}

impl YouTubeApi for ReqwestYouTubeApi {
    fn search_list(&self, query: &str, max_results: i64, order: &str) -> Result<Value, String> {
        self.get(
            "search",
            &[
                ("q", query.to_string()),
                ("part", "snippet".to_string()),
                ("type", "video".to_string()),
                ("maxResults", clamp_max_results(max_results).to_string()),
                ("order", order.to_string()),
            ],
        )
    }

    fn videos_list(&self, ids: &[String], parts: &str) -> Result<Value, String> {
        self.get("videos", &[("id", ids.join(",")), ("part", parts.to_string())])
    }

    fn channels_list(&self, channel_id: &str) -> Result<Value, String> {
        self.get(
            "channels",
            &[
                ("id", channel_id.to_string()),
                ("part", "snippet,statistics,brandingSettings".to_string()),
            ],
        )
    }

    fn comment_threads_list(&self, video_id: &str) -> Result<Value, String> {
        self.get(
            "commentThreads",
            &[
                ("videoId", video_id.to_string()),
                ("part", "snippet".to_string()),
                ("maxResults", "10".to_string()),
                ("order", "relevance".to_string()),
                ("textFormat", "plainText".to_string()),
            ],
        )
    }
}

// ---------------------------------------------------------------------
// Orchestration (r44): `search_videos`/`get_video_details`/
// `get_channel_info`, generic over `YouTubeApi`.
// ---------------------------------------------------------------------

/// `search_videos(...)`'s return dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchResult {
    pub query: String,
    pub videos: Vec<SearchVideo>,
    pub total_results: u64,
    pub error: Option<String>,
}

/// Port of `search_videos(query, max_results, order, api_key)`. `api`
/// mirrors `_build_youtube_service(api_key)` returning `None` when
/// `api is None` (no configured key).
pub fn search_videos(api: Option<&dyn YouTubeApi>, query: &str, max_results: i64, order: &str) -> SearchResult {
    let mut result = SearchResult { query: query.to_string(), videos: Vec::new(), total_results: 0, error: None };
    let api = match api {
        Some(api) => api,
        None => {
            result.error = Some(NO_API_KEY_ERROR_SEARCH.to_string());
            return result;
        }
    };
    let response = match api.search_list(query, max_results, order) {
        Ok(response) => response,
        Err(e) => {
            result.error = Some(classify_search_error(&e));
            return result;
        }
    };
    result.total_results = response
        .get("pageInfo")
        .and_then(|p| p.get("totalResults"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let items = response.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut video_ids: Vec<String> = Vec::new();
    let mut snippets: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for item in &items {
        if let Some(vid) = item.get("id").and_then(|i| i.get("videoId")).and_then(Value::as_str) {
            video_ids.push(vid.to_string());
            snippets.insert(vid.to_string(), item.get("snippet").cloned().unwrap_or(Value::Null));
        }
    }
    if video_ids.is_empty() {
        return result;
    }
    let stats_response = match api.videos_list(&video_ids, "statistics,contentDetails") {
        Ok(response) => response,
        Err(e) => {
            result.error = Some(classify_search_error(&e));
            return result;
        }
    };
    let mut stats_map: std::collections::HashMap<String, VideoStats> = std::collections::HashMap::new();
    for item in stats_response.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            stats_map.insert(id.to_string(), video_stats_from_item(&item));
        }
    }
    for vid in &video_ids {
        let empty = Value::Null;
        let snippet = snippets.get(vid).unwrap_or(&empty);
        result.videos.push(shape_search_video(vid, snippet, stats_map.get(vid)));
    }
    result
}

/// `get_video_details(...)`'s return dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VideoDetailsResult {
    pub video_id: String,
    pub details: Option<VideoDetails>,
    pub comments: Vec<VideoComment>,
    pub error: Option<String>,
}

/// Port of `get_video_details(video_id, api_key)`.
pub fn get_video_details(api: Option<&dyn YouTubeApi>, video_id: &str) -> VideoDetailsResult {
    let mut result = VideoDetailsResult { video_id: video_id.to_string(), details: None, comments: Vec::new(), error: None };
    let api = match api {
        Some(api) => api,
        None => {
            result.error = Some(NO_API_KEY_ERROR_OTHER.to_string());
            return result;
        }
    };
    let response = match api.videos_list(&[video_id.to_string()], "snippet,statistics,contentDetails,topicDetails") {
        Ok(response) => response,
        Err(e) => {
            result.error = Some(format!("YouTube API error: {e}"));
            return result;
        }
    };
    let items = response.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    let Some(item) = items.first() else {
        result.error = Some(format!("Video not found: {video_id}"));
        return result;
    };
    result.details = Some(shape_video_details(video_id, item));
    // `except Exception: pass` — comments are best-effort in Python; a
    // failed comments call never touches `result.error`.
    if let Ok(comments_response) = api.comment_threads_list(video_id) {
        let threads = comments_response.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        for thread in threads.iter().take(10) {
            result.comments.push(shape_comment(thread));
        }
    }
    result
}

/// `get_channel_info(...)`'s return dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelResult {
    pub channel_id: String,
    pub channel: Option<ChannelInfo>,
    pub error: Option<String>,
}

/// Port of `get_channel_info(channel_id, api_key)`.
pub fn get_channel_info(api: Option<&dyn YouTubeApi>, channel_id: &str) -> ChannelResult {
    let mut result = ChannelResult { channel_id: channel_id.to_string(), channel: None, error: None };
    let api = match api {
        Some(api) => api,
        None => {
            result.error = Some(NO_API_KEY_ERROR_OTHER.to_string());
            return result;
        }
    };
    let response = match api.channels_list(channel_id) {
        Ok(response) => response,
        Err(e) => {
            result.error = Some(format!("YouTube API error: {e}"));
            return result;
        }
    };
    let items = response.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
    let Some(item) = items.first() else {
        result.error = Some(format!("Channel not found: {channel_id}"));
        return result;
    };
    result.channel = Some(shape_channel_info(item));
    result
}

// ---------------------------------------------------------------------
// CLI (r44): `main()` in `youtube_search.py`.
// `{search,video,channel} QUERY [--limit N] [--order O] [--api-key K] [--json|-j]`.
// ---------------------------------------------------------------------

/// Parsed CLI args, mirroring `argparse`'s namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct CliArgs {
    pub command: String,
    pub query: String,
    pub limit: i64,
    pub order: String,
    pub api_key: Option<String>,
    pub json: bool,
}

/// Error mirroring `argparse`'s usage failure (`parser.error(...)`, exit 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliParseError {
    #[error("argument command: invalid choice: '{0}' (choose from 'search', 'video', 'channel')")]
    UnknownCommand(String),
    #[error("the following arguments are required: query")]
    MissingQuery,
    #[error("argument --order: invalid choice: '{0}'")]
    UnknownOrder(String),
    #[error("argument --limit: invalid int value")]
    InvalidLimit,
    #[error("unrecognized arguments: {0}")]
    UnrecognizedArgument(String),
}

const ORDER_CHOICES: [&str; 5] = ["relevance", "date", "rating", "viewCount", "title"];

/// Port of `main()`'s `argparse.ArgumentParser` setup and parsing.
pub fn parse_cli_args(args: &[String]) -> Result<CliArgs, CliParseError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut limit: i64 = 10;
    let mut order = "relevance".to_string();
    let mut api_key: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--limit" => {
                i += 1;
                let value = args.get(i).ok_or(CliParseError::InvalidLimit)?;
                limit = value.parse().map_err(|_| CliParseError::InvalidLimit)?;
            }
            "--order" => {
                i += 1;
                let value = args.get(i).cloned().unwrap_or_default();
                if !ORDER_CHOICES.contains(&value.as_str()) {
                    return Err(CliParseError::UnknownOrder(value));
                }
                order = value;
            }
            "--api-key" => {
                i += 1;
                api_key = args.get(i).cloned();
            }
            "--json" | "-j" => {
                json = true;
            }
            other if other.starts_with("--") => {
                return Err(CliParseError::UnrecognizedArgument(other.to_string()));
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }
    let command = positionals.first().cloned().ok_or(CliParseError::MissingQuery)?;
    if !["search", "video", "channel"].contains(&command.as_str()) {
        return Err(CliParseError::UnknownCommand(command));
    }
    let query = positionals.get(1).cloned().ok_or(CliParseError::MissingQuery)?;
    Ok(CliArgs { command, query, limit, order, api_key, json })
}

/// Outcome of a CLI run, mirroring `main()`'s `print(...)`/`sys.exit(...)`
/// without actually calling `std::process::exit`.
pub struct CliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn format_search_text(result: &SearchResult) -> String {
    let mut out = format!("=== YouTube Search: {} ===\n", result.query);
    out.push_str(&format!("Results: {}\n", result.total_results));
    for (i, v) in result.videos.iter().enumerate() {
        out.push_str(&format!("\n  {}. {}\n", i + 1, v.title));
        out.push_str(&format!("     {} | {} views | {} likes | {}\n", v.channel, v.views, v.likes, v.duration));
        out.push_str(&format!("     {}\n", v.url));
    }
    out
}

fn format_video_text(result: &VideoDetailsResult) -> String {
    let Some(d) = &result.details else { return String::new() };
    let mut out = format!("=== {} ===\n", d.title);
    out.push_str(&format!("Channel: {}\n", d.channel));
    out.push_str(&format!("Views: {} | Likes: {} | Comments: {}\n", d.views, d.likes, d.comments_count));
    let published_date: String = d.published.chars().take(10).collect();
    out.push_str(&format!("Published: {} | Duration: {}\n", published_date, d.duration));
    if !d.tags.is_empty() {
        let shown: Vec<&str> = d.tags.iter().take(10).map(String::as_str).collect();
        out.push_str(&format!("Tags: {}\n", shown.join(", ")));
    }
    if !result.comments.is_empty() {
        out.push_str(&format!("\nTop Comments ({}):\n", result.comments.len()));
        for c in result.comments.iter().take(5) {
            let text: String = c.text.chars().take(100).collect();
            out.push_str(&format!("  [{} likes] {}: {}\n", c.likes, c.author, text));
        }
    }
    out
}

fn format_channel_text(result: &ChannelResult) -> String {
    let Some(c) = &result.channel else { return String::new() };
    let mut out = format!("=== {} ===\n", c.title);
    out.push_str(&format!("Subscribers: {} | Videos: {} | Views: {}\n", c.subscribers, c.videos, c.views));
    out
}

/// Port of `main()`. `env_api_key` mirrors `google_auth.get_api_key()`
/// (`load_config().api_key`); `client_for_key` builds the real
/// [`ReqwestYouTubeApi`] for a resolved key — injected so tests never make
/// a real HTTP call.
pub fn run(args: &[String], env_api_key: Option<String>, client_for_key: impl FnOnce(String) -> Box<dyn YouTubeApi>) -> CliOutcome {
    let parsed = match parse_cli_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            return CliOutcome { exit_code: 2, stdout: String::new(), stderr: format!("{e}\n") };
        }
    };
    let resolved_key = parsed.api_key.clone().or(env_api_key);
    let api: Option<Box<dyn YouTubeApi>> = resolved_key.map(client_for_key);
    let api_ref = api.as_deref();

    let mut stderr = String::new();
    let mut stdout = String::new();
    let mut exit_code = 0;

    match parsed.command.as_str() {
        "search" => {
            let result = search_videos(api_ref, &parsed.query, parsed.limit, &parsed.order);
            if let Some(err) = &result.error {
                stderr.push_str(&format!("Error: {err}\n"));
                if !parsed.json {
                    exit_code = 1;
                }
            }
            stdout = if parsed.json {
                serde_json::to_string_pretty(&result).unwrap_or_default() + "\n"
            } else {
                format_search_text(&result)
            };
        }
        "video" => {
            let result = get_video_details(api_ref, &parsed.query);
            if let Some(err) = &result.error {
                stderr.push_str(&format!("Error: {err}\n"));
                if !parsed.json {
                    exit_code = 1;
                }
            }
            stdout = if parsed.json {
                serde_json::to_string_pretty(&result).unwrap_or_default() + "\n"
            } else {
                format_video_text(&result)
            };
        }
        "channel" => {
            let result = get_channel_info(api_ref, &parsed.query);
            if let Some(err) = &result.error {
                stderr.push_str(&format!("Error: {err}\n"));
                if !parsed.json {
                    exit_code = 1;
                }
            }
            stdout = if parsed.json {
                serde_json::to_string_pretty(&result).unwrap_or_default() + "\n"
            } else {
                format_channel_text(&result)
            };
        }
        _ => unreachable!("validated by parse_cli_args"),
    }

    CliOutcome { exit_code, stdout, stderr }
}

#[cfg(test)]
mod network_and_cli_tests {
    use super::*;
    use serde_json::json;

    struct FakeApi {
        search: Option<Result<Value, String>>,
        videos: Option<Result<Value, String>>,
        channels: Option<Result<Value, String>>,
        comments: Option<Result<Value, String>>,
    }
    impl YouTubeApi for FakeApi {
        fn search_list(&self, _q: &str, _m: i64, _o: &str) -> Result<Value, String> {
            self.search.clone().unwrap()
        }
        fn videos_list(&self, _ids: &[String], _parts: &str) -> Result<Value, String> {
            self.videos.clone().unwrap()
        }
        fn channels_list(&self, _id: &str) -> Result<Value, String> {
            self.channels.clone().unwrap()
        }
        fn comment_threads_list(&self, _id: &str) -> Result<Value, String> {
            self.comments.clone().unwrap_or_else(|| Ok(json!({"items": []})))
        }
    }

    #[test]
    fn search_videos_without_api_key_reports_no_key_error() {
        let result = search_videos(None, "claude code seo", 10, "relevance");
        assert_eq!(result.error, Some(NO_API_KEY_ERROR_SEARCH.to_string()));
        assert!(result.videos.is_empty());
    }

    #[test]
    fn search_videos_happy_path_merges_snippet_and_stats() {
        let api = FakeApi {
            search: Some(Ok(json!({
                "pageInfo": {"totalResults": 42},
                "items": [{"id": {"videoId": "abc"}, "snippet": {"title": "T", "channelTitle": "C"}}]
            }))),
            videos: Some(Ok(json!({"items": [{"id": "abc", "statistics": {"viewCount": "5"}, "contentDetails": {"duration": "PT1M"}}]}))),
            channels: None,
            comments: None,
        };
        let result = search_videos(Some(&api), "q", 10, "relevance");
        assert_eq!(result.total_results, 42);
        assert_eq!(result.videos.len(), 1);
        assert_eq!(result.videos[0].views, 5);
        assert!(result.error.is_none());
    }

    #[test]
    fn search_videos_classifies_403_error() {
        let api = FakeApi { search: Some(Err("403 Forbidden".to_string())), videos: None, channels: None, comments: None };
        let result = search_videos(Some(&api), "q", 10, "relevance");
        assert!(result.error.unwrap().starts_with("YouTube Data API access denied"));
    }

    #[test]
    fn get_video_details_not_found() {
        let api = FakeApi { search: None, videos: Some(Ok(json!({"items": []}))), channels: None, comments: None };
        let result = get_video_details(Some(&api), "missing");
        assert_eq!(result.error, Some("Video not found: missing".to_string()));
        assert!(result.details.is_none());
    }

    #[test]
    fn get_video_details_happy_path_includes_comments() {
        let api = FakeApi {
            search: None,
            videos: Some(Ok(json!({"items": [{"snippet": {"title": "T"}, "statistics": {"viewCount": "1"}, "contentDetails": {"duration": "PT1M"}}]}))),
            channels: None,
            comments: Some(Ok(json!({"items": [{"snippet": {"topLevelComment": {"snippet": {"authorDisplayName": "A", "textDisplay": "hi", "likeCount": 2}}}}]}))),
        };
        let result = get_video_details(Some(&api), "abc");
        assert!(result.error.is_none());
        assert_eq!(result.comments.len(), 1);
        assert_eq!(result.comments[0].author, "A");
    }

    #[test]
    fn get_channel_info_not_found() {
        let api = FakeApi { search: None, videos: None, channels: Some(Ok(json!({"items": []}))), comments: None };
        let result = get_channel_info(Some(&api), "missing");
        assert_eq!(result.error, Some("Channel not found: missing".to_string()));
    }

    #[test]
    fn parse_cli_args_rejects_unknown_command() {
        let args: Vec<String> = ["bogus", "q"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(parse_cli_args(&args), Err(CliParseError::UnknownCommand(_))));
    }

    #[test]
    fn parse_cli_args_requires_query() {
        let args: Vec<String> = ["search"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_cli_args(&args), Err(CliParseError::MissingQuery));
    }

    #[test]
    fn parse_cli_args_parses_flags() {
        let args: Vec<String> = ["search", "q", "--limit", "5", "--order", "date", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_cli_args(&args).unwrap();
        assert_eq!(parsed.limit, 5);
        assert_eq!(parsed.order, "date");
        assert!(parsed.json);
    }

    #[test]
    fn parse_cli_args_rejects_unknown_order() {
        let args: Vec<String> = ["search", "q", "--order", "bogus"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(parse_cli_args(&args), Err(CliParseError::UnknownOrder(_))));
    }

    #[test]
    fn run_reports_missing_api_key_and_exits_nonzero_in_text_mode() {
        let args: Vec<String> = ["search", "q"].iter().map(|s| s.to_string()).collect();
        let outcome = run(&args, None, |_key| {
            Box::new(FakeApi { search: Some(Ok(json!({}))), videos: None, channels: None, comments: None })
        });
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("No API key"));
    }

    #[test]
    fn run_uses_explicit_api_key_flag_over_missing_env_key() {
        let args: Vec<String> = ["search", "q", "--api-key", "explicit", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outcome = run(&args, None, |key| {
            assert_eq!(key, "explicit");
            Box::new(FakeApi {
                search: Some(Ok(json!({"pageInfo": {"totalResults": 0}, "items": []}))),
                videos: None,
                channels: None,
                comments: None,
            })
        });
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("\"totalResults\"") || outcome.stdout.contains("\"total_results\""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_search_video_with_truncated_description_and_url() {
        let snippet = json!({
            "title": "How to Rank #1",
            "channelTitle": "SEO Channel",
            "channelId": "UC123",
            "publishedAt": "2026-01-01T00:00:00Z",
            "description": "x".repeat(400),
            "thumbnails": {"high": {"url": "https://img.example/high.jpg"}}
        });
        let stats = VideoStats { views: 1000, likes: 50, comments: 3, duration: "PT5M".to_string() };
        let shaped = shape_search_video("abc123", &snippet, Some(&stats));
        assert_eq!(shaped.video_id, "abc123");
        assert_eq!(shaped.description.chars().count(), 300);
        assert_eq!(shaped.url, "https://www.youtube.com/watch?v=abc123");
        assert_eq!(shaped.views, 1000);
    }

    #[test]
    fn missing_stats_default_to_zero() {
        let snippet = json!({"title": "T"});
        let shaped = shape_search_video("vid", &snippet, None);
        assert_eq!(shaped.views, 0);
        assert_eq!(shaped.duration, "");
    }

    #[test]
    fn classifies_403_and_429_and_generic_errors() {
        assert!(classify_search_error("HttpError 403 returned").contains("access denied"));
        assert!(classify_search_error("HttpError 429 returned").contains("quota exceeded"));
        assert_eq!(classify_search_error("boom"), "YouTube API error: boom");
    }

    #[test]
    fn shapes_video_details_defaults_caption_to_false_string() {
        let item = json!({
            "snippet": {"title": "T", "tags": ["seo", "ai"]},
            "statistics": {"viewCount": "42"},
            "contentDetails": {},
            "topicDetails": {"topicCategories": ["https://en.wikipedia.org/wiki/Marketing"]}
        });
        let details = shape_video_details("vid1", &item);
        assert_eq!(details.caption, "false");
        assert_eq!(details.tags, vec!["seo".to_string(), "ai".to_string()]);
        assert_eq!(details.views, 42);
        assert_eq!(details.topic_categories.len(), 1);
    }

    #[test]
    fn shapes_comment_truncated_to_500_chars() {
        let thread = json!({
            "snippet": {"topLevelComment": {"snippet": {
                "authorDisplayName": "A",
                "textDisplay": "y".repeat(600),
                "likeCount": 5,
                "publishedAt": "2026-01-01T00:00:00Z"
            }}}
        });
        let c = shape_comment(&thread);
        assert_eq!(c.text.chars().count(), 500);
        assert_eq!(c.likes, 5);
    }

    #[test]
    fn shapes_channel_info() {
        let item = json!({
            "snippet": {"title": "Ch", "description": "d".repeat(600), "customUrl": "@ch"},
            "statistics": {"subscriberCount": "10", "videoCount": "2", "viewCount": "300"}
        });
        let ch = shape_channel_info(&item);
        assert_eq!(ch.title, "Ch");
        assert_eq!(ch.description.chars().count(), 500);
        assert_eq!(ch.subscribers, 10);
    }

    #[test]
    fn clamps_max_results_to_fifty() {
        assert_eq!(clamp_max_results(10), 10);
        assert_eq!(clamp_max_results(100), 50);
    }
}
