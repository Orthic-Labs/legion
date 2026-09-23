//! Rust port of the pure, deterministic core of `skills/seo/scripts/youtube_search.py`.
//!
//! The script is almost entirely a thin wrapper over the YouTube Data API v3 client
//! (`googleapiclient`): every code path that matters — `search_videos`,
//! `get_video_details`, `get_channel_info` — makes a live network call and returns
//! whatever the API responds with. That network call, the API-key lookup
//! (`google_auth.get_api_key`), and the client construction are host IO and are not
//! ported. What is faithfully ported here is the pure, independently testable part:
//! shaping an already-received API response (`items[].snippet`/`statistics`/
//! `contentDetails` JSON, exactly as `service.videos().list(...).execute()` etc. would
//! return it) into the same result dictionaries the Python functions build, plus the
//! `403`/`429` error-message classification in `search_videos`'s `except` block. A host
//! wrapper performs the HTTP calls and passes the parsed JSON to these functions.

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
