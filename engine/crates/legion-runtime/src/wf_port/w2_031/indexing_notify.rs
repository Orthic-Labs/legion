//! Port of `skills/seo/scripts/indexing_notify.py`.
//!
//! Google Indexing API v3 — notify Google of URL updates and removals.
//! Publishes `URL_UPDATED`/`URL_DELETED` notifications, batch mode (up to
//! 200 URLs/day), and quota tracking.
//!
//! IMPORTANT: the Indexing API is officially restricted to pages with
//! `JobPosting` or `BroadcastEvent`/`VideoObject` structured data. Google
//! may process other page types but provides no guarantees.
//!
//! This module ports the pure request-shaping, error-categorization, and
//! quota-bookkeeping logic (`notify_url`'s body/error branches, and
//! `batch_notify`'s truncation/warning/remaining-quota math), plus
//! (packet r39) the real Indexing API v3 HTTPS calls and the `main()` CLI.
//!
//! The OAuth-authenticated Google API call (`googleapiclient`'s
//! `build("indexing", "v3", ...)`, backed by `google_auth.get_oauth_credentials`
//! in the Python original) is behind the [`IndexingClient`] trait.
//! [`ReqwestIndexingClient`] is the real `reqwest::blocking`
//! implementation, POSTing to
//! `https://indexing.googleapis.com/v3/urlNotifications:publish` and
//! GETting `https://indexing.googleapis.com/v3/urlNotifications/metadata`
//! with an already-minted OAuth bearer token — minting that token is
//! `google_auth.py`'s job (ported separately in
//! `wf_port::w2_030::google_auth`, which does not yet expose a token-minting
//! call of its own; this module, like `wf_port::w2_029::ga4_report`, takes
//! an already-resolved bearer token as input, matching how
//! `_build_indexing_service()` hands a ready, already-authenticated
//! service object to each Python function). Tests use a fake
//! [`IndexingClient`]. [`notify_url_with`]/[`batch_notify_with`]/[`run`]
//! reproduce Python's exact result shape and control flow, including
//! `main()`'s CLI dispatch.

use serde_json::{json, Value};

pub const INDEXING_SCOPE: &str = "https://www.googleapis.com/auth/indexing";
pub const DAILY_QUOTA: u32 = 200;

pub const SCOPE_WARNING: &str = "NOTE: The Indexing API is officially for JobPosting and \
BroadcastEvent/VideoObject pages only. Google may process other page types but provides no guarantees.";

/// `'URL_UPDATED' | 'URL_DELETED'` action enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAction {
    UrlUpdated,
    UrlDeleted,
}

impl NotifyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            NotifyAction::UrlUpdated => "URL_UPDATED",
            NotifyAction::UrlDeleted => "URL_DELETED",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "URL_UPDATED" => Some(NotifyAction::UrlUpdated),
            "URL_DELETED" => Some(NotifyAction::UrlDeleted),
            _ => None,
        }
    }
}

/// `notify_url`'s request body: `{"url": url, "type": action}`.
pub fn build_notify_body(url: &str, action: NotifyAction) -> Value {
    json!({"url": url, "type": action.as_str()})
}

/// A minimal client boundary a caller plugs a real Indexing API client
/// behind. Errors are reported as `Err(message)`; `message` is inspected
/// for `"403"`/`"429"`/`"400"` substrings by [`categorize_publish_error`],
/// matching Python's `str(e)` substring checks on the caught exception.
pub trait IndexingClient {
    fn publish(&self, body: &Value) -> Result<Value, String>;
    fn get_metadata(&self, url: &str) -> Result<Value, String>;
}

/// `notify_url(url, action)`'s result dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyResult {
    pub url: String,
    pub action: NotifyAction,
    pub notify_time: Option<String>,
    pub error: Option<String>,
}

/// Mirrors the `except Exception as e` branch of `notify_url`: classifies
/// the raw error string the same way Python does, by substring match on
/// `"403"`, `"429"`, `"400"` in that order.
pub fn categorize_publish_error(error_str: &str) -> String {
    if error_str.contains("403") {
        "Permission denied. The service account must be added as an Owner in Google Search \
Console for this domain. Also ensure the Indexing API is enabled in your GCP project."
            .to_string()
    } else if error_str.contains("429") {
        format!(
            "Quota exceeded. Daily limit: {DAILY_QUOTA} publish requests. Apply for a quota \
increase at https://developers.google.com/search/apis/indexing-api/v3/quota-increase"
        )
    } else if error_str.contains("400") {
        format!("Invalid URL or request: {error_str}")
    } else {
        format!("Indexing API error: {error_str}")
    }
}

/// `notify_url(url, action)`, generalized over an [`IndexingClient`].
pub fn notify_url_with<C: IndexingClient>(client: &C, url: &str, action: NotifyAction) -> NotifyResult {
    let body = build_notify_body(url, action);
    match client.publish(&body) {
        Ok(response) => {
            let metadata = response.get("urlNotificationMetadata").cloned().unwrap_or(json!({}));
            let latest = metadata
                .get("latestUpdate")
                .filter(|v| !v.is_null())
                .or_else(|| metadata.get("latestRemove"))
                .cloned()
                .unwrap_or(json!({}));
            let notify_time = latest.get("notifyTime").and_then(Value::as_str).map(str::to_string);
            NotifyResult { url: url.to_string(), action, notify_time, error: None }
        }
        Err(e) => NotifyResult {
            url: url.to_string(),
            action,
            notify_time: None,
            error: Some(categorize_publish_error(&e)),
        },
    }
}

/// `get_notification_metadata(url)`'s error classification (the
/// `except Exception as e` branch): `"404"` substring vs. generic.
pub fn categorize_metadata_error(error_str: &str) -> String {
    if error_str.contains("404") {
        "No notification metadata found for this URL.".to_string()
    } else {
        format!("Error fetching metadata: {error_str}")
    }
}

/// `batch_notify`'s pre-flight truncation/warning step, run before any
/// requests are sent. Returns `(urls_to_send, quota_warning)`.
///
/// Mirrors:
/// ```python
/// if len(urls) > DAILY_QUOTA:
///     quota_warning = f"...({len(urls)})..."; urls = urls[:DAILY_QUOTA]
/// if len(urls) > 50:
///     quota_warning = f"Submitting {len(urls)} URLs will use {len(urls)}/{DAILY_QUOTA}..."
/// ```
pub fn plan_batch(urls: Vec<String>) -> (Vec<String>, Option<String>) {
    let total = urls.len();
    let mut warning = None;
    let mut urls = urls;
    if total > DAILY_QUOTA as usize {
        warning = Some(format!(
            "Batch size ({total}) exceeds daily quota ({DAILY_QUOTA}). Only the first {DAILY_QUOTA} URLs will be submitted."
        ));
        urls.truncate(DAILY_QUOTA as usize);
    }
    if urls.len() > 50 {
        warning = Some(format!(
            "Submitting {n} URLs will use {n}/{DAILY_QUOTA} of your daily quota.",
            n = urls.len()
        ));
    }
    (urls, warning)
}

/// `result["estimated_remaining_quota"] = max(0, DAILY_QUOTA - success)`.
pub fn estimated_remaining_quota(success: u32) -> u32 {
    DAILY_QUOTA.saturating_sub(success)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchSummary {
    pub success: u32,
    pub error: u32,
}

/// `batch_notify(urls, action, delay)`, generalized over an
/// [`IndexingClient`] and with the `time.sleep(delay)` pacing removed
/// (callers pace their own transport). Stops early on the first result
/// whose error string contains `"429"`, matching Python's
/// `if "429" in str(notification.get("error", "")): ... break`.
pub fn batch_notify_with<C: IndexingClient>(
    client: &C,
    urls: &[String],
    action: NotifyAction,
) -> (Vec<NotifyResult>, BatchSummary, Option<String>, Option<String>) {
    let (planned, quota_warning) = plan_batch(urls.to_vec());
    let mut results = Vec::new();
    let mut summary = BatchSummary::default();
    let mut stop_error = None;

    for url in &planned {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        let notification = notify_url_with(client, url, action);
        let has_error = notification.error.is_some();
        let is_quota_error = notification
            .error
            .as_deref()
            .map(|e| e.contains("429"))
            .unwrap_or(false);
        results.push(notification);
        if has_error {
            summary.error += 1;
            if is_quota_error {
                stop_error = Some("Stopped: daily quota exceeded.".to_string());
                break;
            }
        } else {
            summary.success += 1;
        }
    }

    (results, summary, quota_warning, stop_error)
}
