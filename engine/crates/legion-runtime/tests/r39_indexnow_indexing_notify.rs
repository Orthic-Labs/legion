//! Integration coverage added for packet r39: extends the w2_031 port of
//! `skills/seo/scripts/{indexnow,indexing_notify}.py` to close the gap
//! left by the original chunk — the real HTTP transport and the `main()`
//! CLI, both now ported (not just the pure request-shaping core).
//!
//! No test here hits the network or launches a real browser: HTTP is
//! behind `Transport`/`IndexingClient`, file reads are behind
//! `UrlsFileReader`/`BatchFileReader`, exercised with fakes.

use legion_runtime::wf_port::w2_031::{indexing_notify, indexnow};
use serde_json::json;
use std::cell::RefCell;

// ---------------------------------------------------------------------
// indexnow.py — CLI (`main()`)
// ---------------------------------------------------------------------

struct FakeTransport {
    response: Result<(u16, String), String>,
}

impl indexnow::Transport for FakeTransport {
    fn post_json(&self, _url: &str, _body: &serde_json::Value) -> Result<(u16, String), String> {
        self.response.clone()
    }
}

struct FakeFiles {
    files: std::collections::HashMap<String, String>,
}

impl indexnow::UrlsFileReader for FakeFiles {
    fn read_to_string(&self, path: &str) -> Result<String, String> {
        self.files.get(path).cloned().ok_or_else(|| format!("Error reading batch file: no such file: {path}"))
    }
}

fn no_files() -> FakeFiles {
    FakeFiles { files: Default::default() }
}

#[test]
fn indexnow_run_genkey_prints_32_char_key_and_exits_zero() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let outcome = indexnow::run(&["genkey".to_string()], &transport, &files, None);
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout.trim().len(), 32);
    assert!(outcome.write_file.is_none());
}

#[test]
fn indexnow_run_submit_without_key_env_exits_two() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let args = vec!["submit".to_string(), "--host".to_string(), "example.com".to_string(), "--url".to_string(), "https://example.com/a".to_string()];
    let outcome = indexnow::run(&args, &transport, &files, None);
    assert_eq!(outcome.exit_code, 2);
    assert!(outcome.stderr.contains("INDEXNOW_KEY not set"));
}

#[test]
fn indexnow_run_submit_without_host_is_usage_error() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let args = vec!["submit".to_string(), "--url".to_string(), "https://example.com/a".to_string()];
    let outcome = indexnow::run(&args, &transport, &files, Some("thekey"));
    assert_eq!(outcome.exit_code, 2);
    assert!(outcome.stderr.contains("submit needs --host"));
}

#[test]
fn indexnow_run_submit_success_exits_zero_and_reports_json() {
    let transport = FakeTransport { response: Ok((202, String::new())) };
    let files = no_files();
    let args = vec![
        "submit".to_string(),
        "--host".to_string(),
        "example.com".to_string(),
        "--url".to_string(),
        "https://example.com/a".to_string(),
        "--json".to_string(),
        "/tmp/out.json".to_string(),
    ];
    let outcome = indexnow::run(&args, &transport, &files, Some("thekey"));
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("\"status\": 202"));
    let (path, contents) = outcome.write_file.expect("write_file expected for --json OUT");
    assert_eq!(path, "/tmp/out.json");
    assert!(contents.contains("\"submitted\": 1"));
}

#[test]
fn indexnow_run_submit_http_error_exits_one() {
    let transport = FakeTransport { response: Ok((403, "forbidden".to_string())) };
    let files = no_files();
    let args = vec!["submit".to_string(), "--host".to_string(), "example.com".to_string(), "--url".to_string(), "https://example.com/a".to_string()];
    let outcome = indexnow::run(&args, &transport, &files, Some("thekey"));
    assert_eq!(outcome.exit_code, 1);
}

#[test]
fn indexnow_run_submit_reads_urls_file() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let mut files_map = std::collections::HashMap::new();
    files_map.insert("urls.txt".to_string(), "https://a\n\nhttps://b\n".to_string());
    let files = FakeFiles { files: files_map };
    let args = vec!["submit".to_string(), "--host".to_string(), "example.com".to_string(), "--urls".to_string(), "urls.txt".to_string()];
    let outcome = indexnow::run(&args, &transport, &files, Some("thekey"));
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("\"submitted\": 2"));
}

#[test]
fn indexnow_run_submit_missing_urls_file_reports_error() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let args = vec!["submit".to_string(), "--host".to_string(), "example.com".to_string(), "--urls".to_string(), "missing.txt".to_string()];
    let outcome = indexnow::run(&args, &transport, &files, Some("thekey"));
    assert_eq!(outcome.exit_code, 2);
    assert!(outcome.stderr.contains("Error reading batch file"));
}

#[test]
fn indexnow_run_unknown_command_is_usage_error() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let outcome = indexnow::run(&["bogus".to_string()], &transport, &files, None);
    assert_eq!(outcome.exit_code, 2);
}

#[test]
fn indexnow_run_no_args_is_usage_error() {
    let transport = FakeTransport { response: Ok((200, String::new())) };
    let files = no_files();
    let outcome = indexnow::run(&[], &transport, &files, None);
    assert_eq!(outcome.exit_code, 2);
}

#[test]
fn indexnow_reqwest_transport_constructs() {
    // Compile-time / smoke check that the real transport wires up cleanly
    // (no network call is made).
    let _transport = indexnow::ReqwestTransport::new();
}

// ---------------------------------------------------------------------
// indexing_notify.py — CLI (`main()`)
// ---------------------------------------------------------------------

struct FakeIndexingClient {
    publish_responses: RefCell<Vec<Result<serde_json::Value, String>>>,
    metadata_response: Result<serde_json::Value, String>,
}

impl indexing_notify::IndexingClient for FakeIndexingClient {
    fn publish(&self, _body: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.publish_responses.borrow_mut().remove(0)
    }
    fn get_metadata(&self, _url: &str) -> Result<serde_json::Value, String> {
        self.metadata_response.clone()
    }
}

struct FakeBatchFiles {
    files: std::collections::HashMap<String, String>,
}

impl indexing_notify::BatchFileReader for FakeBatchFiles {
    fn read_to_string(&self, path: &str) -> Result<String, String> {
        self.files.get(path).cloned().ok_or_else(|| "no such file".to_string())
    }
}

fn no_batch_files() -> FakeBatchFiles {
    FakeBatchFiles { files: Default::default() }
}

#[test]
fn indexing_notify_run_single_url_success() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![Ok(json!({
            "urlNotificationMetadata": {"latestUpdate": {"url": "https://e/1", "type": "URL_UPDATED", "notifyTime": "2026-01-01T00:00:00Z"}}
        }))]),
        metadata_response: Err("unused".to_string()),
    };
    let files = no_batch_files();
    let args = vec!["https://e/1".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("Notified: https://e/1 (URL_UPDATED) at 2026-01-01T00:00:00Z"));
}

#[test]
fn indexing_notify_run_status_reports_metadata() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Ok(json!({
            "latestUpdate": {"url": "https://e/1", "type": "URL_UPDATED", "notifyTime": "t1"}
        })),
    };
    let files = no_batch_files();
    let args = vec!["--status".to_string(), "https://e/1".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("=== Notification Status: https://e/1 ==="));
    assert!(outcome.stdout.contains("Latest Update: t1 (URL_UPDATED)"));
}

#[test]
fn indexing_notify_run_status_no_notifications_found() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Ok(json!({})),
    };
    let files = no_batch_files();
    let args = vec!["--status".to_string(), "https://e/1".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("No notifications found."));
}

#[test]
fn indexing_notify_run_batch_reports_summary() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![
            Ok(json!({"urlNotificationMetadata": {"latestUpdate": {"notifyTime": "t1"}}})),
            Ok(json!({"urlNotificationMetadata": {"latestUpdate": {"notifyTime": "t2"}}})),
        ]),
        metadata_response: Err("unused".to_string()),
    };
    let mut files_map = std::collections::HashMap::new();
    files_map.insert("batch.txt".to_string(), "https://e/1\nhttps://e/2\n".to_string());
    let files = FakeBatchFiles { files: files_map };
    let args = vec!["--batch".to_string(), "batch.txt".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("Total: 2 | Success: 2 | Errors: 0"));
}

#[test]
fn indexing_notify_run_batch_missing_file_exits_one() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Err("unused".to_string()),
    };
    let files = no_batch_files();
    let args = vec!["--batch".to_string(), "missing.txt".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 1);
    assert!(outcome.stderr.contains("Error reading batch file"));
}

#[test]
fn indexing_notify_run_no_args_prints_usage_and_exits_one() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Err("unused".to_string()),
    };
    let files = no_batch_files();
    let outcome = indexing_notify::run(&[], &client, &files);
    assert_eq!(outcome.exit_code, 1);
    assert!(outcome.stdout.contains("usage:"));
}

#[test]
fn indexing_notify_run_json_flag_outputs_json() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![Ok(json!({
            "urlNotificationMetadata": {"latestUpdate": {"notifyTime": "t1"}}
        }))]),
        metadata_response: Err("unused".to_string()),
    };
    let files = no_batch_files();
    let args = vec!["https://e/1".to_string(), "--json".to_string()];
    let outcome = indexing_notify::run(&args, &client, &files);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.contains("\"notify_time\": \"t1\""));
}

#[test]
fn indexing_notify_get_notification_metadata_with_extracts_both_fields() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Ok(json!({
            "latestUpdate": {"url": "https://e/1", "type": "URL_UPDATED", "notifyTime": "t1"},
            "latestRemove": {"url": "https://e/1", "type": "URL_DELETED", "notifyTime": "t2"}
        })),
    };
    let result = indexing_notify::get_notification_metadata_with(&client, "https://e/1");
    assert!(result.latest_update.is_some());
    assert!(result.latest_remove.is_some());
    assert!(result.error.is_none());
}

#[test]
fn indexing_notify_get_notification_metadata_with_404_is_categorized() {
    let client = FakeIndexingClient {
        publish_responses: RefCell::new(vec![]),
        metadata_response: Err("404 not found".to_string()),
    };
    let result = indexing_notify::get_notification_metadata_with(&client, "https://e/1");
    assert_eq!(result.error.as_deref(), Some("No notification metadata found for this URL."));
}

#[test]
fn indexing_notify_reqwest_client_constructs() {
    // Compile-time / smoke check that the real client wires up cleanly
    // (no network call is made).
    let _client = indexing_notify::ReqwestIndexingClient::new("token".to_string());
}
