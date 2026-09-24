//! Port of `skills/designer/engine/huashu/scripts/fetch_images.py`.
//!
//! Closes the gap left by `wf_port::q_q0::fetch_images` (arg/shape parsing
//! only, no HTTP layer): this module adds the actual Wikimedia Commons
//! search + download round trip behind [`CommonsClient`], with a real
//! `reqwest`-backed implementation ([`HttpCommonsClient`]) and a fake used
//! in tests so no test hits the network.
//!
//! Faithful to the Python original:
//! - strips proxy env vars before any request (`ALL_PROXY`/`all_proxy`/
//!   `HTTP_PROXY`/`http_proxy`/`HTTPS_PROXY`/`https_proxy`)
//! - same Commons API query shape, same compliant User-Agent string
//! - same filename derivation (`_safe()` slug, 60-char cap on slugs, 55-char
//!   cap on the joined stem before the extension) and same license/artist
//!   extraction (HTML-tag-stripped `Artist.value`, default `"?"`)
//! - same `[OK]` / `[FAIL search]` / `[FAIL dl]` / `[EMPTY]` message shapes
//!   and the same "all failed -> exit 1" behaviour

use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const API_URL: &str = "https://commons.wikimedia.org/w/api.php";
pub const USER_AGENT: &str =
    "huashu-design-image-fetcher/1.0 (https://huasheng.ai; skill contact)";

const PROXY_VARS: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
];

/// Removes proxy env vars, mirroring the `os.environ.pop` loop at the top of
/// `fetch_images.py` (local curl/urllib through a proxy TLS-fails).
pub fn clear_proxy_env() {
    for k in PROXY_VARS {
        std::env::remove_var(k);
    }
}

/// `_safe()`: keep `[\w.-]`, replace everything else with `_`, cap at 60 chars.
pub fn safe_slug(name: &str) -> String {
    let re = Regex::new(r"[^\w\-.]").expect("static regex");
    let replaced = re.replace_all(name, "_");
    replaced.chars().take(60).collect()
}

/// `re.sub("<[^>]+>", "", value).strip()`.
pub fn strip_html_tags(value: &str) -> String {
    let re = Regex::new(r"<[^>]+>").expect("static regex");
    re.replace_all(value, "").trim().to_string()
}

/// `os.path.splitext(thumb)[1].split("?")[0] or ".jpg"`.
pub fn thumb_extension(thumb_url: &str) -> String {
    let without_query = thumb_url.split('?').next().unwrap_or("");
    match without_query.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && !ext.contains('/') => format!(".{ext}"),
        _ => ".jpg".to_string(),
    }
}

/// Builds the same filename the Python does:
/// `safe(query) + "_" + safe(title.replace("File:", ""))`, then
/// `splitext(fn)[0][:55] + ext`.
pub fn output_filename(query: &str, title: &str, ext: &str) -> String {
    let title_no_prefix = title.replace("File:", "");
    let stem = format!("{}_{}", safe_slug(query), safe_slug(&title_no_prefix));
    let stem: String = stem.chars().take(55).collect();
    format!("{stem}{ext}")
}

/// Search query-string params, matching the Python `params` dict.
pub fn search_params(query: &str, count: u32, width: u32) -> Vec<(&'static str, String)> {
    vec![
        ("action", "query".to_string()),
        ("format", "json".to_string()),
        ("generator", "search".to_string()),
        ("gsrsearch", query.to_string()),
        ("gsrnamespace", "6".to_string()),
        ("gsrlimit", count.to_string()),
        ("prop", "imageinfo".to_string()),
        ("iiprop", "url|extmetadata".to_string()),
        ("iiurlwidth", width.to_string()),
    ]
}

/// One resolved image ready to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    pub thumb_url: String,
    pub license: String,
    pub artist: String,
    pub description_url: String,
    pub filename: String,
}

/// Parses the Commons `action=query` JSON response into up to `count`
/// [`ResolvedImage`] entries, mirroring the `for p in list(pages.values())[:count]`
/// loop (pages missing a usable `thumburl`/`url` are silently skipped, as
/// in the Python).
pub fn parse_search_response(body: &Value, query: &str, count: usize) -> Vec<ResolvedImage> {
    let mut out = Vec::new();
    let pages = body
        .get("query")
        .and_then(|q| q.get("pages"))
        .and_then(|p| p.as_object());
    let Some(pages) = pages else {
        return out;
    };
    for p in pages.values().take(count) {
        let ii = p
            .get("imageinfo")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first());
        let Some(ii) = ii else { continue };
        let thumb = ii
            .get("thumburl")
            .and_then(|v| v.as_str())
            .or_else(|| ii.get("url").and_then(|v| v.as_str()));
        let Some(thumb) = thumb else { continue };

        let meta = ii.get("extmetadata");
        let license = meta
            .and_then(|m| m.get("LicenseShortName"))
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let artist_raw = meta
            .and_then(|m| m.get("Artist"))
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let artist = strip_html_tags(artist_raw);
        let ext = thumb_extension(thumb);
        let title = p
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("img")
            .to_string();
        let filename = output_filename(query, &title, &ext);
        let description_url = ii
            .get("descriptionurl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        out.push(ResolvedImage {
            thumb_url: thumb.to_string(),
            license,
            artist,
            description_url,
            filename,
        });
    }
    out
}

/// I/O boundary: Commons API search + raw image download. Production impl
/// is [`HttpCommonsClient`]; tests use a fake.
#[async_trait::async_trait]
pub trait CommonsClient {
    async fn search(&self, params: &[(&str, String)]) -> Result<Value, String>;
    async fn download(&self, url: &str) -> Result<Vec<u8>, String>;
}

pub struct HttpCommonsClient {
    client: reqwest::Client,
}

impl HttpCommonsClient {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl CommonsClient for HttpCommonsClient {
    async fn search(&self, params: &[(&str, String)]) -> Result<Value, String> {
        let resp = self
            .client
            .get(API_URL)
            .query(params)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json::<Value>().await.map_err(|e| e.to_string())
    }

    async fn download(&self, url: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok(bytes.to_vec())
    }
}

/// One line of the `[OK]`/`[FAIL ...]` progress log the Python prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchLogLine {
    Ok {
        path: String,
        license: String,
        artist: String,
        description_url: String,
    },
    FailSearch {
        query: String,
        error: String,
    },
    FailDownload {
        thumb_url: String,
        error: String,
    },
    Empty {
        query: String,
    },
}

/// `fetch(query, out, count, width)`: search then download each hit,
/// returning the written paths and a log mirroring stdout/stderr lines.
pub async fn fetch(
    client: &dyn CommonsClient,
    write_file: &dyn Fn(&Path, &[u8]) -> std::io::Result<()>,
    query: &str,
    out_dir: &Path,
    count: u32,
    width: u32,
) -> (Vec<PathBuf>, Vec<FetchLogLine>) {
    let mut got = Vec::new();
    let mut log = Vec::new();

    let params = search_params(query, count, width);
    let body = match client.search(&params).await {
        Ok(b) => b,
        Err(e) => {
            log.push(FetchLogLine::FailSearch {
                query: query.to_string(),
                error: e,
            });
            return (got, log);
        }
    };

    let images = parse_search_response(&body, query, count as usize);
    for img in images {
        match client.download(&img.thumb_url).await {
            Ok(bytes) => {
                let path = out_dir.join(&img.filename);
                match write_file(&path, &bytes) {
                    Ok(()) => {
                        log.push(FetchLogLine::Ok {
                            path: path.to_string_lossy().to_string(),
                            license: img.license,
                            artist: img.artist,
                            description_url: img.description_url,
                        });
                        got.push(path);
                    }
                    Err(e) => log.push(FetchLogLine::FailDownload {
                        thumb_url: img.thumb_url,
                        error: e.to_string(),
                    }),
                }
            }
            Err(e) => log.push(FetchLogLine::FailDownload {
                thumb_url: img.thumb_url,
                error: e,
            }),
        }
    }

    if got.is_empty() {
        log.push(FetchLogLine::Empty {
            query: query.to_string(),
        });
    }

    (got, log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn safe_slug_matches_python_regex_and_cap() {
        assert_eq!(safe_slug("Petronas Towers!"), "Petronas_Towers_");
        let long = "a".repeat(100);
        assert_eq!(safe_slug(&long).len(), 60);
    }

    #[test]
    fn strip_html_tags_trims_and_removes_tags() {
        assert_eq!(
            strip_html_tags("  <a href=\"x\">Jane Doe</a>  "),
            "Jane Doe"
        );
        assert_eq!(strip_html_tags("?"), "?");
    }

    #[test]
    fn thumb_extension_falls_back_to_jpg() {
        assert_eq!(thumb_extension("https://x/y/img.png?width=100"), ".png");
        assert_eq!(thumb_extension("https://x/y/img"), ".jpg");
    }

    #[test]
    fn output_filename_strips_file_prefix_and_caps_stem() {
        let name = output_filename("Petronas Towers", "File:Petronas Towers KL.jpg", ".jpg");
        assert!(name.starts_with("Petronas_Towers_Petronas_Towers_KL"));
        assert!(name.ends_with(".jpg"));
        let stem_len = name.len() - ".jpg".len();
        assert!(stem_len <= 55);
    }

    #[test]
    fn search_params_match_python_dict() {
        let params = search_params("Langkawi beach", 2, 1600);
        assert_eq!(
            params,
            vec![
                ("action", "query".to_string()),
                ("format", "json".to_string()),
                ("generator", "search".to_string()),
                ("gsrsearch", "Langkawi beach".to_string()),
                ("gsrnamespace", "6".to_string()),
                ("gsrlimit", "2".to_string()),
                ("prop", "imageinfo".to_string()),
                ("iiprop", "url|extmetadata".to_string()),
                ("iiurlwidth", "1600".to_string()),
            ]
        );
    }

    #[test]
    fn parse_search_response_extracts_fields_and_defaults() {
        let body = json!({
            "query": {
                "pages": {
                    "123": {
                        "title": "File:Petronas Towers.jpg",
                        "imageinfo": [{
                            "thumburl": "https://x/thumb.jpg",
                            "descriptionurl": "https://commons/page",
                            "extmetadata": {
                                "LicenseShortName": {"value": "CC BY-SA 4.0"},
                                "Artist": {"value": "<a>Jane</a>"}
                            }
                        }]
                    },
                    "456": {
                        "title": "File:No Thumb.jpg",
                        "imageinfo": [{}]
                    }
                }
            }
        });
        let images = parse_search_response(&body, "petronas", 5);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].license, "CC BY-SA 4.0");
        assert_eq!(images[0].artist, "Jane");
        assert_eq!(images[0].description_url, "https://commons/page");
    }

    #[test]
    fn parse_search_response_defaults_license_and_artist_to_question_mark() {
        let body = json!({
            "query": {"pages": {"1": {"title": "File:X.jpg", "imageinfo": [{"url": "https://x/x.jpg"}]}}}
        });
        let images = parse_search_response(&body, "x", 5);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].license, "?");
        assert_eq!(images[0].artist, "?");
    }

    struct FakeClient {
        search_result: Result<Value, String>,
        downloads: Mutex<HashMap<String, Result<Vec<u8>, String>>>,
    }

    #[async_trait::async_trait]
    impl CommonsClient for FakeClient {
        async fn search(&self, _params: &[(&str, String)]) -> Result<Value, String> {
            self.search_result.clone()
        }
        async fn download(&self, url: &str) -> Result<Vec<u8>, String> {
            self.downloads
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .unwrap_or_else(|| Err(format!("no fake response for {url}")))
        }
    }

    #[tokio::test]
    async fn fetch_downloads_each_hit_and_logs_ok() {
        let body = json!({
            "query": {"pages": {"1": {"title": "File:X.jpg", "imageinfo": [{
                "thumburl": "https://x/x.jpg",
                "descriptionurl": "https://commons/x",
                "extmetadata": {"LicenseShortName": {"value": "PD"}, "Artist": {"value": "A"}}
            }]}}}
        });
        let mut downloads = HashMap::new();
        downloads.insert("https://x/x.jpg".to_string(), Ok(vec![1, 2, 3]));
        let client = FakeClient {
            search_result: Ok(body),
            downloads: Mutex::new(downloads),
        };
        let written = Mutex::new(Vec::new());
        let write = |path: &Path, bytes: &[u8]| {
            written.lock().unwrap().push((path.to_path_buf(), bytes.to_vec()));
            Ok(())
        };
        let (got, log) = fetch(
            &client,
            &write,
            "x",
            Path::new("/out"),
            2,
            1600,
        )
        .await;
        assert_eq!(got.len(), 1);
        assert!(matches!(log[0], FetchLogLine::Ok { .. }));
    }

    #[tokio::test]
    async fn fetch_logs_empty_when_search_fails() {
        let client = FakeClient {
            search_result: Err("boom".to_string()),
            downloads: Mutex::new(HashMap::new()),
        };
        let write = |_: &Path, _: &[u8]| Ok(());
        let (got, log) = fetch(&client, &write, "x", Path::new("/out"), 2, 1600).await;
        assert!(got.is_empty());
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0], FetchLogLine::FailSearch { .. }));
    }
}
