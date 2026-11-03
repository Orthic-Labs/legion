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
pub const USER_AGENT: &str = "huashu-design-image-fetcher/1.0 (https://huasheng.ai; skill contact)";

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

// ---------------------------------------------------------------------------
// CLI wrapper — port of `main()`.
// ---------------------------------------------------------------------------

/// Parsed `argparse` result: `--query` (`nargs="+"`, required), `--out`
/// (required), `--count` (default 2), `--width` (default 1600).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub query: Vec<String>,
    pub out: PathBuf,
    pub count: u32,
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgsError {
    /// `--query` is `required`, `nargs="+"` (at least one value).
    MissingQuery,
    /// `--out` is `required`.
    MissingOut,
}

/// Port of the `argparse.ArgumentParser` setup in `main()`. Accepts
/// `--query` as one or more space-separated values up to the next `--flag`
/// (mirroring `nargs="+"`), and `--count`/`--width` as `int` with the same
/// defaults (`2`, `1600`) the Python declares.
pub fn parse_args(argv: &[String]) -> Result<Args, ParseArgsError> {
    let mut query: Vec<String> = Vec::new();
    let mut out: Option<String> = None;
    let mut count: u32 = 2;
    let mut width: u32 = 1600;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--query" => {
                i += 1;
                while i < argv.len() && !argv[i].starts_with("--") {
                    query.push(argv[i].clone());
                    i += 1;
                }
            }
            "--out" => {
                out = argv.get(i + 1).cloned();
                i += 2;
            }
            "--count" => {
                if let Some(v) = argv.get(i + 1).and_then(|s| s.parse().ok()) {
                    count = v;
                }
                i += 2;
            }
            "--width" => {
                if let Some(v) = argv.get(i + 1).and_then(|s| s.parse().ok()) {
                    width = v;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    if query.is_empty() {
        return Err(ParseArgsError::MissingQuery);
    }
    let out = out.ok_or(ParseArgsError::MissingOut)?;

    Ok(Args {
        query,
        out: PathBuf::from(out),
        count,
        width,
    })
}

/// One line of `main()`'s tail summary/warning/failure output, after all
/// queries have run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryLogLine {
    /// `f"\n=== 共下载 {n} 张到 {out} ==="`.
    Downloaded { count: usize, out: String },
    /// The fixed honesty-check reminder line, printed unconditionally.
    HonestyReminder,
    /// `"❌ 全部失败 → ..."` (stderr), printed only when nothing downloaded.
    AllFailed,
}

/// `main()`: create `out`, run `fetch()` for every `--query`, print the
/// summary, and report whether the process should exit 1 (`allgot` empty).
/// `ensure_dir` mirrors `os.makedirs(a.out, exist_ok=True)`.
pub async fn run(
    client: &dyn CommonsClient,
    write_file: &dyn Fn(&Path, &[u8]) -> std::io::Result<()>,
    ensure_dir: &dyn Fn(&Path) -> std::io::Result<()>,
    args: &Args,
) -> (Vec<PathBuf>, Vec<FetchLogLine>, Vec<SummaryLogLine>, i32) {
    let _ = ensure_dir(&args.out);

    let mut all_got = Vec::new();
    let mut all_log = Vec::new();
    for q in &args.query {
        let (got, log) = fetch(client, write_file, q, &args.out, args.count, args.width).await;
        all_got.extend(got);
        all_log.extend(log);
    }

    let mut summary = vec![
        SummaryLogLine::Downloaded {
            count: all_got.len(),
            out: args.out.to_string_lossy().to_string(),
        },
        SummaryLogLine::HonestyReminder,
    ];

    let exit_code = if all_got.is_empty() {
        summary.push(SummaryLogLine::AllFailed);
        1
    } else {
        0
    };

    (all_got, all_log, summary, exit_code)
}
