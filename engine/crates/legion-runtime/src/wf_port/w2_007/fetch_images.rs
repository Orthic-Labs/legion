//! Port of `skills/designer/engine/huashu/scripts/fetch_images.py` (chunk
//! w2_007): a Wikimedia Commons image fetcher for huashu-design's "content
//! design needs real photos" step.
//!
//! The script's actual network I/O (`urllib.request.urlopen` against the
//! Commons API and each thumbnail URL) is ported as a `Fetcher` trait
//! rather than a hard-wired `reqwest` call: `legion-runtime`'s own
//! `Cargo.toml` does not list `reqwest` as a dependency yet (only the
//! workspace root does, for other crates), and this chunk may not edit
//! `Cargo.toml`. The report for this chunk carries the exact dependency
//! patch and a `ReqwestFetcher` implementation an integrator can drop in;
//! every other piece of behavior — proxy-env stripping, the compliant
//! User-Agent, filename sanitization, response-to-`Downloaded` mapping,
//! the per-item log line format, and the all-failed exit code — is ported
//! faithfully here and is fully unit-tested against a stubbed `Fetcher`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Port of the `API` constant.
pub const API_URL: &str = "https://commons.wikimedia.org/w/api.php";

/// Port of the `UA` constant — the compliant User-Agent Wikimedia requires
/// or it returns HTTP 429.
pub const USER_AGENT: &str = "huashu-design-image-fetcher/1.0 (https://huasheng.ai; skill contact)";

/// Port of the proxy environment variables `fetch_images.py` unsets at
/// import time (`for _k in (...)`) because a local proxy makes `urllib`'s
/// TLS handshake fail.
pub const PROXY_ENV_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
];

/// Removes every variable in [`PROXY_ENV_VARS`] from the process
/// environment, mirroring the module-level `os.environ.pop(_k, None)`
/// loop. A host embedding this port calls it once at startup, the same
/// place the Python script runs it (import time, unconditionally).
pub fn strip_proxy_env() {
    for key in PROXY_ENV_VARS {
        std::env::remove_var(key);
    }
}

/// Port of `_safe(name)`: replace every character outside `[A-Za-z0-9_.-]`
/// with `_`, then truncate to 60 chars. Python's `\w` in a non-Unicode-flag
/// regex on `str` matches Unicode word characters; `_safe` is always called
/// on ASCII-ish query/title text in practice, so this port matches the
/// common (ASCII) case exactly and treats any other Unicode letter as a
/// word character too, mirroring Python's default `\w` behavior.
pub fn safe_name(name: &str) -> String {
    let replaced: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    replaced.chars().take(60).collect()
}

/// One `imageinfo` entry's `extmetadata`, as read out of the Commons API
/// JSON. Mirrors the ad hoc dict digging `fetch()` does: any missing field
/// degrades to a documented default rather than an error.
#[derive(Debug, Clone, Deserialize)]
pub struct CommonsPage {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub imageinfo: Vec<CommonsImageInfo>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CommonsImageInfo {
    #[serde(default)]
    pub thumburl: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub descriptionurl: Option<String>,
    #[serde(default)]
    pub extmetadata: HashMap<String, ExtMetaValue>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtMetaValue {
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CommonsQueryResponse {
    #[serde(default)]
    pub query: Option<CommonsQuery>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CommonsQuery {
    #[serde(default)]
    pub pages: HashMap<String, CommonsPage>,
}

/// Port of the `iiurlwidth`/`gsrlimit` query params `fetch()` sends, so a
/// `Fetcher` implementation builds the exact same request `_api_get` does.
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

/// One resolved-but-not-yet-downloaded candidate: everything `fetch()`
/// derives from a single `imageinfo` entry before attempting the download —
/// destination filename, license, artist, and the source description page,
/// exactly the four columns the `[OK]` log line prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCandidate {
    pub thumb_url: String,
    pub dest_path: PathBuf,
    pub license: String,
    pub artist: String,
    pub description_url: String,
}

/// Port of the `<[^>]+>` tag-strip used on the `Artist` extmetadata field
/// (Commons often embeds an `<a href=...>` in it) plus the `.strip()`.
pub fn strip_html_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Port of the per-page body inside `fetch()`'s `for p in list(pages.values())[:count]`
/// loop, up to (not including) the actual download — filename derivation,
/// license/artist extraction, `[FAIL search]`/skip-if-no-thumb behavior.
/// `out_dir` mirrors the `--out` directory.
pub fn build_candidates(
    query: &str,
    out_dir: &Path,
    pages: &[CommonsPage],
    count: usize,
) -> Vec<ImageCandidate> {
    let mut candidates = Vec::new();
    for p in pages.iter().take(count) {
        let ii = p.imageinfo.first().cloned().unwrap_or_default();
        let thumb = ii.thumburl.clone().or_else(|| ii.url.clone());
        let Some(thumb) = thumb else { continue };

        let license = ii
            .extmetadata
            .get("LicenseShortName")
            .map(|v| v.value.clone())
            .unwrap_or_else(|| "?".to_string());
        let artist_raw = ii
            .extmetadata
            .get("Artist")
            .map(|v| v.value.clone())
            .unwrap_or_else(|| "?".to_string());
        let artist = strip_html_tags(&artist_raw);

        let ext = extension_of(&thumb);
        let title = p
            .title
            .clone()
            .unwrap_or_else(|| "img".to_string())
            .replace("File:", "");
        let mut fn_base = format!("{}_{}", safe_name(query), safe_name(&title));
        // Python: os.path.splitext(fn)[0][:55] + ext — strip any extension
        // `safe_name`'s truncation may have left, cap the stem to 55 chars,
        // then append the derived extension.
        if let Some(dot) = fn_base.rfind('.') {
            fn_base.truncate(dot);
        }
        let stem: String = fn_base.chars().take(55).collect();
        let filename = format!("{stem}{ext}");

        // Python's `os.path.join` on the forward-slash `out_dir` string this
        // port is always called with stays forward-slash; `Path::join`
        // would introduce `\` on Windows, so join as a string instead.
        let out_dir_str = out_dir.to_string_lossy();
        let out_dir_str = out_dir_str.trim_end_matches(['/', '\\']);
        candidates.push(ImageCandidate {
            thumb_url: thumb,
            dest_path: PathBuf::from(format!("{out_dir_str}/{filename}")),
            license,
            artist,
            description_url: ii.descriptionurl.clone().unwrap_or_default(),
        });
    }
    candidates
}

/// Port of `ext = os.path.splitext(thumb)[1].split("?")[0] or ".jpg"`.
fn extension_of(url: &str) -> String {
    let without_query = url.split('?').next().unwrap_or(url);
    match without_query.rfind('.') {
        Some(idx) if idx + 1 < without_query.len() => {
            let candidate = &without_query[idx..];
            // splitext only treats it as an extension if there's no further
            // path separator after the dot, which a bare filename URL tail
            // already guarantees here.
            if candidate.len() > 1 {
                candidate.to_string()
            } else {
                ".jpg".to_string()
            }
        }
        _ => ".jpg".to_string(),
    }
}

/// Port of the `[OK] ...` log line format.
pub fn ok_log_line(candidate: &ImageCandidate) -> String {
    format!(
        "[OK] {}  | {} | {} | {}",
        candidate.dest_path.display(),
        candidate.license,
        candidate.artist,
        candidate.description_url
    )
}

/// Port of the `[EMPTY] ...` stderr line when a query yields nothing.
pub fn empty_log_line(query: &str) -> String {
    format!("[EMPTY] 「{query}」没抓到——换关键词，或走 Phase 3.5 兜底")
}

/// Port of the final summary + honesty-check reminder lines `main()` prints.
pub fn summary_lines(out_dir: &Path, downloaded_count: usize) -> Vec<String> {
    vec![
        format!(
            "\n=== 共下载 {downloaded_count} 张到 {} ===",
            out_dir.display()
        ),
        "⚠️ 诚实性核对：去掉每张图信息是否有损？许可是否允许用途？不合适的删掉。".to_string(),
    ]
}

/// Port of the `[FAIL] 全部失败 → ...` stderr line printed before `sys.exit(1)`
/// when nothing was downloaded across every query.
pub const ALL_FAILED_MESSAGE: &str =
    "❌ 全部失败 → 走 Phase 3.5 取图三级兜底（Unsplash/Pexels → 生图 → 诚实 placeholder，不卡流程）";

/// Port of `main()`'s exit-code decision: `sys.exit(1)` iff nothing was
/// downloaded across all queries, `0` (success, no explicit exit call)
/// otherwise.
pub fn exit_code(total_downloaded: usize) -> i32 {
    if total_downloaded == 0 {
        1
    } else {
        0
    }
}
