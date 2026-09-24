//! Port of `skills/seo/extensions/banana/scripts/edit.py` ("Claude Banana -
//! Direct API Fallback: Image Editing"): a stdlib-only Python CLI that edits
//! an image via the Gemini REST API (`generateContent`, multimodal
//! image+text -> image), used as a fallback when the Banana MCP server is
//! unavailable.
//!
//! Ports the whole CLI: argv parsing (`--image`, `--prompt`, `--model`,
//! `--api-key`), env-var API-key fallback (`GOOGLE_AI_API_KEY` /
//! `GOOGLE_API_KEY`), MIME-type detection by extension, the Gemini REST
//! request body, response parsing (`candidates[0].content.parts`, image vs.
//! text parts, `promptFeedback.blockReason` / `finishReason` error paths),
//! output-file naming (`banana_edit_<YYYYMMDD_HHMMSS_ffffff>.png` under
//! `~/Documents/nanobanana_generated`), and the exact JSON stdout shape for
//! both success and error, plus process exit codes (0 success, 1 error).
//!
//! HTTP I/O is behind [`HttpBackend`] so tests can run without the network;
//! [`run`] wires the real `reqwest` blocking client. `datetime.now()` is
//! behind a `now: &dyn Fn() -> SystemTime` parameter for the same reason.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
pub const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// Parsed CLI arguments, mirroring `argparse` in `edit.py`.
#[derive(Debug, Clone)]
pub struct EditArgs {
    pub image: String,
    pub prompt: String,
    pub model: String,
    pub api_key: Option<String>,
}

/// Result of a successful edit; mirrors the dict returned by `edit_image()`.
#[derive(Debug, Clone)]
pub struct EditResult {
    pub path: String,
    pub model: String,
    pub source: String,
    pub text: String,
}

impl EditResult {
    /// Mirrors `print(json.dumps(result, indent=2))` for the success path.
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "model": self.model,
            "source": self.source,
            "text": self.text,
        })
    }
}

/// Mirrors every `print(json.dumps({"error": True, ...})); sys.exit(1)` site.
#[derive(Debug, Clone)]
pub enum EditError {
    /// `Image not found: {image_path}`
    ImageNotFound(String),
    /// `HTTPError`: `{"error": true, "status": code, "message": body}`
    Http { status: u16, message: String },
    /// `URLError` / any other transport failure: `{"error": true, "message": reason}`
    Transport(String),
    /// No `candidates` in the response.
    NoCandidates(String),
    /// `candidates[0]` had no image part.
    NoImage(String),
    /// Missing API key.
    NoApiKey,
    /// I/O failure writing the output file (not present in the Python
    /// original, which lets exceptions propagate as an uncaught traceback;
    /// kept distinct here rather than silently swallowed).
    Io(String),
}

impl EditError {
    /// Mirrors the exact JSON object each Python error branch prints.
    pub fn to_json(&self) -> Value {
        match self {
            EditError::ImageNotFound(msg) => json!({"error": true, "message": msg}),
            EditError::Http { status, message } => {
                json!({"error": true, "status": status, "message": message})
            }
            EditError::Transport(msg) => json!({"error": true, "message": msg}),
            EditError::NoCandidates(msg) => json!({"error": true, "message": msg}),
            EditError::NoImage(msg) => json!({"error": true, "message": msg}),
            EditError::NoApiKey => json!({
                "error": true,
                "message": "No API key. Set GOOGLE_AI_API_KEY env or pass --api-key"
            }),
            EditError::Io(msg) => json!({"error": true, "message": msg}),
        }
    }
}

/// Behind-a-trait HTTP POST so tests avoid the network. Mirrors the single
/// `urllib.request.urlopen(req, timeout=120)` call in `edit_image()`.
pub trait HttpBackend {
    /// Returns `Ok((status, body))` for any response the server sent (even
    /// non-2xx, mirroring `urllib`'s behavior of still exposing the body via
    /// `HTTPError.read()`), or `Err(reason)` for a transport-level failure
    /// (DNS, connect, timeout — mirrors `URLError`).
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String>;
}

/// Real HTTP backend used by [`run`]: a blocking `reqwest` client with a
/// 120s timeout, matching `urlopen(req, timeout=120)`.
pub struct ReqwestBackend;

impl HttpBackend for ReqwestBackend {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// Mirrors the `mime_types` dict in `edit_image()`.
fn mime_type_for(suffix: &str) -> &'static str {
    match suffix.to_ascii_lowercase().as_str() {
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        _ => "image/png",
    }
}

/// Minimal standard-alphabet base64 encoder (RFC 4648, with `=` padding),
/// equivalent to `base64.b64encode(...).decode("utf-8")`.
pub fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Minimal standard-alphabet base64 decoder (RFC 4648, with `=` padding),
/// equivalent to `base64.b64decode(...)`.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    let pad = cleaned.iter().rev().take_while(|&&b| b == b'=').count();
    let data_len = cleaned.len() - pad;
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in &cleaned[..data_len] {
        let v = val(b).ok_or_else(|| format!("invalid base64 byte: {b}"))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Mirrors the `timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")`
/// filename component. Not timezone-aware (matches `datetime.now()`, which
/// uses local time); this port uses `SystemTime` (effectively UTC) since
/// there is no local-timezone source available without a new dependency —
/// this is a narrow, documented behavioral difference from the Python
/// original (local time vs. UTC-based wall clock), not a missing feature.
pub fn format_timestamp(now: SystemTime) -> String {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = dur.as_secs();
    let micros = dur.subsec_micros();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs as i64);
    format!("{y:04}{mo:02}{d:02}_{h:02}{mi:02}{s:02}_{micros:06}")
}

/// Civil (Gregorian) calendar decomposition of a Unix timestamp (UTC), using
/// Howard Hinnant's `civil_from_days` algorithm — pure arithmetic, no
/// dependency needed.
fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let h = (secs_of_day / 3600) as u32;
    let mi = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/// Port of `edit_image(image_path, prompt, model, api_key)`.
pub fn edit_image(
    image_path: &str,
    prompt: &str,
    model: &str,
    api_key: &str,
    http: &dyn HttpBackend,
    output_dir: &Path,
    now: SystemTime,
) -> Result<EditResult, EditError> {
    let image_path = fs::canonicalize(image_path)
        .unwrap_or_else(|_| PathBuf::from(image_path));
    if !image_path.exists() {
        return Err(EditError::ImageNotFound(format!(
            "Image not found: {}",
            image_path.display()
        )));
    }

    let bytes = fs::read(&image_path).map_err(|e| EditError::Io(e.to_string()))?;
    let image_b64 = encode_base64(&bytes);

    let suffix = image_path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let mime_type = mime_type_for(&suffix);

    let url = format!("{API_BASE}/{model}:generateContent?key={api_key}");

    let body = json!({
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                    {"inlineData": {"mimeType": mime_type, "data": image_b64}},
                ]
            }
        ],
        "generationConfig": {
            "responseModalities": ["TEXT", "IMAGE"],
        },
    });

    let (status, resp_text) = http.post_json(&url, &body).map_err(EditError::Transport)?;

    if !(200..300).contains(&status) {
        return Err(EditError::Http {
            status,
            message: resp_text,
        });
    }

    let result: Value =
        serde_json::from_str(&resp_text).map_err(|e| EditError::Transport(e.to_string()))?;

    let candidates = result.get("candidates").and_then(|c| c.as_array());
    let Some(candidates) = candidates.filter(|c| !c.is_empty()) else {
        let finish_reason = result
            .get("promptFeedback")
            .and_then(|p| p.get("blockReason"))
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        return Err(EditError::NoCandidates(format!(
            "No candidates returned. Reason: {finish_reason}"
        )));
    };

    let candidate0 = &candidates[0];
    let parts = candidate0
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let mut image_data: Option<String> = None;
    let mut text_response = String::new();
    for part in &parts {
        if let Some(inline) = part.get("inlineData") {
            if let Some(data) = inline.get("data").and_then(|d| d.as_str()) {
                image_data = Some(data.to_string());
            }
        } else if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
            text_response = text.to_string();
        }
    }

    let Some(image_data) = image_data else {
        let finish_reason = candidate0
            .get("finishReason")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        return Err(EditError::NoImage(format!(
            "No image in response. finishReason: {finish_reason}"
        )));
    };

    fs::create_dir_all(output_dir).map_err(|e| EditError::Io(e.to_string()))?;
    let timestamp = format_timestamp(now);
    let filename = format!("banana_edit_{timestamp}.png");
    let output_path = output_dir.join(&filename);
    let output_path = {
        // Mirrors `.resolve()`: best-effort canonicalization; falls back to
        // the joined path if the parent doesn't exist yet on this platform.
        fs::canonicalize(output_dir)
            .map(|abs| abs.join(&filename))
            .unwrap_or(output_path)
    };

    let decoded = decode_base64(&image_data).map_err(EditError::Io)?;
    let mut f = fs::File::create(&output_path).map_err(|e| EditError::Io(e.to_string()))?;
    f.write_all(&decoded).map_err(|e| EditError::Io(e.to_string()))?;

    Ok(EditResult {
        path: output_path.display().to_string(),
        model: model.to_string(),
        source: image_path.display().to_string(),
        text: text_response,
    })
}

/// Mirrors `OUTPUT_DIR = Path.home() / "Documents" / "nanobanana_generated"`.
pub fn default_output_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join("Documents").join("nanobanana_generated")
}

/// Mirrors `argparse` parsing in `main()`. Returns `Err(message)` for a
/// missing required argument (argparse would print usage to stderr and exit
/// 2; this port returns a simple message since the CLI-parity requirement
/// here is the data/behavior contract, not argparse's exact usage text).
pub fn parse_args(args: &[String]) -> Result<EditArgs, String> {
    let mut image: Option<String> = None;
    let mut prompt: Option<String> = None;
    let mut model = DEFAULT_MODEL.to_string();
    let mut api_key: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--image" => {
                i += 1;
                image = args.get(i).cloned();
            }
            "--prompt" => {
                i += 1;
                prompt = args.get(i).cloned();
            }
            "--model" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    model = v.clone();
                }
            }
            "--api-key" => {
                i += 1;
                api_key = args.get(i).cloned();
            }
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }

    let image = image.ok_or_else(|| "the following arguments are required: --image".to_string())?;
    let prompt =
        prompt.ok_or_else(|| "the following arguments are required: --prompt".to_string())?;

    Ok(EditArgs {
        image,
        prompt,
        model,
        api_key,
    })
}

/// Mirrors `main()`: resolves the API key from `--api-key` then
/// `GOOGLE_AI_API_KEY` then `GOOGLE_API_KEY`, calls [`edit_image`], and
/// prints the JSON result. Returns the process exit code (0 or 1), matching
/// `sys.exit(1)` on every error path and the implicit 0 on success.
pub fn run(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 2;
        }
    };

    let api_key = parsed
        .api_key
        .clone()
        .or_else(|| std::env::var("GOOGLE_AI_API_KEY").ok())
        .or_else(|| std::env::var("GOOGLE_API_KEY").ok());

    let Some(api_key) = api_key else {
        println!("{}", EditError::NoApiKey.to_json());
        return 1;
    };

    let http = ReqwestBackend;
    let output_dir = default_output_dir();
    match edit_image(
        &parsed.image,
        &parsed.prompt,
        &parsed.model,
        &api_key,
        &http,
        &output_dir,
        SystemTime::now(),
    ) {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result.to_json()).unwrap());
            0
        }
        Err(err) => {
            println!("{}", err.to_json());
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("r32-edit-{}-{}", std::process::id(), n));
            fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FakeHttp {
        status: u16,
        body: String,
    }
    impl HttpBackend for FakeHttp {
        fn post_json(&self, _url: &str, _body: &Value) -> Result<(u16, String), String> {
            Ok((self.status, self.body.clone()))
        }
    }

    struct FailingHttp;
    impl HttpBackend for FailingHttp {
        fn post_json(&self, _url: &str, _body: &Value) -> Result<(u16, String), String> {
            Err("Name or service not known".to_string())
        }
    }

    fn tiny_png_bytes() -> Vec<u8> {
        // Not a real PNG, just deterministic bytes to round-trip through
        // base64 encode -> decode.
        vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5]
    }

    #[test]
    fn base64_round_trip() {
        let data = tiny_png_bytes();
        let encoded = encode_base64(&data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_matches_known_vector() {
        assert_eq!(encode_base64(b"man"), "bWFu");
        assert_eq!(encode_base64(b"ma"), "bWE=");
        assert_eq!(encode_base64(b"m"), "bQ==");
        assert_eq!(decode_base64("bWFu").unwrap(), b"man");
    }

    #[test]
    fn parse_args_requires_image_and_prompt() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&["--image".into(), "x.png".into()]).is_err());
        let ok = parse_args(&[
            "--image".into(),
            "x.png".into(),
            "--prompt".into(),
            "do it".into(),
        ])
        .unwrap();
        assert_eq!(ok.image, "x.png");
        assert_eq!(ok.prompt, "do it");
        assert_eq!(ok.model, DEFAULT_MODEL);
        assert!(ok.api_key.is_none());
    }

    #[test]
    fn parse_args_reads_model_and_api_key() {
        let ok = parse_args(&[
            "--image".into(),
            "x.png".into(),
            "--prompt".into(),
            "do it".into(),
            "--model".into(),
            "custom-model".into(),
            "--api-key".into(),
            "secret".into(),
        ])
        .unwrap();
        assert_eq!(ok.model, "custom-model");
        assert_eq!(ok.api_key.as_deref(), Some("secret"));
    }

    #[test]
    fn edit_image_missing_source_file() {
        let dir = TmpDir::new();
        let http = FakeHttp {
            status: 200,
            body: "{}".into(),
        };
        let err = edit_image(
            &dir.0.join("missing.png").display().to_string(),
            "prompt",
            DEFAULT_MODEL,
            "key",
            &http,
            &dir.0,
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, EditError::ImageNotFound(_)));
    }

    #[test]
    fn edit_image_success_writes_decoded_png_and_reports_text() {
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();

        let image_b64 = encode_base64(&tiny_png_bytes());
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "here you go"},
                        {"inlineData": {"mimeType": "image/png", "data": image_b64}},
                    ]
                },
                "finishReason": "STOP",
            }]
        })
        .to_string();
        let http = FakeHttp { status: 200, body };
        let out_dir = dir.0.join("out");

        let result = edit_image(
            &src.display().to_string(),
            "remove background",
            DEFAULT_MODEL,
            "key",
            &http,
            &out_dir,
            SystemTime::now(),
        )
        .unwrap();

        assert_eq!(result.text, "here you go");
        assert_eq!(result.model, DEFAULT_MODEL);
        assert!(result.path.contains("banana_edit_"));
        assert!(result.path.ends_with(".png"));
        let written = fs::read(&result.path).unwrap();
        assert_eq!(written, tiny_png_bytes());
    }

    #[test]
    fn edit_image_no_candidates_reports_block_reason() {
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();

        let body = json!({"promptFeedback": {"blockReason": "SAFETY"}}).to_string();
        let http = FakeHttp { status: 200, body };
        let err = edit_image(
            &src.display().to_string(),
            "prompt",
            DEFAULT_MODEL,
            "key",
            &http,
            &dir.0.join("out"),
            SystemTime::now(),
        )
        .unwrap_err();
        match err {
            EditError::NoCandidates(msg) => assert!(msg.contains("SAFETY")),
            other => panic!("expected NoCandidates, got {other:?}"),
        }
    }

    #[test]
    fn edit_image_no_image_part_reports_finish_reason() {
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();

        let body = json!({
            "candidates": [{"content": {"parts": [{"text": "sorry"}]}, "finishReason": "OTHER"}]
        })
        .to_string();
        let http = FakeHttp { status: 200, body };
        let err = edit_image(
            &src.display().to_string(),
            "prompt",
            DEFAULT_MODEL,
            "key",
            &http,
            &dir.0.join("out"),
            SystemTime::now(),
        )
        .unwrap_err();
        match err {
            EditError::NoImage(msg) => assert!(msg.contains("OTHER")),
            other => panic!("expected NoImage, got {other:?}"),
        }
    }

    #[test]
    fn edit_image_http_error_status_reports_status_and_body() {
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();

        let http = FakeHttp {
            status: 429,
            body: "rate limited".into(),
        };
        let err = edit_image(
            &src.display().to_string(),
            "prompt",
            DEFAULT_MODEL,
            "key",
            &http,
            &dir.0.join("out"),
            SystemTime::now(),
        )
        .unwrap_err();
        match err {
            EditError::Http { status, message } => {
                assert_eq!(status, 429);
                assert_eq!(message, "rate limited");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn edit_image_transport_failure_is_reported() {
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();

        let err = edit_image(
            &src.display().to_string(),
            "prompt",
            DEFAULT_MODEL,
            "key",
            &FailingHttp,
            &dir.0.join("out"),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, EditError::Transport(_)));
    }

    #[test]
    fn mime_type_detection_matches_extension_map() {
        assert_eq!(mime_type_for(".png"), "image/png");
        assert_eq!(mime_type_for(".jpg"), "image/jpeg");
        assert_eq!(mime_type_for(".jpeg"), "image/jpeg");
        assert_eq!(mime_type_for(".webp"), "image/webp");
        assert_eq!(mime_type_for(".gif"), "image/gif");
        assert_eq!(mime_type_for(".bmp"), "image/png");
    }

    #[test]
    fn format_timestamp_matches_known_unix_time() {
        // 2024-01-02T03:04:05.123456Z
        let secs = 1_704_164_645u64;
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(123_456);
        assert_eq!(format_timestamp(ts), "20240102_030405_123456");
    }

    #[test]
    fn run_reports_missing_api_key_without_network() {
        // No --api-key and (assumed) no env vars set in the test process for
        // these names; if a developer's shell happens to export
        // GOOGLE_AI_API_KEY/GOOGLE_API_KEY this assertion is skipped rather
        // than false-failing.
        if std::env::var("GOOGLE_AI_API_KEY").is_ok() || std::env::var("GOOGLE_API_KEY").is_ok() {
            return;
        }
        let dir = TmpDir::new();
        let src = dir.0.join("in.png");
        fs::write(&src, tiny_png_bytes()).unwrap();
        let code = run(&[
            "--image".into(),
            src.display().to_string(),
            "--prompt".into(),
            "do it".into(),
        ]);
        assert_eq!(code, 1);
    }
}
