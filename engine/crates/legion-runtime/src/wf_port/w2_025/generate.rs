//! Port of `skills/seo/extensions/banana/scripts/generate.py` (packet r33
//! closes the previously-open HTTP/filesystem gap).
//!
//! The Python script is a stdlib-only Gemini REST fallback: it validates
//! CLI input, builds a `generateContent` request body, performs the HTTP
//! call with `urllib.request`, and extracts/saves the returned image.
//! Every deterministic piece — input validation, request-body
//! construction, response-part extraction, output filename/path
//! construction, and result shaping — is ported as pure functions. The
//! HTTP call and the image write are now wired too, behind
//! [`ImageTransport`] and [`OutputFs`] so tests never touch the network or
//! disk: [`run`] reproduces `main()`'s full flow (validate, resolve key,
//! POST, extract, save, build the printed JSON result), and
//! [`ReqwestImageTransport`] / [`StdFs`] are the production
//! implementations ([`reqwest::blocking`] is already a workspace
//! dependency of this crate).

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
pub const DEFAULT_RESOLUTION: &str = "1K";
pub const DEFAULT_RATIO: &str = "1:1";
pub const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

pub fn valid_ratios() -> BTreeSet<&'static str> {
    [
        "1:1", "16:9", "9:16", "4:3", "3:4", "2:3", "3:2", "4:5", "5:4", "1:4", "4:1", "1:8",
        "8:1", "21:9",
    ]
    .into_iter()
    .collect()
}

pub fn valid_resolutions() -> BTreeSet<&'static str> {
    ["512", "1K", "2K", "4K"].into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    InvalidAspectRatio(String),
    InvalidResolution(String),
    MissingApiKey,
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAspectRatio(v) => {
                let mut ratios: Vec<_> = valid_ratios().into_iter().collect();
                ratios.sort_unstable();
                write!(f, "Invalid aspect ratio '{v}'. Valid: {ratios:?}")
            }
            Self::InvalidResolution(v) => {
                let mut resolutions: Vec<_> = valid_resolutions().into_iter().collect();
                resolutions.sort_unstable();
                write!(f, "Invalid resolution '{v}'. Valid: {resolutions:?}")
            }
            Self::MissingApiKey => write!(
                f,
                "No API key. Set GOOGLE_AI_API_KEY env or pass --api-key"
            ),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Validate CLI-style generation inputs, matching `main()`'s validation
/// block (aspect ratio, then resolution, then API key presence). Returns
/// the first failure in that order, exactly like Python's sequential exits.
pub fn validate_inputs(
    aspect_ratio: &str,
    resolution: &str,
    api_key: Option<&str>,
) -> Result<(), GenerateError> {
    if !valid_ratios().contains(aspect_ratio) {
        return Err(GenerateError::InvalidAspectRatio(aspect_ratio.to_string()));
    }
    if !valid_resolutions().contains(resolution) {
        return Err(GenerateError::InvalidResolution(resolution.to_string()));
    }
    if api_key.map(str::is_empty).unwrap_or(true) {
        return Err(GenerateError::MissingApiKey);
    }
    Ok(())
}

/// Resolve the API key the way Python's `args.api_key or
/// os.environ.get("GOOGLE_AI_API_KEY") or os.environ.get("GOOGLE_API_KEY")`
/// does: first non-empty of (explicit flag, `GOOGLE_AI_API_KEY`,
/// `GOOGLE_API_KEY`).
pub fn resolve_api_key(
    flag: Option<&str>,
    google_ai_api_key: Option<&str>,
    google_api_key: Option<&str>,
) -> Option<String> {
    for candidate in [flag, google_ai_api_key, google_api_key] {
        if let Some(v) = candidate {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ImageConfig {
    #[serde(rename = "aspectRatio")]
    pub aspect_ratio: String,
    #[serde(rename = "imageSize")]
    pub image_size: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ThinkingConfig {
    #[serde(rename = "thinkingLevel")]
    pub thinking_level: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenerationConfig {
    #[serde(rename = "responseModalities")]
    pub response_modalities: Vec<String>,
    #[serde(rename = "imageConfig")]
    pub image_config: ImageConfig,
    #[serde(rename = "thinkingConfig", skip_serializing_if = "Option::is_none")]
    pub thinking_config: Option<ThinkingConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Part {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Content {
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenerateRequestBody {
    pub contents: Vec<Content>,
    #[serde(rename = "generationConfig")]
    pub generation_config: GenerationConfig,
}

/// Build the `generateContent` request body, matching `generate_image`'s
/// `body` dict exactly (including that `responseModalities` omits `"TEXT"`
/// when `image_only` is set, and `thinkingConfig` is present only when a
/// thinking level was given).
pub fn build_request_body(
    prompt: &str,
    aspect_ratio: &str,
    resolution: &str,
    thinking_level: Option<&str>,
    image_only: bool,
) -> GenerateRequestBody {
    let response_modalities = if image_only {
        vec!["IMAGE".to_string()]
    } else {
        vec!["TEXT".to_string(), "IMAGE".to_string()]
    };

    GenerateRequestBody {
        contents: vec![Content {
            parts: vec![Part {
                text: prompt.to_string(),
            }],
        }],
        generation_config: GenerationConfig {
            response_modalities,
            image_config: ImageConfig {
                aspect_ratio: aspect_ratio.to_string(),
                image_size: resolution.to_string(),
            },
            thinking_config: thinking_level.map(|level| ThinkingConfig {
                thinking_level: level.to_string(),
            }),
        },
    }
}

/// Build the request URL, matching
/// `f"{API_BASE}/{model}:generateContent?key={api_key}"`.
pub fn request_url(model: &str, api_key: &str) -> String {
    format!("{API_BASE}/{model}:generateContent?key={api_key}")
}

/// A single `parts[]` entry from the Gemini response, as far as this
/// script inspects it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResponsePart {
    pub inline_data_b64: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractError {
    /// Mirrors `"No candidates returned. Reason: {finish_reason}"`.
    NoCandidates { block_reason: String },
    /// Mirrors `"No image in response. finishReason: {finish_reason}"`.
    NoImage { finish_reason: String },
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCandidates { block_reason } => {
                write!(f, "No candidates returned. Reason: {block_reason}")
            }
            Self::NoImage { finish_reason } => {
                write!(f, "No image in response. finishReason: {finish_reason}")
            }
        }
    }
}

impl std::error::Error for ExtractError {}

/// Extracted result of a successful generation, before it is written to
/// disk: matches the fields Python assembles into its returned dict, minus
/// `path` (filesystem-dependent — see [`output_filename`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedImage {
    pub image_data_b64: String,
    pub text: String,
}

/// Extract the generated image (base64) and any text from a candidate's
/// parts, matching the `for part in parts: ...` loop plus the two
/// `if not candidates` / `if not image_data` failure branches.
///
/// `candidates` is `(finish_reason, parts)` per candidate, already decoded
/// from JSON by the caller (this module owns no JSON parsing of the wire
/// response, only the shape-walking logic).
pub fn extract_image(
    candidates: &[(Option<String>, Vec<ResponsePart>)],
    prompt_feedback_block_reason: Option<&str>,
) -> Result<ExtractedImage, ExtractError> {
    let Some((finish_reason, parts)) = candidates.first() else {
        return Err(ExtractError::NoCandidates {
            block_reason: prompt_feedback_block_reason.unwrap_or("UNKNOWN").to_string(),
        });
    };

    let mut image_data = None;
    let mut text_response = String::new();
    for part in parts {
        if let Some(data) = &part.inline_data_b64 {
            image_data = Some(data.clone());
        } else if let Some(text) = &part.text {
            text_response = text.clone();
        }
    }

    match image_data {
        Some(image_data_b64) => Ok(ExtractedImage {
            image_data_b64,
            text: text_response,
        }),
        None => Err(ExtractError::NoImage {
            finish_reason: finish_reason.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        }),
    }
}

/// Build the output filename, matching
/// `f"banana_{timestamp}.png"` with `timestamp` from
/// `datetime.now().strftime("%Y%m%d_%H%M%S_%f")`. `timestamp` is injected
/// so this stays pure and deterministic in tests.
pub fn output_filename(timestamp: &str) -> String {
    format!("banana_{timestamp}.png")
}

/// The final JSON-able result Python prints, matching the dict
/// `generate_image` returns (minus `path`, which is filesystem-dependent
/// and constructed by the caller as `OUTPUT_DIR / output_filename(...)`).
#[derive(Debug, Clone, PartialEq)]
pub struct GenerateResult {
    pub model: String,
    pub aspect_ratio: String,
    pub resolution: String,
    pub text: String,
}

/// Parses the raw Gemini `generateContent` JSON response into the shape
/// [`extract_image`] consumes, matching `result.get("candidates", [])`,
/// each candidate's `content.parts` and `finishReason`, and
/// `promptFeedback.blockReason`.
pub fn parse_candidates(body: &Value) -> (Vec<(Option<String>, Vec<ResponsePart>)>, Option<String>) {
    let block_reason = body
        .get("promptFeedback")
        .and_then(|f| f.get("blockReason"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let candidates = body
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let parsed = candidates
        .into_iter()
        .map(|c| {
            let finish_reason = c
                .get("finishReason")
                .and_then(Value::as_str)
                .map(str::to_string);
            let parts = c
                .get("content")
                .and_then(|content| content.get("parts"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|p| ResponsePart {
                    inline_data_b64: p
                        .get("inlineData")
                        .and_then(|d| d.get("data"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    text: p.get("text").and_then(Value::as_str).map(str::to_string),
                })
                .collect();
            (finish_reason, parts)
        })
        .collect();

    (parsed, block_reason)
}

/// HTTP boundary for the Gemini `generateContent` POST. Mirrors
/// `urllib.request.urlopen`/`HTTPError`: any response that reached the
/// server (2xx or an error status) is `Ok((status, body))`; a transport
/// failure (DNS, connect, timeout — Python's `URLError`) is `Err`.
pub trait ImageTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String>;
}

/// Filesystem boundary for saving the decoded image, mirroring
/// `OUTPUT_DIR.mkdir(parents=True, exist_ok=True)` +
/// `open(output_path, "wb").write(...)`.
pub trait OutputFs {
    fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()>;
    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()>;
}

/// CLI-shaped arguments, matching `argparse`'s flags.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerateArgs {
    pub prompt: String,
    pub aspect_ratio: String,
    pub resolution: String,
    pub model: String,
    pub api_key: Option<String>,
    pub thinking: Option<String>,
    pub image_only: bool,
}

impl Default for GenerateArgs {
    fn default() -> Self {
        Self {
            prompt: String::new(),
            aspect_ratio: DEFAULT_RATIO.to_string(),
            resolution: DEFAULT_RESOLUTION.to_string(),
            model: DEFAULT_MODEL.to_string(),
            api_key: None,
            thinking: None,
            image_only: false,
        }
    }
}

/// Outcome of [`run`]: either the printed JSON result (matching Python's
/// `print(json.dumps(result, indent=2))` on success, or `print(json.dumps({...}))`
/// plus `sys.exit(1)` on any error path) and the process exit code.
#[derive(Debug, Clone, PartialEq)]
pub struct RunOutcome {
    pub printed: String,
    pub exit_code: i32,
}

fn error_outcome(message: String) -> RunOutcome {
    RunOutcome {
        printed: serde_json::json!({ "error": true, "message": message }).to_string(),
        exit_code: 1,
    }
}

/// `main()` + `generate_image()`: validate, resolve the API key, POST to
/// Gemini, extract the image, save it via `fs`, and build the printed
/// result. `timestamp` and `output_dir` are injected (Python derives the
/// former from `datetime.now()` and the latter is the fixed
/// `~/Documents/nanobanana_generated`) so this stays deterministic under
/// test.
pub fn run(
    args: &GenerateArgs,
    google_ai_api_key_env: Option<&str>,
    google_api_key_env: Option<&str>,
    transport: &dyn ImageTransport,
    fs: &dyn OutputFs,
    output_dir: &std::path::Path,
    timestamp: &str,
) -> RunOutcome {
    if let Err(e) = validate_inputs(&args.aspect_ratio, &args.resolution, Some("placeholder")) {
        // Aspect-ratio/resolution checks run before key resolution in
        // Python's `main()`; re-run just those two (key is checked next,
        // separately, since its message differs from `validate_inputs`'s).
        if matches!(e, GenerateError::InvalidAspectRatio(_) | GenerateError::InvalidResolution(_)) {
            return error_outcome(e.to_string());
        }
    }

    let api_key = resolve_api_key(
        args.api_key.as_deref(),
        google_ai_api_key_env,
        google_api_key_env,
    );
    let Some(api_key) = api_key else {
        return error_outcome(GenerateError::MissingApiKey.to_string());
    };

    let url = request_url(&args.model, &api_key);
    let body = build_request_body(
        &args.prompt,
        &args.aspect_ratio,
        &args.resolution,
        args.thinking.as_deref(),
        args.image_only,
    );
    let body_value = serde_json::to_value(&body).unwrap_or(Value::Null);

    let (status, resp_body) = match transport.post_json(&url, &body_value) {
        Ok(pair) => pair,
        Err(reason) => {
            return error_outcome(reason);
        }
    };

    if status >= 400 {
        return RunOutcome {
            printed: serde_json::json!({ "error": true, "status": status, "message": resp_body })
                .to_string(),
            exit_code: 1,
        };
    }

    let parsed: Value = match serde_json::from_str(&resp_body) {
        Ok(v) => v,
        Err(e) => return error_outcome(e.to_string()),
    };
    let (candidates, block_reason) = parse_candidates(&parsed);

    let extracted = match extract_image(&candidates, block_reason.as_deref()) {
        Ok(e) => e,
        Err(e) => return error_outcome(e.to_string()),
    };

    if fs.create_dir_all(output_dir).is_err() {
        return error_outcome("failed to create output directory".to_string());
    }

    let filename = output_filename(timestamp);
    let output_path = output_dir.join(&filename);

    let decoded = match base64_decode(&extracted.image_data_b64) {
        Ok(bytes) => bytes,
        Err(e) => return error_outcome(e),
    };

    if let Err(e) = fs.write(&output_path, &decoded) {
        return error_outcome(e.to_string());
    }

    let result = serde_json::json!({
        "path": output_path.to_string_lossy(),
        "model": args.model,
        "aspect_ratio": args.aspect_ratio,
        "resolution": args.resolution,
        "text": extracted.text,
    });

    RunOutcome {
        printed: serde_json::to_string_pretty(&result).unwrap_or_default(),
        exit_code: 0,
    }
}

/// Minimal standard-alphabet base64 decoder (matches Python's
/// `base64.b64decode`, no external base64 crate dependency needed for this
/// one call site).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        table[b as usize] = i as u8;
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4 + 3);
    for chunk in clean.chunks(4) {
        let mut buf = [0u8; 4];
        let mut n = 0;
        for &c in chunk {
            let v = table[c as usize];
            if v == 255 {
                return Err("invalid base64 input".to_string());
            }
            buf[n] = v;
            n += 1;
        }
        let b0 = (buf[0] << 2) | (buf[1] >> 4);
        out.push(b0);
        if n > 2 {
            let b1 = (buf[1] << 4) | (buf[2] >> 2);
            out.push(b1);
        }
        if n > 3 {
            let b2 = (buf[2] << 6) | buf[3];
            out.push(b2);
        }
    }
    Ok(out)
}

/// Production [`ImageTransport`]: a blocking `reqwest::blocking::Client`
/// POST, matching `urllib.request.urlopen(req, timeout=120)`.
pub struct ReqwestImageTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestImageTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for ReqwestImageTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageTransport for ReqwestImageTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String> {
        let resp = self
            .client
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

/// Production [`OutputFs`]: plain `std::fs`.
pub struct StdFs;

impl OutputFs for StdFs {
    fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
}

/// Default output directory, matching
/// `Path.home() / "Documents" / "nanobanana_generated"`.
pub fn default_output_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("Documents").join("nanobanana_generated")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    struct FakeTransport {
        response: Result<(u16, String), String>,
    }

    impl ImageTransport for FakeTransport {
        fn post_json(&self, _url: &str, _body: &Value) -> Result<(u16, String), String> {
            self.response.clone()
        }
    }

    #[derive(Default)]
    struct FakeFs {
        written: RefCell<Vec<(PathBuf, Vec<u8>)>>,
    }

    impl OutputFs for FakeFs {
        fn create_dir_all(&self, _path: &std::path::Path) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
            self.written.borrow_mut().push((path.to_path_buf(), bytes.to_vec()));
            Ok(())
        }
    }

    fn gemini_success_body() -> String {
        serde_json::json!({
            "candidates": [{
                "finishReason": "STOP",
                "content": {
                    "parts": [
                        {"text": "here"},
                        {"inlineData": {"data": "QUJD"}}
                    ]
                }
            }]
        })
        .to_string()
    }

    #[test]
    fn parse_candidates_extracts_parts_and_block_reason() {
        let body = serde_json::json!({
            "promptFeedback": {"blockReason": "SAFETY"},
            "candidates": []
        });
        let (candidates, block_reason) = parse_candidates(&body);
        assert!(candidates.is_empty());
        assert_eq!(block_reason, Some("SAFETY".to_string()));
    }

    #[test]
    fn run_end_to_end_success_writes_image_and_prints_result() {
        let transport = FakeTransport {
            response: Ok((200, gemini_success_body())),
        };
        let fs = FakeFs::default();
        let args = GenerateArgs {
            prompt: "a cat".to_string(),
            ..GenerateArgs::default()
        };
        let outcome = run(
            &args,
            Some("env-key"),
            None,
            &transport,
            &fs,
            std::path::Path::new("/home/user/Documents/nanobanana_generated"),
            "20260924_000000_000000",
        );
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.printed.contains("\"text\": \"here\""));
        let written = fs.written.borrow();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].1, base64_decode("QUJD").unwrap());
        assert!(written[0]
            .0
            .to_string_lossy()
            .ends_with("banana_20260924_000000_000000.png"));
    }

    #[test]
    fn run_rejects_bad_aspect_ratio_before_calling_transport() {
        struct PanicTransport;
        impl ImageTransport for PanicTransport {
            fn post_json(&self, _url: &str, _body: &Value) -> Result<(u16, String), String> {
                panic!("must not be called");
            }
        }
        let fs = FakeFs::default();
        let args = GenerateArgs {
            prompt: "x".to_string(),
            aspect_ratio: "bogus".to_string(),
            ..GenerateArgs::default()
        };
        let outcome = run(
            &args,
            Some("k"),
            None,
            &PanicTransport,
            &fs,
            std::path::Path::new("/tmp/out"),
            "ts",
        );
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.printed.contains("Invalid aspect ratio"));
    }

    #[test]
    fn run_missing_api_key_short_circuits() {
        struct PanicTransport;
        impl ImageTransport for PanicTransport {
            fn post_json(&self, _url: &str, _body: &Value) -> Result<(u16, String), String> {
                panic!("must not be called");
            }
        }
        let fs = FakeFs::default();
        let args = GenerateArgs {
            prompt: "x".to_string(),
            ..GenerateArgs::default()
        };
        let outcome = run(
            &args,
            None,
            None,
            &PanicTransport,
            &fs,
            std::path::Path::new("/tmp/out"),
            "ts",
        );
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.printed.contains("No API key"));
    }

    #[test]
    fn run_http_error_status_reports_message() {
        let transport = FakeTransport {
            response: Ok((429, "rate limited".to_string())),
        };
        let fs = FakeFs::default();
        let args = GenerateArgs {
            prompt: "x".to_string(),
            ..GenerateArgs::default()
        };
        let outcome = run(
            &args,
            Some("k"),
            None,
            &transport,
            &fs,
            std::path::Path::new("/tmp/out"),
            "ts",
        );
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.printed.contains("rate limited"));
    }

    #[test]
    fn base64_decode_roundtrip() {
        assert_eq!(base64_decode("QUJD").unwrap(), b"ABC");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn default_output_dir_matches_python_layout() {
        assert_eq!(
            default_output_dir(std::path::Path::new("/home/user")),
            std::path::PathBuf::from("/home/user/Documents/nanobanana_generated")
        );
    }

    #[test]
    fn validate_inputs_rejects_bad_ratio_first() {
        assert_eq!(
            validate_inputs("bogus", "1K", Some("key")),
            Err(GenerateError::InvalidAspectRatio("bogus".into()))
        );
    }

    #[test]
    fn validate_inputs_rejects_bad_resolution() {
        assert_eq!(
            validate_inputs("1:1", "8K", Some("key")),
            Err(GenerateError::InvalidResolution("8K".into()))
        );
    }

    #[test]
    fn validate_inputs_requires_api_key() {
        assert_eq!(
            validate_inputs("1:1", "1K", None),
            Err(GenerateError::MissingApiKey)
        );
        assert_eq!(
            validate_inputs("1:1", "1K", Some("")),
            Err(GenerateError::MissingApiKey)
        );
    }

    #[test]
    fn validate_inputs_accepts_defaults() {
        assert_eq!(
            validate_inputs(DEFAULT_RATIO, DEFAULT_RESOLUTION, Some("key")),
            Ok(())
        );
    }

    #[test]
    fn resolve_api_key_prefers_flag_then_env_vars() {
        assert_eq!(
            resolve_api_key(Some("flag"), Some("ai"), Some("plain")),
            Some("flag".to_string())
        );
        assert_eq!(
            resolve_api_key(None, Some("ai"), Some("plain")),
            Some("ai".to_string())
        );
        assert_eq!(
            resolve_api_key(None, None, Some("plain")),
            Some("plain".to_string())
        );
        assert_eq!(resolve_api_key(None, None, None), None);
        // Empty flag is falsy in Python's `or` chain.
        assert_eq!(
            resolve_api_key(Some(""), Some("ai"), None),
            Some("ai".to_string())
        );
    }

    #[test]
    fn build_request_body_text_and_image_modalities() {
        let body = build_request_body("a cat in space", "16:9", "1K", None, false);
        assert_eq!(
            body.generation_config.response_modalities,
            vec!["TEXT".to_string(), "IMAGE".to_string()]
        );
        assert!(body.generation_config.thinking_config.is_none());
        assert_eq!(body.contents[0].parts[0].text, "a cat in space");
    }

    #[test]
    fn build_request_body_image_only_omits_text_modality() {
        let body = build_request_body("p", "1:1", "2K", Some("high"), true);
        assert_eq!(body.generation_config.response_modalities, vec!["IMAGE".to_string()]);
        assert_eq!(
            body.generation_config.thinking_config,
            Some(ThinkingConfig {
                thinking_level: "high".to_string()
            })
        );
    }

    #[test]
    fn request_url_matches_python_format() {
        assert_eq!(
            request_url("gemini-3.1-flash-image-preview", "KEY123"),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-image-preview:generateContent?key=KEY123"
        );
    }

    #[test]
    fn extract_image_errors_on_no_candidates() {
        let err = extract_image(&[], Some("SAFETY")).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoCandidates {
                block_reason: "SAFETY".to_string()
            }
        );
    }

    #[test]
    fn extract_image_errors_on_no_candidates_defaults_unknown() {
        let err = extract_image(&[], None).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoCandidates {
                block_reason: "UNKNOWN".to_string()
            }
        );
    }

    #[test]
    fn extract_image_errors_when_no_image_part() {
        let candidates = vec![(
            Some("SAFETY".to_string()),
            vec![ResponsePart {
                inline_data_b64: None,
                text: Some("blocked".to_string()),
            }],
        )];
        let err = extract_image(&candidates, None).unwrap_err();
        assert_eq!(
            err,
            ExtractError::NoImage {
                finish_reason: "SAFETY".to_string()
            }
        );
    }

    #[test]
    fn extract_image_returns_image_and_text() {
        let candidates = vec![(
            Some("STOP".to_string()),
            vec![
                ResponsePart {
                    inline_data_b64: None,
                    text: Some("here you go".to_string()),
                },
                ResponsePart {
                    inline_data_b64: Some("QUJD".to_string()),
                    text: None,
                },
            ],
        )];
        let extracted = extract_image(&candidates, None).unwrap();
        assert_eq!(extracted.image_data_b64, "QUJD");
        assert_eq!(extracted.text, "here you go");
    }

    #[test]
    fn output_filename_matches_python_pattern() {
        assert_eq!(
            output_filename("20260923_120000_000000"),
            "banana_20260923_120000_000000.png"
        );
    }
}
