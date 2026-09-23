//! Port of `skills/designer/engine/huashu/scripts/tts-doubao.mjs` (packet
//! Q0, chunk `q_q0`).
//!
//! The legacy script is a Node CLI that POSTs to the Doubao/Volcengine
//! `openspeech` TTS endpoint, writes the returned base64 audio to a file,
//! and shells out to `ffprobe` for the resulting duration. This port
//! covers the pure, I/O-free pieces faithfully:
//!
//! - [`parse_args`] — the `--text`/`--text-file`/`--out`/`--speed`/
//!   `--voice`/`--encoding`/`--help` argv parser (mirrors `parseArgs`).
//! - [`parse_env_line`] / [`parse_dotenv`] — the `.env` line parser
//!   (mirrors `loadEnv`'s line-splitting and quote-stripping, `KEY=value`
//!   with `#`-comment and blank-line skipping, values already quoted with
//!   `'` or `"` unwrapped).
//! - [`TtsRequest::build_body`] — the outbound JSON request body shape
//!   (mirrors the `body` object literal in `tts()`).
//! - [`parse_tts_response`] — the inbound JSON response envelope's
//!   success/error decoding (mirrors the `code !== 3000` / missing-`data`
//!   error branches in `tts()`), returning the raw base64 audio payload
//!   on success.
//!
//! NOT-PORTED: the actual `fetch()` POST and the `ffprobe` duration probe.
//! `legion-runtime`'s `Cargo.toml` has no HTTP client crate (`reqwest` is
//! present elsewhere in the workspace `Cargo.lock` but is not a dependency
//! of this crate), so no real network call can be made here without an
//! `engine/Cargo.toml` edit — out of scope for this packet; see the Q0
//! report for the exact patch. Callers wire [`TtsRequest::build_body`]'s
//! output into their own HTTP client and feed the response body to
//! [`parse_tts_response`].

use serde_json::{json, Value};

/// Parsed CLI arguments, mirroring `parseArgs(argv)` in the legacy script.
/// `speed` and `encoding` carry the same defaults as the JS (`"1.0"` and
/// `"mp3"`); `help` mirrors `--help`/`-h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TtsArgs {
    pub text: Option<String>,
    pub text_file: Option<String>,
    pub out: Option<String>,
    pub speed: String,
    pub voice: Option<String>,
    pub encoding: String,
    pub help: bool,
}

/// Parses argv (excluding the program name / script path, i.e. the slice
/// the legacy script sees as `argv.slice(2)`) the same way `parseArgs` does:
/// unknown flags are silently ignored, and a flag missing its value reads
/// past the end as `None` rather than panicking (mirroring `argv[++i]`
/// being `undefined` at the end of the array).
pub fn parse_args<I, S>(argv: I) -> TtsArgs
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = argv.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut args = TtsArgs {
        speed: "1.0".to_string(),
        encoding: "mp3".to_string(),
        ..Default::default()
    };
    let mut i = 0usize;
    while i < items.len() {
        let a = items[i].as_str();
        match a {
            "--text" => {
                i += 1;
                args.text = items.get(i).cloned();
            }
            "--text-file" => {
                i += 1;
                args.text_file = items.get(i).cloned();
            }
            "--out" => {
                i += 1;
                args.out = items.get(i).cloned();
            }
            "--speed" => {
                i += 1;
                if let Some(v) = items.get(i) {
                    args.speed = v.clone();
                }
            }
            "--voice" => {
                i += 1;
                args.voice = items.get(i).cloned();
            }
            "--encoding" => {
                i += 1;
                if let Some(v) = items.get(i) {
                    args.encoding = v.clone();
                }
            }
            "--help" | "-h" => {
                args.help = true;
            }
            _ => {}
        }
        i += 1;
    }
    args
}

/// Parses one `.env` line into a `(key, value)` pair, mirroring the body of
/// the `for (const line of text.split('\n'))` loop in `loadEnv()`:
/// - leading/trailing whitespace on the whole line is trimmed;
/// - blank lines and lines starting with `#` (after trim) yield `None`;
/// - lines with no `=` yield `None`;
/// - the key is the substring before the first `=`, trimmed;
/// - the value is the substring after the first `=`, trimmed, then unwrapped
///   one level of matching `'...'` or `"..."` quoting if present.
pub fn parse_env_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let idx = trimmed.find('=')?;
    let key = trimmed[..idx].trim().to_string();
    let mut val = trimmed[idx + 1..].trim().to_string();
    let is_quoted = (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2);
    if is_quoted {
        val = val[1..val.len() - 1].to_string();
    }
    Some((key, val))
}

/// Parses a full `.env` file's text into an ordered list of `(key, value)`
/// pairs, mirroring `loadEnv()`'s loop over `text.split('\n')` (skipping
/// lines [`parse_env_line`] rejects). Unlike the JS, which mutates
/// `process.env` only for keys not already set, this is a pure parse —
/// callers apply the "don't override an existing env var" precedence
/// themselves.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    text.lines().filter_map(parse_env_line).collect()
}

/// The resolved inputs to a TTS request, mirroring the destructured
/// `{ text, voice, speed, encoding }` plus the resolved `apiKey`/`cluster`/
/// `voiceId` in `tts()`.
#[derive(Debug, Clone)]
pub struct TtsRequest {
    pub cluster: String,
    pub voice_id: String,
    pub encoding: String,
    pub speed: f64,
    pub reqid: String,
    pub text: String,
}

impl TtsRequest {
    /// Builds the outbound JSON request body, mirroring the `body` object
    /// literal in `tts()` field-for-field (`app.cluster`, `user.uid`
    /// hardcoded to `"huashu-design"`, `audio.voice_type`/`encoding`/
    /// `speed_ratio`, `request.reqid`/`text`/`operation: "query"`).
    pub fn build_body(&self) -> Value {
        json!({
            "app": { "cluster": self.cluster },
            "user": { "uid": "huashu-design" },
            "audio": {
                "voice_type": self.voice_id,
                "encoding": self.encoding,
                "speed_ratio": self.speed,
            },
            "request": {
                "reqid": self.reqid,
                "text": self.text,
                "operation": "query",
            },
        })
    }
}

/// Errors from decoding a Doubao TTS response body, mirroring the thrown
/// `Error`s in `tts()`'s response-handling branch (the HTTP-status branch,
/// `res.ok` check, is the caller's concern since it owns the HTTP call).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TtsResponseError {
    #[error("response body is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("API 返回错误 code={code} msg={message}")]
    ApiError { code: i64, message: String },
    #[error("API 响应无 data 字段：{0}")]
    MissingData(String),
}

/// Parses a Doubao TTS JSON response body and returns the base64-encoded
/// audio payload (`json.data`) on success, mirroring:
/// - `json.code !== undefined && json.code !== 3000` → `ApiError`
///   (message falls back to the whole JSON, truncated to 500 chars, same
///   as `JSON.stringify(json)` when `message` is absent);
/// - missing/falsy `json.data` → `MissingData` (message truncated to 500
///   chars, same as the JS `.slice(0, 500)`).
pub fn parse_tts_response(body: &str) -> Result<String, TtsResponseError> {
    let json: Value =
        serde_json::from_str(body).map_err(|e| TtsResponseError::InvalidJson(e.to_string()))?;

    if let Some(code) = json.get("code").and_then(|c| c.as_i64()) {
        if code != 3000 {
            let message = json
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| truncate_500(&json.to_string()));
            return Err(TtsResponseError::ApiError { code, message });
        }
    }

    match json.get("data").and_then(|d| d.as_str()) {
        Some(data) if !data.is_empty() => Ok(data.to_string()),
        _ => Err(TtsResponseError::MissingData(truncate_500(&json.to_string()))),
    }
}

fn truncate_500(s: &str) -> String {
    s.chars().take(500).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let args = parse_args(Vec::<String>::new());
        assert_eq!(args.speed, "1.0");
        assert_eq!(args.encoding, "mp3");
        assert!(!args.help);
        assert!(args.text.is_none());
    }

    #[test]
    fn parse_args_full() {
        let args = parse_args([
            "--text", "hello", "--out", "out.mp3", "--speed", "1.5", "--voice", "v1",
            "--encoding", "wav",
        ]);
        assert_eq!(args.text.as_deref(), Some("hello"));
        assert_eq!(args.out.as_deref(), Some("out.mp3"));
        assert_eq!(args.speed, "1.5");
        assert_eq!(args.voice.as_deref(), Some("v1"));
        assert_eq!(args.encoding, "wav");
    }

    #[test]
    fn parse_args_help_flag() {
        assert!(parse_args(["--help"]).help);
        assert!(parse_args(["-h"]).help);
    }

    #[test]
    fn parse_args_flag_missing_value_does_not_panic() {
        let args = parse_args(["--text"]);
        assert_eq!(args.text, None);
    }

    #[test]
    fn parse_args_unknown_flag_ignored() {
        let args = parse_args(["--bogus", "x", "--text", "hi"]);
        assert_eq!(args.text.as_deref(), Some("hi"));
    }

    #[test]
    fn env_line_basic() {
        assert_eq!(
            parse_env_line("DOUBAO_TTS_API_KEY=abc123"),
            Some(("DOUBAO_TTS_API_KEY".to_string(), "abc123".to_string()))
        );
    }

    #[test]
    fn env_line_quoted_values() {
        assert_eq!(
            parse_env_line(r#"KEY="hello world""#),
            Some(("KEY".to_string(), "hello world".to_string()))
        );
        assert_eq!(
            parse_env_line("KEY='hello'"),
            Some(("KEY".to_string(), "hello".to_string()))
        );
    }

    #[test]
    fn env_line_comments_and_blank() {
        assert_eq!(parse_env_line(""), None);
        assert_eq!(parse_env_line("   "), None);
        assert_eq!(parse_env_line("# a comment"), None);
        assert_eq!(parse_env_line("  # indented comment"), None);
    }

    #[test]
    fn env_line_no_equals() {
        assert_eq!(parse_env_line("NOT_AN_ASSIGNMENT"), None);
    }

    #[test]
    fn dotenv_full_file() {
        let text = "# comment\nA=1\n\nB=\"two\"\nC='three'\nBAD_LINE\n";
        let parsed = parse_dotenv(text);
        assert_eq!(
            parsed,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two".to_string()),
                ("C".to_string(), "three".to_string()),
            ]
        );
    }

    #[test]
    fn build_body_matches_shape() {
        let req = TtsRequest {
            cluster: "volcano_icl".to_string(),
            voice_id: "voice-1".to_string(),
            encoding: "mp3".to_string(),
            speed: 1.0,
            reqid: "req-1".to_string(),
            text: "你好".to_string(),
        };
        let body = req.build_body();
        assert_eq!(body["app"]["cluster"], "volcano_icl");
        assert_eq!(body["user"]["uid"], "huashu-design");
        assert_eq!(body["audio"]["voice_type"], "voice-1");
        assert_eq!(body["audio"]["encoding"], "mp3");
        assert_eq!(body["audio"]["speed_ratio"], 1.0);
        assert_eq!(body["request"]["reqid"], "req-1");
        assert_eq!(body["request"]["text"], "你好");
        assert_eq!(body["request"]["operation"], "query");
    }

    #[test]
    fn response_success() {
        let body = r#"{"code":3000,"data":"QUJD"}"#;
        assert_eq!(parse_tts_response(body).unwrap(), "QUJD");
    }

    #[test]
    fn response_no_code_field_treated_as_success_if_data_present() {
        // Mirrors `json.code !== undefined && ...`: when `code` is absent
        // the error branch is skipped entirely, same as this port's
        // `and_then(|c| c.as_i64())` returning `None`.
        let body = r#"{"data":"QUJD"}"#;
        assert_eq!(parse_tts_response(body).unwrap(), "QUJD");
    }

    #[test]
    fn response_api_error_code() {
        let body = r#"{"code":4000,"message":"bad voice id"}"#;
        let err = parse_tts_response(body).unwrap_err();
        assert_eq!(
            err,
            TtsResponseError::ApiError {
                code: 4000,
                message: "bad voice id".to_string()
            }
        );
    }

    #[test]
    fn response_missing_data() {
        let body = r#"{"code":3000}"#;
        let err = parse_tts_response(body).unwrap_err();
        assert!(matches!(err, TtsResponseError::MissingData(_)));
    }

    #[test]
    fn response_invalid_json() {
        let err = parse_tts_response("not json").unwrap_err();
        assert!(matches!(err, TtsResponseError::InvalidJson(_)));
    }
}
