//! Full port of `skills/designer/engine/huashu/scripts/tts-doubao.mjs`.
//!
//! `wf_port::q_q0::tts_doubao` already ported the pure pieces (argv parsing,
//! `.env` line parsing, the outbound JSON body shape, the inbound envelope's
//! success/error decoding) and documented the remaining gap: no HTTP client
//! or subprocess wrapper was wired into `legion-runtime` yet. Both are now
//! available (`reqwest` with the `blocking` feature, and `std::process`
//! needs nothing extra), so this module is the complete port: it performs
//! the real `POST` to the Doubao/Volcengine `openspeech` TTS endpoint and
//! the real `ffprobe` duration probe, behind [`HttpPost`] and
//! [`DurationProbe`] traits so tests never touch the network or spawn a
//! process.
//!
//! Faithful to the legacy script:
//! - same flags (`--text`, `--text-file`, `--out`, `--speed`, `--voice`,
//!   `--encoding`, `--help`/`-h`) and defaults (`speed="1.0"`,
//!   `encoding="mp3"`)
//! - same `.env` loading semantics: read from `<skill-root>/.env`, only set
//!   keys not already present in the environment
//! - same required-field errors (`缺 DOUBAO_TTS_API_KEY（检查 .env）`, `缺
//!   DOUBAO_TTS_VOICE_ID（检查 .env 或用 --voice 传）`, `错：缺 --text 或
//!   --text-file`, `错：缺 --out`) and usage text
//! - same request body shape, response decoding (`code !== 3000` is an
//!   error; missing/empty `data` is an error), and `HTTP {status}: {body}`
//!   error format (body truncated to 500 chars)
//! - same stdout: one JSON line `{"path":...,"bytes":...,"duration":...,
//!   "text_chars":...}`
//! - same failure mode: `TTS 失败：{message}` to stderr, exit code 1

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Argument parsing — mirrors `parseArgs(argv)`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Args {
    pub text: Option<String>,
    pub text_file: Option<String>,
    pub out: Option<String>,
    pub speed: String,
    pub voice: Option<String>,
    pub encoding: String,
    pub help: bool,
}

/// Parses argv (the CLI's own arguments, i.e. what the legacy script sees
/// as `argv.slice(2)`), matching `parseArgs`: unknown flags are ignored,
/// and a flag missing its value reads past the end as `None`/unchanged
/// rather than panicking.
pub fn parse_args(argv: &[String]) -> Args {
    let mut args = Args {
        speed: "1.0".to_string(),
        encoding: "mp3".to_string(),
        ..Default::default()
    };
    let mut i = 0usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "--text" => {
                i += 1;
                args.text = argv.get(i).cloned();
            }
            "--text-file" => {
                i += 1;
                args.text_file = argv.get(i).cloned();
            }
            "--out" => {
                i += 1;
                args.out = argv.get(i).cloned();
            }
            "--speed" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.speed = v.clone();
                }
            }
            "--voice" => {
                i += 1;
                args.voice = argv.get(i).cloned();
            }
            "--encoding" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.encoding = v.clone();
                }
            }
            "--help" | "-h" => args.help = true,
            _ => {}
        }
        i += 1;
    }
    args
}

/// Exact text of `usage()`'s template literal (trimmed, as the JS does).
pub const USAGE_TEXT: &str = "tts-doubao.mjs · 豆包语音 TTS\n\n  --text <str>          要合成的文本\n  --text-file <path>    从文件读取文本（与 --text 二选一）\n  --out <path>          输出 mp3 路径（必填）\n  --speed <float>       语速倍率，默认 1.0（0.5-2.0）\n  --voice <voice_id>    覆盖 .env 里的音色 id\n  --encoding <ext>      mp3 / wav / pcm，默认 mp3";

// ---------------------------------------------------------------------------
// `.env` parsing — mirrors `loadEnv()`.
// ---------------------------------------------------------------------------

/// Parses one `.env` line into `(key, value)`, mirroring the loop body in
/// `loadEnv()`: blank/`#`-comment lines (after trim) are skipped, split on
/// the first `=`, both sides trimmed, one layer of matching `'...'`/`"..."`
/// quoting stripped from the value.
pub fn parse_env_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let idx = trimmed.find('=')?;
    let key = trimmed[..idx].trim().to_string();
    let mut val = trimmed[idx + 1..].trim().to_string();
    let is_quoted = val.len() >= 2
        && ((val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\'')));
    if is_quoted {
        val = val[1..val.len() - 1].to_string();
    }
    Some((key, val))
}

/// Parses full `.env` text into an ordered list of pairs.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    text.split('\n').filter_map(parse_env_line).collect()
}

/// Applies parsed `.env` pairs onto `env`, only setting keys not already
/// present — mirrors `if (!(key in process.env)) process.env[key] = val;`.
pub fn apply_dotenv(env: &mut HashMap<String, String>, pairs: &[(String, String)]) {
    for (k, v) in pairs {
        env.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

// ---------------------------------------------------------------------------
// TTS request/response — mirrors `tts({ text, voice, speed, encoding })`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedRequest {
    pub endpoint: String,
    pub api_key: String,
    pub cluster: String,
    pub voice_id: String,
    pub encoding: String,
    pub speed: f64,
    pub reqid: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TtsError {
    #[error("缺 DOUBAO_TTS_API_KEY（检查 .env）")]
    MissingApiKey,
    #[error("缺 DOUBAO_TTS_VOICE_ID（检查 .env 或用 --voice 传）")]
    MissingVoiceId,
    #[error("HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("{0}")]
    Network(String),
    #[error("response body is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("API 返回错误 code={code} msg={message}")]
    ApiError { code: i64, message: String },
    #[error("API 响应无 data 字段：{0}")]
    MissingData(String),
    #[error("base64 解码失败：{0}")]
    Base64(String),
}

/// Resolves the request from CLI args + environment, mirroring the top of
/// `tts()`: `apiKey`/`cluster`/`endpoint`/`voiceId` resolution and the two
/// required-field checks (`apiKey`, `voiceId`).
pub fn resolve_request(
    args: &Args,
    env: &HashMap<String, String>,
    text: &str,
    reqid: String,
) -> Result<ResolvedRequest, TtsError> {
    let api_key = env
        .get("DOUBAO_TTS_API_KEY")
        .cloned()
        .ok_or(TtsError::MissingApiKey)?;
    let cluster = env
        .get("DOUBAO_TTS_CLUSTER")
        .cloned()
        .unwrap_or_else(|| "volcano_icl".to_string());
    let endpoint = env
        .get("DOUBAO_TTS_ENDPOINT")
        .cloned()
        .unwrap_or_else(|| "https://openspeech.bytedance.com/api/v1/tts".to_string());
    let voice_id = args
        .voice
        .clone()
        .or_else(|| env.get("DOUBAO_TTS_VOICE_ID").cloned())
        .ok_or(TtsError::MissingVoiceId)?;
    let speed: f64 = args.speed.parse().unwrap_or(f64::NAN);

    Ok(ResolvedRequest {
        endpoint,
        api_key,
        cluster,
        voice_id,
        encoding: args.encoding.clone(),
        speed,
        reqid,
        text: text.to_string(),
    })
}

/// Builds the outbound JSON body, mirroring the `body` object literal in
/// `tts()` field-for-field. `speed_ratio` is built via
/// [`serde_json::Number::from_f64`] rather than the `json!` macro's direct
/// float substitution: a non-finite `speed` (e.g. an unparseable `--speed`
/// flag, mirrored as `f64::NAN`) would make `json!`'s `serde_json::to_value`
/// path panic, whereas `JSON.stringify(NaN)` in the legacy script silently
/// serializes to `null` — this keeps that same non-panicking behavior.
pub fn build_body(req: &ResolvedRequest) -> Value {
    let speed_ratio = serde_json::Number::from_f64(req.speed)
        .map(Value::Number)
        .unwrap_or(Value::Null);
    json!({
        "app": { "cluster": req.cluster },
        "user": { "uid": "huashu-design" },
        "audio": {
            "voice_type": req.voice_id,
            "encoding": req.encoding,
            "speed_ratio": speed_ratio,
        },
        "request": {
            "reqid": req.reqid,
            "text": req.text,
            "operation": "query",
        },
    })
}

fn truncate_500(s: &str) -> String {
    s.chars().take(500).collect()
}

/// Decodes the JSON response body into raw audio bytes, mirroring the
/// `res.json()` handling in `tts()` (the `!res.ok` HTTP-status branch is
/// handled by the caller before this is reached — see [`tts`]).
pub fn parse_tts_response(body: &str) -> Result<Vec<u8>, TtsError> {
    let json: Value =
        serde_json::from_str(body).map_err(|e| TtsError::InvalidJson(e.to_string()))?;

    if let Some(code) = json.get("code") {
        if code.as_i64() != Some(3000) {
            let message = json
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| json.to_string());
            return Err(TtsError::ApiError {
                code: code.as_i64().unwrap_or_default(),
                message,
            });
        }
    }

    let data = json
        .get("data")
        .and_then(|d| d.as_str())
        .filter(|d| !d.is_empty());
    let Some(data) = data else {
        return Err(TtsError::MissingData(truncate_500(&json.to_string())));
    };

    decode_base64(data).map_err(TtsError::Base64)
}

/// Minimal standard-alphabet base64 decoder (RFC 4648, `=` padding),
/// equivalent to `Buffer.from(json.data, 'base64')` for the well-formed
/// padded base64 the Doubao API returns.
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
    let mut chunk = [0u8; 4];
    let mut chunk_len = 0usize;
    for &b in &cleaned[..data_len] {
        let v = val(b).ok_or_else(|| format!("invalid base64 byte: {b}"))?;
        chunk[chunk_len] = v;
        chunk_len += 1;
        if chunk_len == 4 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
            out.push((chunk[2] << 6) | chunk[3]);
            chunk_len = 0;
        }
    }
    match chunk_len {
        2 => out.push((chunk[0] << 2) | (chunk[1] >> 4)),
        3 => {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        1 => return Err("truncated base64 input".to_string()),
        _ => {}
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// I/O boundaries.
// ---------------------------------------------------------------------------

/// The HTTP transport boundary, mirroring `fetch(endpoint, { method: 'POST',
/// headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
/// body: JSON.stringify(body) })`. Returns `(status, body_text)`.
pub trait HttpPost {
    fn post_json(&self, url: &str, api_key: &str, body: &Value) -> Result<(u16, String), String>;
}

/// The `ffprobe` duration probe, mirroring `getDuration(filePath)`: on any
/// failure (missing binary, non-zero exit, unparseable stdout) returns
/// `None`, matching the JS `catch (e) { return null; }`.
pub trait DurationProbe {
    fn duration_seconds(&self, path: &Path) -> Option<f64>;
}

/// The full `tts()` call: resolve request, POST, decode response.
pub fn tts(
    args: &Args,
    env: &HashMap<String, String>,
    text: &str,
    reqid: String,
    http: &dyn HttpPost,
) -> Result<Vec<u8>, TtsError> {
    let req = resolve_request(args, env, text, reqid)?;
    let body = build_body(&req);
    let (status, body_text) = http
        .post_json(&req.endpoint, &req.api_key, &body)
        .map_err(TtsError::Network)?;
    if !(200..300).contains(&status) {
        return Err(TtsError::HttpStatus {
            status,
            body: truncate_500(&body_text),
        });
    }
    parse_tts_response(&body_text)
}

/// Real blocking HTTP transport backed by `reqwest::blocking`.
pub struct ReqwestHttpPost;

impl HttpPost for ReqwestHttpPost {
    fn post_json(&self, url: &str, api_key: &str, body: &Value) -> Result<(u16, String), String> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(url)
            .header("x-api-key", api_key)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// Real `ffprobe`-backed duration probe, mirroring the exact argv:
/// `ffprobe -v error -show_entries format=duration -of
/// default=noprint_wrappers=1:nokey=1 <path>`.
pub struct RealFfprobe;

impl DurationProbe for RealFfprobe {
    fn duration_seconds(&self, path: &Path) -> Option<f64> {
        let out = std::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
            ])
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
}

// ---------------------------------------------------------------------------
// CLI entry point — mirrors `main()`.
// ---------------------------------------------------------------------------

pub trait FileIo {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn read_dotenv(&self, skill_root: &Path) -> Option<String>;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
}

/// Runs the CLI end to end, mirroring `main().catch(...)`. `argv` excludes
/// the program/script name (what the JS sees as `process.argv.slice(2)`).
/// `skill_root` is the directory `.env` is read from (`path.resolve(
/// __dirname, '..')` in the JS). `reqid` is caller-supplied since the JS
/// calls the nondeterministic `randomUUID()`. Writes the result JSON line to
/// `stdout` on success or `TTS 失败：{msg}` to `stderr` on failure, and
/// returns the process exit code (0 or 1), matching the legacy script.
#[allow(clippy::too_many_arguments)]
pub fn run(
    argv: &[String],
    skill_root: &Path,
    process_env: &HashMap<String, String>,
    reqid: String,
    io: &dyn FileIo,
    http: &dyn HttpPost,
    duration_probe: &dyn DurationProbe,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let mut env = process_env.clone();
    if let Some(dotenv_text) = io.read_dotenv(skill_root) {
        apply_dotenv(&mut env, &parse_dotenv(&dotenv_text));
    }

    let args = parse_args(argv);
    if args.help {
        let _ = writeln!(stderr, "\n{USAGE_TEXT}");
        return 1;
    }

    let text = match resolve_text(&args, io) {
        Ok(Some(t)) => t,
        Ok(None) => {
            let _ = writeln!(stderr, "错：缺 --text 或 --text-file");
            let _ = writeln!(stderr, "\n{USAGE_TEXT}");
            return 1;
        }
        Err(e) => {
            let _ = writeln!(stderr, "TTS 失败：{e}");
            return 1;
        }
    };
    let Some(out) = args.out.clone() else {
        let _ = writeln!(stderr, "错：缺 --out");
        let _ = writeln!(stderr, "\n{USAGE_TEXT}");
        return 1;
    };

    let out_path = PathBuf::from(&out);
    if let Some(parent) = out_path.parent() {
        if let Err(e) = io.create_dir_all(parent) {
            let _ = writeln!(stderr, "TTS 失败：{e}");
            return 1;
        }
    }

    let audio = match tts(&args, &env, &text, reqid, http) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "TTS 失败：{e}");
            return 1;
        }
    };

    if let Err(e) = io.write(&out_path, &audio) {
        let _ = writeln!(stderr, "TTS 失败：{e}");
        return 1;
    }

    let duration = duration_probe.duration_seconds(&out_path);
    let result = json!({
        "path": out_path.to_string_lossy(),
        "bytes": audio.len(),
        "duration": duration,
        "text_chars": text.chars().count(),
    });
    let _ = writeln!(stdout, "{result}");
    0
}

fn resolve_text(args: &Args, io: &dyn FileIo) -> Result<Option<String>, String> {
    if let Some(t) = &args.text {
        return Ok(Some(t.clone()));
    }
    if let Some(f) = &args.text_file {
        let text = io
            .read_to_string(Path::new(f))
            .map_err(|e| e.to_string())?;
        return Ok(Some(text.trim().to_string()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults() {
        let args = parse_args(&[]);
        assert_eq!(args.speed, "1.0");
        assert_eq!(args.encoding, "mp3");
        assert!(!args.help);
    }

    #[test]
    fn parse_args_full() {
        let args = parse_args(&a(&[
            "--text",
            "hello",
            "--out",
            "out.mp3",
            "--speed",
            "1.5",
            "--voice",
            "v1",
            "--encoding",
            "wav",
        ]));
        assert_eq!(args.text.as_deref(), Some("hello"));
        assert_eq!(args.out.as_deref(), Some("out.mp3"));
        assert_eq!(args.speed, "1.5");
        assert_eq!(args.voice.as_deref(), Some("v1"));
        assert_eq!(args.encoding, "wav");
    }

    #[test]
    fn parse_args_help_and_unknown_flag() {
        assert!(parse_args(&a(&["--help"])).help);
        assert!(parse_args(&a(&["-h"])).help);
        let args = parse_args(&a(&["--bogus", "x", "--text", "hi"]));
        assert_eq!(args.text.as_deref(), Some("hi"));
    }

    #[test]
    fn env_line_and_dotenv() {
        assert_eq!(
            parse_env_line("KEY=abc"),
            Some(("KEY".to_string(), "abc".to_string()))
        );
        assert_eq!(parse_env_line("# c"), None);
        assert_eq!(parse_env_line(""), None);
        let pairs = parse_dotenv("A=1\n# c\nB=\"two\"\nC='three'\nbad\n");
        assert_eq!(
            pairs,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two".to_string()),
                ("C".to_string(), "three".to_string()),
            ]
        );
    }

    #[test]
    fn apply_dotenv_does_not_override_existing() {
        let mut env = HashMap::new();
        env.insert("A".to_string(), "preset".to_string());
        apply_dotenv(
            &mut env,
            &[
                ("A".to_string(), "from-dotenv".to_string()),
                ("B".to_string(), "b".to_string()),
            ],
        );
        assert_eq!(env.get("A").unwrap(), "preset");
        assert_eq!(env.get("B").unwrap(), "b");
    }

    #[test]
    fn resolve_request_missing_api_key() {
        let args = parse_args(&[]);
        let env = HashMap::new();
        let err = resolve_request(&args, &env, "hi", "r1".into()).unwrap_err();
        assert_eq!(err, TtsError::MissingApiKey);
    }

    #[test]
    fn resolve_request_missing_voice_id() {
        let args = parse_args(&[]);
        let mut env = HashMap::new();
        env.insert("DOUBAO_TTS_API_KEY".to_string(), "k".to_string());
        let err = resolve_request(&args, &env, "hi", "r1".into()).unwrap_err();
        assert_eq!(err, TtsError::MissingVoiceId);
    }

    #[test]
    fn resolve_request_defaults_and_voice_flag_override() {
        let args = parse_args(&a(&["--voice", "flag-voice"]));
        let mut env = HashMap::new();
        env.insert("DOUBAO_TTS_API_KEY".to_string(), "k".to_string());
        env.insert("DOUBAO_TTS_VOICE_ID".to_string(), "env-voice".to_string());
        let req = resolve_request(&args, &env, "hi", "r1".into()).unwrap();
        assert_eq!(req.voice_id, "flag-voice");
        assert_eq!(req.cluster, "volcano_icl");
        assert_eq!(req.endpoint, "https://openspeech.bytedance.com/api/v1/tts");
    }

    #[test]
    fn build_body_matches_shape() {
        let req = ResolvedRequest {
            endpoint: "https://x".into(),
            api_key: "k".into(),
            cluster: "volcano_icl".into(),
            voice_id: "voice-1".into(),
            encoding: "mp3".into(),
            speed: 1.0,
            reqid: "req-1".into(),
            text: "你好".into(),
        };
        let body = build_body(&req);
        assert_eq!(body["app"]["cluster"], "volcano_icl");
        assert_eq!(body["user"]["uid"], "huashu-design");
        assert_eq!(body["audio"]["voice_type"], "voice-1");
        assert_eq!(body["request"]["operation"], "query");
    }

    #[test]
    fn parse_tts_response_success_and_errors() {
        assert_eq!(
            parse_tts_response(r#"{"code":3000,"data":"aGk="}"#).unwrap(),
            b"hi"
        );
        assert_eq!(
            parse_tts_response(r#"{"data":"aGk="}"#).unwrap(),
            b"hi",
            "absent code field is treated as success"
        );
        let err = parse_tts_response(r#"{"code":4000,"message":"bad voice id"}"#).unwrap_err();
        assert_eq!(
            err,
            TtsError::ApiError {
                code: 4000,
                message: "bad voice id".to_string()
            }
        );
        assert!(matches!(
            parse_tts_response(r#"{"code":3000}"#).unwrap_err(),
            TtsError::MissingData(_)
        ));
        assert!(matches!(
            parse_tts_response("not json").unwrap_err(),
            TtsError::InvalidJson(_)
        ));
    }

    #[test]
    fn base64_round_trip() {
        for sample in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = naive_encode(sample.as_bytes());
            assert_eq!(decode_base64(&encoded).unwrap(), sample.as_bytes());
        }
    }

    fn naive_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(b2 & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    // -- run() end-to-end with fakes --------------------------------------

    struct FakeIo {
        files: HashMap<PathBuf, String>,
        dotenv: Option<String>,
        writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
    }
    impl FileIo for FakeIo {
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
        }
        fn read_dotenv(&self, _skill_root: &Path) -> Option<String> {
            self.dotenv.clone()
        }
        fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
            self.writes
                .borrow_mut()
                .insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
    }

    struct FakeHttp {
        status: u16,
        body: String,
    }
    impl HttpPost for FakeHttp {
        fn post_json(&self, _url: &str, _key: &str, _body: &Value) -> Result<(u16, String), String> {
            Ok((self.status, self.body.clone()))
        }
    }

    struct FakeDuration(Option<f64>);
    impl DurationProbe for FakeDuration {
        fn duration_seconds(&self, _path: &Path) -> Option<f64> {
            self.0
        }
    }

    #[test]
    fn run_writes_audio_and_prints_json_line() {
        let io = FakeIo {
            files: HashMap::new(),
            dotenv: Some("DOUBAO_TTS_API_KEY=k\nDOUBAO_TTS_VOICE_ID=v\n".to_string()),
            writes: RefCell::new(HashMap::new()),
        };
        let http = FakeHttp {
            status: 200,
            body: r#"{"code":3000,"data":"aGk="}"#.to_string(),
        };
        let duration = FakeDuration(Some(1.23));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &a(&["--text", "hi", "--out", "out.mp3"]),
            Path::new("/skill"),
            &HashMap::new(),
            "req-1".to_string(),
            &io,
            &http,
            &duration,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(io.writes.borrow().contains_key(&PathBuf::from("out.mp3")));
        let stdout_text = String::from_utf8(stdout).unwrap();
        let json: Value = serde_json::from_str(stdout_text.trim()).unwrap();
        assert_eq!(json["bytes"], 2);
        assert_eq!(json["duration"], 1.23);
        assert_eq!(json["text_chars"], 2);
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_missing_out_flag_errors() {
        let io = FakeIo {
            files: HashMap::new(),
            dotenv: None,
            writes: RefCell::new(HashMap::new()),
        };
        let http = FakeHttp {
            status: 200,
            body: "{}".to_string(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &a(&["--text", "hi"]),
            Path::new("/skill"),
            &HashMap::new(),
            "req".to_string(),
            &io,
            &http,
            &FakeDuration(None),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8(stderr).unwrap().contains("缺 --out"));
    }

    #[test]
    fn run_reads_text_from_file_and_trims() {
        let mut files = HashMap::new();
        files.insert(PathBuf::from("script.txt"), "  hello world  \n".to_string());
        let io = FakeIo {
            files,
            dotenv: Some("DOUBAO_TTS_API_KEY=k\nDOUBAO_TTS_VOICE_ID=v\n".to_string()),
            writes: RefCell::new(HashMap::new()),
        };
        let http = FakeHttp {
            status: 200,
            body: r#"{"code":3000,"data":"aGk="}"#.to_string(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &a(&["--text-file", "script.txt", "--out", "out.mp3"]),
            Path::new("/skill"),
            &HashMap::new(),
            "req".to_string(),
            &io,
            &http,
            &FakeDuration(None),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        let stdout_text = String::from_utf8(stdout).unwrap();
        let json: Value = serde_json::from_str(stdout_text.trim()).unwrap();
        assert_eq!(json["text_chars"], "hello world".chars().count());
    }

    #[test]
    fn run_http_error_status_reported() {
        let io = FakeIo {
            files: HashMap::new(),
            dotenv: Some("DOUBAO_TTS_API_KEY=k\nDOUBAO_TTS_VOICE_ID=v\n".to_string()),
            writes: RefCell::new(HashMap::new()),
        };
        let http = FakeHttp {
            status: 500,
            body: "server exploded".to_string(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &a(&["--text", "hi", "--out", "out.mp3"]),
            Path::new("/skill"),
            &HashMap::new(),
            "req".to_string(),
            &io,
            &http,
            &FakeDuration(None),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        let err_text = String::from_utf8(stderr).unwrap();
        assert!(err_text.contains("TTS 失败："));
        assert!(err_text.contains("HTTP 500"));
    }

    #[test]
    fn run_missing_text_errors() {
        let io = FakeIo {
            files: HashMap::new(),
            dotenv: None,
            writes: RefCell::new(HashMap::new()),
        };
        let http = FakeHttp {
            status: 200,
            body: "{}".to_string(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &a(&["--out", "out.mp3"]),
            Path::new("/skill"),
            &HashMap::new(),
            "req".to_string(),
            &io,
            &http,
            &FakeDuration(None),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("缺 --text 或 --text-file"));
    }
}
