//! Port of `tts-doubao.mjs`'s pure `.env` parsing and TTS request/response
//! (de)serialization logic.
//!
//! Mirrors `loadEnv()` (a minimal `.env` parser: skips blank lines and `#`
//! comments, splits on the first `=`, trims both sides, strips one layer of
//! matching `'...'`/`"..."` quoting), the JSON request body `tts()` builds,
//! and its response handling (`code !== 3000` is an error, `data` is
//! required and is the base64-encoded audio).
//!
//! Not ported: `getDuration` (shells out to `ffprobe`), the `fetch()` HTTP
//! call itself, and `main()`'s file I/O / CLI argument parsing. `reqwest` is
//! already a workspace dependency elsewhere in `engine/Cargo.lock` but is
//! not currently a `legion-runtime` dependency, so wiring the actual HTTP
//! POST is left to the caller (see the port report for the dependency this
//! would need); [`build_tts_request`] and [`parse_tts_response`] give that
//! caller the exact request body and response handling to use around it.
//! Base64 decoding is implemented locally ([`decode_base64`]) rather than
//! pulling in the `base64` crate, since it is not a `legion-runtime`
//! dependency either and the decode is a handful of lines.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Parse `.env`-style text into a key -> value map. Mirrors `loadEnv()`:
/// blank lines and lines starting with `#` (after trimming) are skipped;
/// each remaining line splits on the first `=`; both sides are trimmed; a
/// value wrapped in matching `'...'` or `"..."` has that one layer of
/// quoting stripped. Unlike the JS (which only sets `process.env[key]` when
/// the key isn't already set), this returns a plain map — the "don't
/// override existing env" precedence is a `process.env`-specific concern the
/// caller applies when merging this map into its own environment.
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(idx) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..idx].trim().to_string();
        let mut val = trimmed[idx + 1..].trim().to_string();
        let is_quoted = val.len() >= 2
            && ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')));
        if is_quoted {
            val = val[1..val.len() - 1].to_string();
        }
        map.insert(key, val);
    }
    map
}

/// Parameters for [`build_tts_request`], mirroring the fields `tts({ text,
/// voice, speed, encoding })` reads off its argument object plus the
/// resolved `apiKey`/`cluster`/`endpoint`/`voiceId` env-derived values.
#[derive(Debug, Clone, PartialEq)]
pub struct TtsRequestParams<'a> {
    pub text: &'a str,
    pub voice_id: &'a str,
    pub cluster: &'a str,
    pub speed: f64,
    pub encoding: &'a str,
    pub reqid: &'a str,
    pub uid: &'a str,
}

/// Build the JSON request body `tts()` sends. Mirrors:
/// ```js
/// {
///   app: { cluster },
///   user: { uid: 'huashu-design' },
///   audio: { voice_type: voiceId, encoding, speed_ratio: parseFloat(speed) },
///   request: { reqid: randomUUID(), text, operation: 'query' },
/// }
/// ```
/// `reqid` is caller-supplied (the JS calls `randomUUID()` per request,
/// which is nondeterministic and therefore a caller concern, not this pure
/// builder's).
pub fn build_tts_request(params: &TtsRequestParams) -> Value {
    json!({
        "app": { "cluster": params.cluster },
        "user": { "uid": params.uid },
        "audio": {
            "voice_type": params.voice_id,
            "encoding": params.encoding,
            "speed_ratio": params.speed,
        },
        "request": {
            "reqid": params.reqid,
            "text": params.text,
            "operation": "query",
        },
    })
}

/// Decode the Doubao TTS response, returning the raw audio bytes on success.
///
/// Mirrors:
/// ```js
/// const json = await res.json();
/// if (json.code !== undefined && json.code !== 3000) {
///   throw new Error(`API 返回错误 code=${json.code} msg=${json.message || JSON.stringify(json)}`);
/// }
/// if (!json.data) {
///   throw new Error(`API 响应无 data 字段：${JSON.stringify(json).slice(0, 500)}`);
/// }
/// return Buffer.from(json.data, 'base64');
/// ```
/// The `!res.ok` HTTP-status branch (`HTTP ${res.status}: ...`) is not
/// mirrored here since it's a transport-layer concern checked before the
/// body is even parsed as JSON; a caller checks the HTTP status itself
/// before calling this function on the response body.
pub fn parse_tts_response(body: &str) -> Result<Vec<u8>, String> {
    let json: Value = serde_json::from_str(body).map_err(|e| format!("响应不是合法 JSON：{e}"))?;

    // Mirrors `json.code !== undefined && json.code !== 3000`: a *present*
    // `code` field (including an explicit `null`) that isn't exactly 3000 is
    // an error; a wholly absent `code` field skips this check.
    if let Some(code) = json.get("code") {
        if code.as_i64() != Some(3000) {
            let msg = json
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| json.to_string());
            return Err(format!("API 返回错误 code={code} msg={msg}"));
        }
    }

    let data = json.get("data").and_then(|d| d.as_str());
    let Some(data) = data.filter(|d| !d.is_empty()) else {
        let mut truncated = json.to_string();
        truncated.truncate(500);
        return Err(format!("API 响应无 data 字段：{truncated}"));
    };

    decode_base64(data).map_err(|e| format!("base64 解码失败：{e}"))
}

/// Minimal standard-alphabet base64 decoder (RFC 4648, with `=` padding),
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

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
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

    if chunk_len == 2 {
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
    } else if chunk_len == 3 {
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        out.push((chunk[1] << 4) | (chunk[2] >> 2));
    } else if chunk_len == 1 {
        return Err("truncated base64 input".to_string());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_skipping_blank_and_comment_lines() {
        let text = "\n# comment\nDOUBAO_TTS_API_KEY=abc123\nDOUBAO_TTS_VOICE_ID = \"S_JSdgdWk22\"\nDOUBAO_TTS_CLUSTER='volcano_icl'\nmalformed-line\n";
        let map = parse_env(text);
        assert_eq!(map.get("DOUBAO_TTS_API_KEY").unwrap(), "abc123");
        assert_eq!(map.get("DOUBAO_TTS_VOICE_ID").unwrap(), "S_JSdgdWk22");
        assert_eq!(map.get("DOUBAO_TTS_CLUSTER").unwrap(), "volcano_icl");
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn env_value_with_equals_sign_splits_on_first() {
        let map = parse_env("KEY=a=b=c");
        assert_eq!(map.get("KEY").unwrap(), "a=b=c");
    }

    #[test]
    fn build_tts_request_matches_js_shape() {
        let params = TtsRequestParams {
            text: "你好",
            voice_id: "S_JSdgdWk22",
            cluster: "volcano_icl",
            speed: 1.0,
            encoding: "mp3",
            reqid: "fixed-uuid",
            uid: "huashu-design",
        };
        let body = build_tts_request(&params);
        assert_eq!(body["app"]["cluster"], "volcano_icl");
        assert_eq!(body["user"]["uid"], "huashu-design");
        assert_eq!(body["audio"]["voice_type"], "S_JSdgdWk22");
        assert_eq!(body["audio"]["encoding"], "mp3");
        assert_eq!(body["audio"]["speed_ratio"], 1.0);
        assert_eq!(body["request"]["reqid"], "fixed-uuid");
        assert_eq!(body["request"]["text"], "你好");
        assert_eq!(body["request"]["operation"], "query");
    }

    #[test]
    fn parse_tts_response_success() {
        // base64 for b"hi" is "aGk="
        let body = r#"{"code":3000,"message":"ok","data":"aGk="}"#;
        let audio = parse_tts_response(body).unwrap();
        assert_eq!(audio, b"hi");
    }

    #[test]
    fn parse_tts_response_missing_code_field_treated_as_success() {
        // Mirrors `json.code !== undefined && json.code !== 3000` — an
        // absent `code` field skips the error branch entirely.
        let body = r#"{"data":"aGk="}"#;
        let audio = parse_tts_response(body).unwrap();
        assert_eq!(audio, b"hi");
    }

    #[test]
    fn parse_tts_response_error_code() {
        let body = r#"{"code":4001,"message":"invalid voice"}"#;
        let err = parse_tts_response(body).unwrap_err();
        assert!(err.contains("code=4001"));
        assert!(err.contains("invalid voice"));
    }

    #[test]
    fn parse_tts_response_missing_data() {
        let body = r#"{"code":3000}"#;
        let err = parse_tts_response(body).unwrap_err();
        assert!(err.contains("无 data 字段"));
    }

    #[test]
    fn base64_round_trip() {
        for sample in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = naive_encode(sample.as_bytes());
            let decoded = decode_base64(&encoded).unwrap();
            assert_eq!(decoded, sample.as_bytes());
        }
    }

    // Minimal reference encoder used only by the round-trip test above, to
    // avoid depending on an external base64 crate in tests.
    fn naive_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}
