//! `legion script council/nim-seat`: run one Council seat on an NVIDIA NIM model.
//!
//! Streaming is required: the NIM gateway answers HTTP 504 at about 300 s for long
//! non-streamed generations, and free-tier queueing can take 4-20 minutes before the
//! first token, so the deadline covers the whole stream rather than a read gap.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub const HELP: &str = "usage: legion script council/nim-seat --model <nim-model-id> --prompt-file <seat.md> --out <reply.md> [--reasoning-effort low|high|max] [--max-tokens N] [--timeout-secs N]\n\
Stream one chat completion from NVIDIA NIM (https://integrate.api.nvidia.com/v1/chat/completions).\n\
Reply text goes to --out, reasoning text to <out>.reasoning; one JSON status line goes to stdout.\n\
API key: env NIM_API_KEY or NVIDIA_API_KEY, else the OS credential store entry NIM_API_KEY (macOS Keychain / Windows Credential Manager).\n\
Defaults: --max-tokens 32768, --timeout-secs 1800. Exit 0 on non-empty content, 1 on HTTP/timeout/empty failure, 2 on usage or IO.";

const ENDPOINT: &str = "https://integrate.api.nvidia.com/v1/chat/completions";
const KEY_NAME: &str = "NIM_API_KEY";

#[derive(Debug, PartialEq)]
struct Options {
    model: String,
    prompt_file: String,
    out: String,
    reasoning_effort: Option<String>,
    max_tokens: u64,
    timeout_secs: u64,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut model = None;
    let mut prompt_file = None;
    let mut out = None;
    let mut reasoning_effort = None;
    let mut max_tokens = 32768u64;
    let mut timeout_secs = 1800u64;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = |name: &str| {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "--model" => model = Some(value("--model")?),
            "--prompt-file" => prompt_file = Some(value("--prompt-file")?),
            "--out" => out = Some(value("--out")?),
            "--reasoning-effort" => {
                let v = value("--reasoning-effort")?;
                if !matches!(v.as_str(), "low" | "high" | "max") {
                    return Err("--reasoning-effort must be low, high, or max".into());
                }
                reasoning_effort = Some(v);
            }
            "--max-tokens" => {
                max_tokens = value("--max-tokens")?
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--max-tokens must be a positive integer")?;
            }
            "--timeout-secs" => {
                timeout_secs = value("--timeout-secs")?
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--timeout-secs must be a positive integer")?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Options {
        model: model.ok_or("--model is required")?,
        prompt_file: prompt_file.ok_or("--prompt-file is required")?,
        out: out.ok_or("--out is required")?,
        reasoning_effort,
        max_tokens,
        timeout_secs,
    })
}

/// Incremental SSE accumulator for OpenAI-compatible chat-completion chunks.
#[derive(Debug, Default)]
struct SseAccumulator {
    pending: Vec<u8>,
    content: String,
    reasoning: String,
    finish_reason: Option<String>,
    model: Option<String>,
    stream_error: Option<String>,
    done: bool,
    skipped_lines: usize,
}

impl SseAccumulator {
    /// Feeds raw bytes; returns true when new content or reasoning text arrived.
    fn push(&mut self, bytes: &[u8]) -> bool {
        let before = self.content.len() + self.reasoning.len();
        self.pending.extend_from_slice(bytes);
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            self.line(&line);
        }
        self.content.len() + self.reasoning.len() > before
    }

    /// Flushes a trailing line that lacked a newline.
    fn finish(&mut self) {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.line(&line);
        }
    }

    fn line(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let text = text.trim();
        let Some(payload) = text.strip_prefix("data:") else {
            return; // blank separators, comments, event:/id: fields
        };
        let payload = payload.trim();
        if payload == "[DONE]" {
            self.done = true;
            return;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
            self.skipped_lines += 1;
            return;
        };
        if let Some(model) = chunk.get("model").and_then(Value::as_str) {
            self.model = Some(model.to_string());
        }
        if let Some(error) = chunk.get("error") {
            self.stream_error = Some(
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("stream error")
                    .chars()
                    .take(300)
                    .collect(),
            );
        }
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            return;
        };
        for choice in choices {
            if let Some(delta) = choice.get("delta") {
                if let Some(part) = delta.get("content").and_then(Value::as_str) {
                    self.content.push_str(part);
                }
                let reasoning = delta
                    .get("reasoning_content")
                    .and_then(Value::as_str)
                    .or_else(|| delta.get("reasoning").and_then(Value::as_str));
                if let Some(part) = reasoning {
                    self.reasoning.push_str(part);
                }
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_string());
            }
        }
    }
}

/// NVIDIA's own name for the same key; accepted after `NIM_API_KEY`.
const ALT_ENV_NAME: &str = "NVIDIA_API_KEY";

fn resolve_key() -> Option<String> {
    [KEY_NAME, ALT_ENV_NAME]
        .iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .or_else(|| legion_effects::credential::read_generic_secret(KEY_NAME))
}

fn redact(text: &str, key: &str) -> String {
    let cleaned = if key.is_empty() {
        text.to_string()
    } else {
        text.replace(key, "[redacted]")
    };
    cleaned.chars().take(600).collect()
}

struct Outcome {
    acc: SseAccumulator,
    http_status: Option<u16>,
    error: Option<String>,
    first_token: Option<f64>,
}

async fn stream_request(
    opts: &Options,
    key: &str,
    prompt: &str,
    started: Instant,
    out: &mut Outcome,
) {
    let mut body = json!({
        "model": opts.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": opts.max_tokens,
        "stream": true,
    });
    if let Some(effort) = &opts.reasoning_effort {
        body["reasoning_effort"] = json!(effort);
    }
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            out.error = Some(format!(
                "client init failed: {}",
                redact(&e.to_string(), key)
            ));
            return;
        }
    };
    let mut response = match client
        .post(ENDPOINT)
        .bearer_auth(key)
        .header("accept", "text/event-stream")
        .json(&body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            out.error = Some(format!("request failed: {}", redact(&e.to_string(), key)));
            return;
        }
    };
    let status = response.status();
    out.http_status = Some(status.as_u16());
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        out.error = Some(format!("HTTP {}: {}", status.as_u16(), redact(&text, key)));
        return;
    }
    loop {
        match response.chunk().await {
            Ok(Some(bytes)) => {
                if out.acc.push(&bytes) && out.first_token.is_none() {
                    out.first_token = Some(started.elapsed().as_secs_f64());
                }
                if out.acc.done {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                out.error = Some(format!(
                    "stream read failed: {}",
                    redact(&e.to_string(), key)
                ));
                break;
            }
        }
    }
    out.acc.finish();
}

fn secs(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return 0;
    }
    let opts = match parse_options(args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("error: {e}\n{HELP}");
            return 2;
        }
    };
    let prompt = match std::fs::read_to_string(&opts.prompt_file) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", opts.prompt_file);
            return 2;
        }
    };
    let Some(key) = resolve_key() else {
        eprintln!("error: {KEY_NAME} or NVIDIA_API_KEY not found in the environment or the OS credential store");
        println!(
            "{}",
            json!({"requestedModel": opts.model, "error": format!("{KEY_NAME} unavailable")})
        );
        return 2;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: cannot start async runtime: {e}");
            return 2;
        }
    };
    let started = Instant::now();
    let deadline = Duration::from_secs(opts.timeout_secs);
    let mut outcome = Outcome {
        acc: SseAccumulator::default(),
        http_status: None,
        error: None,
        first_token: None,
    };
    // Dropping the timed-out future keeps whatever the stream had accumulated so far.
    let timed_out = runtime
        .block_on(tokio::time::timeout(
            deadline,
            stream_request(&opts, &key, &prompt, started, &mut outcome),
        ))
        .is_err();
    if timed_out && outcome.error.is_none() {
        outcome.error = Some(format!("timeout after {}s", opts.timeout_secs));
    }
    let total = started.elapsed().as_secs_f64();
    let acc = &outcome.acc;
    let mut io_error = None;
    let reasoning_path = format!("{}.reasoning", opts.out);
    if !acc.reasoning.is_empty() {
        if let Err(e) = std::fs::write(&reasoning_path, &acc.reasoning) {
            io_error = Some(format!("cannot write {reasoning_path}: {e}"));
        }
    }
    let success =
        outcome.error.is_none() && acc.stream_error.is_none() && !acc.content.trim().is_empty();
    let content_path = if success {
        opts.out.clone()
    } else {
        format!("{}.partial", opts.out)
    };
    if !acc.content.is_empty() {
        if let Err(e) = std::fs::write(&content_path, &acc.content) {
            io_error = Some(format!("cannot write {content_path}: {e}"));
        }
    }
    let mut error = outcome.error.clone().or_else(|| acc.stream_error.clone());
    if error.is_none() && acc.content.trim().is_empty() {
        error = Some("empty content".into());
    }
    let error = error.or(io_error);
    let mut status = json!({
        "requestedModel": opts.model,
        "reportedModel": acc.model,
        "finishReason": acc.finish_reason,
        "contentChars": acc.content.chars().count(),
        "reasoningChars": acc.reasoning.chars().count(),
        "firstTokenSecs": outcome.first_token.map(secs),
        "totalSecs": secs(total),
        "httpStatus": outcome.http_status,
        "skippedLines": acc.skipped_lines,
    });
    if let Some(error) = &error {
        status["error"] = json!(error);
    }
    println!("{status}");
    if error.is_none() {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(delta: &str, finish: &str) -> String {
        format!(
            "data: {{\"model\":\"m/x\",\"choices\":[{{\"delta\":{delta},\"finish_reason\":{finish}}}]}}\n\n"
        )
    }

    #[test]
    fn accumulates_content_reasoning_finish_and_done() {
        let mut acc = SseAccumulator::default();
        let stream = [
            ": keepalive\n\n".to_string(),
            chunk("{\"reasoning_content\":\"think \"}", "null"),
            chunk("{\"reasoning\":\"more\"}", "null"),
            "data: {not json}\n\n".to_string(),
            chunk("{\"content\":\"Hel\"}", "null"),
            chunk("{\"content\":\"lo \u{e9}\"}", "\"stop\""),
            "data: [DONE]\n\n".to_string(),
        ]
        .concat();
        // Split mid-line and mid-codepoint to exercise buffering.
        let bytes = stream.as_bytes();
        let cut = bytes.len() / 2;
        acc.push(&bytes[..cut]);
        acc.push(&bytes[cut..]);
        acc.finish();
        assert_eq!(acc.content, "Hello \u{e9}");
        assert_eq!(acc.reasoning, "think more");
        assert_eq!(acc.finish_reason.as_deref(), Some("stop"));
        assert_eq!(acc.model.as_deref(), Some("m/x"));
        assert_eq!(acc.skipped_lines, 1);
        assert!(acc.done);
    }

    #[test]
    fn crlf_and_unterminated_final_line() {
        let mut acc = SseAccumulator::default();
        acc.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}");
        acc.finish();
        assert_eq!(acc.content, "ab");
        assert!(!acc.done);
    }

    #[test]
    fn parses_options_and_rejects_bad_input() {
        let args: Vec<String> = [
            "--model",
            "a/b",
            "--prompt-file",
            "p.md",
            "--out",
            "o.md",
            "--reasoning-effort",
            "high",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = parse_options(&args).unwrap();
        assert_eq!(opts.max_tokens, 32768);
        assert_eq!(opts.timeout_secs, 1800);
        assert_eq!(opts.reasoning_effort.as_deref(), Some("high"));
        assert!(parse_options(&args[..4]).is_err());
        let bad: Vec<String> = ["--model", "a", "--reasoning-effort", "x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_options(&bad).is_err());
    }

    #[test]
    fn redact_removes_key() {
        assert_eq!(
            redact("bad nvapi-123 here", "nvapi-123"),
            "bad [redacted] here"
        );
    }
}
