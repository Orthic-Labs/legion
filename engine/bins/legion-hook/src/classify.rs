//! Tier-1 adapter: scores one text against typed yes/no labels with ScaleDown Classify.
//!
//! API (first-party docs, https://docs.scaledown.ai/api-reference/classify.md): `POST https://api.scaledown.xyz/classify`,
//! header `x-api-key`, body `{text, labels:[{name, rubric}], multi_label, reasoning}`, response `scores`
//! (label name to probability). `multi_label: true` scores each label on its own (at most 16 labels);
//! `reasoning: false` skips the explanation call.
//!
//! The transport is `rightkit_http::Client` (blocking), first-party to `api.scaledown.xyz` only: HTTPS only,
//! public addresses only, no redirects, no retries. Fail-open: every failure (no key, timeout, HTTP error, bad
//! body) is an `Err` the caller reads as "no verdict". The whole call, key lookup included, is capped at 3
//! seconds. The key lives in a redacting `Secret`, is exposed only at the header write, and is never logged,
//! printed, stored or put in an error; every error is a fixed string. Kill switch: `classify` in
//! `LEGION_HOOK_OFF`. Not wired into any hook yet.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rightkit_http::{Client, ClientConfig, Request, RetryPolicy, Secret};
use serde_json::{json, Value};

use crate::state::off;

const HOST: &str = "api.scaledown.xyz";
const ENDPOINT: &str = "https://api.scaledown.xyz/classify";
/// Hard cap for the whole classify call.
const CALL_CAP: Duration = Duration::from_secs(3);
/// Cap for the Keychain read; a prompt that nobody answers must not eat the call budget.
const KEYCHAIN_CAP: Duration = Duration::from_millis(800);
/// A classify answer is a few hundred bytes; anything bigger is not one.
const MAX_RESPONSE: usize = 64 * 1024;
/// ScaleDown accepts at most 16 labels when `multi_label` is true.
const MAX_LABELS: usize = 16;

/// One question: `name` keys the score, `rubric` is a yes/no question where "yes" means the label applies.
pub struct Label<'a> {
    pub name: &'a str,
    pub rubric: &'a str,
}

/// Probability per label name, in the order ScaleDown returned them. `Err` means "no verdict".
pub fn classify(labels: &[Label], text: &str) -> Result<Vec<(String, f64)>, &'static str> {
    if off("classify") {
        return Err("classify is switched off");
    }
    if labels.is_empty() || labels.len() > MAX_LABELS {
        return Err("label count out of range");
    }
    let started = Instant::now();
    let key = api_key().ok_or("no api key")?;
    let left = CALL_CAP
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or("classify timed out")?;
    let body = json!({
        "text": text,
        "labels": labels
            .iter()
            .map(|label| json!({"name": label.name, "rubric": label.rubric}))
            .collect::<Vec<_>>(),
        "multi_label": true,
        "reasoning": false,
    });
    let mut config = ClientConfig::first_party(vec![HOST.to_string()]);
    config.connect_timeout = Some(left);
    config.request_timeout = left;
    config.response_timeout = Some(left);
    config.max_response_bytes = MAX_RESPONSE;
    config.retry = RetryPolicy::none();
    let request = Request::post(ENDPOINT)
        .secret_header("x-api-key", key.expose())
        .json(&body)
        .map_err(|_| "request body unavailable")?
        .timeout(left)
        .deadline(left);
    let response = Client::new(config)
        .send(&request)
        .map_err(|_| "classify request failed")?;
    let value: Value = response.json().map_err(|_| "unreadable response")?;
    scores(&value).ok_or("response had no scores")
}

/// `scores` at the top level, or in the first entry of `results` (the shape used for chunked input).
fn scores(value: &Value) -> Option<Vec<(String, f64)>> {
    let map = value
        .get("scores")
        .or_else(|| value.get("results")?.get(0)?.get("scores"))?
        .as_object()?;
    let found: Vec<(String, f64)> = map
        .iter()
        .filter_map(|(name, score)| Some((name.clone(), score.as_f64()?)))
        .collect();
    (!found.is_empty()).then_some(found)
}

/// Env `SCALEDOWN_API_KEY`, then the macOS login Keychain, then `~/.legion/scaledown-api-key`.
fn api_key() -> Option<Secret> {
    let clean = |raw: String| Some(raw.trim().to_string()).filter(|key| !key.is_empty());
    if let Some(key) = std::env::var("SCALEDOWN_API_KEY").ok().and_then(clean) {
        return Some(Secret::new(key));
    }
    if let Some(key) = keychain_key().and_then(clean) {
        return Some(Secret::new(key));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|home| !home.is_empty()))?;
    let path = PathBuf::from(home).join(".legion").join("scaledown-api-key");
    fs::read_to_string(path).ok().and_then(clean).map(Secret::new)
}

/// The Keychain item `legion-scaledown`. Output is piped, never echoed, and a command that blocks on a
/// prompt is killed at the cap.
#[cfg(target_os = "macos")]
fn keychain_key() -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", "legion-scaledown", "-w"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < KEYCHAIN_CAP => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut key = String::new();
    child.stdout.take()?.read_to_string(&mut key).ok()?;
    status.success().then_some(key)
}

#[cfg(not(target_os = "macos"))]
fn keychain_key() -> Option<String> {
    let _ = KEYCHAIN_CAP;
    None
}
