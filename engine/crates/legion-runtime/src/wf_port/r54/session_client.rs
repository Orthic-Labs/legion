//! Port of `qa.mjs`'s CDP page-control primitives: `elementPoint`, `runtimeEval`, `waitForEval`,
//! `capture`, `applyConditions`, `loadSession`, `saveSession` (lines 106-147, 454-502).
//!
//! The JS file hand-rolls a WebSocket + CDP client (`cdpConnect`, `makeFrame`, `readFrames`,
//! lines 326-452) to talk to Chrome. That wire protocol is an implementation detail of reaching
//! Chrome, not part of qa.mjs's observable behavior; per the port brief, browser/DOM work here is
//! ported behind a trait backed by the `headless_chrome` crate, which already speaks CDP over a
//! real WebSocket client. `BrowserSession` is that trait: every method matches one qa.mjs
//! operation 1:1, so callers (this crate's `actions`/`run` modules) are byte-for-byte the same
//! orchestration logic as the original, and are tested against a fake implementing this trait
//! without a real browser.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub left: f64,
    pub top: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ElementPoint {
    pub x: f64,
    pub y: f64,
    pub rect: Rect,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Conditions {
    pub width: f64,
    pub height: f64,
    pub dpr: f64,
    pub mobile: bool,
    pub throttle: Option<super::args::ThrottleProfile>,
    pub cpu: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SessionData {
    #[serde(default)]
    pub cookies: Value,
    #[serde(default, rename = "localStorage")]
    pub local_storage: Value,
}

/// One page-control operation per qa.mjs primitive. Timeouts are milliseconds, matching the JS
/// defaults (`waitForEval`'s 10000ms default is the caller's job, same as JS callers passing
/// their own `timeout` field).
pub trait BrowserSession {
    /// `wait(ms)` (qa.mjs line 214-216): a plain sleep.
    fn wait(&mut self, ms: u64);
    /// `waitForEval(client, expression, timeoutMs)` (lines 467-476): polls `eval` every 250ms
    /// until `.ok` is truthy or the timeout elapses, in which case it errors with the message
    /// `Timed out waiting for expression. Last result: <json>`.
    fn wait_for_eval(&mut self, expression: &str, timeout_ms: u64) -> Result<Value, String>;
    /// `runtimeEval(client, expression, timeoutMs)` (lines 454-465): evaluates once, erroring on
    /// a thrown exception.
    fn eval(&mut self, expression: &str) -> Result<Value, String>;
    /// `elementPoint(client, selector)` (lines 482-494): resolves a selector to its center point
    /// via `waitForEval`, so it also polls/times out.
    fn element_point(&mut self, selector: &str) -> Result<ElementPoint, String>;
    fn click(&mut self, x: f64, y: f64) -> Result<(), String>;
    fn mouse_move(&mut self, x: f64, y: f64) -> Result<(), String>;
    fn insert_text(&mut self, text: &str) -> Result<(), String>;
    fn press_key(&mut self, key: &str) -> Result<(), String>;
    fn mouse_wheel(&mut self, x: f64, y: f64, delta_x: f64, delta_y: f64) -> Result<(), String>;
    /// `capture(client, out)` (lines 496-502): screenshot to an absolute path, returns that path.
    fn capture(&mut self, out: &str) -> Result<String, String>;
    /// `applyConditions(client, args)` (lines 107-121): viewport + optional network/CPU
    /// throttling, applied before navigation.
    fn apply_conditions(&mut self, conditions: &Conditions) -> Result<(), String>;
    fn navigate(&mut self, url: &str) -> Result<(), String>;
    /// `loadSession`/`saveSession` (lines 125-147).
    fn load_session(&mut self, data: &SessionData) -> Result<(), String>;
    fn save_session(&mut self) -> Result<SessionData, String>;
    /// Drains and returns the console `error`/`warning` and uncaught-exception lines observed
    /// since the last call (qa.mjs's `runActions` `consoleErrors` accumulator, lines 685,
    /// 692-701: `console.${type}: ${text}` for `Runtime.consoleAPICalled` with type `error` or
    /// `warning`, `exception: ${description}` for `Runtime.exceptionThrown`). Sessions that
    /// cannot observe console events (fakes, or the fast `--shot` path) default to none.
    fn take_console_errors(&mut self) -> Vec<String> {
        Vec::new()
    }
}

/// Port of `elementPoint`'s polling body (lines 483-493), generic over any `eval`-capable
/// session, so `element_point` implementations can share this instead of re-deriving the JS
/// expression string.
pub fn element_point_expression(selector_js_string: &str) -> String {
    format!(
        "(() => {{ const el = document.querySelector({sel}); if (!el) return {{ ok: false, reason: \"missing\" }}; const r = el.getBoundingClientRect(); if (!r.width || !r.height) return {{ ok: false, reason: \"empty rect\" }}; return {{ ok: true, x: r.left + r.width / 2, y: r.top + r.height / 2, rect: {{ left: r.left, top: r.top, width: r.width, height: r.height }} }}; }})()",
        sel = selector_js_string
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_point_expression_matches_js_shape() {
        let e = element_point_expression("\"#go\"");
        assert!(e.contains("document.querySelector(\"#go\")"));
        assert!(e.contains("empty rect"));
    }

    #[test]
    fn session_data_round_trips_default_json() {
        let s = SessionData::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: SessionData = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
