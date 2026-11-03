//! Port of `qa.mjs`'s action-file schema and `runAction()` dispatch (lines 478-600).
//!
//! Actual page control (evaluate/click/hover/etc.) is delegated to the `BrowserSession` trait in
//! `super::session_client`, so this module is pure dispatch/formatting logic, testable with a
//! fake session.

use serde::Deserialize;
use serde_json::Value;

use crate::wf_port::r54::session_client::{BrowserSession, Rect};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "sleep")]
    Sleep { ms: Option<u64> },
    #[serde(rename = "waitFor")]
    WaitFor {
        selector: String,
        timeout: Option<u64>,
    },
    #[serde(rename = "waitForText")]
    WaitForText { text: String, timeout: Option<u64> },
    #[serde(rename = "click")]
    Click { selector: String },
    #[serde(rename = "hover")]
    Hover {
        selector: String,
        settle: Option<u64>,
    },
    #[serde(rename = "type")]
    Type { text: Option<String> },
    #[serde(rename = "press")]
    Press { key: Option<String> },
    #[serde(rename = "eval")]
    Eval { expression: String },
    #[serde(rename = "assertVisible")]
    AssertVisible {
        selector: String,
        timeout: Option<u64>,
    },
    #[serde(rename = "assertText")]
    AssertText { selector: String, text: String },
    #[serde(rename = "assertAriaLabel")]
    AssertAriaLabel {
        selector: String,
        label: String,
        exact: Option<bool>,
    },
    #[serde(rename = "assertCursor")]
    AssertCursor {
        selector: String,
        cursor: Option<String>,
    },
    #[serde(rename = "assertStyle")]
    AssertStyle {
        selector: String,
        property: String,
        value: String,
        exact: Option<bool>,
    },
    #[serde(rename = "wheel")]
    Wheel {
        x: Option<f64>,
        y: Option<f64>,
        clicks: Option<u32>,
        #[serde(rename = "deltaX")]
        delta_x: Option<f64>,
        #[serde(rename = "deltaY")]
        delta_y: Option<f64>,
        gap: Option<u64>,
    },
    #[serde(rename = "screenshot")]
    Screenshot { out: String },
}

/// Parses an `--actions` JSON file (qa.mjs line 668-669: must be a JSON array).
pub fn parse_actions(json: &str) -> Result<Vec<Action>, String> {
    let value: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if !value.is_array() {
        return Err("--actions file must contain a JSON array.".to_string());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn action_type_name(a: &Action) -> &'static str {
    match a {
        Action::Sleep { .. } => "sleep",
        Action::WaitFor { .. } => "waitFor",
        Action::WaitForText { .. } => "waitForText",
        Action::Click { .. } => "click",
        Action::Hover { .. } => "hover",
        Action::Type { .. } => "type",
        Action::Press { .. } => "press",
        Action::Eval { .. } => "eval",
        Action::AssertVisible { .. } => "assertVisible",
        Action::AssertText { .. } => "assertText",
        Action::AssertAriaLabel { .. } => "assertAriaLabel",
        Action::AssertCursor { .. } => "assertCursor",
        Action::AssertStyle { .. } => "assertStyle",
        Action::Wheel { .. } => "wheel",
        Action::Screenshot { .. } => "screenshot",
    }
}

/// Port of `runAction(client, action, index)` (qa.mjs lines 504-600). Returns the `[qa] <label>
/// ok` line on success (matching the trailing `console.log` every branch falls through to) or an
/// `Err` message matching the JS `throw new Error(...)` text, prefixed with the `N:type` label.
pub fn run_action(
    session: &mut dyn BrowserSession,
    action: &Action,
    index: usize,
) -> Result<String, String> {
    let label = format!("{}:{}", index + 1, action_type_name(action));
    match action {
        Action::Sleep { ms } => session.wait(ms.unwrap_or(250)),
        Action::WaitFor { selector, timeout } => {
            session.wait_for_eval(
                &format!(
                    "(() => ({{ ok: !!document.querySelector({}) }}))()",
                    js_string(selector)
                ),
                timeout.unwrap_or(10000),
            )?;
        }
        Action::WaitForText { text, timeout } => {
            session.wait_for_eval(
                &format!(
                    "(() => ({{ ok: (document.body?.innerText || \"\").includes({}) }}))()",
                    js_string(text)
                ),
                timeout.unwrap_or(10000),
            )?;
        }
        Action::Click { selector } => {
            let p = session.element_point(selector)?;
            session.click(p.x, p.y)?;
        }
        Action::Hover { selector, settle } => {
            let p = session.element_point(selector)?;
            session.mouse_move(p.x, p.y)?;
            session.wait(settle.unwrap_or(150));
        }
        Action::Type { text } => session.insert_text(text.as_deref().unwrap_or(""))?,
        Action::Press { key } => session.press_key(key.as_deref().unwrap_or("Enter"))?,
        Action::Eval { expression } => {
            let value = session.eval(expression)?;
            if value.get("ok").and_then(|v| v.as_bool()) == Some(false) {
                return Err(format!("{label} eval returned not ok: {value}"));
            }
            // The value goes on its own line, serialised as one line of JSON, so callers can read
            // it back without trusting anything the page printed.
            return Ok(format!(
                "[qa] {label} ok\n[qa] {label} value {}",
                eval_value_json(&value)
            ));
        }
        Action::AssertVisible { selector, timeout } => {
            let expr = format!(
                "(() => {{ const el = document.querySelector({sel}); if (!el) return {{ ok: false, reason: \"missing\" }}; const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return {{ ok: !!(r.width && r.height && cs.visibility !== \"hidden\" && cs.display !== \"none\"), rect: {{ width: r.width, height: r.height }}, display: cs.display, visibility: cs.visibility }}; }})()",
                sel = js_string(selector)
            );
            session.wait_for_eval(&expr, timeout.unwrap_or(10000))?;
        }
        Action::AssertText { selector, text } => {
            let expr = format!(
                "(() => {{ const el = document.querySelector({sel}); const text = el?.textContent || \"\"; return {{ ok: text.includes({txt}), text }}; }})()",
                sel = js_string(selector),
                txt = js_string(text)
            );
            let value = session.eval(&expr)?;
            if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err(format!("{label} text assertion failed: {value}"));
            }
        }
        Action::AssertAriaLabel {
            selector,
            label: expected,
            exact,
        } => {
            let cmp = if exact.unwrap_or(false) {
                format!("label === {}", js_string(expected))
            } else {
                format!("label.includes({})", js_string(expected))
            };
            let expr = format!(
                "(() => {{ const el = document.querySelector({sel}); const label = el?.getAttribute(\"aria-label\") || el?.getAttribute(\"title\") || \"\"; return {{ ok: {cmp}, label }}; }})()",
                sel = js_string(selector)
            );
            let value = session.eval(&expr)?;
            if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err(format!("{label} aria/title assertion failed: {value}"));
            }
        }
        Action::AssertCursor { selector, cursor } => {
            let expected = cursor.clone().unwrap_or_else(|| "pointer".to_string());
            let expr = format!(
                "(() => {{ const el = document.querySelector({sel}); const cursor = el ? getComputedStyle(el).cursor : \"\"; return {{ ok: cursor === {exp}, cursor }}; }})()",
                sel = js_string(selector),
                exp = js_string(&expected)
            );
            let value = session.eval(&expr)?;
            if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err(format!("{label} cursor assertion failed: {value}"));
            }
        }
        Action::AssertStyle {
            selector,
            property,
            value: expected,
            exact,
        } => {
            let cmp = if exact.unwrap_or(false) {
                "actual.trim() === expected"
            } else {
                "actual.includes(expected)"
            };
            let expr = format!(
                "(() => {{ const el = document.querySelector({sel}); const actual = el ? getComputedStyle(el).getPropertyValue({prop}) : \"\"; const expected = {exp}; return {{ ok: {cmp}, actual }}; }})()",
                sel = js_string(selector),
                prop = js_string(property),
                exp = js_string(expected)
            );
            let value = session.eval(&expr)?;
            if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                return Err(format!("{label} style assertion failed: {value}"));
            }
        }
        Action::Wheel {
            x,
            y,
            clicks,
            delta_x,
            delta_y,
            gap,
        } => {
            let x = x.unwrap_or(400.0);
            let y = y.unwrap_or(400.0);
            for _ in 0..clicks.unwrap_or(1) {
                session.mouse_wheel(x, y, delta_x.unwrap_or(0.0), delta_y.unwrap_or(100.0))?;
                session.wait(gap.unwrap_or(120));
            }
        }
        Action::Screenshot { out } => {
            let file = session.capture(out)?;
            return Ok(format!("[qa] screenshot {file}\n[qa] {label} ok"));
        }
    }
    Ok(format!("[qa] {label} ok"))
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Largest serialised `eval` value printed in full (64 KiB).
pub const EVAL_VALUE_MAX_BYTES: usize = 64 * 1024;

/// Compact single-line JSON for an `eval` value. `serde_json` escapes every newline inside
/// strings, so the output never spans lines. Values over `EVAL_VALUE_MAX_BYTES` are replaced by
/// a `{"truncated":true,"bytes":<n>}` marker; `undefined` arrives as `null`.
pub fn eval_value_json(value: &Value) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    if json.len() > EVAL_VALUE_MAX_BYTES {
        return format!("{{\"truncated\":true,\"bytes\":{}}}", json.len());
    }
    json
}

/// Minimal helper mirroring `elementPoint`'s return shape for callers building fakes.
pub fn point(x: f64, y: f64, rect: Rect) -> crate::wf_port::r54::session_client::ElementPoint {
    crate::wf_port::r54::session_client::ElementPoint { x, y, rect }
}
