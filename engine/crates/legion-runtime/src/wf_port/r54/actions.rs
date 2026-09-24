//! Port of `qa.mjs`'s action-file schema and `runAction()` dispatch (lines 478-600).
//!
//! Actual page control (evaluate/click/hover/etc.) is delegated to the `BrowserSession` trait in
//! `super::session_client`, so this module is pure dispatch/formatting logic, testable with a
//! fake session.

use serde::Deserialize;
use serde_json::Value;

use super::session_client::{BrowserSession, Rect};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "sleep")]
    Sleep { ms: Option<u64> },
    #[serde(rename = "waitFor")]
    WaitFor { selector: String, timeout: Option<u64> },
    #[serde(rename = "waitForText")]
    WaitForText { text: String, timeout: Option<u64> },
    #[serde(rename = "click")]
    Click { selector: String },
    #[serde(rename = "hover")]
    Hover { selector: String, settle: Option<u64> },
    #[serde(rename = "type")]
    Type { text: Option<String> },
    #[serde(rename = "press")]
    Press { key: Option<String> },
    #[serde(rename = "eval")]
    Eval { expression: String },
    #[serde(rename = "assertVisible")]
    AssertVisible { selector: String, timeout: Option<u64> },
    #[serde(rename = "assertText")]
    AssertText { selector: String, text: String },
    #[serde(rename = "assertAriaLabel")]
    AssertAriaLabel { selector: String, label: String, exact: Option<bool> },
    #[serde(rename = "assertCursor")]
    AssertCursor { selector: String, cursor: Option<String> },
    #[serde(rename = "assertStyle")]
    AssertStyle { selector: String, property: String, value: String, exact: Option<bool> },
    #[serde(rename = "wheel")]
    Wheel { x: Option<f64>, y: Option<f64>, clicks: Option<u32>, #[serde(rename = "deltaX")] delta_x: Option<f64>, #[serde(rename = "deltaY")] delta_y: Option<f64>, gap: Option<u64> },
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
pub fn run_action(session: &mut dyn BrowserSession, action: &Action, index: usize) -> Result<String, String> {
    let label = format!("{}:{}", index + 1, action_type_name(action));
    match action {
        Action::Sleep { ms } => session.wait(ms.unwrap_or(250)),
        Action::WaitFor { selector, timeout } => {
            session.wait_for_eval(&format!("(() => ({{ ok: !!document.querySelector({}) }}))()", js_string(selector)), timeout.unwrap_or(10000))?;
        }
        Action::WaitForText { text, timeout } => {
            session.wait_for_eval(
                &format!("(() => ({{ ok: (document.body?.innerText || \"\").includes({}) }}))()", js_string(text)),
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
        Action::AssertAriaLabel { selector, label: expected, exact } => {
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
        Action::AssertStyle { selector, property, value: expected, exact } => {
            let cmp = if exact.unwrap_or(false) { "actual.trim() === expected" } else { "actual.includes(expected)" };
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
        Action::Wheel { x, y, clicks, delta_x, delta_y, gap } => {
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

/// Minimal helper mirroring `elementPoint`'s return shape for callers building fakes.
pub fn point(x: f64, y: f64, rect: Rect) -> super::session_client::ElementPoint {
    super::session_client::ElementPoint { x, y, rect }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::r54::session_client::{ElementPoint, Rect};
    use serde_json::json;

    #[derive(Default)]
    struct FakeSession {
        waited_ms: Vec<u64>,
        clicked: Vec<(f64, f64)>,
        moved: Vec<(f64, f64)>,
        typed: Vec<String>,
        pressed: Vec<String>,
        wheels: Vec<(f64, f64, f64, f64)>,
        eval_result: Value,
        wait_for_ok: bool,
        capture_path: String,
    }

    impl BrowserSession for FakeSession {
        fn wait(&mut self, ms: u64) {
            self.waited_ms.push(ms);
        }
        fn wait_for_eval(&mut self, _expr: &str, _timeout_ms: u64) -> Result<Value, String> {
            if self.wait_for_ok { Ok(json!({"ok": true})) } else { Err("Timed out waiting for expression. Last result: null".to_string()) }
        }
        fn eval(&mut self, _expr: &str) -> Result<Value, String> {
            Ok(self.eval_result.clone())
        }
        fn element_point(&mut self, _selector: &str) -> Result<ElementPoint, String> {
            Ok(point(10.0, 20.0, Rect { left: 0.0, top: 0.0, width: 5.0, height: 5.0 }))
        }
        fn click(&mut self, x: f64, y: f64) -> Result<(), String> {
            self.clicked.push((x, y));
            Ok(())
        }
        fn mouse_move(&mut self, x: f64, y: f64) -> Result<(), String> {
            self.moved.push((x, y));
            Ok(())
        }
        fn insert_text(&mut self, text: &str) -> Result<(), String> {
            self.typed.push(text.to_string());
            Ok(())
        }
        fn press_key(&mut self, key: &str) -> Result<(), String> {
            self.pressed.push(key.to_string());
            Ok(())
        }
        fn mouse_wheel(&mut self, x: f64, y: f64, dx: f64, dy: f64) -> Result<(), String> {
            self.wheels.push((x, y, dx, dy));
            Ok(())
        }
        fn capture(&mut self, _out: &str) -> Result<String, String> {
            Ok(self.capture_path.clone())
        }
        fn apply_conditions(&mut self, _conditions: &super::session_client::Conditions) -> Result<(), String> {
            Ok(())
        }
        fn navigate(&mut self, _url: &str) -> Result<(), String> {
            Ok(())
        }
        fn load_session(&mut self, _data: &super::session_client::SessionData) -> Result<(), String> {
            Ok(())
        }
        fn save_session(&mut self) -> Result<super::session_client::SessionData, String> {
            Ok(super::session_client::SessionData { cookies: Value::Array(vec![]), local_storage: Value::Object(Default::default()) })
        }
        fn take_console_errors(&mut self) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn parse_actions_rejects_non_array() {
        let e = parse_actions("{}").unwrap_err();
        assert!(e.contains("must contain a JSON array"));
    }

    #[test]
    fn parse_actions_parses_click() {
        let actions = parse_actions(r##"[{"type":"click","selector":"#go"}]"##).unwrap();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::Click { selector } if selector == "#go"));
    }

    #[test]
    fn sleep_waits_default_250ms() {
        let mut s = FakeSession::default();
        let out = run_action(&mut s, &Action::Sleep { ms: None }, 0).unwrap();
        assert_eq!(s.waited_ms, vec![250]);
        assert_eq!(out, "[qa] 1:sleep ok");
    }

    #[test]
    fn click_resolves_point_then_clicks() {
        let mut s = FakeSession::default();
        let a = Action::Click { selector: "#go".into() };
        run_action(&mut s, &a, 3).unwrap();
        assert_eq!(s.clicked, vec![(10.0, 20.0)]);
    }

    #[test]
    fn eval_not_ok_errors_with_label() {
        let mut s = FakeSession { eval_result: json!({"ok": false}), ..Default::default() };
        let a = Action::Eval { expression: "1".into() };
        let e = run_action(&mut s, &a, 0).unwrap_err();
        assert!(e.starts_with("1:eval eval returned not ok"));
    }

    #[test]
    fn assert_text_failure_reports_label_and_type() {
        let mut s = FakeSession { eval_result: json!({"ok": false, "text": "nope"}), ..Default::default() };
        let a = Action::AssertText { selector: "#t".into(), text: "hi".into() };
        let e = run_action(&mut s, &a, 4).unwrap_err();
        assert!(e.starts_with("5:assertText text assertion failed"));
    }

    #[test]
    fn wheel_repeats_clicks_times() {
        let mut s = FakeSession::default();
        let a = Action::Wheel { x: None, y: None, clicks: Some(3), delta_x: None, delta_y: None, gap: Some(0) };
        run_action(&mut s, &a, 0).unwrap();
        assert_eq!(s.wheels.len(), 3);
        assert_eq!(s.wheels[0], (400.0, 400.0, 0.0, 100.0));
    }

    #[test]
    fn screenshot_logs_both_lines() {
        let mut s = FakeSession { capture_path: "/out/a.png".into(), ..Default::default() };
        let a = Action::Screenshot { out: "a.png".into() };
        let out = run_action(&mut s, &a, 0).unwrap();
        assert_eq!(out, "[qa] screenshot /out/a.png\n[qa] 1:screenshot ok");
    }
}
