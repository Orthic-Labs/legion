//! `headless_chrome`-backed production implementation of `session_client::BrowserSession`
//! (packet r54). Not covered by this packet's tests: cargo cannot launch a real browser in this
//! environment, so the CDP calls below are exercised only through fakes at the orchestration level
//! (`run::open_page`, `session::save_session_to_file`).
//!
//! Each CDP call here is the raw call qa.mjs sent:
//! - `Emulation.setDeviceMetricsOverride` and `Emulation.setCPUThrottlingRate` (`apply_conditions`).
//! - `Network.emulateNetworkConditions` (`apply_conditions`, throttled runs only).
//! - `Network.setCookies` (`set_cookies`) and `Network.getCookies` with no URL filter
//!   (`save_session`).
//! - `Input.dispatchMouseEvent` (click, mouse_move, mouse_wheel), `Input.dispatchKeyEvent`
//!   (press_key) and `Input.insertText` (insert_text). This is real input, not synthetic DOM
//!   events. A CDP error is returned to the caller and never replaced with a fallback.
//!
//! Not sent: qa.mjs called `Network.enable` before the network calls. Its
//! `Network::Enable` field list is not confirmed for headless_chrome 1.0.22, so it is omitted.
//! Whether Chrome needs it for these two calls is unverified in this environment.
//!
//! Gaps: none originate here. `run.rs` reports `cookies-skipped:<n>` when a loaded session file
//! holds cookies that cannot be applied.
//!
//! The field lists below come from the confirmed `headless_chrome` 1.0.22 CDP types recorded in
//! the packet notes. The struct literals name every field because none of these types has a
//! `Default` impl.

use headless_chrome::protocol::cdp::Network::CookieParam;
use headless_chrome::protocol::cdp::{Emulation, Input, Network};
use headless_chrome::Tab;
use serde_json::Value;
use std::sync::{Arc, Mutex};

use super::session_client::{BrowserSession, Conditions, ElementPoint, Rect, SessionData};

pub struct ChromeSession {
    pub tab: Arc<Tab>,
    console_errors: Arc<Mutex<Vec<String>>>,
}

impl ChromeSession {
    pub fn new(tab: Arc<Tab>) -> Self {
        // `client.on("Runtime.consoleAPICalled"/"Runtime.exceptionThrown", ...)` (qa.mjs
        // `runActions`, lines 692-701). Field shape confirmed against this crate's other CDP
        // event-subscription use (`wf_port::r03::verify::ChromeBrowserDriver::open`), which is
        // the only other packet here to have needed `Tab::add_event_listener` rather than plain
        // request/response CDP calls.
        let console_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = console_errors.clone();
        let _ = tab.add_event_listener(Arc::new(
            move |event: &headless_chrome::protocol::cdp::types::Event| match event {
                headless_chrome::protocol::cdp::types::Event::RuntimeConsoleAPICalled(ev) => {
                    let level = format!("{:?}", ev.params.Type).to_lowercase();
                    if level == "error" || level == "warning" {
                        let text = ev
                            .params
                            .args
                            .iter()
                            .filter_map(|a| a.value.as_ref().map(|v| v.to_string()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        sink.lock()
                            .unwrap()
                            .push(format!("console.{level}: {text}"));
                    }
                }
                headless_chrome::protocol::cdp::types::Event::RuntimeExceptionThrown(ev) => {
                    let text = ev.params.exception_details.text.clone();
                    sink.lock().unwrap().push(format!("exception: {text}"));
                }
                _ => {}
            },
        ));
        ChromeSession {
            tab,
            console_errors,
        }
    }

    fn eval_raw(&self, expression: &str) -> Result<Value, String> {
        // `runtimeEval` (qa.mjs lines 454-465): confirmed shape, see module doc.
        let remote = self
            .tab
            .evaluate(expression, true)
            .map_err(|e| e.to_string())?;
        Ok(remote.value.unwrap_or(Value::Null))
    }

    /// One `Input.dispatchMouseEvent` call. `delta` is `(deltaX, deltaY)` for wheel events only.
    fn dispatch_mouse(
        &self,
        event_type: Input::DispatchMouseEventTypeOption,
        x: f64,
        y: f64,
        button: Option<Input::MouseButton>,
        click_count: Option<u32>,
        delta: Option<(f64, f64)>,
    ) -> Result<(), String> {
        self.tab
            .call_method(Input::DispatchMouseEvent {
                Type: event_type,
                x,
                y,
                modifiers: None,
                timestamp: None,
                button,
                buttons: None,
                click_count,
                force: None,
                tangential_pressure: None,
                tilt_x: None,
                tilt_y: None,
                twist: None,
                delta_x: delta.map(|(dx, _)| dx),
                delta_y: delta.map(|(_, dy)| dy),
                pointer_Type: None,
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// One `Input.dispatchKeyEvent` call carrying the key name, plus `text` when given.
    fn dispatch_key(
        &self,
        event_type: Input::DispatchKeyEventTypeOption,
        key: &str,
        text: Option<String>,
    ) -> Result<(), String> {
        self.tab
            .call_method(Input::DispatchKeyEvent {
                Type: event_type,
                modifiers: None,
                timestamp: None,
                text,
                unmodified_text: None,
                key_identifier: None,
                code: None,
                key: Some(key.to_string()),
                windows_virtual_key_code: None,
                native_virtual_key_code: None,
                auto_repeat: None,
                is_keypad: None,
                is_system_key: None,
                location: None,
                commands: None,
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Text a keyDown carries for a printable single character, so the key inserts that character.
/// Multi-character key names such as `Enter`, and control characters, carry no text.
fn printable_text(key: &str) -> Option<String> {
    let mut chars = key.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if !c.is_control() => Some(key.to_string()),
        _ => None,
    }
}

impl BrowserSession for ChromeSession {
    fn wait(&mut self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn wait_for_eval(&mut self, expression: &str, timeout_ms: u64) -> Result<Value, String> {
        // `waitForEval` (qa.mjs lines 467-476): poll every 250ms until `.ok` truthy or timeout.
        let started = std::time::Instant::now();
        let mut last = Value::Null;
        loop {
            last = self.eval_raw(expression)?;
            if last.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                return Ok(last);
            }
            if started.elapsed().as_millis() as u64 >= timeout_ms {
                return Err(format!(
                    "Timed out waiting for expression. Last result: {last}"
                ));
            }
            self.wait(250);
        }
    }

    fn eval(&mut self, expression: &str) -> Result<Value, String> {
        self.eval_raw(expression)
    }

    fn element_point(&mut self, selector: &str) -> Result<ElementPoint, String> {
        let expr = super::session_client::element_point_expression(&js_string(selector));
        let v = self.wait_for_eval(&expr, 10000)?;
        let x = v.get("x").and_then(|v| v.as_f64()).ok_or("missing x")?;
        let y = v.get("y").and_then(|v| v.as_f64()).ok_or("missing y")?;
        let rect = v.get("rect").ok_or("missing rect")?;
        Ok(ElementPoint {
            x,
            y,
            rect: Rect {
                left: rect.get("left").and_then(|v| v.as_f64()).unwrap_or(0.0),
                top: rect.get("top").and_then(|v| v.as_f64()).unwrap_or(0.0),
                width: rect.get("width").and_then(|v| v.as_f64()).unwrap_or(0.0),
                height: rect.get("height").and_then(|v| v.as_f64()).unwrap_or(0.0),
            },
        })
    }

    fn click(&mut self, x: f64, y: f64) -> Result<(), String> {
        // qa.mjs `click`: mousePressed then mouseReleased, left button, clickCount 1.
        self.dispatch_mouse(
            Input::DispatchMouseEventTypeOption::MousePressed,
            x,
            y,
            Some(Input::MouseButton::Left),
            Some(1),
            None,
        )?;
        self.dispatch_mouse(
            Input::DispatchMouseEventTypeOption::MouseReleased,
            x,
            y,
            Some(Input::MouseButton::Left),
            Some(1),
            None,
        )
    }

    fn mouse_move(&mut self, x: f64, y: f64) -> Result<(), String> {
        // qa.mjs `hover`: mouseMoved at the element's center.
        self.dispatch_mouse(
            Input::DispatchMouseEventTypeOption::MouseMoved,
            x,
            y,
            None,
            None,
            None,
        )
    }

    fn insert_text(&mut self, text: &str) -> Result<(), String> {
        // qa.mjs `type`: Input.insertText.
        self.tab
            .call_method(Input::InsertText {
                text: text.to_string(),
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn press_key(&mut self, key: &str) -> Result<(), String> {
        // qa.mjs `press`: keyDown then keyUp with the key name. The keyDown also carries `text`
        // for a printable single character (see `printable_text`).
        self.dispatch_key(
            Input::DispatchKeyEventTypeOption::KeyDown,
            key,
            printable_text(key),
        )?;
        self.dispatch_key(Input::DispatchKeyEventTypeOption::KeyUp, key, None)
    }

    fn mouse_wheel(&mut self, x: f64, y: f64, delta_x: f64, delta_y: f64) -> Result<(), String> {
        // qa.mjs `wheel`: mouseWheel with deltaX/deltaY at the given point.
        self.dispatch_mouse(
            Input::DispatchMouseEventTypeOption::MouseWheel,
            x,
            y,
            None,
            None,
            Some((delta_x, delta_y)),
        )
    }

    fn capture(&mut self, out: &str) -> Result<String, String> {
        // `capture` (qa.mjs lines 496-502): `Page.captureScreenshot` format png, fromSurface
        // true. `tab.capture_screenshot(format, quality, clip, from_surface)` is the confirmed
        // convenience wrapper (see module doc) and returns raw bytes directly, no base64 step.
        let bytes = self
            .tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                true,
            )
            .map_err(|e| e.to_string())?;
        if let Some(parent) = std::path::Path::new(out).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(out, bytes).map_err(|e| e.to_string())?;
        Ok(out.to_string())
    }

    fn apply_conditions(&mut self, conditions: &Conditions) -> Result<(), String> {
        // `applyConditions` (qa.mjs lines 107-121), same call order: viewport, network, CPU.
        self.tab
            .call_method(Emulation::SetDeviceMetricsOverride {
                width: conditions.width as u32,
                height: conditions.height as u32,
                device_scale_factor: conditions.dpr,
                mobile: conditions.mobile,
                scale: None,
                screen_width: None,
                screen_height: None,
                position_x: None,
                position_y: None,
                dont_set_visible_size: None,
                screen_orientation: None,
                viewport: None,
                display_feature: None,
                device_posture: None,
            })
            .map_err(|e| e.to_string())?;
        if let Some(profile) = conditions.throttle {
            // qa.mjs: `{ offline: false, ...THROTTLE[name] }`. Every other field is left unset.
            self.tab
                .call_method(Network::EmulateNetworkConditions {
                    offline: false,
                    latency: profile.latency,
                    download_throughput: profile.download_throughput,
                    upload_throughput: profile.upload_throughput,
                    connection_Type: None,
                    packet_loss: None,
                    packet_queue_length: None,
                    packet_reordering: None,
                })
                .map_err(|e| e.to_string())?;
        }
        if let Some(rate) = conditions.cpu {
            self.tab
                .call_method(Emulation::SetCPUThrottlingRate { rate })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn navigate(&mut self, url: &str) -> Result<(), String> {
        // Confirmed shape (module doc): `navigate_to` + `wait_until_navigated`, then the same
        // `document.readyState` poll qa.mjs itself uses (lines 654/707) as an extra guard.
        self.tab.navigate_to(url).map_err(|e| e.to_string())?;
        self.tab
            .wait_until_navigated()
            .map_err(|e| format!("Timed out loading {url}: {e}"))?;
        self.wait_for_eval(
            "(() => ({ ok: document.readyState !== 'loading' && !!document.body }))()",
            30000,
        )?;
        Ok(())
    }

    fn set_cookies(&mut self, cookies: &[CookieParam]) -> Result<(), String> {
        // qa.mjs `loadSession`: `Network.setCookies` with the saved cookie objects.
        self.tab
            .call_method(Network::SetCookies {
                cookies: cookies.to_vec(),
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn load_session(&mut self, data: &SessionData) -> Result<(), String> {
        // `loadSession`'s localStorage half (qa.mjs lines 133-136) via the confirmed `evaluate`
        // path. The caller has already restored cookies before the first navigation (see
        // `set_cookies`) and calls this after it, so the page origin exists.
        if let Some(obj) = data.local_storage.as_object() {
            if !obj.is_empty() {
                let expr = format!(
                    "(() => {{ try {{ const s = {}; for (const k in s) localStorage.setItem(k, s[k]); }} catch (e) {{}} }})();",
                    serde_json::to_string(&data.local_storage).map_err(|e| e.to_string())?
                );
                self.eval_raw(&expr)?;
            }
        }
        Ok(())
    }

    fn save_session(&mut self) -> Result<SessionData, String> {
        // `saveSession` (qa.mjs lines 138-147). Cookies: `Network.getCookies` with no URL filter,
        // which returns the cookies for the current page. A browser error is returned, not
        // replaced by an empty list. localStorage: `evaluate`, with failures tolerated as qa.mjs's
        // try/catch tolerated them.
        let captured = self
            .tab
            .call_method(Network::GetCookies { urls: None })
            .map_err(|e| e.to_string())?;
        let cookies = serde_json::to_value(&captured.cookies).map_err(|e| e.to_string())?;
        let local_storage = self
            .eval_raw("JSON.stringify(Object.assign({}, window.localStorage))")
            .ok()
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or(Value::Object(Default::default()));
        Ok(SessionData {
            cookies,
            local_storage,
        })
    }

    fn take_console_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut *self.console_errors.lock().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::printable_text;

    #[test]
    fn printable_single_character_carries_text() {
        assert_eq!(printable_text("a"), Some("a".to_string()));
        assert_eq!(printable_text("7"), Some("7".to_string()));
    }

    #[test]
    fn named_keys_and_control_characters_carry_no_text() {
        assert_eq!(printable_text("Enter"), None);
        assert_eq!(printable_text("ArrowDown"), None);
        assert_eq!(printable_text("\n"), None);
        assert_eq!(printable_text(""), None);
    }
}
