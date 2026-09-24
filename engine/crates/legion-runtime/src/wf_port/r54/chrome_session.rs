//! `headless_chrome`-backed production implementation of `session_client::BrowserSession`
//! (packet r54). Not covered by this packet's tests: cargo cannot launch a real browser in this
//! environment, and (per the port brief) browser/DOM work is exercised only through fakes.
//!
//! API choices below are matched against this crate's other `headless_chrome` usages
//! (`wf_port::r07::real`, `wf_port::w2_028::web_page_probe`), which confirm `Browser::new`,
//! `browser.new_tab()`, `tab.navigate_to`/`wait_until_navigated`, `tab.evaluate(expr, bool)` ->
//! `RemoteObject.value`, `tab.capture_screenshot(format, quality, clip, full_page)` -> `Vec<u8>`,
//! `tab.find_element(selector)`, and the exact field list of
//! `protocol::cdp::Emulation::SetDeviceMetricsOverride` (no `Default` impl — every field must be
//! named, per `w2_028::web_page_probe::ChromePageBrowser::set_viewport`).
//!
//! `qa.mjs`'s raw `Input.dispatchMouseEvent`/`dispatchKeyEvent`/`Network.emulateNetworkConditions`
//! CDP calls (click, hover, press, wheel, network throttling) have no confirmed-field precedent
//! anywhere else in this crate, and this environment cannot compile-check a guess at their exact
//! struct shape. Rather than risk a build break on an unverifiable field list, those five
//! operations are ported as JS-dispatched synthetic DOM events via the same `evaluate()` path
//! already confirmed above (`MouseEvent`/`WheelEvent`/`KeyboardEvent` construction, dispatched
//! with `bubbles: true`). This is a **PORTED-PARTIAL** gap versus qa.mjs's real OS-level CDP
//! input: synthetic events pass listeners bound with `addEventListener` (what the QA actions this
//! file exists for actually assert against) but do not move the OS cursor or satisfy
//! `:hover`/native drag/scroll-snap the way genuine CDP input does. CPU throttling
//! (`Emulation.setCPUThrottlingRate`) has one `rate: f64` field and is low-risk, so it is kept as
//! a direct `call_method`.

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
        let _ = tab.add_event_listener(Arc::new(move |event: &headless_chrome::protocol::cdp::types::Event| {
            match event {
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
                        sink.lock().unwrap().push(format!("console.{level}: {text}"));
                    }
                }
                headless_chrome::protocol::cdp::types::Event::RuntimeExceptionThrown(ev) => {
                    let text = ev.params.exception_details.text.clone();
                    sink.lock().unwrap().push(format!("exception: {text}"));
                }
                _ => {}
            }
        }));
        ChromeSession { tab, console_errors }
    }

    fn eval_raw(&self, expression: &str) -> Result<Value, String> {
        // `runtimeEval` (qa.mjs lines 454-465): confirmed shape, see module doc.
        let remote = self.tab.evaluate(expression, true).map_err(|e| e.to_string())?;
        Ok(remote.value.unwrap_or(Value::Null))
    }
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
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
                return Err(format!("Timed out waiting for expression. Last result: {last}"));
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
        // See module doc: synthetic `mousedown`/`mouseup`/`click` dispatch at the viewport point,
        // in place of qa.mjs's `Input.dispatchMouseEvent` (unverifiable field shape here).
        let expr = format!(
            "(() => {{ const el = document.elementFromPoint({x}, {y}); if (!el) return {{ ok: false }}; for (const type of ['mousedown','mouseup','click']) el.dispatchEvent(new MouseEvent(type, {{ bubbles: true, cancelable: true, clientX: {x}, clientY: {y} }})); return {{ ok: true }}; }})()"
        );
        self.eval_raw(&expr).map(|_| ())
    }

    fn mouse_move(&mut self, x: f64, y: f64) -> Result<(), String> {
        let expr = format!(
            "(() => {{ const el = document.elementFromPoint({x}, {y}); if (!el) return {{ ok: false }}; el.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true, clientX: {x}, clientY: {y} }})); el.dispatchEvent(new MouseEvent('mousemove', {{ bubbles: true, clientX: {x}, clientY: {y} }})); return {{ ok: true }}; }})()"
        );
        self.eval_raw(&expr).map(|_| ())
    }

    fn insert_text(&mut self, text: &str) -> Result<(), String> {
        let expr = format!(
            "(() => {{ const el = document.activeElement; if (!el) return {{ ok: false }}; if ('value' in el) {{ el.value += {t}; el.dispatchEvent(new Event('input', {{ bubbles: true }})); }} else if (el.isContentEditable) {{ el.textContent += {t}; }} return {{ ok: true }}; }})()",
            t = js_string(text)
        );
        self.eval_raw(&expr).map(|_| ())
    }

    fn press_key(&mut self, key: &str) -> Result<(), String> {
        let expr = format!(
            "(() => {{ const el = document.activeElement || document.body; for (const type of ['keydown','keyup']) el.dispatchEvent(new KeyboardEvent(type, {{ bubbles: true, cancelable: true, key: {k} }})); return {{ ok: true }}; }})()",
            k = js_string(key)
        );
        self.eval_raw(&expr).map(|_| ())
    }

    fn mouse_wheel(&mut self, x: f64, y: f64, delta_x: f64, delta_y: f64) -> Result<(), String> {
        let expr = format!(
            "(() => {{ const el = document.elementFromPoint({x}, {y}); if (!el) return {{ ok: false }}; el.dispatchEvent(new WheelEvent('wheel', {{ bubbles: true, cancelable: true, clientX: {x}, clientY: {y}, deltaX: {delta_x}, deltaY: {delta_y} }})); return {{ ok: true }}; }})()"
        );
        self.eval_raw(&expr).map(|_| ())
    }

    fn capture(&mut self, out: &str) -> Result<String, String> {
        // `capture` (qa.mjs lines 496-502): `Page.captureScreenshot` format png, fromSurface
        // true. `tab.capture_screenshot(format, quality, clip, from_surface)` is the confirmed
        // convenience wrapper (see module doc) and returns raw bytes directly, no base64 step.
        let bytes = self
            .tab
            .capture_screenshot(headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, None, None, true)
            .map_err(|e| e.to_string())?;
        if let Some(parent) = std::path::Path::new(out).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(out, bytes).map_err(|e| e.to_string())?;
        Ok(out.to_string())
    }

    fn apply_conditions(&mut self, conditions: &Conditions) -> Result<(), String> {
        // `applyConditions` (qa.mjs lines 107-121). Device metrics: confirmed field list (module
        // doc). Network throttling uses the JS-side `navigator.connection`-independent approach
        // is unavailable without the real CDP call, so — like click/hover/wheel/press above —
        // network/CPU conditions beyond viewport are PORTED-PARTIAL here: CPU throttling has a
        // single, low-risk `rate` field and is wired directly; network throttling's exact
        // `Network::EmulateNetworkConditions` field list is unverifiable in this environment and
        // is left as a no-op with the gap documented, rather than guessed.
        self.tab
            .call_method(headless_chrome::protocol::cdp::Emulation::SetDeviceMetricsOverride {
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
        if let Some(rate) = conditions.cpu {
            self.tab
                .call_method(headless_chrome::protocol::cdp::Emulation::SetCPUThrottlingRate { rate })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn navigate(&mut self, url: &str) -> Result<(), String> {
        // Confirmed shape (module doc): `navigate_to` + `wait_until_navigated`, then the same
        // `document.readyState` poll qa.mjs itself uses (lines 654/707) as an extra guard.
        self.tab.navigate_to(url).map_err(|e| e.to_string())?;
        self.tab.wait_until_navigated().map_err(|e| format!("Timed out loading {url}: {e}"))?;
        self.wait_for_eval("(() => ({ ok: document.readyState !== 'loading' && !!document.body }))()", 30000)?;
        Ok(())
    }

    fn load_session(&mut self, data: &SessionData) -> Result<(), String> {
        // `loadSession`'s localStorage half (qa.mjs lines 133-136) via the confirmed `evaluate`
        // path. The cookie half (`Network.setCookies`) shares the same unverifiable-CDP-struct
        // gap as network throttling above and is PORTED-PARTIAL: cookies are not restored by
        // this production impl (localStorage restore, the more commonly used half for skipping
        // re-login per the qa.mjs module doc at line 124, is fully wired).
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
        // `saveSession` (qa.mjs lines 138-147): localStorage via `evaluate` (confirmed path).
        // Cookies share the gap noted in `load_session` above.
        let local_storage = self
            .eval_raw("JSON.stringify(Object.assign({}, window.localStorage))")
            .ok()
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or(Value::Object(Default::default()));
        Ok(SessionData { cookies: Value::Array(vec![]), local_storage })
    }

    fn take_console_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut *self.console_errors.lock().unwrap())
    }
}
