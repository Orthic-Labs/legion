//! Integration test for packet r54's port of `src/lib/qa-engine/qa.mjs`.
//!
//! This file depends on `legion_runtime::wf_port::r54`, which is not yet wired into
//! `legion-runtime`'s public module tree (the integrator adds `pub mod r54;` to
//! `src/wf_port/mod.rs` per the port brief's "do not edit wf_port/mod.rs" rule — same situation
//! as packet wf018's integration test). Until that wiring lands, this file will not compile as
//! part of the crate's test target.

use legion_runtime::wf_port::r54::actions::{parse_actions, run_action, Action};
use legion_runtime::wf_port::r54::args::{parse_args, split_qa_env};
use legion_runtime::wf_port::r54::ports::{free_port, wait_for_http, HttpAttempt, HttpProbe, PortProbe};
use legion_runtime::wf_port::r54::run::{needs_cdp_shot, plan, resolve_url, Plan};
use legion_runtime::wf_port::r54::session::{read_session_file, write_session_file, SessionFile};
use legion_runtime::wf_port::r54::session_client::{BrowserSession, ElementPoint, Rect, SessionData};
use serde_json::{json, Value};
use std::collections::HashMap;

#[test]
fn cli_flags_flow_into_the_run_plan() {
    let args = parse_args(&["--actions".to_string(), "a.json".to_string(), "--slow-3g".to_string()]).unwrap();
    assert!(needs_cdp_shot(&args));
    assert_eq!(
        plan(&args),
        Plan::Run { needs_server: true, needs_cdp_shot: true, do_shot: false, do_actions: true }
    );
    assert_eq!(resolve_url(&args, Some(1422)).unwrap(), "http://127.0.0.1:1422/?qa=1");
}

#[test]
fn qa_env_default_matches_js_when_no_value() {
    assert_eq!(split_qa_env("VITE_APP_BROWSER_QA"), Some(("VITE_APP_BROWSER_QA".to_string(), "1".to_string())));
}

struct SequencedPorts(Vec<bool>);
impl PortProbe for SequencedPorts {
    fn is_taken(&mut self, _port: u32) -> bool {
        if self.0.is_empty() { false } else { self.0.remove(0) }
    }
}

struct OkThenFail {
    calls: usize,
    elapsed: u64,
}
impl HttpProbe for OkThenFail {
    fn attempt(&mut self, _url: &str) -> HttpAttempt {
        self.calls += 1;
        if self.calls == 1 {
            HttpAttempt::Error("connect ECONNREFUSED".to_string())
        } else {
            HttpAttempt::Ok
        }
    }
    fn elapsed_ms(&self) -> u64 {
        self.elapsed
    }
    fn sleep(&mut self, ms: u64) {
        self.elapsed += ms;
    }
}

#[test]
fn server_startup_uses_free_port_then_waits_for_http() {
    let mut ports = SequencedPorts(vec![true, true, false]);
    let port = free_port(&mut ports, 1422).unwrap();
    assert_eq!(port, 1424);

    let mut http = OkThenFail { calls: 0, elapsed: 0 };
    let url = format!("http://127.0.0.1:{port}/?qa=1");
    assert!(wait_for_http(&mut http, &url, 30000).is_ok());
    assert_eq!(http.calls, 2);
}

#[derive(Default)]
struct FakeBrowserSession {
    log: Vec<String>,
}
impl BrowserSession for FakeBrowserSession {
    fn wait(&mut self, _ms: u64) {}
    fn wait_for_eval(&mut self, _expression: &str, _timeout_ms: u64) -> Result<Value, String> {
        Ok(json!({"ok": true}))
    }
    fn eval(&mut self, _expression: &str) -> Result<Value, String> {
        Ok(json!({"ok": true, "text": "Hello world"}))
    }
    fn element_point(&mut self, selector: &str) -> Result<ElementPoint, String> {
        self.log.push(format!("point {selector}"));
        Ok(ElementPoint { x: 1.0, y: 2.0, rect: Rect { left: 0.0, top: 0.0, width: 1.0, height: 1.0 } })
    }
    fn click(&mut self, x: f64, y: f64) -> Result<(), String> {
        self.log.push(format!("click {x},{y}"));
        Ok(())
    }
    fn mouse_move(&mut self, _x: f64, _y: f64) -> Result<(), String> {
        Ok(())
    }
    fn insert_text(&mut self, _text: &str) -> Result<(), String> {
        Ok(())
    }
    fn press_key(&mut self, _key: &str) -> Result<(), String> {
        Ok(())
    }
    fn mouse_wheel(&mut self, _x: f64, _y: f64, _dx: f64, _dy: f64) -> Result<(), String> {
        Ok(())
    }
    fn capture(&mut self, out: &str) -> Result<String, String> {
        Ok(format!("/abs/{out}"))
    }
    fn apply_conditions(&mut self, _conditions: &legion_runtime::wf_port::r54::session_client::Conditions) -> Result<(), String> {
        Ok(())
    }
    fn navigate(&mut self, _url: &str) -> Result<(), String> {
        Ok(())
    }
    fn load_session(&mut self, _data: &SessionData) -> Result<(), String> {
        Ok(())
    }
    fn save_session(&mut self) -> Result<SessionData, String> {
        Ok(SessionData { cookies: json!([]), local_storage: json!({}) })
    }
}

#[test]
fn actions_file_parses_and_replays_against_a_fake_session() {
    let file = r#"[
        {"type": "waitFor", "selector": "#app"},
        {"type": "click", "selector": "#go"},
        {"type": "assertText", "selector": "#msg", "text": "Hello"},
        {"type": "screenshot", "out": "shot.png"}
    ]"#;
    let actions = parse_actions(file).unwrap();
    assert_eq!(actions.len(), 4);
    let mut session = FakeBrowserSession::default();
    let mut lines = Vec::new();
    for (i, action) in actions.iter().enumerate() {
        lines.push(run_action(&mut session, action, i).unwrap());
    }
    assert_eq!(lines[1], "[qa] 2:click ok");
    assert_eq!(lines[3], "[qa] screenshot /abs/shot.png\n[qa] 4:screenshot ok");
    assert_eq!(session.log[0], "point #go");
    assert!(matches!(&actions[3], Action::Screenshot { out } if out == "shot.png"));
}

struct FakeSessionFs {
    files: HashMap<String, String>,
}
impl SessionFile for FakeSessionFs {
    fn read(&self, path: &str) -> Result<String, String> {
        self.files.get(path).cloned().ok_or_else(|| "ENOENT".to_string())
    }
    fn write(&mut self, path: &str, contents: &str) -> Result<(), String> {
        self.files.insert(path.to_string(), contents.to_string());
        Ok(())
    }
}

#[test]
fn save_then_load_session_file_round_trips() {
    let mut fs = FakeSessionFs { files: HashMap::new() };
    let data = SessionData { cookies: json!([{"name": "sid", "value": "abc"}]), local_storage: json!({"theme": "dark"}) };
    write_session_file(&mut fs, "session.json", &data).unwrap();
    let back = read_session_file(&fs, "session.json").unwrap();
    assert_eq!(back, data);
}
