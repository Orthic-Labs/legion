//! Integration test for packet r54's port of `src/lib/qa-engine/qa.mjs`.
//!
//! Exercises the orchestration through `BrowserSession` fakes. The real CDP calls live only in
//! `wf_port::r54::chrome_session::ChromeSession`, which needs a browser and is not run here.

use headless_chrome::protocol::cdp::Network::CookieParam;
use legion_runtime::wf_port::r54::actions::{parse_actions, run_action, Action};
use legion_runtime::wf_port::r54::args::{parse_args, parse_cdp_port, split_qa_env};
use legion_runtime::wf_port::r54::ports::{
    free_port, wait_for_http, HttpAttempt, HttpProbe, PortProbe,
};
use legion_runtime::wf_port::r54::run::{
    needs_cdp_shot, open_page, plan, report_gaps, resolve_url, session_gaps, Plan,
};
use legion_runtime::wf_port::r54::session::{
    cookie_params, read_session_file, save_session_to_file, write_session_file, SessionFile,
};
use legion_runtime::wf_port::r54::session_client::{
    BrowserSession, Conditions, ElementPoint, Rect, SessionData,
};
use serde_json::{json, Value};
use std::collections::HashMap;

#[test]
fn cli_flags_flow_into_the_run_plan() {
    let args = parse_args(&[
        "--actions".to_string(),
        "a.json".to_string(),
        "--slow-3g".to_string(),
    ])
    .unwrap();
    assert!(needs_cdp_shot(&args));
    assert_eq!(
        plan(&args),
        Plan::Run {
            needs_server: true,
            needs_cdp_shot: true,
            do_shot: false,
            do_actions: true
        }
    );
    assert_eq!(
        resolve_url(&args, Some(1422)).unwrap(),
        "http://127.0.0.1:1422/?qa=1"
    );
}

#[test]
fn qa_env_default_matches_js_when_no_value() {
    assert_eq!(
        split_qa_env("VITE_APP_BROWSER_QA"),
        Some(("VITE_APP_BROWSER_QA".to_string(), "1".to_string()))
    );
}

#[test]
fn cdp_port_flag_is_validated_as_a_usage_error() {
    assert_eq!(parse_cdp_port("9222"), Ok(9222));
    assert!(parse_cdp_port("65536").is_err());
    let args = parse_args(&["--cdp-port".to_string(), "9222".to_string()]).unwrap();
    assert_eq!(args.cdp_port, 9222);
    assert!(parse_args(&["--cdp-port".to_string(), "65536".to_string()]).is_err());
}

struct SequencedPorts(Vec<bool>);
impl PortProbe for SequencedPorts {
    fn is_taken(&mut self, _port: u32) -> bool {
        if self.0.is_empty() {
            false
        } else {
            self.0.remove(0)
        }
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

    let mut http = OkThenFail {
        calls: 0,
        elapsed: 0,
    };
    let url = format!("http://127.0.0.1:{port}/?qa=1");
    assert!(wait_for_http(&mut http, &url, 30000).is_ok());
    assert_eq!(http.calls, 2);
}

/// Records every orchestration call in order. Cookie calls log their count.
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
        Ok(ElementPoint {
            x: 1.0,
            y: 2.0,
            rect: Rect {
                left: 0.0,
                top: 0.0,
                width: 1.0,
                height: 1.0,
            },
        })
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
    fn apply_conditions(
        &mut self,
        _conditions: &legion_runtime::wf_port::r54::session_client::Conditions,
    ) -> Result<(), String> {
        self.log.push("apply".to_string());
        Ok(())
    }
    fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.log.push(format!("navigate {url}"));
        Ok(())
    }
    fn set_cookies(&mut self, cookies: &[CookieParam]) -> Result<(), String> {
        self.log.push(format!("cookies {}", cookies.len()));
        Ok(())
    }
    fn load_session(&mut self, _data: &SessionData) -> Result<(), String> {
        self.log.push("load".to_string());
        Ok(())
    }
    fn save_session(&mut self) -> Result<SessionData, String> {
        Ok(SessionData {
            cookies: json!([{"name": "sid", "value": "abc"}]),
            local_storage: json!({"theme": "dark"}),
        })
    }
}

fn plain_conditions() -> Conditions {
    Conditions {
        width: 1365.0,
        height: 900.0,
        dpr: 1.0,
        mobile: false,
        throttle: None,
        cpu: None,
    }
}

#[test]
fn restored_storage_is_written_after_first_navigation_then_page_reloads() {
    let mut session = FakeBrowserSession::default();
    let data = SessionData {
        cookies: json!([]),
        local_storage: json!({"theme": "dark"}),
    };
    let mut gaps = Vec::new();
    open_page(
        &mut session,
        &plain_conditions(),
        "http://x/",
        Some(&data),
        &mut gaps,
    )
    .unwrap();
    assert_eq!(
        session.log,
        vec!["apply", "navigate http://x/", "load", "navigate http://x/"]
    );
    assert!(gaps.is_empty());
}

#[test]
fn restored_cookies_are_set_before_the_first_navigation() {
    let mut session = FakeBrowserSession::default();
    let data = SessionData {
        cookies: json!([{"name": "sid", "value": "abc", "domain": "x.test", "path": "/"}]),
        local_storage: json!({"theme": "dark"}),
    };
    let mut gaps = Vec::new();
    let skipped = open_page(
        &mut session,
        &plain_conditions(),
        "http://x/",
        Some(&data),
        &mut gaps,
    )
    .unwrap();
    assert_eq!(
        session.log,
        vec![
            "apply",
            "cookies 1",
            "navigate http://x/",
            "load",
            "navigate http://x/"
        ]
    );
    assert_eq!(skipped, 0);
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn cookies_that_cannot_be_applied_are_counted_and_reported_as_a_gap() {
    let mut session = FakeBrowserSession::default();
    let data = SessionData {
        cookies: json!([
            {"name": "sid", "value": "abc"},
            {"value": "no-name"},
            {"name": "no-value"}
        ]),
        local_storage: json!({}),
    };
    let mut gaps = Vec::new();
    let skipped = open_page(
        &mut session,
        &plain_conditions(),
        "http://x/",
        Some(&data),
        &mut gaps,
    )
    .unwrap();
    assert_eq!(skipped, 2);
    assert_eq!(session.log[1], "cookies 1");
    assert_eq!(gaps, vec!["cookies-skipped:2".to_string()]);
}

#[test]
fn when_every_cookie_is_skipped_no_set_call_is_made() {
    let mut session = FakeBrowserSession::default();
    let data = SessionData {
        cookies: json!([{"value": "no-name"}]),
        local_storage: json!({}),
    };
    let mut gaps = Vec::new();
    let skipped = open_page(
        &mut session,
        &plain_conditions(),
        "http://x/",
        Some(&data),
        &mut gaps,
    )
    .unwrap();
    assert_eq!(skipped, 1);
    assert_eq!(
        session.log,
        vec!["apply", "navigate http://x/", "load", "navigate http://x/"]
    );
    assert_eq!(gaps, vec!["cookies-skipped:1".to_string()]);
}

#[test]
fn page_without_session_navigates_once_and_reports_no_gaps() {
    let mut session = FakeBrowserSession::default();
    let mut gaps = Vec::new();
    open_page(
        &mut session,
        &plain_conditions(),
        "http://x/",
        None,
        &mut gaps,
    )
    .unwrap();
    assert_eq!(session.log, vec!["apply", "navigate http://x/"]);
    assert!(gaps.is_empty());
}

#[test]
fn no_gap_is_printed_when_every_cookie_applied() {
    assert!(session_gaps(0).is_empty());
    report_gaps(&session_gaps(0));
    assert_eq!(session_gaps(3), vec!["cookies-skipped:3".to_string()]);
}

#[test]
fn actions_file_parses_and_replays_against_a_fake_session() {
    let file = r##"[
        {"type": "waitFor", "selector": "#app"},
        {"type": "click", "selector": "#go"},
        {"type": "assertText", "selector": "#msg", "text": "Hello"},
        {"type": "screenshot", "out": "shot.png"}
    ]"##;
    let actions = parse_actions(file).unwrap();
    assert_eq!(actions.len(), 4);
    let mut session = FakeBrowserSession::default();
    let mut lines = Vec::new();
    for (i, action) in actions.iter().enumerate() {
        lines.push(run_action(&mut session, action, i).unwrap());
    }
    assert_eq!(lines[1], "[qa] 2:click ok");
    assert_eq!(
        lines[3],
        "[qa] screenshot /abs/shot.png\n[qa] 4:screenshot ok"
    );
    assert_eq!(session.log[0], "point #go");
    assert!(matches!(&actions[3], Action::Screenshot { out } if out == "shot.png"));
}

struct FakeSessionFs {
    files: HashMap<String, String>,
}
impl SessionFile for FakeSessionFs {
    fn read(&self, path: &str) -> Result<String, String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| "ENOENT".to_string())
    }
    fn write(&mut self, path: &str, contents: &str) -> Result<(), String> {
        self.files.insert(path.to_string(), contents.to_string());
        Ok(())
    }
}

#[test]
fn save_then_load_session_file_round_trips() {
    let mut fs = FakeSessionFs {
        files: HashMap::new(),
    };
    let data = SessionData {
        cookies: json!([{"name": "sid", "value": "abc"}]),
        local_storage: json!({"theme": "dark"}),
    };
    write_session_file(&mut fs, "session.json", &data).unwrap();
    let back = read_session_file(&fs, "session.json").unwrap();
    assert_eq!(back, data);
}

#[test]
fn saved_session_file_records_captured_cookies_and_loads_back_into_cookie_params() {
    let mut session = FakeBrowserSession::default();
    let mut fs = FakeSessionFs {
        files: HashMap::new(),
    };
    save_session_to_file(&mut session, &mut fs, "session.json").unwrap();

    let raw: Value = serde_json::from_str(fs.files.get("session.json").unwrap()).unwrap();
    assert_eq!(raw["cookiesCaptured"], json!(true));
    assert_eq!(raw["cookies"], json!([{"name": "sid", "value": "abc"}]));
    assert_eq!(raw["localStorage"], json!({"theme": "dark"}));

    let back = read_session_file(&fs, "session.json").unwrap();
    let (params, skipped) = cookie_params(&back.cookies);
    assert_eq!(skipped, 0);
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "sid");
    assert_eq!(params[0].value, "abc");
}
