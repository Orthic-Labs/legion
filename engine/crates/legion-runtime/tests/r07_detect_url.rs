//! Integration tests for the r07 port of
//! `skills/designer/engine/scripts/detector/engines/browser/detect-url-cdp.mjs`
//! and `.../detect-url.mjs`.
//!
//! NOTE: requires the integrator to wire `pub mod r07;` into
//! `legion-runtime::wf_port` (see `engine/crates/legion-runtime/src/wf_port/mod.rs`)
//! before this file will compile/run — left unwired per this packet's
//! instructions (do not edit `wf_port/mod.rs`).
//!
//! No test here launches a real browser or touches the network: `ChromeDriver`
//! is faked, matching the packet rule that browser/CDP I/O stays behind a
//! trait in tests.

use std::collections::HashMap;

use serde_json::{json, Value};

use legion_runtime::wf_port::r07::browser::{
    find_browser_executable, ChromeDriver, EnvLookup, FsLookup, Platform,
};
use legion_runtime::wf_port::r07::detect_url::{
    detect_url, detect_url_cdp, serialize_design_system_for_browser, DesignSystemInput,
    DetectUrlOptions, Rgb,
};
use legion_runtime::wf_port::r07::findings::{AntipatternLookup, AntipatternRule};

struct FakeEnv(HashMap<String, String>);
impl EnvLookup for FakeEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

struct FakeFs(Vec<String>);
impl FsLookup for FakeFs {
    fn exists(&self, path: &str) -> bool {
        self.0.iter().any(|p| p == path)
    }
}

#[test]
fn find_browser_executable_prefers_chrome_path_override() {
    let env = FakeEnv(HashMap::from([(
        "CHROME_PATH".to_string(),
        "/opt/my-chrome".to_string(),
    )]));
    let fs = FakeFs(vec!["/opt/my-chrome".to_string()]);
    let found = find_browser_executable(Platform::Other, &env, &fs).unwrap();
    assert_eq!(found.to_str().unwrap(), "/opt/my-chrome");
}

#[test]
fn find_browser_executable_override_missing_is_error() {
    let env = FakeEnv(HashMap::from([(
        "QA_BROWSER".to_string(),
        "/nowhere".to_string(),
    )]));
    let fs = FakeFs(vec![]);
    let err = find_browser_executable(Platform::Other, &env, &fs).unwrap_err();
    assert!(err.contains("CHROME_PATH/QA_BROWSER set but not found"));
}

#[test]
fn find_browser_executable_falls_back_to_candidate_list() {
    let env = FakeEnv(HashMap::new());
    let fs = FakeFs(vec!["/usr/bin/chromium".to_string()]);
    let found = find_browser_executable(Platform::Other, &env, &fs).unwrap();
    assert_eq!(found.to_str().unwrap(), "/usr/bin/chromium");
}

#[test]
fn find_browser_executable_windows_candidates() {
    let env = FakeEnv(HashMap::new());
    let fs = FakeFs(vec![
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe".to_string(),
    ]);
    let found = find_browser_executable(Platform::Windows, &env, &fs).unwrap();
    assert_eq!(
        found.to_str().unwrap(),
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    );
}

#[test]
fn find_browser_executable_none_found_is_error() {
    let env = FakeEnv(HashMap::new());
    let fs = FakeFs(vec![]);
    let err = find_browser_executable(Platform::Other, &env, &fs).unwrap_err();
    assert_eq!(
        err,
        "URL scanning needs puppeteer or an installed Chrome/Edge. Neither was found."
    );
}

struct FakeDriver {
    navigated: Vec<String>,
    responses: Vec<Value>,
}
impl ChromeDriver for FakeDriver {
    fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.navigated.push(url.to_string());
        Ok(())
    }
    fn evaluate(&mut self, _expression: &str) -> Result<Value, String> {
        Ok(self.responses.remove(0))
    }
}

struct FakeRegistry(HashMap<String, AntipatternRule>);
impl AntipatternLookup for FakeRegistry {
    fn get(&self, id: &str) -> Option<AntipatternRule> {
        self.0.get(id).cloned()
    }
    fn has_gated_providers(&self) -> bool {
        false
    }
}

fn registry() -> FakeRegistry {
    let mut m = HashMap::new();
    m.insert(
        "low-contrast".to_string(),
        AntipatternRule {
            name: "Low contrast".to_string(),
            description: "d".to_string(),
            severity: "warning".to_string(),
            gated: None,
        },
    );
    FakeRegistry(m)
}

#[test]
fn detect_url_cdp_end_to_end_with_design_system() {
    let mut driver = FakeDriver {
        navigated: vec![],
        responses: vec![
            Value::Null,
            Value::Null,
            json!([{ "findings": [{ "type": "low-contrast", "detail": "snip", "ignoreValue": "#fff" }] }]),
        ],
    };
    let reg = registry();
    let mut opts = DetectUrlOptions::default();
    opts.design_system = Some(DesignSystemInput {
        present: true,
        has_colors: true,
        allowed_color_keys: vec![Rgb { r: 1.0, g: 2.0, b: 3.0 }],
        ..Default::default()
    });
    let out = detect_url_cdp(&mut driver, &reg, "https://example.test", "/*script*/", &opts).unwrap();
    assert_eq!(driver.navigated, vec!["https://example.test".to_string()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ignore_value.as_deref(), Some("#fff"));
}

#[test]
fn serialize_design_system_none_when_not_present() {
    assert_eq!(serialize_design_system_for_browser(None), None);
}

#[test]
fn detect_url_without_visual_contrast_matches_cdp_only_path() {
    let mut driver_a = FakeDriver {
        navigated: vec![],
        responses: vec![Value::Null, Value::Null, json!([])],
    };
    let mut driver_b = FakeDriver {
        navigated: vec![],
        responses: vec![Value::Null, Value::Null, json!([])],
    };
    let reg = registry();
    let opts = DetectUrlOptions::default();
    let a = detect_url_cdp(&mut driver_a, &reg, "https://x", "/*s*/", &opts).unwrap();
    let b = detect_url(&mut driver_b, &reg, "https://x", "/*s*/", &opts, |_| Ok(vec![])).unwrap();
    assert_eq!(a, b);
}
