//! Integration tests for wf_port packet r03's tts-doubao.mjs port
//! (`legion_runtime::wf_port::r03::tts_doubao`). See that module's doc
//! comment for the full mapping back to the legacy script.
//!
//! This file depends on `legion_runtime::wf_port::r03`, which is not yet
//! wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod r03;` in `src/wf_port/mod.rs`; `pub mod wf_port;` is already
//! present in `src/lib.rs`). Until that wiring lands, this file will not
//! compile as part of the crate's test target — the same not-yet-wired
//! state already left by the `r00`/`r07`/`r09`/`r15`/`r18` packets in this
//! crate (see `src/wf_port/r00/mod.rs`).
//!
//! No test here touches the network or spawns `ffprobe`: [`FakeHttp`] and
//! [`FakeDuration`] stand in for [`HttpPost`]/[`DurationProbe`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r03::tts_doubao::{
    apply_dotenv, build_body, decode_base64, parse_args, parse_dotenv, parse_tts_response,
    resolve_request, run, DurationProbe, FileIo, HttpPost, ResolvedRequest, TtsError,
};
use serde_json::Value;

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_args_matches_legacy_defaults_and_flags() {
    let a = parse_args(&[]);
    assert_eq!(a.speed, "1.0");
    assert_eq!(a.encoding, "mp3");

    let a = parse_args(&args(&["--text", "hi", "--out", "o.mp3", "--voice", "v1"]));
    assert_eq!(a.text.as_deref(), Some("hi"));
    assert_eq!(a.out.as_deref(), Some("o.mp3"));
    assert_eq!(a.voice.as_deref(), Some("v1"));
}

#[test]
fn dotenv_parsing_and_precedence() {
    let pairs = parse_dotenv("A=1\n# comment\nB=\"two\"\n");
    let mut env = HashMap::new();
    env.insert("A".to_string(), "preset".to_string());
    apply_dotenv(&mut env, &pairs);
    assert_eq!(env.get("A").unwrap(), "preset", "existing env wins over .env");
    assert_eq!(env.get("B").unwrap(), "two");
}

#[test]
fn resolve_request_requires_api_key_and_voice_id() {
    let a = parse_args(&[]);
    assert_eq!(
        resolve_request(&a, &HashMap::new(), "hi", "r".into()).unwrap_err(),
        TtsError::MissingApiKey
    );
}

#[test]
fn build_body_and_response_round_trip() {
    let req = ResolvedRequest {
        endpoint: "https://x".into(),
        api_key: "k".into(),
        cluster: "volcano_icl".into(),
        voice_id: "voice-1".into(),
        encoding: "mp3".into(),
        speed: 1.0,
        reqid: "req-1".into(),
        text: "你好".into(),
    };
    let body = build_body(&req);
    assert_eq!(body["audio"]["speed_ratio"], 1.0);

    let audio = parse_tts_response(r#"{"code":3000,"data":"aGk="}"#).unwrap();
    assert_eq!(audio, b"hi");
    assert_eq!(decode_base64("aGk=").unwrap(), b"hi");
}

struct FakeIo {
    files: HashMap<PathBuf, String>,
    dotenv: Option<String>,
    writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
}
impl FileIo for FakeIo {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
    }
    fn read_dotenv(&self, _skill_root: &Path) -> Option<String> {
        self.dotenv.clone()
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes.borrow_mut().insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

struct FakeHttp {
    status: u16,
    body: String,
}
impl HttpPost for FakeHttp {
    fn post_json(&self, _url: &str, _key: &str, _body: &Value) -> Result<(u16, String), String> {
        Ok((self.status, self.body.clone()))
    }
}

struct FakeDuration(Option<f64>);
impl DurationProbe for FakeDuration {
    fn duration_seconds(&self, _path: &Path) -> Option<f64> {
        self.0
    }
}

#[test]
fn run_end_to_end_success_writes_file_and_prints_json_line() {
    let io = FakeIo {
        files: HashMap::new(),
        dotenv: Some("DOUBAO_TTS_API_KEY=k\nDOUBAO_TTS_VOICE_ID=v\n".to_string()),
        writes: RefCell::new(HashMap::new()),
    };
    let http = FakeHttp {
        status: 200,
        body: r#"{"code":3000,"data":"aGk="}"#.to_string(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        &args(&["--text", "hi", "--out", "out.mp3"]),
        Path::new("/skill"),
        &HashMap::new(),
        "req-1".to_string(),
        &io,
        &http,
        &FakeDuration(Some(2.0)),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&stderr));
    assert!(io.writes.borrow().contains_key(&PathBuf::from("out.mp3")));
    let stdout_text = String::from_utf8(stdout).unwrap();
    let json: Value = serde_json::from_str(stdout_text.trim()).unwrap();
    assert_eq!(json["bytes"], 2);
    assert_eq!(json["duration"], 2.0);
}

#[test]
fn run_missing_env_reports_tts_failure() {
    let io = FakeIo {
        files: HashMap::new(),
        dotenv: None,
        writes: RefCell::new(HashMap::new()),
    };
    let http = FakeHttp {
        status: 200,
        body: "{}".to_string(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        &args(&["--text", "hi", "--out", "out.mp3"]),
        Path::new("/skill"),
        &HashMap::new(),
        "req".to_string(),
        &io,
        &http,
        &FakeDuration(None),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 1);
    assert!(String::from_utf8(stderr).unwrap().contains("TTS 失败："));
}
