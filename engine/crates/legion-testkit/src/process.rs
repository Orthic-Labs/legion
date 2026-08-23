use std::collections::BTreeMap;

use legion_contracts::canonical_digest_hex;
use serde_json::json;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRequest {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
}

impl ProcessRequest {
    pub fn new(executable: impl Into<String>, args: Vec<String>, cwd: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            args,
            cwd: cwd.into(),
        }
    }
    pub fn digest(&self) -> String {
        canonical_digest_hex(
            &json!({"args": self.args, "cwd": self.cwd, "executable": self.executable}),
        )
        .expect("JSON process request is canonicalizable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessEvent {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ProcessEvent {
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessError {
    Unscripted(String),
}
impl std::fmt::Display for ProcessError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unscripted(digest) => write!(output, "unscripted process request: {digest}"),
        }
    }
}
impl std::error::Error for ProcessError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeProcess {
    events: BTreeMap<String, ProcessEvent>,
}

impl FakeProcess {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn script(&mut self, digest: impl Into<String>, event: ProcessEvent) {
        self.events.insert(digest.into(), event);
    }
    pub fn script_request(&mut self, request: &ProcessRequest, event: ProcessEvent) {
        self.script(request.digest(), event);
    }
    pub fn run(&self, request: &ProcessRequest) -> Result<ProcessEvent, ProcessError> {
        self.events
            .get(&request.digest())
            .cloned()
            .ok_or_else(|| ProcessError::Unscripted(request.digest()))
    }
}
