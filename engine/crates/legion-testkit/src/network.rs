use std::collections::BTreeMap;

use legion_contracts::canonical_digest_hex;
use serde_json::{json, Value};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRequest {
    pub method: String,
    pub url: String,
    pub body: Value,
}

impl NetworkRequest {
    pub fn new(method: impl Into<String>, url: impl Into<String>, body: Value) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            body,
        }
    }
    pub fn digest(&self) -> String {
        canonical_digest_hex(&json!({"body": self.body, "method": self.method, "url": self.url}))
            .expect("JSON request is canonicalizable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkResponse {
    pub status: u16,
    pub body: Value,
    pub headers: BTreeMap<String, String>,
}

impl NetworkResponse {
    pub fn new(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkError {
    Unscripted(String),
}
impl std::fmt::Display for NetworkError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unscripted(digest) => write!(output, "unscripted network request: {digest}"),
        }
    }
}
impl std::error::Error for NetworkError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeNetwork {
    responses: BTreeMap<String, NetworkResponse>,
}

impl FakeNetwork {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn script(&mut self, digest: impl Into<String>, response: NetworkResponse) {
        self.responses.insert(digest.into(), response);
    }
    pub fn script_request(&mut self, request: &NetworkRequest, response: NetworkResponse) {
        self.script(request.digest(), response);
    }
    pub fn request(&self, request: &NetworkRequest) -> Result<NetworkResponse, NetworkError> {
        self.responses
            .get(&request.digest())
            .cloned()
            .ok_or_else(|| NetworkError::Unscripted(request.digest()))
    }
}
