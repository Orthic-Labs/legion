use std::fmt;

/// Public MCP errors intentionally contain no paths, credentials, or backend details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpError {
    Parse,
    InvalidRequest,
    InvalidParams,
    MethodNotFound,
    InitializationRequired,
    ReleaseBinding(String),
    ToolNotFound,
    ScopeDenied,
    Backend,
    OutputLimit,
}

impl McpError {
    pub const fn code(&self) -> i64 {
        match self {
            Self::Parse => -32700,
            Self::InvalidRequest => -32600,
            Self::InvalidParams => -32602,
            Self::MethodNotFound => -32601,
            Self::InitializationRequired | Self::ReleaseBinding(_) => -32000,
            Self::ToolNotFound | Self::ScopeDenied | Self::Backend | Self::OutputLimit => -32603,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Parse => "parse error",
            Self::InvalidRequest => "invalid request",
            Self::InvalidParams => "invalid params",
            Self::MethodNotFound => "method not found",
            Self::InitializationRequired => "MCP initialization required",
            Self::ReleaseBinding(repair) => repair,
            Self::ToolNotFound => "unknown tool",
            Self::ScopeDenied => "explicit scope required",
            Self::Backend => "native backend failure",
            Self::OutputLimit => "tool output exceeds configured limit",
        }
    }

    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::Parse => "PARSE_ERROR",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InvalidParams => "INVALID_PARAMS",
            Self::MethodNotFound => "METHOD_NOT_FOUND",
            Self::InitializationRequired => "INITIALIZATION_REQUIRED",
            Self::ReleaseBinding(_) => "RELEASE_BINDING",
            Self::ToolNotFound => "TOOL_NOT_FOUND",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::Backend => "BACKEND_UNAVAILABLE",
            Self::OutputLimit => "OUTPUT_LIMIT",
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(self, Self::Backend | Self::ReleaseBinding(_))
    }

    pub fn remediation(&self) -> &str {
        match self {
            Self::ReleaseBinding(repair) => repair,
            Self::Parse => "send valid JSON",
            Self::InvalidRequest => "send a valid JSON-RPC 2.0 request",
            Self::InvalidParams => "provide arguments matching the advertised tool schema",
            Self::MethodNotFound => "use initialize, tools/list, or tools/call",
            Self::InitializationRequired => "call initialize before using MCP tools",
            Self::ToolNotFound => "use a tool advertised by tools/list",
            Self::ScopeDenied => "provide valid arguments for the selected tool",
            Self::Backend => "retry the request after checking native application health",
            Self::OutputLimit => "reduce the requested output below one megabyte",
        }
    }

    pub fn data(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.public_code(),
            "retryable": self.retryable(),
            "remediation": self.remediation(),
        })
    }

    pub const fn tool_message(&self) -> &'static str {
        match self {
            Self::Parse => "tool request could not be parsed",
            Self::InvalidRequest => "tool request was invalid",
            Self::InvalidParams => "tool arguments were invalid",
            Self::MethodNotFound => "MCP method was not found",
            Self::InitializationRequired => "MCP initialization is required",
            Self::ReleaseBinding(_) => "release binding failed",
            Self::ToolNotFound => "tool was not found",
            Self::ScopeDenied => "tool scope was denied",
            Self::Backend => "native backend failed",
            Self::OutputLimit => "tool output exceeded the configured limit",
        }
    }
}

impl fmt::Display for McpError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.message())
    }
}

impl std::error::Error for McpError {}

impl From<legion_runtime::RuntimeError> for McpError {
    fn from(_: legion_runtime::RuntimeError) -> Self {
        Self::Backend
    }
}
