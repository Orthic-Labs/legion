use std::fmt;

/// Public MCP errors intentionally contain no paths, credentials, or backend details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpError {
    Parse,
    InvalidRequest,
    InvalidParams,
    MethodNotFound,
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
            Self::ToolNotFound | Self::ScopeDenied | Self::Backend | Self::OutputLimit => -32603,
        }
    }

    pub const fn message(&self) -> &'static str {
        match self {
            Self::Parse => "parse error",
            Self::InvalidRequest => "invalid request",
            Self::InvalidParams => "invalid params",
            Self::MethodNotFound => "method not found",
            Self::ToolNotFound => "unknown tool",
            Self::ScopeDenied => "explicit scope required",
            Self::Backend => "native backend failure",
            Self::OutputLimit => "tool output exceeds configured limit",
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
