use std::fmt;

#[derive(Debug)]
pub enum HookError {
    InvalidRequest(String),
    MalformedInput(String),
    UnsupportedVersion(u32),
    Io(String),
    Serialization(String),
}

impl HookError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }
    pub fn malformed(error: impl fmt::Display) -> Self {
        Self::MalformedInput(error.to_string())
    }
    pub fn unsupported_version(version: u32) -> Self {
        Self::UnsupportedVersion(version)
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::MalformedInput(_) => "malformed_input",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::Io(_) => "io_error",
            Self::Serialization(_) => "serialization_error",
        }
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::MalformedInput(_) | Self::UnsupportedVersion(_) => {
                "invalid hook request"
            }
            Self::Io(_) => "hook transport unavailable",
            Self::Serialization(_) => "hook response unavailable",
        }
    }
}

impl fmt::Display for HookError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(value) => write!(out, "invalid request: {value}"),
            Self::MalformedInput(value) => write!(out, "malformed input: {value}"),
            Self::UnsupportedVersion(value) => write!(out, "unsupported schema version: {value}"),
            Self::Io(value) => write!(out, "I/O error: {value}"),
            Self::Serialization(value) => write!(out, "serialization error: {value}"),
        }
    }
}

impl std::error::Error for HookError {}
