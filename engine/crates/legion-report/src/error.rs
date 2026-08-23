use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ReportError {
    Contract(String),
    Serialization(String),
    InvalidUtf8,
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "invalid report: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "report serialization failed: {message}")
            }
            Self::InvalidUtf8 => formatter.write_str("canonical JSON was not valid UTF-8"),
        }
    }
}

impl Error for ReportError {}

impl From<serde_json::Error> for ReportError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

pub(crate) fn validate(report: &legion_contracts::ReportV1) -> Result<(), ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))
}
