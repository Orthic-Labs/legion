use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct MinimizeError(pub String);

impl MinimizeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
