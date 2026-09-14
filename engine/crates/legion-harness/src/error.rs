use thiserror::Error;

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("{message}")]
    Conflict { message: String },
    #[error("{message}")]
    DescriptorInvalid { message: String },
    #[error("{message}")]
    Usage { message: String },
    #[error("{message}")]
    Internal { message: String },
}

impl HarnessError {
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    pub fn descriptor_invalid(message: impl Into<String>) -> Self {
        Self::DescriptorInvalid {
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}
