use serde::{Deserialize, Serialize};

use legion_contracts::{EffectClass, EffectRequest};

use crate::error::AuditError;

pub trait WorktreeEffect: Send + Sync {
    fn request(&self, request: &EffectRequest) -> Result<String, AuditError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorktreeReceipt {
    pub operation: String,
    pub path: String,
    pub request_id: String,
    pub complete: bool,
    pub cleanup: bool,
    pub gap: Option<String>,
}

pub fn create(
    effect: &dyn WorktreeEffect,
    request: EffectRequest,
) -> Result<WorktreeReceipt, AuditError> {
    if request.effect_class != EffectClass::FILE_WRITE {
        return Err(AuditError::Invalid(
            "worktree creation requires FILE_WRITE effect".into(),
        ));
    }
    let path = request.target.clone();
    let request_id = request.request_id.to_string();
    let result = effect.request(&request)?;
    Ok(WorktreeReceipt {
        operation: "create".into(),
        path,
        request_id,
        complete: true,
        cleanup: false,
        gap: if result.is_empty() {
            Some("effect-result-empty".into())
        } else {
            None
        },
    })
}

pub fn cleanup(
    effect: &dyn WorktreeEffect,
    request: EffectRequest,
    path: impl Into<String>,
) -> Result<WorktreeReceipt, AuditError> {
    if request.effect_class != EffectClass::FILE_DELETE {
        return Err(AuditError::Invalid(
            "worktree cleanup requires FILE_DELETE effect".into(),
        ));
    }
    let request_id = request.request_id.to_string();
    let path = path.into();
    match effect.request(&request) {
        Ok(_) => Ok(WorktreeReceipt {
            operation: "cleanup".into(),
            path,
            request_id,
            complete: true,
            cleanup: true,
            gap: None,
        }),
        Err(error) => Ok(WorktreeReceipt {
            operation: "cleanup".into(),
            path,
            request_id,
            complete: false,
            cleanup: true,
            gap: Some(error.to_string()),
        }),
    }
}
