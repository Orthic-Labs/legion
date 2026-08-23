use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PathError {
    #[error("path scope identity must be non-empty")]
    EmptyScope,
    #[error("path must be absolute")]
    NotAbsolute,
    #[error("path escapes its root")]
    EscapesRoot,
    #[error("path contains an empty or non-normal component")]
    InvalidComponent,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathScope {
    pub repository: String,
    pub worktree: String,
}

impl PathScope {
    pub fn validate(&self) -> Result<(), PathError> {
        if self.repository.trim().is_empty() || self.worktree.trim().is_empty() {
            return Err(PathError::EmptyScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOperation {
    Read,
    Write,
    Delete,
    Move,
    Execute,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SymlinkState {
    NotFollowed,
    Resolved { target: String },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPath {
    pub root_identity: String,
    pub scope: PathScope,
    pub normalized_absolute_path: String,
    pub normalized_relative_path: String,
    pub symlink: SymlinkState,
}

impl CanonicalPath {
    pub fn new(
        root_identity: impl Into<String>,
        scope: PathScope,
        absolute: &str,
        symlink: SymlinkState,
    ) -> Result<Self, PathError> {
        scope.validate()?;
        let root_identity = root_identity.into();
        if root_identity.trim().is_empty() {
            return Err(PathError::EmptyScope);
        }
        if !is_absolute(absolute) {
            return Err(PathError::NotAbsolute);
        }
        let normalized_absolute_path = normalize_absolute(absolute)?;
        let normalized_relative_path = normalized_absolute_path.trim_start_matches('/').to_owned();
        Ok(Self {
            root_identity,
            scope,
            normalized_absolute_path,
            normalized_relative_path,
            symlink,
        })
    }

    pub fn from_relative(
        root_identity: impl Into<String>,
        scope: PathScope,
        relative: &str,
        symlink: SymlinkState,
    ) -> Result<Self, PathError> {
        scope.validate()?;
        let root_identity = root_identity.into();
        if root_identity.trim().is_empty() {
            return Err(PathError::EmptyScope);
        }
        let normalized_relative_path = normalize_relative(relative)?;
        let normalized_absolute_path = format!("/{normalized_relative_path}");
        Ok(Self {
            root_identity,
            scope,
            normalized_absolute_path,
            normalized_relative_path,
            symlink,
        })
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.root_identity == other.root_identity
            && self.scope == other.scope
            && self.symlink == other.symlink
            && (self.normalized_absolute_path == other.normalized_absolute_path
                || other
                    .normalized_absolute_path
                    .starts_with(&(self.normalized_absolute_path.clone() + "/")))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathOwnership {
    pub path: CanonicalPath,
    pub operation: PathOperation,
    pub symlink_resolution: SymlinkState,
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || (path.len() >= 3
            && path.as_bytes()[1] == b':'
            && (path.as_bytes()[2] == b'/' || path.as_bytes()[2] == b'\\'))
}

fn normalize_absolute(path: &str) -> Result<String, PathError> {
    let mut parts = Vec::new();
    let normalized = path.replace('\\', "/");
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(PathError::EscapesRoot);
                }
            }
            value if value.chars().any(char::is_control) => {
                return Err(PathError::InvalidComponent)
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        return Err(PathError::InvalidComponent);
    }
    Ok(format!("/{}", parts.join("/")))
}

fn normalize_relative(path: &str) -> Result<String, PathError> {
    if is_absolute(path) {
        return Err(PathError::NotAbsolute);
    }
    let mut parts = Vec::new();
    let normalized = path.replace('\\', "/");
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(PathError::EscapesRoot),
            value if value.chars().any(char::is_control) => {
                return Err(PathError::InvalidComponent)
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        return Err(PathError::InvalidComponent);
    }
    Ok(parts.join("/"))
}
