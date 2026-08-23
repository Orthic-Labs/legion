use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkKind {
    Symlink(String),
    Junction(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsError {
    InvalidPath(String),
    MissingPath(String),
    NotAFile(String),
    LinkCycle(String),
}

impl std::fmt::Display for FsError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(output, "invalid logical path: {path}"),
            Self::MissingPath(path) => write!(output, "missing logical path: {path}"),
            Self::NotAFile(path) => write!(output, "not a file: {path}"),
            Self::LinkCycle(path) => write!(output, "link cycle at: {path}"),
        }
    }
}
impl std::error::Error for FsError {}

pub fn normalize_path(path: &str) -> Result<String, FsError> {
    let path = path.replace('\\', "/");
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(FsError::InvalidPath(path));
                }
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        Err(FsError::InvalidPath(path))
    } else {
        Ok(parts.join("/"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeFilesystem {
    files: BTreeMap<String, Vec<u8>>,
    links: BTreeMap<String, LinkKind>,
}

impl FakeFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: &str, contents: impl Into<Vec<u8>>) -> Result<(), FsError> {
        let path = normalize_path(path)?;
        self.files.insert(path.clone(), contents.into());
        self.links.remove(&path);
        Ok(())
    }

    pub fn add_symlink(&mut self, path: &str, target: &str) -> Result<(), FsError> {
        self.add_link(path, LinkKind::Symlink(target.into()))
    }

    pub fn add_junction(&mut self, path: &str, target: &str) -> Result<(), FsError> {
        self.add_link(path, LinkKind::Junction(target.into()))
    }

    fn add_link(&mut self, path: &str, link: LinkKind) -> Result<(), FsError> {
        let path = normalize_path(path)?;
        let target = match &link {
            LinkKind::Symlink(target) | LinkKind::Junction(target) => normalize_path(target)?,
        };
        let link = match link {
            LinkKind::Symlink(_) => LinkKind::Symlink(target),
            LinkKind::Junction(_) => LinkKind::Junction(target),
        };
        self.links.insert(path.clone(), link);
        self.files.remove(&path);
        Ok(())
    }

    pub fn read(&self, path: &str) -> Result<&[u8], FsError> {
        let path = self.resolve(path)?;
        self.files
            .get(&path)
            .map(Vec::as_slice)
            .ok_or(FsError::NotAFile(path))
    }

    pub fn link(&self, path: &str) -> Result<&LinkKind, FsError> {
        let path = normalize_path(path)?;
        self.links.get(&path).ok_or(FsError::MissingPath(path))
    }

    pub fn contains(&self, path: &str) -> bool {
        self.resolve(path).is_ok()
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    fn resolve(&self, path: &str) -> Result<String, FsError> {
        let mut current = normalize_path(path)?;
        let mut seen = Vec::new();
        while let Some(link) = self.links.get(&current) {
            if seen.contains(&current) {
                return Err(FsError::LinkCycle(current));
            }
            seen.push(current.clone());
            current = match link {
                LinkKind::Symlink(target) | LinkKind::Junction(target) => target.clone(),
            };
        }
        if self.files.contains_key(&current) {
            Ok(current)
        } else {
            Err(FsError::MissingPath(current))
        }
    }
}
