use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use walkdir::WalkDir;

use crate::{
    catalog::{normalize_path, Catalog, CatalogEntry},
    error::CatalogError,
};

const ROOTS: &[&str] = &["skills", "agents", "lenses", "recipes", "roster"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryInput {
    pub root: PathBuf,
    pub relative_paths: Vec<PathBuf>,
}

pub fn discover(root: impl AsRef<Path>) -> Result<Catalog, CatalogError> {
    let root = root.as_ref();
    let mut paths = Vec::new();
    for directory in ROOTS {
        let path = root.join(directory);
        if !path.exists() {
            continue;
        }
        for item in WalkDir::new(&path).follow_links(false).into_iter() {
            let item = item.map_err(|error| CatalogError::Io {
                path: error
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.clone()),
                source: error
                    .into_io_error()
                    .unwrap_or_else(|| std::io::Error::other("walk failed")),
            })?;
            if item.file_type().is_file() && supported(item.path()) {
                paths.push(item.path().to_path_buf());
            }
        }
    }
    paths.sort_by_key(|path| {
        normalize_path(path.strip_prefix(root).unwrap_or(path))
            .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
    });
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = fs::read(&path).map_err(|source| CatalogError::Io {
            path: path.clone(),
            source,
        })?;
        let relative = path.strip_prefix(root).unwrap_or(&path);
        entries.push(CatalogEntry::from_bytes(relative, &bytes)?);
    }
    Catalog::new(entries)
}

pub fn discover_paths(
    root: impl AsRef<Path>,
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Catalog, CatalogError> {
    let root = root.as_ref();
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for path in paths {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let normalized = normalize_path(relative)?;
        if !seen.insert(normalized.clone()) {
            return Err(CatalogError::OwnershipCollision {
                identity: format!("source path `{normalized}`"),
            });
        }
        let bytes = fs::read(root.join(&normalized)).map_err(|source| CatalogError::Io {
            path: root.join(&normalized),
            source,
        })?;
        entries.push(CatalogEntry::from_bytes(normalized, &bytes)?);
    }
    Catalog::new(entries)
}

fn supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("md" | "markdown" | "yaml" | "yml" | "json")
    )
}
