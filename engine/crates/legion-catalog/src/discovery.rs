use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use walkdir::WalkDir;

use crate::{
    catalog::{
        normalize_path, Catalog, CatalogEntry, CompactCatalog, CompactCatalogDocument,
        CompactCatalogEntry,
    },
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

/// Read the generated compact catalog index without opening any capability body.
pub fn load_compact(
    root: impl AsRef<Path>,
    index_path: impl AsRef<Path>,
) -> Result<CompactCatalog, CatalogError> {
    let root = root.as_ref();
    let index_path = index_path.as_ref();
    let index_relative = normalize_path(index_path)?;
    let index = root.join(&index_relative);
    let bytes = fs::read(&index).map_err(|source| CatalogError::Io {
        path: index.clone(),
        source,
    })?;
    let document: CompactCatalogDocument = serde_json::from_slice(&bytes)?;
    let entries = document
        .bundles
        .into_iter()
        .map(|entry| {
            let source_path = normalize_path(Path::new(&entry.source))?;
            let manifest_path = entry
                .manifest
                .map(|path| normalize_path(Path::new(&path)))
                .transpose()?;
            Ok(CompactCatalogEntry {
                canonical_id: entry.id,
                source_path,
                manifest_path,
                name: entry.name,
                description: entry.description,
                kind: entry.kind,
                discoverability: entry.discoverability,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()?;
    CompactCatalog::new(root.to_path_buf(), document.schema_version, entries)
}

fn supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("md" | "markdown" | "yaml" | "yml" | "json")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-compact-catalog-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("registry")).expect("registry");
        root
    }

    #[test]
    fn compact_load_does_not_read_bodies_and_resolves_one_lazily() {
        let root = temp_root();
        fs::write(
            root.join("registry/index.json"),
            r#"{"schemaVersion":2,"bundles":[{"id":"visible","source":"skills/visible/SKILL.md","description":"metadata"},{"id":"missing","source":"skills/missing/SKILL.md"}]}"#,
        ).expect("index");
        fs::create_dir_all(root.join("skills/visible")).expect("visible directory");
        fs::write(root.join("skills/visible/SKILL.md"), "visible body").expect("visible body");

        let catalog = load_compact(&root, "registry/index.json").expect("metadata only");
        assert_eq!(catalog.entries.len(), 2);
        assert_eq!(
            catalog
                .get("visible")
                .and_then(|entry| entry.description.as_deref()),
            Some("metadata")
        );
        assert_eq!(
            catalog.resolve_body("visible").expect("lazy body"),
            b"visible body"
        );
        assert!(matches!(
            catalog.resolve_body("missing"),
            Err(CatalogError::Io { .. })
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
