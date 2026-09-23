//! Port of `src/lib/core/repository-binding.mjs` — see the chunk-level doc
//! comment in [`super`] for the full disposition note.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::l3_inventory::binding::digest as binding_digest;

/// Mirrors JS `FALLBACK_DIRECTORY_EXCLUSIONS`: directory *names* (not
/// paths) skipped by the manual walk used when a repository is not
/// Git-backed.
fn fallback_directory_exclusions() -> BTreeSet<&'static str> {
    [".agent", ".audit", ".git", ".legion", "dist", "node_modules"]
        .into_iter()
        .collect()
}

/// Mirrors JS `FALLBACK_PATH_EXCLUSIONS`: root-relative paths (forward
/// slash separated) skipped by the manual walk.
fn fallback_path_exclusions() -> BTreeSet<&'static str> {
    [
        "engine/target",
        "src/lib/review/cache",
        "src/lib/review/shadow_log",
        "src/lib/research-core/runs",
    ]
    .into_iter()
    .collect()
}

fn normalize_name(name: &str) -> String {
    name.replace('\\', "/")
}

/// Port of `parseGitFileList`: dedupes, normalizes separators, and sorts.
fn parse_git_file_list(output: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    let names: BTreeSet<String> = text
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(normalize_name)
        .collect();
    // BTreeSet already yields sorted, de-duplicated order.
    names.into_iter().collect::<Vec<_>>()
}

/// Port of `gitFiles(root)`. Returns `None` when the directory is not a Git
/// work tree (mirrors JS returning `null` from `isGitUnavailable`), matching
/// `git ls-files --cached --others --exclude-standard -z -- .`.
fn git_files(root: &Path) -> io::Result<Option<Vec<String>>> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            ".",
        ])
        .current_dir(root)
        .output();

    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a git repository") || stderr.contains("outside of a git work tree")
        {
            return Ok(None);
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("git ls-files failed: {stderr}"),
        ));
    }

    Ok(Some(parse_git_file_list(&output.stdout)))
}

fn fallback_path(root: &Path, current: &Path, name: &str) -> String {
    let absolute = current.join(name);
    let relative = absolute.strip_prefix(root).unwrap_or(&absolute);
    normalize_name(&relative.to_string_lossy())
}

/// Port of `files(root, current, output)`: the manual recursive walk used
/// when the repository is not Git-backed.
fn walk_files(root: &Path, current: &Path, output: &mut Vec<String>) -> io::Result<()> {
    let directory_exclusions = fallback_directory_exclusions();
    let path_exclusions = fallback_path_exclusions();

    let mut entries: Vec<_> = fs::read_dir(current)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        let path_name = fallback_path(root, current, &name);
        let file_type = entry.file_type()?;
        let path = current.join(&name);

        if file_type.is_dir() {
            if directory_exclusions.contains(name.as_str()) || path_exclusions.contains(path_name.as_str()) {
                continue;
            }
            walk_files(root, &path, output)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            output.push(normalize_name(&relative.to_string_lossy()));
        }
    }
    Ok(())
}

/// Port of `hashRepositoryEntry`. `git_backed` controls whether a
/// disappeared entry is tolerated as `missing\0` (matching JS's
/// `gitBacked && error?.code === 'ENOENT'` guard) or propagated as an error.
fn hash_repository_entry(
    hash: &mut Sha256,
    absolute_root: &Path,
    name: &str,
    git_backed: bool,
) -> io::Result<()> {
    let path = absolute_root.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if git_backed && error.kind() == io::ErrorKind::NotFound => {
            hash.update(b"missing\0");
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        hash.update(b"symlink\0");
        let target = fs::read_link(&path)?;
        hash.update(target.to_string_lossy().as_bytes());
        return Ok(());
    }
    if !file_type.is_file() {
        let kind = if file_type.is_dir() { "directory" } else { "other" };
        hash.update(format!("non-file:{kind}\0").as_bytes());
        return Ok(());
    }

    match fs::read(&path) {
        Ok(contents) => {
            hash.update(&contents);
            Ok(())
        }
        Err(error) if git_backed && error.kind() == io::ErrorKind::NotFound => {
            hash.update(b"missing\0");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Options accepted by [`bind_repository`], mirroring the JS destructured
/// options object of `bindRepository(root, options)`.
#[derive(Debug, Clone, Default)]
pub struct BindOptions {
    pub revision: Option<String>,
    /// Defaults to `revision` when omitted, matching JS's
    /// `sourceRevision = revision` default.
    pub source_revision: Option<String>,
    pub blueprint_digest: Option<Value>,
    pub skill_registry_digest: Option<Value>,
    pub family_registry_digest: Option<Value>,
    pub provider_registry_digest: Option<Value>,
    pub config_digest: Option<Value>,
}

/// Port of the `bindRepository` return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryBinding {
    pub schema_version: u32,
    pub root: PathBuf,
    pub repository_revision: Option<String>,
    pub source_revision: Option<String>,
    pub dirty_overlay_digest: String,
    pub file_count: usize,
    pub blueprint_digest: Value,
    pub skill_registry_digest: Value,
    pub family_registry_digest: Value,
    pub provider_registry_digest: Value,
    pub config_digest: Value,
    pub digest: String,
}

impl RepositoryBinding {
    /// The JSON shape `bindRepository` returns, useful for callers that
    /// need to feed this into another `digest()`/`sameBinding()` call the
    /// way `run-manifest.mjs`/`verify-run.mjs` do.
    pub fn to_value(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "root": self.root.to_string_lossy(),
            "repositoryRevision": self.repository_revision,
            "sourceRevision": self.source_revision,
            "dirtyOverlayDigest": self.dirty_overlay_digest,
            "fileCount": self.file_count,
            "blueprintDigest": self.blueprint_digest,
            "skillRegistryDigest": self.skill_registry_digest,
            "familyRegistryDigest": self.family_registry_digest,
            "providerRegistryDigest": self.provider_registry_digest,
            "configDigest": self.config_digest,
            "digest": self.digest,
        })
    }
}

/// Lexically absolutizes `path` against the current working directory,
/// mirroring Node's `path.resolve()` (no symlink dereferencing), rather
/// than `fs::canonicalize`, which would also resolve symlinks and require
/// the path to exist.
fn absolutize(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Port of `bindRepository(root, options)`.
pub fn bind_repository(root: &Path, options: BindOptions) -> io::Result<RepositoryBinding> {
    let absolute_root = absolutize(root)?;
    let git_names = git_files(&absolute_root)?;
    let git_backed = git_names.is_some();
    let mut names = match git_names {
        Some(names) => names,
        None => {
            let mut collected = Vec::new();
            walk_files(&absolute_root, &absolute_root, &mut collected)?;
            collected
        }
    };
    names.sort();

    let mut hash = Sha256::new();
    for name in &names {
        hash.update(format!("{name}\0").as_bytes());
        hash_repository_entry(&mut hash, &absolute_root, name, git_backed)?;
    }
    let dirty_overlay_digest = format!("sha256:{}", hex::encode(hash.finalize()));

    let revision = options.revision.clone();
    let source_revision = options.source_revision.or_else(|| options.revision.clone());
    let blueprint_digest = options.blueprint_digest.unwrap_or(Value::Null);
    let skill_registry_digest = options.skill_registry_digest.unwrap_or(Value::Null);
    let family_registry_digest = options.family_registry_digest.unwrap_or(Value::Null);
    let provider_registry_digest = options.provider_registry_digest.unwrap_or(Value::Null);
    let config_digest = options.config_digest.unwrap_or(Value::Null);

    let digest_input = json!({
        "revision": revision.clone(),
        "sourceRevision": source_revision.clone(),
        "dirtyOverlayDigest": dirty_overlay_digest.clone(),
        "names": names.clone(),
        "authorities": {
            "blueprintDigest": blueprint_digest.clone(),
            "skillRegistryDigest": skill_registry_digest.clone(),
            "familyRegistryDigest": family_registry_digest.clone(),
            "providerRegistryDigest": provider_registry_digest.clone(),
            "configDigest": config_digest.clone(),
        },
    });
    let digest = binding_digest(&digest_input);

    Ok(RepositoryBinding {
        schema_version: 1,
        root: absolute_root,
        repository_revision: revision,
        source_revision,
        dirty_overlay_digest,
        file_count: names.len(),
        blueprint_digest,
        skill_registry_digest,
        family_registry_digest,
        provider_registry_digest,
        config_digest,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn run(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    }

    fn tempdir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let unique = format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        dir.push(unique);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn git_repository_binding_tracks_tracked_and_ordinary_untracked_source_while_honoring_nested_ignores() {
        let root = tempdir("legion-repository-binding-git");
        run(&root, &["init", "--quiet"]);
        run(&root, &["config", "user.email", "legion-tests@example.invalid"]);
        run(&root, &["config", "user.name", "Legion Tests"]);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join(".gitignore"),
            ".agent/\n.audit/\n.legion/\nengine/target/\n",
        )
        .unwrap();
        fs::write(root.join("src/tracked.mjs"), "export const tracked = 1;\n").unwrap();
        run(&root, &["add", ".gitignore", "src/tracked.mjs"]);
        run(&root, &["commit", "--quiet", "-m", "baseline"]);

        fs::write(root.join("src/untracked.mjs"), "export const untracked = 1;\n").unwrap();
        fs::create_dir_all(root.join("src/.audit")).unwrap();
        fs::create_dir_all(root.join("src/.agent")).unwrap();
        fs::create_dir_all(root.join("engine/target")).unwrap();
        fs::write(root.join("src/.audit/report.json"), "audit output 1\n").unwrap();
        fs::write(root.join("src/.agent/state.sqlite"), "runtime state 1\n").unwrap();
        fs::write(root.join("engine/target/generated.bin"), "generated output 1\n").unwrap();

        let initial = bind_repository(&root, BindOptions::default()).unwrap();

        fs::write(root.join("src/.audit/report.json"), "audit output 2\n").unwrap();
        fs::write(root.join("src/.agent/state.sqlite"), "runtime state 2\n").unwrap();
        fs::write(root.join("engine/target/generated.bin"), "generated output 2\n").unwrap();
        let after_ignored_mutation = bind_repository(&root, BindOptions::default()).unwrap();
        assert_eq!(
            after_ignored_mutation.dirty_overlay_digest,
            initial.dirty_overlay_digest
        );
        assert_eq!(after_ignored_mutation.digest, initial.digest);
        assert_eq!(after_ignored_mutation.file_count, initial.file_count);

        fs::write(root.join("src/tracked.mjs"), "export const tracked = 2;\n").unwrap();
        let after_tracked_mutation = bind_repository(&root, BindOptions::default()).unwrap();
        assert_ne!(
            after_tracked_mutation.dirty_overlay_digest,
            after_ignored_mutation.dirty_overlay_digest
        );
        assert_ne!(after_tracked_mutation.digest, after_ignored_mutation.digest);

        fs::write(root.join("src/untracked.mjs"), "export const untracked = 2;\n").unwrap();
        let after_untracked_mutation = bind_repository(&root, BindOptions::default()).unwrap();
        assert_ne!(
            after_untracked_mutation.dirty_overlay_digest,
            after_tracked_mutation.dirty_overlay_digest
        );
        assert_ne!(after_untracked_mutation.digest, after_tracked_mutation.digest);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn non_git_repository_binding_excludes_runtime_state_but_tracks_source_mutations() {
        let root = tempdir("legion-repository-binding");
        let source = root.join("src/feature.mjs");
        fs::create_dir_all(root.join("src/.audit")).unwrap();
        fs::create_dir_all(root.join("src/.agent")).unwrap();
        fs::write(&source, "export const value = 1;\n").unwrap();
        fs::write(root.join("src/.audit/fixture.txt"), "source fixture\n").unwrap();
        fs::write(root.join("src/.agent/state.sqlite"), "runtime state 1\n").unwrap();

        let initial = bind_repository(&root, BindOptions::default()).unwrap();
        fs::create_dir_all(root.join(".agent")).unwrap();
        fs::create_dir_all(root.join(".audit")).unwrap();
        fs::create_dir_all(root.join(".legion")).unwrap();
        fs::write(root.join(".agent/state.sqlite"), "runtime state 1\n").unwrap();
        fs::write(root.join(".audit/report.json"), "audit output 1\n").unwrap();
        fs::write(root.join(".legion/binding.json"), "runtime state 1\n").unwrap();
        fs::write(root.join("src/.audit/fixture.txt"), "source fixture 2\n").unwrap();
        fs::write(root.join("src/.agent/state.sqlite"), "runtime state 2\n").unwrap();
        let after_runtime_mutation = bind_repository(&root, BindOptions::default()).unwrap();

        assert_eq!(
            after_runtime_mutation.dirty_overlay_digest,
            initial.dirty_overlay_digest
        );
        assert_eq!(after_runtime_mutation.digest, initial.digest);
        assert_eq!(after_runtime_mutation.file_count, initial.file_count);

        fs::write(&source, "export const value = 2;\n").unwrap();
        let after_source_mutation = bind_repository(&root, BindOptions::default()).unwrap();
        assert_ne!(
            after_source_mutation.dirty_overlay_digest,
            after_runtime_mutation.dirty_overlay_digest
        );
        assert_ne!(after_source_mutation.digest, after_runtime_mutation.digest);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn schema_version_and_authorities_round_trip_into_digest() {
        let root = tempdir("legion-repository-binding-authorities");
        fs::write(root.join("only.txt"), "content\n").unwrap();
        let without_authority = bind_repository(&root, BindOptions::default()).unwrap();
        let with_authority = bind_repository(
            &root,
            BindOptions {
                blueprint_digest: Some(json!("sha256:abc")),
                ..BindOptions::default()
            },
        )
        .unwrap();
        assert_eq!(without_authority.schema_version, 1);
        assert_ne!(without_authority.digest, with_authority.digest);
        assert_eq!(with_authority.blueprint_digest, json!("sha256:abc"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn source_revision_defaults_to_revision_when_omitted() {
        let root = tempdir("legion-repository-binding-revision");
        fs::write(root.join("only.txt"), "content\n").unwrap();
        let binding = bind_repository(
            &root,
            BindOptions {
                revision: Some("rev-1".to_string()),
                ..BindOptions::default()
            },
        )
        .unwrap();
        assert_eq!(binding.repository_revision.as_deref(), Some("rev-1"));
        assert_eq!(binding.source_revision.as_deref(), Some("rev-1"));
        fs::remove_dir_all(&root).ok();
    }
}
