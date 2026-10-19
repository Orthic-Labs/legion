//! Frozen Git-history proof. Current file coverage retains its original unit.
//! All Git reads use Audit-owned bounded, read-only process execution.
use super::common::{digest, digest_json};
use crate::{
    scope::{safe_path, valid_oid, GitRunner},
    snapshot::{FrozenSnapshot, SnapshotAdmission, SnapshotSide},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_COMMITS: usize = 50_000;
const MAX_BLOBS: usize = 200_000;
const MAX_BYTES: usize = 512 * 1024 * 1024;
fn gap(error: impl std::fmt::Display) -> String {
    format!("secret-history-unavailable:{error}")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Blob {
    pub oid: String,
    pub digest: String,
    pub mode: String,
    pub lines: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Commit {
    pub parents: Vec<String>,
    pub files: BTreeMap<String, Blob>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HistoryManifest {
    pub schema_version: u32,
    pub repository_id: String,
    pub inventory_digest: String,
    pub execution_root: PathBuf,
    pub source_root: PathBuf,
    pub object_root: PathBuf,
    pub common_root: PathBuf,
    pub repository_identity: String,
    pub object_identity: String,
    pub shallow: bool,
    pub refs: BTreeMap<String, String>,
    pub head: String,
    pub head_ref: Option<String>,
    pub tips: BTreeSet<String>,
    pub history_selection: String,
    pub selected_oid: Option<String>,
    pub snapshot_digest: Option<String>,
    pub scope_digest: Option<String>,
    pub current: BTreeMap<String, String>,
    pub commits: BTreeMap<String, Commit>,
}

pub(crate) struct FrozenHistory {
    pub manifest: HistoryManifest,
    snapshot: Option<Arc<FrozenSnapshot>>,
    admission: Option<SnapshotAdmission>,
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(gap)
}
fn identity(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(gap)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(gap("root-not-directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(digest_json(&json!([path, metadata.dev(), metadata.ino()])))
    }
    #[cfg(not(unix))]
    {
        // Stable filesystem identity needs an OS-owned directory pin on other
        // hosts; canonical spelling alone cannot prove replacement resistance.
        let _ = metadata;
        Err(gap("filesystem-identity-unavailable"))
    }
}
fn refs(git: &GitRunner) -> Result<BTreeMap<String, String>, String> {
    let output = git
        .text(&["for-each-ref", "--format=%(refname)%00%(objectname)"])
        .map_err(gap)?;
    let mut refs = BTreeMap::new();
    for line in output.lines() {
        let (name, oid) = line.split_once('\0').ok_or_else(|| gap("malformed-ref"))?;
        if !name.starts_with("refs/")
            || name.chars().any(char::is_whitespace)
            || !valid_oid(oid)
            || refs.insert(name.into(), oid.into()).is_some()
        {
            return Err(gap("malformed-ref"));
        }
    }
    Ok(refs)
}
fn head(git: &GitRunner) -> Result<(String, Option<String>), String> {
    let oid = git.oid("HEAD").map_err(gap)?;
    let name = git
        .text(&["rev-parse", "--symbolic-full-name", "HEAD"])
        .map_err(gap)?;
    let name = name.trim();
    let name = if name == "HEAD" || name.is_empty() {
        None
    } else if name.starts_with("refs/") && !name.chars().any(char::is_whitespace) {
        Some(name.into())
    } else {
        return Err(gap("malformed-head"));
    };
    Ok((oid, name))
}
fn common(git: &GitRunner) -> Result<PathBuf, String> {
    let value = git.text(&["rev-parse", "--git-common-dir"]).map_err(gap)?;
    canonical(&git.root().join(value.trim()))
}
fn ensure_full(git: &GitRunner) -> Result<(), String> {
    if git
        .text(&["rev-parse", "--is-shallow-repository"])
        .map_err(gap)?
        .trim()
        != "false"
    {
        return Err(gap("shallow-repository"));
    }
    // Replace refs/grafts change ancestry semantics; never silently accept a
    // scanner view differing from the frozen object graph.
    let common = common(git)?;
    if common.join("info/grafts").exists()
        || common.join("shallow").exists()
        || common.join("objects/info/alternates").exists()
    {
        return Err(gap("nonlocal-or-overridden-object-graph"));
    }
    Ok(())
}
fn read_current(
    root: &Path,
    snapshot: Option<&FrozenSnapshot>,
    path: &str,
) -> Result<Vec<u8>, String> {
    safe_path(path).map_err(gap)?;
    if let Some(snapshot) = snapshot {
        return snapshot
            .read(path, SnapshotSide::Selected, MAX_BYTES)
            .map_err(gap);
    }
    let path = root.join(path);
    let metadata = fs::symlink_metadata(&path).map_err(gap)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_BYTES as u64
    {
        return Err(gap("current-file-unavailable"));
    }
    let canonical = canonical(&path)?;
    if !canonical.starts_with(root) {
        return Err(gap("current-path-escape"));
    }
    fs::read(canonical).map_err(gap)
}

impl FrozenHistory {
    pub(crate) fn capture(
        root: &Path,
        manifest_path: Option<&Path>,
        inventory: &crate::inventory::InventoryEnvelope,
        files: &[String],
    ) -> Result<Self, String> {
        let root = canonical(root)?;
        let snapshot = manifest_path
            .map(FrozenSnapshot::verified_reader)
            .transpose()
            .map_err(gap)?;
        let admission = snapshot
            .as_ref()
            .map(FrozenSnapshot::operation_admission)
            .transpose()
            .map_err(gap)?;
        let (source_root, object_root, snapshot_digest, scope_digest) =
            if let Some(snapshot) = &snapshot {
                if canonical(&snapshot.manifest.execution_root)? != root
                    || !snapshot.manifest.gaps.is_empty()
                {
                    return Err(gap("snapshot-scope-mismatch"));
                }
                let scope = &snapshot.manifest.scope;
                (
                    canonical(&scope.source_root)?,
                    canonical(scope.object_root.as_deref().unwrap_or(&scope.source_root))?,
                    Some(digest_json(
                        &serde_json::to_value(&snapshot.manifest).map_err(gap)?,
                    )),
                    Some(digest_json(&serde_json::to_value(scope).map_err(gap)?)),
                )
            } else {
                // A snapshot marker without its admitted manifest cannot fall back
                // to discovering a parent repository.
                if root.join(".legion-audit-snapshot").exists() {
                    return Err(gap("snapshot-manifest-missing"));
                }
                (root.clone(), root.clone(), None, None)
            };
        let source_git = GitRunner::new(&source_root);
        let source_top = source_git
            .text(&["rev-parse", "--show-toplevel"])
            .map_err(gap)?;
        if canonical(Path::new(source_top.trim()))? != source_root {
            return Err(gap("root-not-git-top-level"));
        }
        let git = GitRunner::new(&object_root);
        ensure_full(&git)?;
        let references = refs(&git)?;
        if references
            .keys()
            .any(|name| name.starts_with("refs/replace/"))
        {
            return Err(gap("replace-refs-present"));
        }
        let (head, head_ref) = head(&source_git)?;
        let narrowed = snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.manifest.scope.spec.is_diff());
        let mut tips = BTreeSet::new();
        if !narrowed {
            tips.insert(head.clone());
            for reference in references.keys() {
                tips.insert(git.oid(reference).map_err(gap)?);
            }
        }
        if let Some(snapshot) = &snapshot {
            if snapshot.manifest.scope.head_oid != head {
                return Err(gap("snapshot-source-head-mismatch"));
            }
            for oid in [
                Some(&snapshot.manifest.scope.selected_oid),
                snapshot.manifest.scope.baseline_oid.as_ref(),
                snapshot.manifest.scope.base_ref_oid.as_ref(),
                snapshot.manifest.scope.merge_base_oid.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if !valid_oid(oid) || git.oid(oid).map_err(gap)? != *oid {
                    return Err(gap("snapshot-object-mismatch"));
                }
                tips.insert(oid.clone());
            }
        }
        let common_root = common(&git)?;
        let mut manifest = HistoryManifest {
            schema_version: 1,
            repository_id: inventory.repository_id.clone(),
            inventory_digest: inventory.digest.clone(),
            execution_root: root.clone(),
            source_root: source_root.clone(),
            object_root: object_root.clone(),
            common_root: common_root.clone(),
            repository_identity: identity(&source_root)?,
            object_identity: identity(&common_root)?,
            shallow: false,
            refs: references,
            head,
            head_ref,
            tips,
            history_selection: if narrowed {
                "snapshot-scope".into()
            } else {
                "repository".into()
            },
            selected_oid: snapshot
                .as_ref()
                .map(|snapshot| snapshot.manifest.scope.selected_oid.clone()),
            snapshot_digest,
            scope_digest,
            current: BTreeMap::new(),
            commits: BTreeMap::new(),
        };
        let mut total_bytes = 0usize;
        for path in files {
            let bytes = read_current(&root, snapshot.as_deref(), path)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| gap("byte-limit"))?;
            let expected = inventory
                .entries
                .iter()
                .find(|entry| entry.path == *path)
                .and_then(|entry| entry.digest.as_deref())
                .ok_or_else(|| gap("current-inventory-digest-missing"))?;
            if digest(&bytes) != expected
                || total_bytes > MAX_BYTES
                || manifest
                    .current
                    .insert(path.clone(), expected.into())
                    .is_some()
            {
                return Err(gap("current-inventory-mismatch"));
            }
        }
        let started = std::time::Instant::now();
        let mut total_rows = 0usize;
        let mut pending = manifest.tips.clone();
        let mut blobs: BTreeMap<String, (String, usize)> = BTreeMap::new();
        while let Some(oid) = pending.pop_first() {
            if manifest.commits.contains_key(&oid) {
                continue;
            }
            if started.elapsed() > std::time::Duration::from_secs(120) {
                return Err(gap("capture-deadline"));
            }
            if manifest.commits.len() >= MAX_COMMITS {
                return Err(gap("commit-limit"));
            }
            let bytes = git.run(&["cat-file", "commit", &oid]).map_err(gap)?;
            let headers = std::str::from_utf8(
                bytes
                    .split(|byte| *byte == b'\n')
                    .next()
                    .unwrap_or_default(),
            )
            .map_err(gap)?;
            if !headers.starts_with("tree ") {
                return Err(gap("malformed-commit"));
            }
            let mut parents = Vec::new();
            for line in bytes
                .split(|byte| *byte == b'\n')
                .take_while(|line| !line.is_empty())
            {
                if let Some(parent) = line.strip_prefix(b"parent ") {
                    let parent = std::str::from_utf8(parent).map_err(gap)?;
                    if !valid_oid(parent) {
                        return Err(gap("malformed-parent"));
                    }
                    parents.push(parent.to_owned());
                    pending.insert(parent.to_owned());
                }
            }
            let tree = git
                .run(&["ls-tree", "-r", "-z", "--full-tree", &oid])
                .map_err(gap)?;
            let mut entries = BTreeMap::new();
            for row in tree.split(|byte| *byte == 0).filter(|row| !row.is_empty()) {
                total_rows += 1;
                if total_rows > MAX_BLOBS {
                    return Err(gap("tree-entry-limit"));
                }
                let row = std::str::from_utf8(row).map_err(gap)?;
                let (header, path) = row.split_once('\t').ok_or_else(|| gap("malformed-tree"))?;
                safe_path(path).map_err(gap)?;
                let fields: Vec<_> = header.split(' ').collect();
                if fields.len() != 3
                    || fields[1] != "blob"
                    || !valid_oid(fields[2])
                    || !matches!(fields[0], "100644" | "100755")
                {
                    return Err(gap("unsupported-tree-entry"));
                }
                if !blobs.contains_key(fields[2]) {
                    if blobs.len() >= MAX_BLOBS {
                        return Err(gap("blob-limit"));
                    }
                    let bytes = git.run(&["cat-file", "blob", fields[2]]).map_err(gap)?;
                    total_bytes = total_bytes
                        .checked_add(bytes.len())
                        .ok_or_else(|| gap("byte-limit"))?;
                    if total_bytes > MAX_BYTES {
                        return Err(gap("byte-limit"));
                    }
                    let lines = bytes.split(|byte| *byte == b'\n').count();
                    blobs.insert(fields[2].into(), (digest(&bytes), lines));
                }
                let (hash, lines) = &blobs[fields[2]];
                if entries
                    .insert(
                        path.into(),
                        Blob {
                            oid: fields[2].into(),
                            digest: hash.clone(),
                            mode: fields[0].into(),
                            lines: *lines,
                        },
                    )
                    .is_some()
                {
                    return Err(gap("duplicate-tree-path"));
                }
            }
            manifest.commits.insert(
                oid,
                Commit {
                    parents,
                    files: entries,
                },
            );
        }
        let frozen = Self {
            manifest,
            snapshot,
            admission,
        };
        frozen.revalidate()?;
        Ok(frozen)
    }
    pub(crate) fn stage_current(&self, target: &Path) -> Result<(), String> {
        fs::create_dir(target).map_err(gap)?;
        for (path, hash) in &self.manifest.current {
            let bytes = read_current(
                &self.manifest.execution_root,
                self.snapshot.as_deref(),
                path,
            )?;
            if digest(&bytes) != *hash {
                return Err(gap("current-source-drift"));
            }
            let destination = target.join(path);
            fs::create_dir_all(destination.parent().ok_or_else(|| gap("current-parent"))?)
                .map_err(gap)?;
            fs::write(destination, bytes).map_err(gap)?;
        }
        Ok(())
    }
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        if let Some(admission) = &self.admission {
            admission.revalidate().map_err(gap)?;
        }
        let manifest = &self.manifest;
        let git = GitRunner::new(&manifest.object_root);
        ensure_full(&git)?;
        if identity(&manifest.source_root)? != manifest.repository_identity
            || common(&git)? != manifest.common_root
            || identity(&manifest.common_root)? != manifest.object_identity
            || refs(&git)? != manifest.refs
            || head(&GitRunner::new(&manifest.source_root))?
                != (manifest.head.clone(), manifest.head_ref.clone())
        {
            return Err(gap("repository-state-race"));
        }
        for (path, hash) in &manifest.current {
            if digest(&read_current(
                &manifest.execution_root,
                self.snapshot.as_deref(),
                path,
            )?) != *hash
            {
                return Err(gap("current-source-drift"));
            }
        }
        // Re-read each named object: an object removed/replaced while scanner
        // ran cannot leave a successful proof behind.
        let mut verified_blobs = BTreeSet::new();
        for (oid, commit) in &manifest.commits {
            git.run(&["cat-file", "commit", oid]).map_err(gap)?;
            for blob in commit.files.values() {
                if !verified_blobs.insert(&blob.oid) {
                    continue;
                }
                if digest(&git.run(&["cat-file", "blob", &blob.oid]).map_err(gap)?) != blob.digest {
                    return Err(gap("historical-object-drift"));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn manifest_value(manifest: &HistoryManifest) -> Value {
    let value = serde_json::to_value(manifest).expect("manifest serialization");
    json!({"digest":digest_json(&value),"manifest":value})
}

/// Integrity & graph reconciliation, separate from frozen current-file count.
/// Caller additionally validates scanner receipts & exact current path hashes.
pub(crate) fn validate_manifest(proof: &Value) -> Option<HistoryManifest> {
    let value = proof.get("manifest")?;
    if proof.get("digest")?.as_str()? != digest_json(value) {
        return None;
    }
    let manifest: HistoryManifest = serde_json::from_value(value.clone()).ok()?;
    if manifest.schema_version != 1
        || manifest.shallow
        || manifest.tips.is_empty()
        || manifest.commits.is_empty()
        || !valid_oid(&manifest.head)
        || !matches!(
            manifest.history_selection.as_str(),
            "repository" | "snapshot-scope"
        )
        || (manifest.history_selection == "repository" && !manifest.tips.contains(&manifest.head))
        || (manifest.history_selection == "snapshot-scope"
            && (manifest.snapshot_digest.is_none()
                || manifest.scope_digest.is_none()
                || manifest
                    .selected_oid
                    .as_ref()
                    .is_none_or(|oid| !manifest.tips.contains(oid))))
        || manifest.refs.values().any(|oid| !valid_oid(oid))
        || manifest.current.iter().any(|(path, hash)| {
            safe_path(path).is_err() || !super::common::valid_digest(Some(&json!(hash)))
        })
    {
        return None;
    }
    let mut visited = BTreeSet::new();
    let mut pending = manifest.tips.clone();
    while let Some(oid) = pending.pop_first() {
        if !visited.insert(oid.clone()) {
            continue;
        }
        let commit = manifest.commits.get(&oid)?;
        if !valid_oid(&oid) || commit.parents.iter().any(|parent| !valid_oid(parent)) {
            return None;
        }
        pending.extend(commit.parents.iter().cloned());
        for (path, blob) in &commit.files {
            if safe_path(path).is_err()
                || !valid_oid(&blob.oid)
                || blob.lines == 0
                || !matches!(blob.mode.as_str(), "100644" | "100755")
                || !super::common::valid_digest(Some(&json!(blob.digest)))
            {
                return None;
            }
        }
    }
    (visited.len() == manifest.commits.len()).then_some(manifest)
}

pub(crate) fn historical_anchor(finding: &Value, proof: &Value) -> bool {
    let Some(manifest) = validate_manifest(proof) else {
        return false;
    };
    if finding.get("mode").and_then(Value::as_str) != Some("history") {
        return false;
    }
    let Some(commit) = finding.get("commit").and_then(Value::as_str) else {
        return false;
    };
    let Some(path) = finding
        .get("path")
        .or_else(|| finding.get("file"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(blob) = manifest
        .commits
        .get(commit)
        .and_then(|commit| commit.files.get(path))
    else {
        return false;
    };
    finding.get("historyManifestDigest") == proof.get("digest")
        && finding.get("blobOid").and_then(Value::as_str) == Some(blob.oid.as_str())
        && finding.get("blobDigest").and_then(Value::as_str) == Some(blob.digest.as_str())
        && finding
            .get("line")
            .and_then(Value::as_u64)
            .is_some_and(|line| line > 0 && line <= blob.lines as u64)
}

/// Recheck a proposed historical source anchor against its captured object
/// store. This narrowly permits deleted paths; no current-path substitution.
pub(crate) fn live_anchor(finding: &Value, proof: &Value) -> bool {
    if !historical_anchor(finding, proof) {
        return false;
    }
    let Some(manifest) = validate_manifest(proof) else {
        return false;
    };
    let validate = || -> Result<bool, String> {
        let git = GitRunner::new(&manifest.object_root);
        ensure_full(&git)?;
        if common(&git)? != manifest.common_root
            || identity(&manifest.source_root)? != manifest.repository_identity
            || identity(&manifest.common_root)? != manifest.object_identity
        {
            return Ok(false);
        }
        let commit = finding["commit"].as_str().ok_or_else(|| gap("commit"))?;
        let path = finding
            .get("path")
            .or_else(|| finding.get("file"))
            .and_then(Value::as_str)
            .ok_or_else(|| gap("path"))?;
        if !manifest.tips.iter().any(|tip| {
            git.merge_base(commit, tip)
                .is_ok_and(|ancestor| ancestor == commit)
        }) {
            return Ok(false);
        }
        let blob = &manifest.commits[commit].files[path];
        let tree = git
            .run(&["ls-tree", "-r", "-z", "--full-tree", commit, "--", path])
            .map_err(gap)?;
        let expected = format!("{} blob {}\t{}\0", blob.mode, blob.oid, path);
        if tree != expected.as_bytes() {
            return Ok(false);
        }
        let bytes = git.run(&["cat-file", "blob", &blob.oid]).map_err(gap)?;
        Ok(digest(&bytes) == blob.digest
            && bytes.split(|byte| *byte == b'\n').count() == blob.lines)
    };
    validate().unwrap_or(false)
}
