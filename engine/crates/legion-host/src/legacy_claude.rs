//! Read-only inspection and conservative repair of pre-plugin Claude skill projections.
//!
//! Claude's plugin is Legion's sole current install owner. Historical installs may
//! still leave `~/.claude/skills/<id>` copies or links behind; this module removes
//! only entries it can prove are Legion projections. It never writes plugin cache
//! state, and a directory that is merely named like a Legion skill remains user-owned
//! until it exactly matches a known Legion package.

use crate::{digest_bytes, HostError};
use legion_catalog::hex_digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

pub const RETIRED_BLUEPRINT_SKILL_ID: &str = "blueprint";
const MAX_TREE_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeLegacyInput {
    pub home: PathBuf,
    /// `skills/` directory belonging to current installed Legion plugin generation.
    pub canonical_skills_root: PathBuf,
    /// Current user-invokable Legion skill ids. Retired Blueprint is rejected here.
    pub current_skill_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeSkillsRootKind {
    Absent,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaudeProjectionOwnership {
    CanonicalSymlink,
    ExactCanonicalCopy,
    CachedLegionSymlink {
        plugin_id: String,
        generation: String,
    },
    ExactCachedLegionCopy {
        plugin_id: String,
        generation: String,
    },
    Unproven,
}

impl ClaudeProjectionOwnership {
    fn proven(&self) -> bool {
        !matches!(self, Self::Unproven)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeStandaloneProjection {
    pub id: String,
    pub path: PathBuf,
    pub current: bool,
    pub retired: bool,
    pub ownership: ClaudeProjectionOwnership,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudePluginCacheGeneration {
    pub plugin_id: String,
    pub generation: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub installed_at: Option<String>,
    #[serde(default)]
    pub git_commit_sha: Option<String>,
    #[serde(default)]
    pub install_path: Option<PathBuf>,
    #[serde(default)]
    pub skills_root: Option<PathBuf>,
    pub install_path_exists: bool,
    pub cache_managed: bool,
    pub legion_plugin_manifest: bool,
    pub canonical_generation: bool,
    pub available_skill_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeLegacyInspection {
    pub home: PathBuf,
    pub standalone_skills_root: PathBuf,
    pub standalone_root_kind: ClaudeSkillsRootKind,
    pub canonical_skills_root: PathBuf,
    pub canonical_skills_root_present: bool,
    pub canonical_skills_root_trusted: bool,
    pub current_skill_ids: Vec<String>,
    pub canonical_missing_skill_ids: Vec<String>,
    pub missing_current_skill_ids: Vec<String>,
    pub standalone_projections: Vec<ClaudeStandaloneProjection>,
    pub plugin_cache_path: PathBuf,
    pub plugin_cache_present: bool,
    #[serde(default)]
    pub plugin_cache_error: Option<String>,
    pub plugin_cache_generations: Vec<ClaudePluginCacheGeneration>,
    pub remediation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeLegacyRepair {
    pub inspection: ClaudeLegacyInspection,
    pub removed: Vec<ClaudeStandaloneProjection>,
    pub kept: Vec<ClaudeStandaloneProjection>,
    pub remediation: Vec<String>,
    /// This is an explicit invariant: plugin cache generations are only observed.
    pub plugin_cache_untouched: bool,
}

#[derive(Clone, Debug)]
struct OwnershipCandidate {
    path: PathBuf,
    source: CandidateSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    kind: SnapshotKind,
    len: u64,
    readonly: bool,
    modified: Option<(i64, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotKind {
    Directory,
    Symlink,
    File,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProjectionSnapshot {
    Directory {
        metadata: MetadataSnapshot,
        tree_digest: String,
    },
    Symlink {
        metadata: MetadataSnapshot,
        target: PathBuf,
        resolved_target: Option<PathBuf>,
    },
}

#[derive(Clone, Debug)]
struct InspectedState {
    inspection: ClaudeLegacyInspection,
    projection_snapshots: BTreeMap<PathBuf, ProjectionSnapshot>,
}

#[derive(Serialize)]
struct TreeDigestEntry {
    path: String,
    kind: &'static str,
    len: u64,
    readonly: bool,
    modified: Option<(i64, u32)>,
    digest: Option<String>,
}

#[derive(Clone, Debug)]
enum CandidateSource {
    Canonical,
    Cached {
        plugin_id: String,
        generation: String,
    },
}

/// Inspect Claude's historical standalone skills tree without changing it.
pub fn inspect_claude_legacy(
    input: &ClaudeLegacyInput,
) -> Result<ClaudeLegacyInspection, HostError> {
    Ok(inspect_state(input)?.inspection)
}

/// Remove only direct-child standalone projections proven to be Legion-owned.
///
/// The function re-inspects immediately before every removal. A changed link,
/// copied fork, root symlink, or cache mismatch is preserved and reported.
pub fn repair_claude_legacy(input: &ClaudeLegacyInput) -> Result<ClaudeLegacyRepair, HostError> {
    let initial_state = inspect_state(input)?;
    let inspection = initial_state.inspection.clone();
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let mut remediation = inspection.remediation.clone();

    if inspection.standalone_root_kind != ClaudeSkillsRootKind::Directory {
        kept = inspection.standalone_projections.clone();
        if inspection.standalone_root_kind == ClaudeSkillsRootKind::Symlink {
            remediation.push(
                "Claude skills root is a symlink; repair leaves it untouched to avoid modifying plugin-owned discovery state.".into(),
            );
        }
        sort_projections(&mut kept);
        remediation.sort();
        remediation.dedup();
        return Ok(ClaudeLegacyRepair {
            inspection,
            removed,
            kept,
            remediation,
            plugin_cache_untouched: true,
        });
    }

    for projection in &inspection.standalone_projections {
        if !projection.ownership.proven() {
            kept.push(projection.clone());
            continue;
        }
        let current_state = inspect_state(input)?;
        let current_inspection = &current_state.inspection;
        let current_projection = current_inspection
            .standalone_projections
            .iter()
            .find(|candidate| candidate.id == projection.id && candidate.path == projection.path)
            .cloned();
        let current = current_projection
            .as_ref()
            .map(|candidate| candidate.ownership.clone())
            .unwrap_or(ClaudeProjectionOwnership::Unproven);
        let expected_snapshot = initial_state
            .projection_snapshots
            .get(&projection.path)
            .cloned();
        let current_snapshot = current_state
            .projection_snapshots
            .get(&projection.path)
            .cloned();
        if !current.proven()
            || !direct_child_of(&projection.path, &inspection.standalone_skills_root)
            || current_projection.as_ref().is_none_or(|candidate| {
                candidate.ownership != projection.ownership || candidate.path != projection.path
            })
            || expected_snapshot.is_none()
            || current_snapshot != expected_snapshot
        {
            let mut preserved = projection.clone();
            preserved.ownership = current;
            kept.push(preserved);
            remediation.push(format!(
                "Kept {} because its ownership proof changed before repair.",
                projection.id
            ));
            continue;
        }
        if current_inspection.standalone_root_kind != ClaudeSkillsRootKind::Directory {
            kept.push(projection.clone());
            remediation.push(format!(
                "Kept {} because Claude skills root changed before repair.",
                projection.id
            ));
            continue;
        }
        let Some(expected_snapshot) = current_snapshot else {
            kept.push(projection.clone());
            remediation.push(format!(
                "Kept {} because its target could not be snapshotted before repair.",
                projection.id
            ));
            continue;
        };
        if !remove_projection_checked(&projection.path, &expected_snapshot)? {
            let mut preserved = projection.clone();
            preserved.ownership = current;
            kept.push(preserved);
            remediation.push(format!(
                "Kept {} because its metadata, type, tree digest, or symlink target changed before removal.",
                projection.id
            ));
            continue;
        }
        let mut removed_projection = projection.clone();
        removed_projection.ownership = current;
        removed.push(removed_projection);
    }

    sort_projections(&mut removed);
    sort_projections(&mut kept);
    remediation.sort();
    remediation.dedup();
    Ok(ClaudeLegacyRepair {
        inspection,
        removed,
        kept,
        remediation,
        plugin_cache_untouched: true,
    })
}

fn inspect_state(input: &ClaudeLegacyInput) -> Result<InspectedState, HostError> {
    let current_skill_ids = normalized_skill_ids(&input.current_skill_ids)?;
    let standalone_skills_root = input.home.join(".claude").join("skills");
    let standalone_root_kind = skills_root_kind(&standalone_skills_root);
    let canonical_skills_root_trusted =
        trusted_canonical_skills_root(&input.canonical_skills_root, &current_skill_ids);
    let canonical_skills_root_present = is_directory(&input.canonical_skills_root);
    let canonical_missing_skill_ids = current_skill_ids
        .iter()
        .filter(|id| {
            !canonical_skills_root_trusted || !is_directory(&input.canonical_skills_root.join(id))
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut observed_ids = current_skill_ids.iter().cloned().collect::<BTreeSet<_>>();
    observed_ids.insert(RETIRED_BLUEPRINT_SKILL_ID.into());
    let plugin_cache_path = input
        .home
        .join(".claude")
        .join("plugins")
        .join("installed_plugins.json");
    let plugin_cache_root = input.home.join(".claude").join("plugins").join("cache");
    let (plugin_cache_present, plugin_cache_error, plugin_cache_generations) = inspect_plugin_cache(
        &plugin_cache_path,
        &input.canonical_skills_root,
        canonical_skills_root_trusted,
        &observed_ids,
    );
    let candidates = ownership_candidates(
        &input.canonical_skills_root,
        canonical_skills_root_trusted,
        &standalone_skills_root,
        &plugin_cache_root,
        &observed_ids,
        &plugin_cache_generations,
    );

    // Claude's packaged plugin is sole install owner.  Standalone discovery
    // entries are historical residue, so their absence is healthy.  A current
    // skill is missing only when current canonical plugin content lacks it.
    let missing_current_skill_ids = canonical_missing_skill_ids.clone();
    let mut standalone_projections = Vec::new();
    let mut projection_snapshots = BTreeMap::new();
    let mut remediation = Vec::new();
    if !canonical_skills_root_trusted {
        remediation.push(
            "Canonical Claude skill root is not bound to an installed Legion release; no canonical-root ownership claims are made."
                .into(),
        );
    }
    match standalone_root_kind {
        ClaudeSkillsRootKind::Absent => {}
        ClaudeSkillsRootKind::Directory => {
            let entries = standalone_entries(&standalone_skills_root)?;
            for (id, path) in entries {
                let retired = id.eq_ignore_ascii_case(RETIRED_BLUEPRINT_SKILL_ID);
                let ownership = classify_projection(
                    &path,
                    candidates.get(&id).map(Vec::as_slice).unwrap_or(&[]),
                );
                let projection = ClaudeStandaloneProjection {
                    current: current_skill_ids.binary_search(&id).is_ok(),
                    retired,
                    id,
                    path,
                    ownership,
                };
                if projection.ownership.proven() {
                    if let Some(snapshot) = projection_snapshot(&projection.path) {
                        projection_snapshots.insert(projection.path.clone(), snapshot);
                    }
                }
                standalone_projections.push(projection);
            }
        }
        ClaudeSkillsRootKind::Symlink => {
            remediation.push(
                "Claude skills root is a symlink; treat it as plugin discovery state, never as a standalone projection tree.".into(),
            );
        }
        ClaudeSkillsRootKind::Other => {
            remediation.push(
                "Claude skills root is not a readable directory; it is preserved without ownership claims."
                    .into(),
            );
        }
    }

    for id in &canonical_missing_skill_ids {
        remediation.push(format!(
            "Current Legion plugin package lacks skill {id}; repair current plugin installation without creating a standalone Claude duplicate."
        ));
    }
    for projection in &standalone_projections {
        if projection.retired {
            if projection.ownership.proven() {
                remediation.push(format!(
                    "Retired Blueprint exposure {} is a proven Legion projection and is safe to remove during repair.",
                    projection.path.display()
                ));
            } else {
                remediation.push(format!(
                    "Retired Blueprint exposure {} is kept because Legion ownership is unproven.",
                    projection.path.display()
                ));
            }
        }
    }
    for generation in &plugin_cache_generations {
        if !generation.canonical_generation {
            remediation.push(format!(
                "Observed non-canonical Legion plugin cache generation {}; repair will not mutate plugin cache.",
                generation.generation
            ));
        }
    }

    standalone_projections.sort_by(|left, right| left.id.cmp(&right.id));
    remediation.sort();
    remediation.dedup();
    Ok(InspectedState {
        inspection: ClaudeLegacyInspection {
            home: input.home.clone(),
            standalone_skills_root,
            standalone_root_kind,
            canonical_skills_root: input.canonical_skills_root.clone(),
            canonical_skills_root_present,
            canonical_skills_root_trusted,
            current_skill_ids,
            canonical_missing_skill_ids,
            missing_current_skill_ids,
            standalone_projections,
            plugin_cache_path,
            plugin_cache_present,
            plugin_cache_error,
            plugin_cache_generations,
            remediation,
        },
        projection_snapshots,
    })
}

/// Canonical skill content is trusted only when it comes from an assembled
/// installed release.  `ClaudeLegacyInput` is public, so an arbitrary path
/// supplied by a caller must never, by itself, authorize deleting a user's
/// standalone skill tree.
fn trusted_canonical_skills_root(root: &Path, current_skill_ids: &[String]) -> bool {
    let Ok(root) = fs::canonicalize(root) else {
        return false;
    };
    let Ok(root_metadata) = fs::symlink_metadata(&root) else {
        return false;
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return false;
    }
    let Some(assets_root) = root.parent() else {
        return false;
    };
    if root.file_name().and_then(|name| name.to_str()) != Some("skills") {
        return false;
    }
    if assets_root.file_name().and_then(|name| name.to_str()) != Some("assets") {
        return false;
    }
    let Some(legion_root) = assets_root.parent() else {
        return false;
    };
    if legion_root.file_name().and_then(|name| name.to_str()) != Some("legion") {
        return false;
    }
    let release_manifest_path = legion_root.join("release.json");
    if !regular_file(&release_manifest_path) {
        return false;
    }
    let Ok(release_manifest) = fs::read(release_manifest_path) else {
        return false;
    };
    let Ok(release_manifest) = serde_json::from_slice::<Value>(&release_manifest) else {
        return false;
    };
    let Some(expected_assets_digest) = release_manifest
        .get("declarativeAssetsSha256")
        .and_then(Value::as_str)
        .map(|digest| digest.strip_prefix("sha256:").unwrap_or(digest))
    else {
        return false;
    };
    if release_manifest
        .get("releaseVersion")
        .and_then(Value::as_str)
        .is_none_or(|version| version.trim().is_empty())
        || !valid_release_digest(expected_assets_digest)
        || release_assets_digest(assets_root).as_deref() != Some(expected_assets_digest)
    {
        return false;
    }
    let registry_path = assets_root.join("registry").join("index.json");
    if !regular_file(&registry_path) {
        return false;
    }
    let Ok(registry_bytes) = fs::read(&registry_path) else {
        return false;
    };
    let Ok(registry) = serde_json::from_slice::<Value>(&registry_bytes) else {
        return false;
    };
    let Some(bundles) = registry.get("bundles").and_then(Value::as_array) else {
        return false;
    };
    let registered_ids = bundles
        .iter()
        .filter_map(|bundle| bundle.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    current_skill_ids.iter().all(|id| {
        registered_ids.contains(id.as_str())
            && regular_file(&root.join(id).join("SKILL.md"))
            && !fs::symlink_metadata(root.join(id))
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
    })
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn release_assets_digest(root: &Path) -> Option<String> {
    let mut files = BTreeMap::new();
    let mut remaining = MAX_TREE_ENTRIES;
    collect_release_files(root, Path::new(""), &mut files, &mut remaining)?;
    let mut digest_input = Vec::new();
    for (path, bytes) in files {
        digest_input.extend_from_slice(path.as_bytes());
        digest_input.push(0);
        digest_input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        digest_input.extend_from_slice(&bytes);
    }
    Some(hex_digest(&digest_input))
}

fn collect_release_files(
    root: &Path,
    relative_root: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    remaining: &mut usize,
) -> Option<()> {
    for (name, child) in directory_entries(root).ok()? {
        if *remaining == 0 {
            return None;
        }
        *remaining -= 1;
        let metadata = fs::symlink_metadata(&child).ok()?;
        if metadata.file_type().is_symlink() {
            return None;
        }
        let relative = relative_root.join(&name);
        if metadata.is_dir() {
            collect_release_files(&child, &relative, files, remaining)?;
        } else if metadata.is_file() {
            files.insert(
                relative.to_string_lossy().replace('\\', "/"),
                fs::read(child).ok()?,
            );
        } else {
            return None;
        }
    }
    Some(())
}

fn valid_release_digest(value: &str) -> bool {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalized_skill_ids(ids: &[String]) -> Result<Vec<String>, HostError> {
    let mut normalized = BTreeSet::new();
    for id in ids {
        if !safe_skill_id(id) {
            return Err(HostError::InvalidDescriptor {
                path: "claude.currentSkillIds".into(),
                reason: format!("skill id {id:?} must be one non-empty path component"),
            });
        }
        if id.eq_ignore_ascii_case(RETIRED_BLUEPRINT_SKILL_ID) {
            return Err(HostError::InvalidDescriptor {
                path: "claude.currentSkillIds".into(),
                reason: "retired Blueprint cannot be a current Legion skill".into(),
            });
        }
        normalized.insert(id.clone());
    }
    Ok(normalized.into_iter().collect())
}

fn safe_skill_id(id: &str) -> bool {
    if id.trim().is_empty() {
        return false;
    }
    let mut components = Path::new(id).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn skills_root_kind(path: &Path) -> ClaudeSkillsRootKind {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => ClaudeSkillsRootKind::Symlink,
        Ok(metadata) if metadata.is_dir() => ClaudeSkillsRootKind::Directory,
        Ok(_) => ClaudeSkillsRootKind::Other,
        Err(error) if error.kind() == ErrorKind::NotFound => ClaudeSkillsRootKind::Absent,
        Err(_) => ClaudeSkillsRootKind::Other,
    }
}

fn is_directory(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn standalone_entries(root: &Path) -> Result<BTreeMap<String, PathBuf>, HostError> {
    let entries = fs::read_dir(root).map_err(|error| HostError::Io {
        path: root.into(),
        reason: error.to_string(),
    })?;
    let mut result = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| HostError::Io {
            path: root.into(),
            reason: error.to_string(),
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !safe_skill_id(&name) {
            continue;
        }
        result.insert(name, entry.path());
    }
    Ok(result)
}

fn inspect_plugin_cache(
    cache_path: &Path,
    canonical_skills_root: &Path,
    canonical_skills_root_trusted: bool,
    observed_ids: &BTreeSet<String>,
) -> (bool, Option<String>, Vec<ClaudePluginCacheGeneration>) {
    let bytes = match fs::read(cache_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return (false, None, Vec::new()),
        Err(error) => return (true, Some(error.to_string()), Vec::new()),
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => return (true, Some(error.to_string()), Vec::new()),
    };
    let Some(root) = value.as_object() else {
        return (
            true,
            Some("installed_plugins.json root is not an object".into()),
            Vec::new(),
        );
    };
    let plugins = root
        .get("plugins")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let cache_root = cache_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("cache");
    let mut generations = Vec::new();
    for (plugin_id, value) in plugins {
        if !is_legion_plugin_id(plugin_id) {
            continue;
        }
        let records = value
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![value.clone()]);
        for (index, record) in records.into_iter().enumerate() {
            let Some(record) = record.as_object() else {
                continue;
            };
            let version = string_field(record, "version");
            let installed_at = string_field(record, "installedAt");
            let git_commit_sha = string_field(record, "gitCommitSha");
            let install_path = string_field(record, "installPath").map(PathBuf::from);
            let skills_root = install_path.as_ref().map(|path| path.join("skills"));
            let install_path_exists = install_path.as_ref().is_some_and(|path| path.exists());
            let cache_managed = install_path
                .as_deref()
                .is_some_and(|path| path_inside(path, &cache_root));
            let legion_plugin_manifest = install_path
                .as_deref()
                .is_some_and(has_legion_plugin_manifest);
            let canonical_generation = canonical_skills_root_trusted
                && cache_managed
                && legion_plugin_manifest
                && skills_root
                    .as_deref()
                    .is_some_and(|path| content_tree_contains(path, canonical_skills_root));
            let available_skill_ids = skills_root
                .as_deref()
                .map(|root| {
                    observed_ids
                        .iter()
                        .filter(|id| is_directory(&root.join(id)))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let version_label = version.clone().unwrap_or_else(|| "unknown".into());
            generations.push(ClaudePluginCacheGeneration {
                plugin_id: plugin_id.clone(),
                generation: format!("{plugin_id}@{version_label}#{index}"),
                version,
                installed_at,
                git_commit_sha,
                install_path,
                skills_root,
                install_path_exists,
                cache_managed,
                legion_plugin_manifest,
                canonical_generation,
                available_skill_ids,
            });
        }
    }
    generations.sort_by(|left, right| left.generation.cmp(&right.generation));
    (true, None, generations)
}

fn string_field(record: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    record
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn content_tree_contains(candidate: &Path, canonical: &Path) -> bool {
    let mut candidate_files = BTreeMap::new();
    let mut candidate_remaining = MAX_TREE_ENTRIES;
    if collect_release_files(
        candidate,
        Path::new(""),
        &mut candidate_files,
        &mut candidate_remaining,
    )
    .is_none()
    {
        return false;
    }
    let mut canonical_files = BTreeMap::new();
    let mut canonical_remaining = MAX_TREE_ENTRIES;
    if collect_release_files(
        canonical,
        Path::new(""),
        &mut canonical_files,
        &mut canonical_remaining,
    )
    .is_none()
    {
        return false;
    }
    canonical_files
        .iter()
        .all(|(path, bytes)| candidate_files.get(path) == Some(bytes))
}

fn is_legion_plugin_id(id: &str) -> bool {
    let normalized = id.to_ascii_lowercase();
    normalized == "legion" || normalized.starts_with("legion@")
}

fn ownership_candidates(
    canonical_skills_root: &Path,
    canonical_skills_root_trusted: bool,
    standalone_skills_root: &Path,
    plugin_cache_root: &Path,
    observed_ids: &BTreeSet<String>,
    cache_generations: &[ClaudePluginCacheGeneration],
) -> BTreeMap<String, Vec<OwnershipCandidate>> {
    let mut candidates = BTreeMap::<String, Vec<OwnershipCandidate>>::new();
    if canonical_skills_root_trusted {
        for id in observed_ids {
            let path = canonical_skills_root.join(id);
            if usable_reference(&path, standalone_skills_root) {
                candidates
                    .entry(id.clone())
                    .or_default()
                    .push(OwnershipCandidate {
                        path,
                        source: CandidateSource::Canonical,
                    });
            }
        }
    }
    for generation in cache_generations {
        if !generation.cache_managed || !generation.legion_plugin_manifest {
            continue;
        }
        let Some(skills_root) = generation.skills_root.as_ref() else {
            continue;
        };
        for id in &generation.available_skill_ids {
            let path = skills_root.join(id);
            if usable_reference(&path, standalone_skills_root)
                && path_inside(&path, plugin_cache_root)
            {
                candidates
                    .entry(id.clone())
                    .or_default()
                    .push(OwnershipCandidate {
                        path,
                        source: CandidateSource::Cached {
                            plugin_id: generation.plugin_id.clone(),
                            generation: generation.generation.clone(),
                        },
                    });
            }
        }
    }
    candidates
}

fn usable_reference(candidate: &Path, standalone_skills_root: &Path) -> bool {
    is_directory(candidate) && !path_inside(candidate, standalone_skills_root)
}

fn path_inside(path: &Path, root: &Path) -> bool {
    match (fs::canonicalize(path), fs::canonicalize(root)) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

fn classify_projection(
    path: &Path,
    candidates: &[OwnershipCandidate],
) -> ClaudeProjectionOwnership {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return ClaudeProjectionOwnership::Unproven;
    };
    if metadata.file_type().is_symlink() {
        for candidate in candidates {
            if symlink_targets_same(path, &candidate.path) {
                return ownership_for(candidate, true);
            }
        }
        return ClaudeProjectionOwnership::Unproven;
    }
    if metadata.is_dir() {
        for candidate in candidates {
            if exact_directory_tree(path, &candidate.path) {
                return ownership_for(candidate, false);
            }
        }
    }
    ClaudeProjectionOwnership::Unproven
}

fn ownership_for(candidate: &OwnershipCandidate, symlink: bool) -> ClaudeProjectionOwnership {
    match &candidate.source {
        CandidateSource::Canonical if symlink => ClaudeProjectionOwnership::CanonicalSymlink,
        CandidateSource::Canonical => ClaudeProjectionOwnership::ExactCanonicalCopy,
        CandidateSource::Cached {
            plugin_id,
            generation,
        } if symlink => ClaudeProjectionOwnership::CachedLegionSymlink {
            plugin_id: plugin_id.clone(),
            generation: generation.clone(),
        },
        CandidateSource::Cached {
            plugin_id,
            generation,
        } => ClaudeProjectionOwnership::ExactCachedLegionCopy {
            plugin_id: plugin_id.clone(),
            generation: generation.clone(),
        },
    }
}

fn symlink_targets_same(path: &Path, target: &Path) -> bool {
    let Ok(link) = fs::read_link(path) else {
        return false;
    };
    let resolved = if link.is_absolute() {
        link
    } else {
        path.parent().unwrap_or_else(|| Path::new("")).join(link)
    };
    same_real_path(&resolved, target)
}

fn same_real_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn has_legion_plugin_manifest(install_path: &Path) -> bool {
    let manifest = install_path.join(".claude-plugin").join("plugin.json");
    fs::read(manifest)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("name").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|name| name.eq_ignore_ascii_case("legion"))
}

fn exact_directory_tree(left: &Path, right: &Path) -> bool {
    let mut remaining = MAX_TREE_ENTRIES;
    exact_directory_tree_inner(left, right, &mut remaining)
}

fn exact_directory_tree_inner(left: &Path, right: &Path, remaining: &mut usize) -> bool {
    let Ok(left_metadata) = fs::symlink_metadata(left) else {
        return false;
    };
    let Ok(right_metadata) = fs::symlink_metadata(right) else {
        return false;
    };
    if left_metadata.file_type().is_symlink()
        || right_metadata.file_type().is_symlink()
        || !left_metadata.is_dir()
        || !right_metadata.is_dir()
    {
        return false;
    }
    let Ok(left_entries) = directory_entries(left) else {
        return false;
    };
    let Ok(right_entries) = directory_entries(right) else {
        return false;
    };
    if left_entries.len() != right_entries.len()
        || left_entries
            .keys()
            .zip(right_entries.keys())
            .any(|(left, right)| left != right)
    {
        return false;
    }
    for (name, left_path) in left_entries {
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        let Some(right_path) = right_entries.get(&name) else {
            return false;
        };
        let Ok(left_metadata) = fs::symlink_metadata(&left_path) else {
            return false;
        };
        let Ok(right_metadata) = fs::symlink_metadata(right_path) else {
            return false;
        };
        if left_metadata.file_type().is_symlink() || right_metadata.file_type().is_symlink() {
            return false;
        }
        match (left_metadata.is_dir(), right_metadata.is_dir()) {
            (true, true) if exact_directory_tree_inner(&left_path, right_path, remaining) => {}
            (false, false) if left_metadata.is_file() && right_metadata.is_file() => {
                let Ok(left_bytes) = fs::read(&left_path) else {
                    return false;
                };
                let Ok(right_bytes) = fs::read(right_path) else {
                    return false;
                };
                if left_bytes != right_bytes {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn directory_entries(path: &Path) -> Result<BTreeMap<String, PathBuf>, ()> {
    let entries = fs::read_dir(path).map_err(|_| ())?;
    let mut result = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name().to_str().map(str::to_owned).ok_or(())?;
        if result.insert(name, entry.path()).is_some() {
            return Err(());
        }
    }
    Ok(result)
}

fn direct_child_of(path: &Path, root: &Path) -> bool {
    path.parent().is_some_and(|parent| parent == root)
}

fn projection_snapshot(path: &Path) -> Option<ProjectionSnapshot> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let metadata_snapshot = metadata_snapshot(&metadata);
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).ok()?;
        let resolved_target = Some(resolve_link_target(path, &target))
            .filter(|resolved| fs::canonicalize(resolved).is_ok())
            .and_then(|resolved| fs::canonicalize(resolved).ok());
        return Some(ProjectionSnapshot::Symlink {
            metadata: metadata_snapshot,
            target,
            resolved_target,
        });
    }
    if metadata.is_dir() {
        return Some(ProjectionSnapshot::Directory {
            metadata: metadata_snapshot,
            tree_digest: directory_tree_digest(path)?,
        });
    }
    None
}

fn metadata_snapshot(metadata: &fs::Metadata) -> MetadataSnapshot {
    let kind = if metadata.file_type().is_dir() {
        SnapshotKind::Directory
    } else if metadata.file_type().is_symlink() {
        SnapshotKind::Symlink
    } else if metadata.is_file() {
        SnapshotKind::File
    } else {
        SnapshotKind::Other
    };
    let modified = metadata.modified().ok().and_then(|time| {
        let duration = time.duration_since(std::time::UNIX_EPOCH).ok()?;
        let seconds = i64::try_from(duration.as_secs()).ok()?;
        Some((seconds, duration.subsec_nanos()))
    });
    MetadataSnapshot {
        kind,
        len: metadata.len(),
        readonly: metadata.permissions().readonly(),
        modified,
    }
}

fn resolve_link_target(path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        path.parent().unwrap_or_else(|| Path::new("")).join(target)
    }
}

fn directory_tree_digest(root: &Path) -> Option<String> {
    let mut entries = Vec::new();
    let mut remaining = MAX_TREE_ENTRIES;
    collect_tree_digest_entries(root, Path::new(""), &mut entries, &mut remaining)?;
    serde_json::to_vec(&entries)
        .ok()
        .map(|bytes| digest_bytes(&bytes))
}

fn collect_tree_digest_entries(
    root: &Path,
    relative_root: &Path,
    entries: &mut Vec<TreeDigestEntry>,
    remaining: &mut usize,
) -> Option<()> {
    let children = directory_entries(root).ok()?;
    for (name, child) in children {
        if *remaining == 0 {
            return None;
        }
        *remaining -= 1;
        let relative = relative_root.join(&name);
        let metadata = fs::symlink_metadata(&child).ok()?;
        let snapshot = metadata_snapshot(&metadata);
        if metadata.file_type().is_symlink() {
            return None;
        }
        if metadata.is_dir() {
            entries.push(TreeDigestEntry {
                path: relative.to_string_lossy().into_owned(),
                kind: "directory",
                len: snapshot.len,
                readonly: snapshot.readonly,
                modified: snapshot.modified,
                digest: None,
            });
            collect_tree_digest_entries(&child, &relative, entries, remaining)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&child).ok()?;
            entries.push(TreeDigestEntry {
                path: relative.to_string_lossy().into_owned(),
                kind: "file",
                len: snapshot.len,
                readonly: snapshot.readonly,
                modified: snapshot.modified,
                digest: Some(digest_bytes(&bytes)),
            });
        } else {
            return None;
        }
    }
    Some(())
}

/// Check target identity immediately before issuing its destructive call.
/// A false result is a safe preserve decision, never an error requiring a
/// caller to retry blindly.
fn remove_projection_checked(
    path: &Path,
    expected: &ProjectionSnapshot,
) -> Result<bool, HostError> {
    let Some(observed) = projection_snapshot(path) else {
        return Ok(false);
    };
    if &observed != expected {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| HostError::Io {
        path: path.into(),
        reason: error.to_string(),
    })?;
    let metadata_matches = match expected {
        ProjectionSnapshot::Directory {
            metadata: expected, ..
        } => metadata_snapshot(&metadata) == *expected && metadata.is_dir(),
        ProjectionSnapshot::Symlink {
            metadata: expected,
            target,
            resolved_target,
        } => {
            metadata_snapshot(&metadata) == *expected
                && metadata.file_type().is_symlink()
                && fs::read_link(path)
                    .is_ok_and(|current_target| current_target.as_path() == target.as_path())
                && fs::canonicalize(resolve_link_target(path, target))
                    .ok()
                    .as_ref()
                    == resolved_target.as_ref()
        }
    };
    if !metadata_matches {
        return Ok(false);
    }
    if metadata.file_type().is_symlink() {
        fs::remove_file(path)
    } else if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        return Ok(false);
    }
    .map(|_| true)
    .map_err(|error| HostError::Io {
        path: path.into(),
        reason: error.to_string(),
    })
}

fn sort_projections(projections: &mut [ClaudeStandaloneProjection]) {
    projections.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.path.cmp(&right.path))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "legion-host-legacy-claude-{label}-{}-{stamp}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_skill(root: &Path, id: &str, body: &str) {
        let path = root.join(id);
        fs::create_dir_all(path.join("references")).unwrap();
        fs::write(path.join("SKILL.md"), body).unwrap();
        fs::write(
            path.join("references").join("guide.md"),
            format!("guide:{body}"),
        )
        .unwrap();
    }

    fn input(home: &Path, canonical: &Path, ids: &[&str]) -> ClaudeLegacyInput {
        let assets_root = canonical.parent().unwrap();
        let release_root = assets_root.parent().unwrap();
        fs::create_dir_all(assets_root.join("registry")).unwrap();
        let bundles = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
        fs::write(
            assets_root.join("registry/index.json"),
            serde_json::to_vec(&json!({ "bundles": bundles })).unwrap(),
        )
        .unwrap();
        let assets_digest = release_assets_digest(assets_root).unwrap();
        fs::write(
            release_root.join("release.json"),
            serde_json::to_vec(&json!({
                "releaseVersion": "0.1.0",
                "declarativeAssetsSha256": assets_digest
            }))
            .unwrap(),
        )
        .unwrap();
        ClaudeLegacyInput {
            home: home.into(),
            canonical_skills_root: canonical.into(),
            current_skill_ids: ids.iter().map(|id| (*id).into()).collect(),
        }
    }

    #[test]
    fn repair_removes_only_exact_current_projection_and_preserves_user_skills() {
        let temp = TempRoot::new("preserve-user-skills");
        let home = temp.0.join("home");
        let canonical = temp
            .0
            .join("release")
            .join("share")
            .join("legion")
            .join("assets")
            .join("skills");
        write_skill(&canonical, "audit", "current audit");
        write_skill(&canonical, "wake", "current wake");

        let standalone = home.join(".claude").join("skills");
        write_skill(&standalone, "audit", "current audit");
        write_skill(&standalone, "compshop", "user-owned compshop");
        write_skill(&standalone, "content", "user-owned content");
        write_skill(&standalone, "blueprint", "unproven retired skill");

        let cache_path = home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json");
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        let cache = serde_json::to_vec_pretty(&json!({
            "version": 1,
            "plugins": {
                "legion@old": [{"version": "0.1.0-dev.1", "installPath": temp.0.join("old-cache")}]
            }
        }))
        .unwrap();
        fs::write(&cache_path, &cache).unwrap();

        let inspection =
            inspect_claude_legacy(&input(&home, &canonical, &["audit", "wake"])).unwrap();
        assert!(inspection.missing_current_skill_ids.is_empty());
        assert!(inspection
            .plugin_cache_generations
            .iter()
            .all(|generation| !generation.canonical_generation));
        assert_eq!(
            inspection
                .standalone_projections
                .iter()
                .find(|projection| projection.id == "audit")
                .unwrap()
                .ownership,
            ClaudeProjectionOwnership::ExactCanonicalCopy
        );
        assert!(inspection
            .standalone_projections
            .iter()
            .filter(|projection| matches!(projection.id.as_str(), "compshop" | "content"))
            .all(|projection| projection.ownership == ClaudeProjectionOwnership::Unproven));

        let repair = repair_claude_legacy(&input(&home, &canonical, &["audit", "wake"])).unwrap();
        assert_eq!(
            repair
                .removed
                .iter()
                .map(|projection| projection.id.as_str())
                .collect::<Vec<_>>(),
            vec!["audit"]
        );
        assert!(standalone.join("compshop").exists());
        assert!(standalone.join("content").exists());
        assert!(standalone.join("blueprint").exists());
        assert_eq!(fs::read(&cache_path).unwrap(), cache);
        assert!(repair.plugin_cache_untouched);
    }

    #[test]
    fn current_claude_cache_copy_is_canonical_generation() {
        let temp = TempRoot::new("current-cache-generation");
        let home = temp.0.join("home");
        let canonical = temp
            .0
            .join("release")
            .join("share")
            .join("legion")
            .join("assets")
            .join("skills");
        write_skill(&canonical, "audit", "current audit");
        let cache = home
            .join(".claude")
            .join("plugins")
            .join("cache")
            .join("orthic-labs")
            .join("legion")
            .join("0.1.0");
        fs::create_dir_all(cache.join(".claude-plugin")).unwrap();
        fs::write(
            cache.join(".claude-plugin").join("plugin.json"),
            r#"{"name":"legion","version":"0.1.0"}"#,
        )
        .unwrap();
        write_skill(&cache.join("skills"), "audit", "current audit");
        fs::create_dir_all(cache.join("skills").join("audit").join("scripts")).unwrap();
        fs::write(
            cache.join("skills").join("audit").join("scripts/helper.py"),
            "print('plugin-only helper')",
        )
        .unwrap();
        let cache_index = home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json");
        fs::write(
            &cache_index,
            serde_json::to_vec(&json!({
                "plugins": {
                    "legion@orthic-labs": [{
                        "version": "0.1.0",
                        "installPath": cache,
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let inspection = inspect_claude_legacy(&input(&home, &canonical, &["audit"])).unwrap();
        assert_eq!(inspection.plugin_cache_generations.len(), 1);
        assert!(inspection.plugin_cache_generations[0].canonical_generation);
        assert!(inspection
            .remediation
            .iter()
            .all(|item| !item.contains("non-canonical Legion plugin cache generation")));
    }

    #[test]
    fn repair_removes_retired_blueprint_only_when_cache_proves_exact_ownership() {
        let temp = TempRoot::new("retired-blueprint");
        let home = temp.0.join("home");
        let canonical = temp
            .0
            .join("release")
            .join("share")
            .join("legion")
            .join("assets")
            .join("skills");
        write_skill(&canonical, "audit", "current audit");
        let old_plugin = home
            .join(".claude")
            .join("plugins")
            .join("cache")
            .join("legion")
            .join("0.1.0-dev.1");
        fs::create_dir_all(old_plugin.join(".claude-plugin")).unwrap();
        fs::write(
            old_plugin.join(".claude-plugin").join("plugin.json"),
            r#"{"name":"legion"}"#,
        )
        .unwrap();
        write_skill(&old_plugin.join("skills"), "blueprint", "retired blueprint");
        let standalone = home.join(".claude").join("skills");
        write_skill(&standalone, "blueprint", "retired blueprint");
        write_skill(&standalone, "content", "personal content");

        let cache_path = home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json");
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        let cache = serde_json::to_vec(&json!({
            "plugins": {
                "legion@local-brief": [{"version": "0.1.0-dev.1", "installPath": old_plugin}]
            }
        }))
        .unwrap();
        fs::write(&cache_path, &cache).unwrap();

        let inspection = inspect_claude_legacy(&input(&home, &canonical, &["audit"])).unwrap();
        let blueprint = inspection
            .standalone_projections
            .iter()
            .find(|projection| projection.id == "blueprint")
            .unwrap();
        assert!(blueprint.retired);
        assert!(matches!(
            &blueprint.ownership,
            ClaudeProjectionOwnership::ExactCachedLegionCopy { .. }
        ));

        let repair = repair_claude_legacy(&input(&home, &canonical, &["audit"])).unwrap();
        assert_eq!(repair.removed.len(), 1);
        assert_eq!(repair.removed[0].id, "blueprint");
        assert!(!standalone.join("blueprint").exists());
        assert!(standalone.join("content").exists());
        assert_eq!(fs::read(&cache_path).unwrap(), cache);
    }

    #[test]
    fn arbitrary_canonical_root_cannot_authorize_cleanup() {
        let temp = TempRoot::new("untrusted-canonical-root");
        let home = temp.0.join("home");
        let canonical = temp.0.join("caller-chosen").join("skills");
        write_skill(&canonical, "audit", "same bytes");
        let standalone = home.join(".claude").join("skills");
        write_skill(&standalone, "audit", "same bytes");
        let legacy = ClaudeLegacyInput {
            home: home.clone(),
            canonical_skills_root: canonical,
            current_skill_ids: vec!["audit".into()],
        };

        let inspection = inspect_claude_legacy(&legacy).unwrap();
        assert!(!inspection.canonical_skills_root_trusted);
        assert_eq!(
            inspection.standalone_projections[0].ownership,
            ClaudeProjectionOwnership::Unproven
        );
        let repair = repair_claude_legacy(&legacy).unwrap();
        assert!(repair.removed.is_empty());
        assert!(standalone.join("audit").exists());
    }

    #[test]
    fn removal_guard_preserves_projection_when_tree_changes() {
        let temp = TempRoot::new("changed-tree");
        let projection = temp.0.join("projection");
        write_skill(projection.parent().unwrap(), "projection", "before");
        let snapshot = projection_snapshot(&projection).unwrap();
        fs::write(projection.join("SKILL.md"), "after").unwrap();

        assert!(!remove_projection_checked(&projection, &snapshot).unwrap());
        assert!(projection.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_skills_root_is_never_treated_as_a_standalone_tree() {
        use std::os::unix::fs::symlink;

        let temp = TempRoot::new("skills-root-link");
        let home = temp.0.join("home");
        let canonical = temp
            .0
            .join("release")
            .join("share")
            .join("legion")
            .join("assets")
            .join("skills");
        write_skill(&canonical, "audit", "current audit");
        let root_parent = home.join(".claude");
        fs::create_dir_all(&root_parent).unwrap();
        symlink(&canonical, root_parent.join("skills")).unwrap();

        let repair = repair_claude_legacy(&input(&home, &canonical, &["audit"])).unwrap();
        assert_eq!(
            repair.inspection.standalone_root_kind,
            ClaudeSkillsRootKind::Symlink
        );
        assert!(repair.inspection.missing_current_skill_ids.is_empty());
        assert!(repair.removed.is_empty());
        assert!(canonical.join("audit").exists());
    }

    #[cfg(unix)]
    #[test]
    fn removal_guard_preserves_projection_when_symlink_target_changes() {
        use std::os::unix::fs::symlink;

        let temp = TempRoot::new("changed-link");
        let target_one = temp.0.join("target-one");
        let target_two = temp.0.join("target-two");
        fs::create_dir_all(&target_one).unwrap();
        fs::create_dir_all(&target_two).unwrap();
        let link = temp.0.join("projection");
        symlink(&target_one, &link).unwrap();
        let snapshot = projection_snapshot(&link).unwrap();
        fs::remove_file(&link).unwrap();
        symlink(&target_two, &link).unwrap();

        assert!(!remove_projection_checked(&link, &snapshot).unwrap());
        assert!(link.exists());
    }
}
