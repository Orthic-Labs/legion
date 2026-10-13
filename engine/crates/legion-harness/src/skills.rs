use crate::error::HarnessError;
use crate::host_projection::canonical_skill_ids;
use regex::Regex;
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub fn canonical_skill_path(legion_root: &Path, id: &str) -> PathBuf {
    legion_root.join("skills").join(id)
}

/// Shared resource directories (`skills/_shared`, ...) that skills reach through
/// `../_shared/...` relative reads. Any `_`-prefixed directory beside the skills
/// is shared; it is projected next to the skill directories, mirroring the
/// plugin layout where `skills/_shared` sits beside `skills/<id>`.
pub fn shared_resource_dirs(legion_root: &Path) -> Vec<String> {
    let mut names = fs::read_dir(legion_root.join("skills"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_dir())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with('_'))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Heuristic for relative reads a skill makes outside its own directory.
/// Only `../`-prefixed targets are considered (in-skill paths travel with the
/// skill); fenced code blocks are skipped; URLs, anchors, absolute paths,
/// globs and placeholders (`* { } < > $ |`) are ignored. Candidates come from
/// markdown link targets `](../x)` and backtick spans `` `../x` ``.
fn escaping_references(text: &str) -> Vec<String> {
    let link = Regex::new(r"\]\((\.\./[^)\s]+)\)").expect("static regex");
    let span = Regex::new(r"`(\.\./[^`\s]+)`").expect("static regex");
    let bare = Regex::new(r"(?:^|[\s(])(\.\./[A-Za-z0-9_./-]+)").expect("static regex");
    let mut refs = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        for re in [&link, &span, &bare] {
            for caps in re.captures_iter(line) {
                let raw = caps[1].split(['#', '?']).next().unwrap_or("");
                let raw = raw.trim_end_matches(['.', ',', ';', ':']);
                if raw.is_empty()
                    || raw.contains("://")
                    || raw.contains(['*', '{', '}', '<', '>', '$', '|'])
                {
                    continue;
                }
                if !refs.iter().any(|existing| existing == raw) {
                    refs.push(raw.to_string());
                }
            }
        }
    }
    refs
}

/// Relative references that resolve in the canonical skills tree but not in the
/// projection. Resolution is lexical (`..` is not followed through symlinks),
/// matching a host that reads the logical projected path.
fn dangling_references(legion_root: &Path, target_dir: &Path, id: &str) -> Vec<Value> {
    let skills_root = legion_root.join("skills");
    let skill_root = skills_root.join(id);
    let mut dangling = Vec::new();
    for entry in walkdir::WalkDir::new(&skill_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "md"))
    {
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Some(dir) = entry
            .path()
            .parent()
            .and_then(|parent| parent.strip_prefix(&skills_root).ok())
        else {
            continue;
        };
        for reference in escaping_references(&text) {
            let canonical = lexical_normalize(&skills_root.join(dir).join(&reference));
            if !canonical.starts_with(&skills_root) || canonical.starts_with(&skill_root) {
                continue;
            }
            if fs::metadata(&canonical).is_err() {
                continue;
            }
            let projected = lexical_normalize(&target_dir.join(dir).join(&reference));
            if fs::metadata(&projected).is_err() {
                let file = entry
                    .path()
                    .strip_prefix(&skill_root)
                    .unwrap_or_else(|_| entry.path())
                    .to_string_lossy()
                    .replace('\\', "/");
                dangling.push(json!({ "skill": id, "file": file, "reference": reference }));
            }
        }
    }
    dangling
}

fn package_files(dir: &Path) -> Result<Vec<String>, HarnessError> {
    let mut files = Vec::new();
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .for_each(|entry| {
            let relative = entry
                .path()
                .strip_prefix(dir)
                .unwrap_or_else(|_| Path::new(""))
                .to_string_lossy()
                .replace('\\', "/");
            files.push(relative);
        });
    files.sort();
    Ok(files)
}

fn package_matches(copy_path: &Path, canonical_path: &Path) -> bool {
    let a = package_files(canonical_path);
    let b = package_files(copy_path);
    if a.is_err() || b.is_err() {
        return false;
    }
    let a = a.expect("checked");
    let b = b.expect("checked");
    if a != b {
        return false;
    }
    a.iter().all(|file| {
        fs::read(canonical_path.join(file))
            .ok()
            .zip(fs::read(copy_path.join(file)).ok())
            .is_some_and(|(left, right)| left == right)
    })
}

fn classify_destination(dest_path: &Path, canonical_path: &Path) -> &'static str {
    let metadata = fs::symlink_metadata(dest_path);
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(_) => return "absent",
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(dest_path);
        if let Ok(target) = target {
            let resolved = dest_path
                .parent()
                .map(|parent| parent.join(&target))
                .unwrap_or(target);
            if fs::canonicalize(&resolved).ok() == fs::canonicalize(canonical_path).ok()
                && (!canonical_path.join("SKILL.md").is_file()
                    || dest_path.join("SKILL.md").is_file())
            {
                return "legion";
            }
        }
        return "foreign";
    }
    if metadata.is_dir() {
        return if package_matches(dest_path, canonical_path) {
            "legion"
        } else {
            "foreign"
        };
    }
    "foreign"
}

pub fn project_skills(
    legion_root: &Path,
    target_dir: &Path,
    copy_fallback: bool,
) -> Result<Value, HarnessError> {
    let ids = canonical_skill_ids(legion_root)?;
    let shared = shared_resource_dirs(legion_root);
    let mut plan = Vec::new();
    for id in ids.iter().chain(shared.iter()) {
        let canonical = canonical_skill_path(legion_root, id);
        let dest = target_dir.join(id);
        let state = classify_destination(&dest, &canonical);
        plan.push((id.clone(), canonical, dest, state));
    }
    let conflicts = plan
        .iter()
        .filter(|(_, _, _, state)| *state == "foreign")
        .map(|(id, _, dest, _)| {
            json!({
                "id": id,
                "path": dest,
                "reason": "destination exists and is not a Legion projection",
            })
        })
        .collect::<Vec<_>>();
    if !conflicts.is_empty() {
        return Err(HarnessError::conflict(format!(
            "skill projection refused: {} destination(s) are not Legion projections: {}",
            conflicts.len(),
            conflicts
                .iter()
                .filter_map(|value| value.get("id").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    fs::create_dir_all(target_dir).map_err(|error| HarnessError::internal(error.to_string()))?;
    let mut linked = Vec::new();
    let mut copied = Vec::new();
    let mut shared_projected = Vec::new();
    for (id, canonical, dest, state) in plan {
        let is_shared = shared.contains(&id);
        if state == "legion" {
            if is_shared {
                shared_projected.push(id);
            } else {
                linked.push(id);
            }
            continue;
        }
        #[cfg(unix)]
        let symlink_result = std::os::unix::fs::symlink(&canonical, &dest);
        #[cfg(windows)]
        let symlink_result = std::os::windows::fs::symlink_dir(&canonical, &dest);
        #[cfg(not(any(unix, windows)))]
        let symlink_result: Result<(), std::io::Error> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink",
        ));
        if symlink_result.is_ok() {
            if is_shared {
                shared_projected.push(id);
            } else {
                linked.push(id);
            }
            continue;
        }
        if !copy_fallback {
            return Err(HarnessError::internal(format!(
                "symlink projection failed for skill {id}"
            )));
        }
        copy_dir_recursive(&canonical, &dest)?;
        if !package_matches(&dest, &canonical) {
            fs::remove_dir_all(&dest).ok();
            return Err(HarnessError::internal(format!(
                "copy fallback produced a non-identical package for skill {id}"
            )));
        }
        if is_shared {
            shared_projected.push(id);
        } else {
            copied.push(id);
        }
    }
    let mode = if copied.is_empty() {
        "symlink"
    } else if linked.is_empty() {
        "copy"
    } else {
        "mixed"
    };
    Ok(json!({
        "targetDir": target_dir,
        "linked": linked,
        "copied": copied,
        "shared": shared_projected,
        "conflicts": [],
        "mode": mode,
    }))
}

pub fn verify_skill_projection(
    legion_root: &Path,
    target_dir: &Path,
) -> Result<Value, HarnessError> {
    let ids = canonical_skill_ids(legion_root)?;
    let mut missing = Vec::new();
    let mut forked = Vec::new();
    let shared = shared_resource_dirs(legion_root);
    let mut shared_missing = Vec::new();
    for id in &shared {
        let state =
            classify_destination(&target_dir.join(id), &canonical_skill_path(legion_root, id));
        if state == "absent" {
            shared_missing.push(id.clone());
        } else if state == "foreign" {
            forked.push(id.clone());
        }
    }
    let mut dangling = Vec::new();
    for id in &ids {
        let state =
            classify_destination(&target_dir.join(id), &canonical_skill_path(legion_root, id));
        if state == "absent" {
            missing.push(id.clone());
        } else if state == "foreign" {
            forked.push(id.clone());
        } else {
            dangling.extend(dangling_references(legion_root, target_dir, id));
        }
    }
    let extra = fs::read_dir(target_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| !ids.contains(name) && !shared.contains(name))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "present": ids.len() - missing.len(),
        "total": ids.len(),
        "missing": missing,
        "forked": forked,
        "sharedMissing": shared_missing,
        "dangling": dangling,
        "extra": extra,
    }))
}

pub fn unproject_skills(legion_root: &Path, target_dir: &Path) -> Result<Value, HarnessError> {
    let ids = canonical_skill_ids(legion_root)?;
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let shared = shared_resource_dirs(legion_root);
    for id in ids.iter().chain(shared.iter()) {
        let dest = target_dir.join(id);
        let state = classify_destination(&dest, &canonical_skill_path(legion_root, id));
        if state == "absent" {
            continue;
        }
        if state == "foreign" {
            kept.push(json!({
                "id": id,
                "path": dest,
                "reason": "not a Legion projection",
            }));
            continue;
        }
        fs::remove_dir_all(&dest).ok();
        removed.push(id.clone());
    }
    if target_dir.is_dir() {
        if fs::read_dir(target_dir)
            .map(|entries| entries.filter_map(Result::ok).next().is_none())
            .unwrap_or(false)
        {
            fs::remove_dir_all(target_dir).ok();
        }
    }
    Ok(json!({ "removed": removed, "kept": kept }))
}

fn copy_dir_recursive(source: &Path, dest: &Path) -> Result<(), HarnessError> {
    fs::create_dir_all(dest).map_err(|error| HarnessError::internal(error.to_string()))?;
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.map_err(|error| HarnessError::internal(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|error| HarnessError::internal(error.to_string()))?;
        let target = dest.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)
                .map_err(|error| HarnessError::internal(error.to_string()))?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| HarnessError::internal(error.to_string()))?;
            }
            fs::copy(entry.path(), &target)
                .map_err(|error| HarnessError::internal(error.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "legion-harness-skills-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("legion");
        let registry = root.join("src").join("registry");
        fs::create_dir_all(&registry).unwrap();
        fs::write(
            registry.join("host-projection.json"),
            r#"{"capabilities":[{"id":"writing","kind":"domain-capability","discoverability":"public"}]}"#,
        )
        .unwrap();
        let skill = root.join("skills").join("writing");
        fs::create_dir_all(&skill).unwrap();
        fs::write(
            skill.join("SKILL.md"),
            "read `../_shared/anti-slop.md` and [p](../_shared/anti-slop.md)\n\
             see https://example.com/../x and `../nowhere/missing.md`\n```\n`../_shared/ghost.md`\n```\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("skills").join("_shared")).unwrap();
        fs::write(
            root.join("skills").join("_shared").join("anti-slop.md"),
            "x",
        )
        .unwrap();
        (root, base.join("target-skills"))
    }

    #[test]
    fn install_projects_shared_dirs_and_verify_passes() {
        let (root, target) = fixture("complete");
        let result = project_skills(&root, &target, true).unwrap();
        assert_eq!(result["shared"], json!(["_shared"]));
        assert!(target.join("_shared").join("anti-slop.md").is_file());
        let verification = verify_skill_projection(&root, &target).unwrap();
        assert_eq!(verification["dangling"], json!([]));
        assert_eq!(verification["sharedMissing"], json!([]));
        assert_eq!(verification["extra"], json!([]));
        assert_eq!(verification["missing"], json!([]));
        assert_eq!(verification["forked"], json!([]));
    }

    #[test]
    fn verify_flags_dangling_relative_reference() {
        let (root, target) = fixture("dangling");
        project_skills(&root, &target, true).unwrap();
        let shared = target.join("_shared");
        fs::remove_file(&shared)
            .or_else(|_| fs::remove_dir_all(&shared))
            .unwrap();
        let verification = verify_skill_projection(&root, &target).unwrap();
        assert_eq!(verification["sharedMissing"], json!(["_shared"]));
        let dangling = verification["dangling"].as_array().unwrap();
        assert_eq!(dangling.len(), 1);
        assert_eq!(dangling[0]["skill"], "writing");
        assert_eq!(dangling[0]["file"], "SKILL.md");
        assert_eq!(dangling[0]["reference"], "../_shared/anti-slop.md");
    }
}
