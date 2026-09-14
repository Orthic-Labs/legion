use crate::error::HarnessError;
use crate::host_projection::canonical_skill_ids;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub fn canonical_skill_path(legion_root: &Path, id: &str) -> PathBuf {
    legion_root.join("skills").join(id)
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
            if fs::canonicalize(&resolved).ok()
                == fs::canonicalize(canonical_path).ok()
                && dest_path.join("SKILL.md").is_file()
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
    let mut plan = Vec::new();
    for id in &ids {
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
    for (id, canonical, dest, state) in plan {
        if state == "legion" {
            linked.push(id);
            continue;
        }
        #[cfg(unix)]
        let symlink_result = std::os::unix::fs::symlink(&canonical, &dest);
        #[cfg(windows)]
        let symlink_result = std::os::windows::fs::symlink_dir(&canonical, &dest);
        #[cfg(not(any(unix, windows)))]
        let symlink_result: Result<(), std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "symlink"));
        if symlink_result.is_ok() {
            linked.push(id);
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
        copied.push(id);
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
        "conflicts": [],
        "mode": mode,
    }))
}

pub fn verify_skill_projection(legion_root: &Path, target_dir: &Path) -> Result<Value, HarnessError> {
    let ids = canonical_skill_ids(legion_root)?;
    let mut missing = Vec::new();
    let mut forked = Vec::new();
    for id in &ids {
        let state = classify_destination(
            &target_dir.join(id),
            &canonical_skill_path(legion_root, id),
        );
        if state == "absent" {
            missing.push(id.clone());
        } else if state == "foreign" {
            forked.push(id.clone());
        }
    }
    let extra = fs::read_dir(target_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| !ids.contains(name))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "present": ids.len() - missing.len(),
        "total": ids.len(),
        "missing": missing,
        "forked": forked,
        "extra": extra,
    }))
}

pub fn unproject_skills(legion_root: &Path, target_dir: &Path) -> Result<Value, HarnessError> {
    let ids = canonical_skill_ids(legion_root)?;
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for id in &ids {
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
            fs::create_dir_all(&target).map_err(|error| HarnessError::internal(error.to_string()))?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| HarnessError::internal(error.to_string()))?;
            }
            fs::copy(entry.path(), &target)
                .map_err(|error| HarnessError::internal(error.to_string()))?;
        }
    }
    Ok(())
}
