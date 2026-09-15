use crate::descriptor::{capabilities_value, HarnessDescriptor, Mechanism};
use crate::error::HarnessError;
use crate::host_projection::capability_catalog_block;
use crate::markers::{strip_marker_block, upsert_marker_block};
use crate::skills::{project_skills, unproject_skills, verify_skill_projection};
use crate::surfaces::SURFACES;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn detect(descriptor: &HarnessDescriptor, root: &Path) -> bool {
    let rule = &descriptor.detect;
    let any_path = rule
        .any_of
        .iter()
        .any(|path| abs(root, path).is_file() || abs(root, path).is_dir());
    let any_env = rule
        .env
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()));
    any_path || any_env
}

pub fn install(
    descriptor: &HarnessDescriptor,
    root: &Path,
    legion_root: &Path,
    surfaces: Option<&[&str]>,
) -> Result<Value, HarnessError> {
    let caps = capabilities_value(descriptor)?;
    if caps.get("installOwner").and_then(Value::as_str) != Some("adapter") {
        return Ok(json!({
            "id": descriptor.id,
            "installOwner": caps.get("installOwner").cloned().unwrap_or(Value::Null),
            "wrote": [],
            "skipped": "installation owned externally (e.g. packaged plugin); use its own installer",
            "surfaces": {},
        }));
    }
    let selected: Vec<String> = surfaces
        .map(|items| items.iter().map(|item| item.to_string()).collect())
        .unwrap_or_else(|| SURFACES.iter().map(|item| item.to_string()).collect());
    let skills_location = descriptor
        .surfaces
        .get("skills")
        .and_then(|surface| surface.mechanism.path.clone());
    let mut applied = BTreeMap::new();
    let mut wrote = Vec::new();
    for surface in &selected {
        let declared = descriptor.surfaces.get(surface.as_str());
        let fidelity = declared
            .map(|value| value.fidelity.as_str())
            .unwrap_or("unsupported");
        if fidelity == "unsupported" {
            continue;
        }
        let mechanism = declared
            .map(|value| value.mechanism.clone())
            .unwrap_or_else(|| Mechanism {
                kind: "none".into(),
                path: None,
                table: None,
                key: None,
            });
        let result = match surface.as_str() {
            "instructions" => install_instructions(&mechanism, root, legion_root, skills_location.as_deref()),
            "skills" => install_skills(&mechanism, root, legion_root),
            "agents" => install_agents(&mechanism, root, legion_root),
            "mcp" => install_mcp(&mechanism, root),
            "hooks" => install_hooks(&mechanism),
            _ => Ok(json!({ "wrote": [] })),
        }?;
        applied.insert(surface.clone(), result.clone());
        if let Some(items) = result.get("wrote").and_then(Value::as_array) {
            wrote.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
    }
    Ok(json!({
        "id": descriptor.id,
        "installOwner": "adapter",
        "wrote": wrote,
        "surfaces": applied,
    }))
}

pub fn verify(descriptor: &HarnessDescriptor, root: &Path, legion_root: &Path) -> Result<Value, HarnessError> {
    let caps = capabilities_value(descriptor)?;
    let mut problems = Vec::new();
    let mut surfaces = BTreeMap::new();
    for surface in SURFACES {
        let declared = descriptor.surfaces.get(surface);
        let fidelity = caps
            .get("surfaces")
            .and_then(|value| value.get(surface))
            .and_then(|value| value.get("fidelity"))
            .and_then(Value::as_str)
            .unwrap_or("unsupported");
        if declared.is_none() || fidelity == "unsupported" {
            surfaces.insert(surface.to_string(), json!({ "fidelity": fidelity, "ok": true }));
            continue;
        }
        let mech = declared
            .map(|value| value.mechanism.clone())
            .unwrap_or_else(|| Mechanism {
                kind: "none".into(),
                path: None,
                table: None,
                key: None,
            });
        if surface == "skills" && mech.kind == "skills-dir" {
            let path = mech.path.as_deref().ok_or_else(|| HarnessError::internal("skills path missing"))?;
            let verification = verify_skill_projection(legion_root, &abs(root, path))?;
            let ok = verification
                .get("missing")
                .and_then(Value::as_array)
                .is_some_and(|items| items.is_empty())
                && verification
                    .get("forked")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.is_empty());
            if !ok {
                problems.push(json!({
                    "surface": surface,
                    "missing": verification.get("missing").cloned().unwrap_or(Value::Null),
                    "forked": verification.get("forked").cloned().unwrap_or(Value::Null),
                }));
            }
            surfaces.insert(
                surface.to_string(),
                json!({ "fidelity": fidelity, "ok": ok, "present": verification.get("present"), "total": verification.get("total"), "missing": verification.get("missing"), "forked": verification.get("forked"), "extra": verification.get("extra") }),
            );
        } else if ["instructions", "mcp", "agents"].contains(&surface) && mech.path.is_some() {
            let path = mech.path.as_deref().expect("checked");
            let ok = caps.get("installOwner").and_then(Value::as_str) != Some("adapter")
                || abs(root, path).is_file()
                || abs(root, path).is_dir();
            if !ok {
                problems.push(json!({ "surface": surface, "missing": path }));
            }
            surfaces.insert(
                surface.to_string(),
                json!({ "fidelity": fidelity, "ok": ok, "path": path }),
            );
        } else {
            let note = if mech.kind == "plugin" {
                "owned by packaged plugin"
            } else {
                ""
            };
            surfaces.insert(
                surface.to_string(),
                json!({ "fidelity": fidelity, "ok": true, "note": if note.is_empty() { Value::Null } else { Value::String(note.into()) } }),
            );
        }
    }
    Ok(json!({
        "id": descriptor.id,
        "installOwner": caps.get("installOwner").cloned().unwrap_or(Value::Null),
        "ok": problems.is_empty(),
        "problems": problems,
        "surfaces": surfaces,
    }))
}

pub fn uninstall(descriptor: &HarnessDescriptor, root: &Path, legion_root: &Path) -> Result<Value, HarnessError> {
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for surface in SURFACES {
        let declared = descriptor.surfaces.get(surface);
        if declared.is_none() {
            continue;
        }
        let mech = &declared.expect("checked").mechanism;
        if surface == "skills" && mech.kind == "skills-dir" {
            let path = mech.path.as_deref().ok_or_else(|| HarnessError::internal("skills path missing"))?;
            let result = unproject_skills(legion_root, &abs(root, path))?;
            if let Some(items) = result.get("removed").and_then(Value::as_array) {
                removed.extend(
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|id| format!("{path}/{id}")),
                );
            }
            if let Some(items) = result.get("kept").and_then(Value::as_array) {
                kept.extend(items.iter().cloned());
            }
        } else if surface == "instructions" && mech.path.is_some() {
            let path = abs(root, mech.path.as_deref().expect("checked"));
            if path.is_file() {
                let before = fs::read_to_string(&path).map_err(|error| HarnessError::internal(error.to_string()))?;
                let stripped = strip_marker_block(&before);
                if stripped != before {
                    fs::write(&path, stripped).map_err(|error| HarnessError::internal(error.to_string()))?;
                    removed.push(mech.path.clone().expect("checked"));
                }
            }
        } else if surface == "agents" && mech.kind == "dir" && mech.path.is_some() {
            let target = abs(root, mech.path.as_deref().expect("checked"));
            let source = legion_root.join("agents");
            if target.is_dir() && source.is_dir() {
                for entry in fs::read_dir(&source).map_err(|error| HarnessError::internal(error.to_string()))? {
                    let entry = entry.map_err(|error| HarnessError::internal(error.to_string()))?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !name.ends_with(".md") {
                        continue;
                    }
                    let dest = target.join(&name);
                    let source_file = source.join(&name);
                    if !dest.is_file() {
                        continue;
                    }
                    let left = fs::read(&dest).map_err(|error| HarnessError::internal(error.to_string()))?;
                    let right = fs::read(&source_file).map_err(|error| HarnessError::internal(error.to_string()))?;
                    if left == right {
                        fs::remove_file(&dest).map_err(|error| HarnessError::internal(error.to_string()))?;
                        removed.push(format!("{}/{name}", mech.path.as_deref().expect("checked")));
                    } else {
                        kept.push(json!({
                            "surface": surface,
                            "path": format!("{}/{name}", mech.path.as_deref().expect("checked")),
                            "reason": "not a Legion projection",
                        }));
                    }
                }
            }
        } else if surface == "mcp" && mech.path.is_some() {
            let path = abs(root, mech.path.as_deref().expect("checked"));
            if !path.is_file() {
                continue;
            }
            if mech.kind == "json" {
                let mut doc = read_json_or_refuse(&path, "mcp")?;
                let key = mech.key.clone().unwrap_or_else(|| "mcpServers".into());
                if let Some(servers) = doc.get_mut(&key).and_then(|value| value.as_object_mut()) {
                    if servers.remove("legion").is_some() {
                        if servers.is_empty() {
                            doc.as_object_mut().expect("object").remove(&key);
                        }
                        write_json_pretty(&path, &doc)?;
                        removed.push(format!("{}#{}.legion", mech.path.as_deref().expect("checked"), key));
                    }
                }
            } else if mech.kind == "toml" {
                assert_plausible_toml(&path, "mcp")?;
                let table = mech.table.clone().unwrap_or_else(|| "mcp_servers".into());
                let before = fs::read_to_string(&path).map_err(|error| HarnessError::internal(error.to_string()))?;
                let after = remove_legion_toml_block(&before, &table);
                if after != before {
                    if after.trim().is_empty() {
                        fs::remove_file(&path).map_err(|error| HarnessError::internal(error.to_string()))?;
                    } else {
                        fs::write(&path, after.trim_start_matches('\n'))
                            .map_err(|error| HarnessError::internal(error.to_string()))?;
                    }
                    removed.push(format!("{}#{}.legion", mech.path.as_deref().expect("checked"), table));
                }
            }
        }
    }
    Ok(json!({ "id": descriptor.id, "removed": removed, "kept": kept }))
}

fn install_instructions(
    mech: &Mechanism,
    root: &Path,
    legion_root: &Path,
    skills_location: Option<&str>,
) -> Result<Value, HarnessError> {
    if mech.kind != "agents-md" && mech.kind != "native-file" {
        return Ok(json!({ "wrote": [] }));
    }
    let path = abs(root, mech.path.as_deref().expect("instructions path"));
    let catalog = capability_catalog_block(legion_root)?;
    let skills_line = format!(
        "Domain expertise ships as Agent Skills packages under `{}`;",
        skills_location.unwrap_or(".agents/skills")
    );
    let block = [
        "# Legion",
        "",
        "Legion authority routing is active. Use it for repository or system-state changes.",
        skills_line.as_str(),
        "read the matching SKILL.md before using a capability. The catalog below is a",
        "pointer to those packages, not a copy of their method.",
        "",
        catalog.as_str(),
    ]
    .join("\n")
    .trim()
    .to_string();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| HarnessError::internal(error.to_string()))?;
    }
    let existing = if path.is_file() {
        fs::read_to_string(&path).map_err(|error| HarnessError::internal(error.to_string()))?
    } else {
        String::new()
    };
    fs::write(&path, upsert_marker_block(&existing, &block))
        .map_err(|error| HarnessError::internal(error.to_string()))?;
    Ok(json!({ "wrote": [mech.path.clone().expect("path")] }))
}

fn install_skills(mech: &Mechanism, root: &Path, legion_root: &Path) -> Result<Value, HarnessError> {
    if mech.kind != "skills-dir" {
        return Ok(json!({ "wrote": [] }));
    }
    let target = abs(root, mech.path.as_deref().expect("skills path"));
    let skills = project_skills(legion_root, &target, true)?;
    Ok(json!({ "wrote": [mech.path.clone().expect("path")], "skills": skills }))
}

fn install_agents(mech: &Mechanism, root: &Path, legion_root: &Path) -> Result<Value, HarnessError> {
    if mech.kind != "dir" {
        return Ok(json!({ "wrote": [] }));
    }
    let target = abs(root, mech.path.as_deref().expect("agents path"));
    fs::create_dir_all(&target).map_err(|error| HarnessError::internal(error.to_string()))?;
    let source = legion_root.join("agents");
    let mut wrote = Vec::new();
    if source.is_dir() {
        let files = fs::read_dir(&source)
            .map_err(|error| HarnessError::internal(error.to_string()))?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".md"))
            .collect::<Vec<_>>();
        for file in &files {
            let dest = target.join(file);
            let source_file = source.join(file);
            if dest.is_file() {
                let left = fs::read(&dest).map_err(|error| HarnessError::internal(error.to_string()))?;
                let right = fs::read(&source_file).map_err(|error| HarnessError::internal(error.to_string()))?;
                if left != right {
                    return Err(HarnessError::conflict(format!(
                        "agents: refused to write {}: an existing file with this name is not a Legion projection",
                        dest.display()
                    )));
                }
            }
        }
        for file in files {
            let dest = target.join(&file);
            fs::copy(source.join(&file), &dest)
                .map_err(|error| HarnessError::internal(error.to_string()))?;
            wrote.push(format!("{}/{file}", mech.path.as_deref().expect("path")));
        }
    }
    Ok(json!({ "wrote": wrote }))
}

fn install_mcp(mech: &Mechanism, root: &Path) -> Result<Value, HarnessError> {
    let server = mcp_server_command();
    if mech.kind == "json" {
        let path = abs(root, mech.path.as_deref().expect("mcp path"));
        let mut doc = read_json_or_refuse(&path, "mcp")?;
        let key = mech.key.clone().unwrap_or_else(|| "mcpServers".into());
        let mut servers = doc
            .get(&key)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        servers.insert("legion".into(), server);
        doc.as_object_mut()
            .expect("object")
            .insert(key.clone(), Value::Object(servers));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| HarnessError::internal(error.to_string()))?;
        }
        write_json_pretty(&path, &doc)?;
        return Ok(json!({ "wrote": [mech.path.clone().expect("path")] }));
    }
    if mech.kind == "toml" {
        let path = abs(root, mech.path.as_deref().expect("mcp path"));
        let table = mech.table.clone().unwrap_or_else(|| "mcp_servers".into());
        assert_plausible_toml(&path, "mcp")?;
        let args = server
            .get("args")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let args_toml = args
            .iter()
            .map(|value| value.as_str().map(|item| json!(item).to_string()).unwrap_or_else(|| value.to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        let command = server
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("legion");
        let block = format!(
            "\n[{table}.legion]\ncommand = {command}\nargs = [{args_toml}]\n",
            command = serde_json::to_string(command).map_err(|error| HarnessError::internal(error.to_string()))?
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| HarnessError::internal(error.to_string()))?;
        }
        let existing = if path.is_file() {
            fs::read_to_string(&path).map_err(|error| HarnessError::internal(error.to_string()))?
        } else {
            String::new()
        };
        let header = format!("[{table}.legion]");
        let found = existing.lines().any(|line| line.trim() == header);
        let collapsed = remove_legion_toml_block(&existing, &table);
        let next = if found {
            format!("{}{}", collapsed.trim_end_matches('\n'), block)
        } else {
            existing + &block
        };
        fs::write(&path, next).map_err(|error| HarnessError::internal(error.to_string()))?;
        return Ok(json!({ "wrote": [mech.path.clone().expect("path")] }));
    }
    Ok(json!({ "wrote": [] }))
}

fn install_hooks(_mech: &Mechanism) -> Result<Value, HarnessError> {
    Ok(json!({ "wrote": [] }))
}

fn mcp_server_command() -> Value {
    json!({ "command": "legion", "args": ["serve", "--stdio"] })
}

fn abs(root: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    }
}

fn read_json_or_refuse(path: &Path, surface: &str) -> Result<Value, HarnessError> {
    if !path.is_file() {
        return Ok(json!({}));
    }
    let text = fs::read_to_string(path).map_err(|error| HarnessError::internal(error.to_string()))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).map_err(|error| {
        HarnessError::conflict(format!(
            "{surface}: refused to write {path}: existing JSON does not parse ({error}); fix or move it, Legion will not overwrite it",
            path = path.display()
        ))
    })
}

fn write_json_pretty(path: &Path, value: &Value) -> Result<(), HarnessError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| HarnessError::internal(error.to_string()))?;
    fs::write(path, format!("{rendered}\n"))
        .map_err(|error| HarnessError::internal(error.to_string()))
}

fn assert_plausible_toml(path: &Path, surface: &str) -> Result<(), HarnessError> {
    if !path.is_file() {
        return Ok(());
    }
    let text = fs::read_to_string(path).map_err(|error| HarnessError::internal(error.to_string()))?;
    let multi = ["\"\"\"", "'''"];
    let mut in_multiline = false;
    for raw in text.lines() {
        let line = raw.trim();
        if in_multiline {
            if multi.iter().any(|marker| line.contains(marker)) {
                in_multiline = false;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if Regex::new(r"^(?:\[[^\]]+\]|\[\[[^\]]+\]\])$")
            .expect("regex")
            .is_match(line)
        {
            continue;
        }
        if Regex::new(r#"^(?:"(?:\\.|[^"\\])*"|'[^']*'|[A-Za-z0-9_.-]+)\s*="#)
            .expect("regex")
            .is_match(line)
        {
            if multi.iter().any(|marker| line.trim_end().ends_with(marker)) {
                in_multiline = true;
            }
            continue;
        }
        if line.starts_with(']')
            || line.starts_with('}')
            || line.ends_with(',')
            || line.ends_with('[')
            || line.ends_with('{')
        {
            continue;
        }
        return Err(HarnessError::conflict(format!(
            "{surface}: refused to write {}: existing TOML does not parse as TOML near: {}",
            path.display(),
            line.chars().take(60).collect::<String>()
        )));
    }
    Ok(())
}

fn remove_legion_toml_block(input: &str, table: &str) -> String {
    let header = format!("[{table}.legion]");
    let lines = input.lines().collect::<Vec<_>>();
    let mut output = Vec::new();
    let mut skipping = false;
    for line in lines {
        if line.trim() == header {
            skipping = true;
            continue;
        }
        if skipping && line.trim_start().starts_with('[') {
            skipping = false;
        }
        if !skipping {
            output.push(line);
        }
    }
    let mut rendered = output.join("\n");
    if input.ends_with('\n') && !rendered.is_empty() {
        rendered.push('\n');
    }
    rendered
}
