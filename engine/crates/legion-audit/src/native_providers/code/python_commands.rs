//! Frozen Python SDK inputs & explicit package/v1 PEP517 wheel contract.
//! No installer, backend fallback or production admission is supplied here.
use super::*;
use std::io::{Read, Write};
const MAX_FILES: usize = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST: u64 = 2 * 1024 * 1024;

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn bounded(path: &Path, remaining: u64) -> Result<Vec<u8>, String> {
    let before = std::fs::symlink_metadata(path).map_err(|_| "python-input-unreadable")?;
    if !before.is_file() || before.len() > remaining {
        return Err("python-input-type-or-limit".into());
    }
    let mut f = std::fs::File::open(path).map_err(|_| "python-input-unreadable")?;
    let opened = f.metadata().map_err(|_| "python-input-unreadable")?;
    if opened.len() != before.len() || opened.modified().ok() != before.modified().ok() {
        return Err("python-input-changed".into());
    }
    let mut bytes = Vec::new();
    (&mut f)
        .take(remaining + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "python-input-unreadable")?;
    let after = std::fs::symlink_metadata(path).map_err(|_| "python-input-unreadable")?;
    if bytes.len() as u64 > remaining
        || bytes.len() as u64 != before.len()
        || !after.is_file()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err("python-input-changed-or-limit".into());
    }
    Ok(bytes)
}
fn file(root: &Path, path: &str, remaining: u64) -> Result<Vec<u8>, String> {
    if !relative(path) {
        return Err("python-input-path".into());
    }
    let mut full = root.to_path_buf();
    for part in Path::new(path).components() {
        full.push(part.as_os_str());
        if std::fs::symlink_metadata(&full)
            .map_err(|_| "python-input-unreadable")?
            .file_type()
            .is_symlink()
        {
            return Err("python-input-symlink".into());
        }
    }
    bounded(&full, remaining)
}
pub(super) fn stage(
    root: &Path,
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
) -> Result<(PathBuf, String), String> {
    if entries.is_empty() || entries.len() > MAX_FILES {
        return Err("python-input-count".into());
    }
    let root = std::fs::canonicalize(root).map_err(|_| "python-root")?;
    let base = scratch.cache_dir().join("python-sdk");
    std::fs::create_dir(&base).map_err(|_| "python-stage-not-fresh")?;
    let stage = base.join("source");
    std::fs::create_dir(&stage).map_err(|_| "python-stage-create")?;
    let mut total = 0u64;
    let mut files = BTreeMap::new();
    for entry in entries {
        let bytes = file(&root, &entry.path, MAX_BYTES.saturating_sub(total))?;
        let hash = sha256_text(&bytes);
        if entry.digest.as_deref() != Some(hash.as_str())
            || files.insert(entry.path.clone(), hash).is_some()
        {
            return Err("python-frozen-digest-or-duplicate".into());
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("python-input-limit")?;
        let dest = stage.join(&entry.path);
        std::fs::create_dir_all(dest.parent().ok_or("python-stage-path")?)
            .map_err(|_| "python-stage-create")?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .and_then(|mut f| f.write_all(&bytes))
            .map_err(|_| "python-stage-write")?;
    }
    let bytes = serde_json::to_vec(
        &json!({"schema":"legion-python-frozen-inputs/1","originalRoot":root,"files":files}),
    )
    .map_err(|_| "python-manifest")?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err("python-manifest-limit".into());
    }
    std::fs::write(base.join("inputs.json"), &bytes).map_err(|_| "python-manifest")?;
    Ok((
        std::fs::canonicalize(stage).map_err(|_| "python-stage-path")?,
        sha256_text(&bytes),
    ))
}
fn staged_inventory(root: &Path, expected: &serde_json::Map<String, Value>) -> Result<(), String> {
    fn walk(
        root: &Path,
        path: &Path,
        files: &mut BTreeSet<String>,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        *nodes += 1;
        if *nodes > MAX_FILES * 4 || depth > 64 {
            return Err("python-stage-inventory-limit".into());
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "python-stage-unreadable")?;
        if metadata.is_dir() {
            for child in std::fs::read_dir(path).map_err(|_| "python-stage-unreadable")? {
                walk(
                    root,
                    &child.map_err(|_| "python-stage-unreadable")?.path(),
                    files,
                    nodes,
                    depth + 1,
                )?;
            }
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "python-stage-path")?
                .to_str()
                .ok_or("python-stage-path")?;
            files.insert(relative.to_owned());
        } else {
            return Err("python-stage-unfrozen-link-or-special".into());
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    walk(root, root, &mut files, &mut 0, 0)?;
    if files != expected.keys().cloned().collect() {
        return Err("python-stage-unfrozen-file".into());
    }
    Ok(())
}

pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let stage = Path::new(&command.cwd_rel);
    if !stage.is_absolute() {
        return Err("python-stage-path".into());
    }
    let raw = bounded(
        &stage
            .parent()
            .ok_or("python-stage-path")?
            .join("inputs.json"),
        MAX_MANIFEST,
    )?;
    if command.source_digest.as_deref() != Some(sha256_text(&raw).as_str()) {
        return Err("python-input-manifest-changed".into());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|_| "python-input-manifest")?;
    if value["schema"] != "legion-python-frozen-inputs/1" {
        return Err("python-input-manifest".into());
    }
    let original = Path::new(
        value["originalRoot"]
            .as_str()
            .ok_or("python-original-root")?,
    );
    let files = value["files"]
        .as_object()
        .filter(|m| !m.is_empty() && m.len() <= MAX_FILES)
        .ok_or("python-input-count")?;
    staged_inventory(stage, files)?;
    let mut observed = Vec::new();
    for root in [original, stage] {
        let mut total = 0u64;
        let mut actual = BTreeMap::new();
        for (path, expected) in files {
            let bytes = file(root, path, MAX_BYTES.saturating_sub(total))?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("python-input-limit")?;
            let hash = sha256_text(&bytes);
            if expected.as_str() != Some(hash.as_str()) {
                return Err("python-source-changed".into());
            }
            actual.insert(path.clone(), hash);
        }
        observed.push(actual);
    }
    Ok(
        json!({"schema":"legion-python-input-snapshot/1","manifestDigest":sha256_text(&raw),"originalRoot":original,
        "stageRoot":stage,"originalFiles":observed[0],"stagedFiles":observed[1]}),
    )
}
fn command(
    tool: &'static str,
    programs: &'static [&'static str],
    stage: &Path,
    hash: &str,
    args: Vec<String>,
    parser: Parser,
    accepted: &'static [i32],
) -> Planned {
    Planned {
        tool,
        programs,
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: stage.to_string_lossy().into_owned(),
        args,
        parser,
        accepted,
        env: vec![("PYTHONSAFEPATH", "1".into())],
        diagnostics_on_stderr: false,
        source_path: None,
        source_digest: Some(hash.into()),
    }
}
pub(super) fn extend(
    entries: &[InventoryEntry],
    scratch: &AuditScratch,
    stage: &Path,
    hash: &str,
    plan: &mut Plan,
) {
    let configured = !dirs_named(entries, PYTHON_PROJECT_FILES).is_empty();
    if configured {
        plan.commands.push(command(
            "type",
            &["mypy"],
            stage,
            hash,
            vec![
                "--no-incremental".into(),
                "--cache-dir".into(),
                scratch
                    .cache_dir()
                    .join("mypy")
                    .to_string_lossy()
                    .into_owned(),
                "--no-color-output".into(),
                "--show-error-codes".into(),
                "--no-pretty".into(),
                ".".into(),
            ],
            Parser::Mypy,
            &[0, 1],
        ));
    } else {
        plan.not_planned.insert("type", "no-config");
    }
    let tests = entries.iter().any(|e| {
        let p = e.path.as_str();
        p.ends_with(".py")
            && (p.starts_with("test_") || p.starts_with("tests/") || p.starts_with("test/"))
    });
    let configured_tests = entries
        .iter()
        .filter(|e| {
            matches!(
                file_name(&e.path),
                "pyproject.toml" | "pytest.ini" | "tox.ini" | "setup.cfg"
            )
        })
        .any(|e| {
            file(stage, &e.path, MAX_MANIFEST)
                .ok()
                .is_some_and(|b| String::from_utf8_lossy(&b).contains("pytest"))
        });
    if tests || configured_tests {
        plan.commands.push(command(
            "test",
            &["pytest"],
            stage,
            hash,
            vec![
                "--assert=plain".into(),
                "-o".into(),
                format!("cache_dir={}", scratch.cache_dir().join("pytest").display()),
                "--basetemp".into(),
                scratch
                    .tmp_dir()
                    .join("pytest")
                    .to_string_lossy()
                    .into_owned(),
            ],
            Parser::Process,
            &[0],
        ));
    } else {
        plan.not_planned.insert("test", "no-tests-or-config");
    }
    let packages = dirs_named(entries, &["pyproject.toml"]);
    if packages.is_empty() {
        plan.not_planned
            .insert("package", "python-package-backend-not-declared");
    }
    for (index, dir) in packages.into_iter().enumerate() {
        if index >= MAX_ROOTS {
            plan.notes.push("python-package-root-limit".into());
            plan.not_planned
                .insert("package", "python-package-root-limit");
            break;
        }
        let root = stage.join(&dir);
        let parsed = file(
            stage,
            &if dir.is_empty() {
                "pyproject.toml".into()
            } else {
                format!("{dir}/pyproject.toml")
            },
            MAX_MANIFEST,
        )
        .ok()
        .and_then(|bytes| toml::from_str::<toml::Value>(std::str::from_utf8(&bytes).ok()?).ok());
        let Some(parsed) = parsed else {
            plan.not_planned
                .insert("package", "python-package-manifest-malformed");
            continue;
        };
        let valid = parsed
            .get("build-system")
            .and_then(toml::Value::as_table)
            .is_some_and(|build| {
                build
                    .get("build-backend")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                    && build
                        .get("requires")
                        .and_then(toml::Value::as_array)
                        .is_some_and(|a| {
                            !a.is_empty()
                                && a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                        })
                    && build.get("backend-path").is_none_or(|v| {
                        v.as_array().is_some_and(|a| {
                            a.iter().all(|v| {
                                v.as_str()
                                    .is_some_and(|p| relative(p) && root.join(p).is_dir())
                            })
                        })
                    })
            });
        let metadata = parsed
            .get("project")
            .and_then(toml::Value::as_table)
            .and_then(|p| {
                Some((
                    p.get("name")?.as_str()?.to_owned(),
                    p.get("version")?.as_str()?.to_owned(),
                ))
            });
        let Some((name, version)) = metadata.filter(|_| valid) else {
            plan.not_planned.insert(
                "package",
                "python-package-declared-backend-or-static-metadata-unavailable",
            );
            continue;
        };
        let output = scratch.cache_dir().join(format!("python-wheels-{index}"));
        if std::fs::create_dir(&output).is_err() {
            plan.not_planned
                .insert("package", "python-wheel-output-not-fresh");
            continue;
        }
        plan.commands.push(command(
            "package",
            &["python3", "python"],
            stage,
            hash,
            vec![
                "-I".into(),
                "-B".into(),
                "-m".into(),
                "build".into(),
                "--wheel".into(),
                "--no-isolation".into(),
                "--outdir".into(),
                output.to_string_lossy().into_owned(),
                root.to_string_lossy().into_owned(),
            ],
            Parser::Process,
            &[0],
        ));
        plan.commands.push(command(
            "package",
            &["python3", "python"],
            stage,
            hash,
            vec![
                "-I".into(),
                "-B".into(),
                "-c".into(),
                WHEEL_INSPECT.into(),
                output.to_string_lossy().into_owned(),
                name,
                version,
                hash.into(),
            ],
            Parser::PythonWheel,
            &[0],
        ));
    }
}

// Actual stdlib validation runs through the same SDK, after actual build. No
// wheel or metadata is synthesized; every RECORD member must hash actual bytes.
const WHEEL_INSPECT: &str = r#"
import base64,csv,email.parser,hashlib,io,json,pathlib,re,sys,zipfile
out,name,version,source = sys.argv[1:]
outpath=pathlib.Path(out)
if outpath.is_symlink() or outpath.resolve()!=outpath: raise ValueError('wheel output path')
items=list(outpath.iterdir())
if len(items)!=1 or items[0].suffix!='.whl' or items[0].is_symlink(): raise ValueError('one genuine wheel required')
p=items[0]
if p.stat().st_size>64*1024*1024: raise ValueError('wheel size limit')
with zipfile.ZipFile(p) as z:
    infos=z.infolist()
    if not infos or len(infos)>4096 or len({i.filename for i in infos})!=len(infos): raise ValueError('wheel inventory')
    if sum(i.file_size for i in infos)>64*1024*1024: raise ValueError('wheel expanded size')
    for i in infos:
        s=pathlib.PurePosixPath(i.filename)
        if str(s)!=i.filename.rstrip('/') or s.is_absolute() or '..' in s.parts or '\x00' in i.filename or '\\' in i.filename or (i.external_attr>>16)&0o170000==0o120000: raise ValueError('wheel path')
    names={i.filename for i in infos if not i.is_dir()}
    meta=[n for n in names if n.endswith('.dist-info/METADATA')]
    records=[n for n in names if n.endswith('.dist-info/RECORD')]
    wheel=[n for n in names if n.endswith('.dist-info/WHEEL')]
    if len(meta)!=1 or len(records)!=1 or len(wheel)!=1: raise ValueError('wheel metadata inventory')
    prefix=meta[0].rsplit('/',1)[0]
    if records[0]!=prefix+'/RECORD' or wheel[0]!=prefix+'/WHEEL': raise ValueError('wheel metadata roots')
    m=email.parser.BytesParser().parsebytes(z.read(meta[0]))
    normalize=lambda s: re.sub(r'[-_.]+','-',s).lower()
    if normalize(m.get('Name',''))!=normalize(name) or m.get('Version')!=version or not m.get('Metadata-Version'): raise ValueError('wheel metadata identity')
    w=email.parser.BytesParser().parsebytes(z.read(wheel[0]))
    if not w.get('Wheel-Version','').startswith('1.') or not w.get_all('Tag'): raise ValueError('wheel format')
    rows=list(csv.reader(io.StringIO(z.read(records[0]).decode('utf-8'))))
    if len(rows)!=len(names) or len({r[0] for r in rows if r})!=len(rows): raise ValueError('wheel RECORD inventory')
    observed={}
    for row in rows:
        if len(row)!=3 or row[0] not in names: raise ValueError('wheel RECORD member')
        key,h,size=row
        b=z.read(key)
        if key==records[0]:
            if h or size: raise ValueError('wheel RECORD self hash')
        else:
            if not h.startswith('sha256=') or size!=str(len(b)) or h[7:]!=base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode(): raise ValueError('wheel RECORD hash')
        observed[key]='sha256:'+hashlib.sha256(b).hexdigest()
    if set(observed)!=names: raise ValueError('wheel RECORD omission')
print(json.dumps({'schema':'legion-python-wheel/1','path':str(p),'digest':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size,'name':m['Name'],'version':m['Version'],'sourceDigest':source,'files':observed},sort_keys=True))
"#;
pub(super) fn parse_wheel(bytes: &[u8], command: &Planned) -> Result<Vec<Diag>, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "python-wheel-output-malformed")?;
    if v["schema"] != "legion-python-wheel/1"
        || v["sourceDigest"].as_str() != command.source_digest.as_deref()
        || v["bytes"].as_u64().is_none_or(|n| n == 0 || n > MAX_BYTES)
        || v["name"].as_str().is_none_or(|s| s.is_empty())
        || v["version"].as_str() != command.args.get(6).map(String::as_str)
        || v["files"].as_object().is_none_or(|m| {
            m.is_empty()
                || m.len() > MAX_FILES
                || m.iter().any(|(p, h)| {
                    !relative(p)
                        || h.as_str().is_none_or(|h| {
                            h.len() != 71
                                || !h.starts_with("sha256:")
                                || !h[7..].bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        })
    {
        return Err("python-wheel-completion-malformed".into());
    }
    let path = v["path"].as_str().ok_or("python-wheel-path")?;
    let output = command
        .args
        .get(4)
        .map(Path::new)
        .ok_or("python-wheel-path")?;
    if std::fs::canonicalize(output).ok().as_deref() != Some(output)
        || Path::new(path).parent() != Some(output)
    {
        return Err("python-wheel-output-path".into());
    }
    let raw = bounded(Path::new(path), MAX_BYTES)?;
    if v["digest"].as_str() != Some(sha256_text(&raw).as_str())
        || v["bytes"].as_u64() != Some(raw.len() as u64)
    {
        return Err("python-wheel-artifact-changed".into());
    }
    Ok(Vec::new())
}

/// Mypy text protocol includes terminal checked-file & error totals; missing,
/// truncated or malformed summaries remain a typed gap, never empty clean.
pub(super) fn parse_mypy(bytes: &[u8], exit: Option<i32>) -> Result<Vec<Diag>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "mypy-output-encoding")?;
    let clean = Regex::new(r"^Success: no issues found in ([1-9][0-9]*) source files?$")
        .expect("owned regex");
    let found=Regex::new(r"^Found ([1-9][0-9]*) errors? in [1-9][0-9]* files? \(checked [1-9][0-9]* source files?\)$").expect("owned regex");
    let diag = Regex::new(
        r"^(.+?):([1-9][0-9]*)(?::[1-9][0-9]*)?: (error|warning|note): (.+?)(?:  \[([^\]]+)\])?$",
    )
    .expect("owned regex");
    let mut summary = None;
    let mut errors = 0u64;
    let mut out = Vec::new();
    for line in text.lines() {
        if summary.is_some() {
            return Err("mypy-output-after-summary".into());
        }
        if clean.is_match(line) {
            summary = Some(0);
            continue;
        }
        if let Some(c) = found.captures(line) {
            summary = Some(c[1].parse::<u64>().map_err(|_| "mypy-summary-count")?);
            continue;
        }
        let c = diag.captures(line).ok_or("mypy-diagnostic-malformed")?;
        let severity = &c[3];
        if severity == "error" {
            errors = errors.checked_add(1).ok_or("mypy-error-count")?;
        }
        if severity != "note" {
            out.push(Diag {
                rule: format!(
                    "mypy:{}",
                    c.get(5).map(|m| m.as_str()).unwrap_or("diagnostic")
                ),
                severity: if severity == "error" {
                    "error"
                } else {
                    "warning"
                },
                path: c[1].into(),
                line: c[2].parse::<usize>().map_err(|_| "mypy-diagnostic-line")?,
                message: shorten(&c[4]),
            });
        }
    }
    if summary != Some(errors) || !matches!(exit, Some(0 | 1)) || (exit == Some(0)) != (errors == 0)
    {
        return Err("mypy-completion-mismatch".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staged_inventory_rejects_generated_unfrozen_code() {
        let base = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let root = base.join(format!(
            "legion-python-stage-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.py"), b"pass\n").unwrap();
        let expected = json!({"app.py": sha256_text(b"pass\n")});
        assert!(staged_inventory(&root, expected.as_object().unwrap()).is_ok());
        std::fs::write(root.join("generated_backend.py"), b"pass\n").unwrap();
        assert_eq!(
            staged_inventory(&root, expected.as_object().unwrap()).unwrap_err(),
            "python-stage-unfrozen-file"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mypy_completion_requires_terminal_reconciled_summary() {
        assert!(
            parse_mypy(b"Success: no issues found in 2 source files\n", Some(0))
                .unwrap()
                .is_empty()
        );
        assert_eq!(parse_mypy(b"a.py:2: error: Wrong value  [assignment]\nFound 1 error in 1 file (checked 2 source files)\n",Some(1)).unwrap().len(),1);
        for (raw, exit) in [
            ("", 0),
            ("Success: no issues found in 0 source files\n", 0),
            ("a.py:1: error: Wrong\n", 1),
            ("Found 1 error in 1 file (checked 2 source files)\n", 1),
            ("Success: no issues found in 2 source files\ntrailing\n", 0),
            ("Success: no issues found in 2 source files\n", 1),
        ] {
            assert!(parse_mypy(raw.as_bytes(), Some(exit)).is_err(), "{raw}");
        }
    }
}
