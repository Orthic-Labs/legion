// CI enrollment of the pinned native linters (Oxlint, Biome) for A07.
//
// Takes pre-downloaded release assets (the download is a single `curl` in
// scripts/ci/right-git-ci.sh), then fails closed unless: the asset sha256
// equals the pin in `src/registry/native-lint-pins.json`; the archive holds
// exactly one top-level regular file within size bounds; `--version` equals
// the pin; and every `NATIVE_RULES` id resolves in the binary. Writes
// `enrollment.json` (consumed by the ignored Rust test
// `real_native_lint_qualification`) with raw output digests. Never runs locally.

use legion_audit::native_providers::code::javascript_native::NATIVE_RULES;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CATALOG: &str = "src/registry/native-lint-pins.json";
const MAX_ASSET: u64 = 256 * 1024 * 1024;
const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn host_platform() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("macos", "x86_64") => Ok("darwin-x64"),
        ("linux", "x86_64") => Ok("linux-x64"),
        ("windows", "x86_64") => Ok("windows-x64"),
        (os, arch) => Err(format!("unsupported host {os}/{arch}")),
    }
}

/// Fail closed unless the bytes match the pinned `sha256:<64 hex>` digest.
pub fn verify_digest(tool: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let well_formed = expected.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    if !well_formed {
        return Err(format!("{tool}: malformed catalog digest"));
    }
    let actual = sha(bytes);
    if actual != expected {
        return Err(format!(
            "{tool}: asset digest mismatch (got {actual}, pinned {expected})"
        ));
    }
    Ok(())
}

/// A member name is acceptable only as one plain top-level file name.
fn single_component(name: &str) -> Option<String> {
    let mut parts = Path::new(name)
        .components()
        .filter(|c| !matches!(c, Component::CurDir));
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(part)), None) => part.to_str().map(str::to_string),
        _ => None,
    }
}

fn read_bounded(reader: &mut dyn Read, size: u64, what: &str) -> Result<Vec<u8>, String> {
    if size > MAX_EXECUTABLE {
        return Err(format!("{what}: member exceeds size bound"));
    }
    let mut out = Vec::new();
    reader
        .take(MAX_EXECUTABLE + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("{what}: {e}"))?;
    if out.len() as u64 > MAX_EXECUTABLE {
        return Err(format!("{what}: member exceeds size bound"));
    }
    Ok(out)
}

/// Extract exactly one top-level regular file from a `.tar.gz` or `.zip`.
/// Any traversal, absolute path, nested path, link, or extra member rejects.
pub fn extract_single(name: &str, data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    if name.ends_with(".tar.gz") {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(data));
        for entry in archive.entries().map_err(|e| format!("{name}: {e}"))? {
            let mut entry = entry.map_err(|e| format!("{name}: {e}"))?;
            let kind = entry.header().entry_type();
            let path = entry
                .path()
                .map_err(|e| format!("{name}: {e}"))?
                .to_string_lossy()
                .into_owned();
            if kind.is_dir() {
                if single_component(&path).is_some()
                    || path.trim_matches('/').is_empty()
                    || path == "./"
                {
                    continue;
                }
                return Err(format!("{name}: nested directory {path:?}"));
            }
            if !kind.is_file() {
                return Err(format!("{name}: non-regular member {path:?}"));
            }
            let file = single_component(&path)
                .ok_or_else(|| format!("{name}: unsafe or nested member {path:?}"))?;
            let size = entry.header().size().map_err(|e| format!("{name}: {e}"))?;
            found.push((file, read_bounded(&mut entry, size, name)?));
            if found.len() > 1 {
                break;
            }
        }
    } else if name.ends_with(".zip") {
        let mut zip =
            zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|e| format!("{name}: {e}"))?;
        for index in 0..zip.len() {
            let mut member = zip.by_index(index).map_err(|e| format!("{name}: {e}"))?;
            let path = member
                .name()
                .map_err(|e| format!("{name}: {e}"))?
                .into_owned();
            if member.is_dir() {
                return Err(format!("{name}: directory member {path:?}"));
            }
            if member.is_symlink() {
                return Err(format!("{name}: non-regular member {path:?}"));
            }
            let file = single_component(&path)
                .ok_or_else(|| format!("{name}: unsafe or nested member {path:?}"))?;
            let size = member.size();
            found.push((file, read_bounded(&mut member, size, name)?));
            if found.len() > 1 {
                break;
            }
        }
    } else {
        return Err(format!("{name}: unknown archive type"));
    }
    if found.len() != 1 {
        return Err(format!(
            "{name}: expected exactly one top-level file, found {}",
            found.len()
        ));
    }
    Ok(found.remove(0))
}

/// `oxlint --rules --format json` -> set of `scope/value` ids.
pub fn parse_oxlint_rules(stdout: &[u8]) -> Result<BTreeSet<String>, String> {
    let value: Value =
        serde_json::from_slice(stdout).map_err(|e| format!("oxlint rules json: {e}"))?;
    let rows = value.as_array().ok_or("oxlint rules json: not an array")?;
    let mut known = BTreeSet::new();
    for row in rows {
        let (Some(scope), Some(rule)) = (row["scope"].as_str(), row["value"].as_str()) else {
            return Err("oxlint rules json: row missing scope/value".into());
        };
        // The listing names plugins by module (`jsx_a11y`, `react_perf`);
        // configuration and rule ids use the hyphenated plugin name.
        known.insert(format!("{}/{rule}", scope.replace('_', "-")));
    }
    Ok(known)
}

/// `biome explain <name>` resolves only when it exits 0 and names the rule.
pub fn biome_explain_resolves(name: &str, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> bool {
    code == Some(0)
        && [stdout, stderr]
            .iter()
            .any(|stream| String::from_utf8_lossy(stream).contains(name))
}

fn parse_version(out: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(out);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let end = text[i..]
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .map_or(text.len(), |n| i + n);
            let parts: Vec<&str> = text[i..end].split('.').collect();
            if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
                return Some(text[i..end].to_string());
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

struct Probe {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_probe(exe: &Path, args: &[&str], retain: &Path, label: &str) -> Result<Probe, String> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", exe.display()))?;
    let mut out = child.stdout.take().ok_or("stdout pipe")?;
    let mut err = child.stderr.take().ok_or("stderr pipe")?;
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.by_ref().take(64 * 1024 * 1024).read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.by_ref().take(64 * 1024 * 1024).read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > PROBE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{label}: probe timed out"));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let stdout = out_thread.join().map_err(|_| "stdout reader panicked")?;
    let stderr = err_thread.join().map_err(|_| "stderr reader panicked")?;
    fs::write(retain.join(format!("{label}.stdout")), &stdout).map_err(|e| e.to_string())?;
    fs::write(retain.join(format!("{label}.stderr")), &stderr).map_err(|e| e.to_string())?;
    Ok(Probe {
        code: status.code(),
        stdout,
        stderr,
    })
}

fn qualify(
    tool: &str,
    entry: &Value,
    plat: &str,
    asset_path: &Path,
    rules: &[(&str, &str)],
    work: &Path,
    retain: &Path,
) -> Result<Value, String> {
    let asset = entry["assets"]
        .get(plat)
        .filter(|a| a.is_object())
        .ok_or_else(|| format!("{tool}: no pin for platform {plat}"))?;
    let field = |key: &str| {
        asset[key]
            .as_str()
            .ok_or_else(|| format!("{tool}: catalog missing {key}"))
    };
    let (name, expected, kind) = (field("name")?, field("digest")?, field("kind")?);
    let version = entry["version"]
        .as_str()
        .ok_or_else(|| format!("{tool}: catalog missing version"))?;
    let mut data = Vec::new();
    fs::File::open(asset_path)
        .and_then(|f| f.take(MAX_ASSET + 1).read_to_end(&mut data))
        .map_err(|e| format!("{tool}: read asset {}: {e}", asset_path.display()))?;
    if data.len() as u64 > MAX_ASSET {
        return Err(format!("{tool}: asset exceeds size bound"));
    }
    verify_digest(tool, &data, expected)?;
    let (file, bytes) = match kind {
        "binary" => (
            single_component(name).ok_or_else(|| format!("{tool}: unsafe asset name"))?,
            data,
        ),
        "archive" => extract_single(name, &data)?,
        other => return Err(format!("{tool}: unknown asset kind {other}")),
    };
    let dir = work.join(tool);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let exe = dir.join(file);
    fs::write(&exe, &bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let probe = run_probe(&exe, &["--version"], retain, &format!("{tool}-version"))?;
    let probed = parse_version(&probe.stdout);
    if probe.code != Some(0) || probed.as_deref() != Some(version) {
        return Err(format!(
            "{tool}: --version probe {probed:?} does not match pin {version}"
        ));
    }
    let mut rule_probe = Map::new();
    if tool == "oxlint" {
        let listing = run_probe(
            &exe,
            &["--rules", "--format", "json"],
            retain,
            "oxlint-rules",
        )?;
        if listing.code != Some(0) {
            return Err("oxlint --rules --format json failed".into());
        }
        let known = parse_oxlint_rules(&listing.stdout)?;
        for (oxlint_id, _) in rules {
            rule_probe.insert((*oxlint_id).into(), json!(known.contains(*oxlint_id)));
        }
    } else {
        for (_, biome_id) in rules {
            let rule = biome_id.rsplit('/').next().unwrap_or(biome_id);
            let out = run_probe(
                &exe,
                &["explain", rule],
                retain,
                &format!("biome-explain-{rule}"),
            )?;
            rule_probe.insert(
                (*biome_id).into(),
                json!(biome_explain_resolves(
                    rule,
                    out.code,
                    &out.stdout,
                    &out.stderr
                )),
            );
        }
    }
    let missing: Vec<&String> = rule_probe
        .iter()
        .filter(|(_, ok)| **ok != json!(true))
        .map(|(id, _)| id)
        .collect();
    if !missing.is_empty() {
        return Err(format!("{tool} {version} does not recognize: {missing:?}"));
    }
    Ok(json!({
        "path": exe.to_string_lossy(),
        "version": version,
        "platform": plat,
        "assetName": name,
        "assetUrl": asset["url"],
        "assetDigest": expected,
        "executableDigest": sha(&bytes),
        "ruleProbe": rule_probe,
    }))
}

pub fn run(root: &Path, output: Option<&Path>, list_assets: bool, assets: &[String]) -> bool {
    let result = if list_assets {
        list(root)
    } else {
        output
            .ok_or_else(|| "--output-root is required".to_string())
            .and_then(|o| enroll(root, o, assets))
    };
    match result {
        Ok(line) => {
            println!("{line}");
            true
        }
        Err(err) => {
            eprintln!("native-lint-qualification: {err}");
            false
        }
    }
}

fn load_catalog(root: &Path) -> Result<Value, String> {
    let catalog: Value = serde_json::from_slice(
        &fs::read(root.join(CATALOG)).map_err(|e| format!("{CATALOG}: {e}"))?,
    )
    .map_err(|e| format!("{CATALOG}: {e}"))?;
    if catalog["schema"] != "legion-native-lint-pins/1" {
        return Err("catalog schema".into());
    }
    Ok(catalog)
}

fn list(root: &Path) -> Result<String, String> {
    let (catalog, plat) = (load_catalog(root)?, host_platform()?);
    let mut lines = Vec::new();
    for tool in ["oxlint", "biome"] {
        let url = catalog["linters"][tool]["assets"][plat]["url"]
            .as_str()
            .ok_or_else(|| format!("{tool}: no pin for platform {plat}"))?;
        if !url.starts_with("https://github.com/") {
            return Err(format!("{tool}: asset url outside allowed host"));
        }
        lines.push(format!("{tool}\t{url}"));
    }
    Ok(lines.join("\n"))
}

fn enroll(root: &Path, output: &Path, assets: &[String]) -> Result<String, String> {
    let mut paths = std::collections::BTreeMap::new();
    for spec in assets {
        let (tool, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--asset expects tool=path, got {spec:?}"))?;
        if !matches!(tool, "oxlint" | "biome") || paths.insert(tool, PathBuf::from(path)).is_some()
        {
            return Err(format!(
                "--asset tool must be oxlint or biome, once each: {spec:?}"
            ));
        }
    }
    if paths.len() != 2 {
        return Err("both --asset oxlint=<path> and --asset biome=<path> are required".into());
    }
    if output.exists()
        && fs::read_dir(output)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("output root must be empty".into());
    }
    let (work, retain) = (output.join("tools"), output.join("raw"));
    fs::create_dir_all(&retain).map_err(|e| e.to_string())?;
    let catalog = load_catalog(root)?;
    let plat = host_platform()?;
    let rules: Vec<(&str, &str)> = NATIVE_RULES.iter().map(|r| (r.oxlint, r.biome)).collect();
    if rules.len() < 18 {
        return Err(format!("NATIVE_RULES has {} rules", rules.len()));
    }
    let mut linters = Map::new();
    for tool in ["oxlint", "biome"] {
        let entry = &catalog["linters"][tool];
        linters.insert(
            tool.into(),
            qualify(tool, entry, plat, &paths[tool], &rules, &work, &retain)?,
        );
    }
    let mut raw = Map::new();
    let mut names: Vec<_> = fs::read_dir(&retain)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();
    names.sort_by_key(|e| e.file_name());
    for item in names {
        raw.insert(
            item.file_name().to_string_lossy().into_owned(),
            json!(sha(&fs::read(item.path()).map_err(|e| e.to_string())?)),
        );
    }
    let enrollment = output.join("enrollment.json");
    let record = json!({"schema": "legion-native-lint-enrollment/1", "platform": plat, "linters": linters, "rawOutputDigests": raw});
    fs::write(
        &enrollment,
        serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(enrollment.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_gz(members: &[(&str, &[u8], Option<tar::EntryType>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body, kind) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_entry_type(kind.unwrap_or(tar::EntryType::Regular));
            header.set_mode(0o755);
            // Write raw name bytes so traversal names survive the builder's checks.
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn digest_mismatch_and_malformed_pin_fail() {
        let good = sha(b"abc");
        assert!(verify_digest("t", b"abc", &good).is_ok());
        assert!(verify_digest("t", b"abd", &good)
            .unwrap_err()
            .contains("digest mismatch"));
        assert!(verify_digest("t", b"abc", "sha256:ABC")
            .unwrap_err()
            .contains("malformed"));
        assert!(verify_digest("t", b"abc", &good.replace("sha256:", "")).is_err());
    }

    #[test]
    fn single_file_archive_extracts() {
        let (name, body) =
            extract_single("x.tar.gz", &tar_gz(&[("oxlint", b"bin", None)])).unwrap();
        assert_eq!((name.as_str(), body.as_slice()), ("oxlint", &b"bin"[..]));
    }

    #[test]
    fn multi_file_and_traversal_archives_are_rejected() {
        let two = tar_gz(&[("a", b"1", None), ("b", b"2", None)]);
        assert!(extract_single("x.tar.gz", &two)
            .unwrap_err()
            .contains("exactly one"));
        for bad in ["../evil", "/abs/evil", "dir/evil", "a/../b"] {
            let archive = tar_gz(&[(bad, b"1", None)]);
            assert!(extract_single("x.tar.gz", &archive).is_err(), "{bad}");
        }
        let link = tar_gz(&[("oxlint", b"", Some(tar::EntryType::Symlink))]);
        assert!(extract_single("x.tar.gz", &link)
            .unwrap_err()
            .contains("non-regular"));
        assert!(extract_single("x.tar.gz", &tar_gz(&[]))
            .unwrap_err()
            .contains("exactly one"));
        assert!(extract_single("x.rar", b"")
            .unwrap_err()
            .contains("unknown archive"));
    }

    #[test]
    fn zip_multi_and_traversal_rejected() {
        let build = |names: &[&str]| {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for name in names {
                zip.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(b"x").unwrap();
            }
            zip.finish().unwrap().into_inner()
        };
        assert_eq!(
            extract_single("x.zip", &build(&["oxlint.exe"])).unwrap().0,
            "oxlint.exe"
        );
        assert!(extract_single("x.zip", &build(&["a", "b"])).is_err());
        assert!(extract_single("x.zip", &build(&["../a"])).is_err());
    }

    #[test]
    fn oxlint_rules_fixture_parses_and_flags_missing() {
        let fixture = br#"[{"scope":"eslint","value":"no-debugger","category":"suspicious"},
                          {"scope":"react","value":"rules-of-hooks"},
                          {"scope":"jsx_a11y","value":"alt-text"}]"#;
        let known = parse_oxlint_rules(fixture).unwrap();
        assert!(known.contains("eslint/no-debugger") && known.contains("react/rules-of-hooks"));
        assert!(known.contains("jsx-a11y/alt-text"));
        assert!(!known.contains("eslint/no-eval"));
        assert!(parse_oxlint_rules(b"{}").is_err());
        assert!(parse_oxlint_rules(br#"[{"scope":"eslint"}]"#).is_err());
    }

    #[test]
    fn biome_explain_requires_success_and_rule_name() {
        let ok = b"# noDebugger\nDisallow the use of debugger\n";
        assert!(biome_explain_resolves("noDebugger", Some(0), ok, b""));
        assert!(!biome_explain_resolves("noDebugger", Some(1), ok, b""));
        assert!(!biome_explain_resolves(
            "noDebugger",
            Some(0),
            b"nothing",
            b""
        ));
        assert!(biome_explain_resolves(
            "noDebugger",
            Some(0),
            b"",
            b"noDebugger docs"
        ));
    }

    #[test]
    fn version_parse_extracts_semver() {
        assert_eq!(
            parse_version(b"Version: 1.89.0\n").as_deref(),
            Some("1.89.0")
        );
        assert_eq!(parse_version(b"biome 2.6.2").as_deref(), Some("2.6.2"));
        assert_eq!(parse_version(b"none"), None);
    }
}
