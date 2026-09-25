//! Rust port of `scripts/finalize-macos-candidate.mjs`, including the
//! signed-runtime rebind (`packageMacosCandidate` re-invoking
//! `assemble-native-release --finalize-signed` after codesign has rewritten
//! `bin/legion`). `createPortableArchive` and the SBOM/provenance
//! materialization calls delegate to `@rightkit/release` via
//! `rightkit_release_bridge` (external package, kept in place per the T4
//! packet decision).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::assemble_native_release::{self, AssembleArgs};
use crate::prepare_unsigned_candidate::{self, CheckArgs};
use crate::rightkit_release_bridge;

const EXECUTABLES: [&str; 3] = ["legion", "legion-hook", "legion-mcp"];

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component::*;
        match component {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn assert_below(path: &Path, root: &Path, label: &str) -> Result<PathBuf, String> {
    let value = normalize_lexical(path);
    let root = normalize_lexical(root);
    if !value.starts_with(&root) || value == root {
        return Err(format!("{label} must be below {}", root.display()));
    }
    Ok(value)
}

/// Real `tar` invocation used by the default `MacosFinalizeDeps::run_tar`.
/// Exposed so tests can wrap it (record the call, then still perform it) the
/// same way the JS test's `commandRunner` wraps real `spawnSync`.
pub fn real_run_tar(args: &[String], cwd: &Path) -> Result<(i32, String, String), String> {
    let output = Command::new("tar").args(args).current_dir(cwd).output().map_err(|e| e.to_string())?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Minimal seam over the `tar` invocations `prepareMacosCandidateFinalization`
/// makes (listing, then extraction), mirroring the JS test's `commandRunner`
/// override in `tests/unsigned-release-candidate.test.mjs`.
pub struct MacosFinalizeDeps<'a> {
    pub run_tar: Box<dyn FnMut(&[String], &Path) -> Result<(i32, String, String), String> + 'a>,
}

impl<'a> Default for MacosFinalizeDeps<'a> {
    fn default() -> Self {
        Self { run_tar: Box::new(|args, cwd| real_run_tar(args, cwd)) }
    }
}

fn assert_safe_archive_entries(archive: &Path, run_tar: &mut dyn FnMut(&[String], &Path) -> Result<(i32, String, String), String>) -> Result<(), String> {
    let args = vec!["-tzf".to_string(), archive.file_name().unwrap().to_string_lossy().to_string()];
    let (status, stdout, stderr) = run_tar(&args, archive.parent().unwrap())?;
    if status != 0 {
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("candidate listing failed: {}", msg.trim()));
    }
    let listing = stdout;
    for raw in listing.split(['\n', '\r']).filter(|s| !s.is_empty()) {
        if raw == "./" || raw == "." {
            continue;
        }
        let entry = raw.strip_prefix("./").unwrap_or(raw);
        let windows_drive = Regex::new(r"^[A-Za-z]:").unwrap();
        if entry.is_empty() || entry.starts_with('/') || windows_drive.is_match(entry) || entry.split('/').any(|seg| seg == "..") {
            return Err(format!("unsafe candidate archive entry: {raw}"));
        }
    }
    Ok(())
}

fn assert_safe_tree(root: &Path, directory: &Path) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("candidate archive contains symlink: {}", path.strip_prefix(root).unwrap().display()));
        }
        if meta.is_dir() {
            assert_safe_tree(root, &path)?;
        } else if !meta.is_file() {
            return Err(format!("candidate archive contains non-file: {}", path.strip_prefix(root).unwrap().display()));
        }
    }
    Ok(())
}

fn find_release_root(extracted: &Path) -> Result<PathBuf, String> {
    let mut candidates = vec![extracted.to_path_buf()];
    for entry in fs::read_dir(extracted).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if fs::symlink_metadata(entry.path()).map(|m| m.is_dir()).unwrap_or(false) {
            candidates.push(entry.path());
        }
    }
    let matches: Vec<_> = candidates.into_iter().filter(|p| p.join("bin/legion").exists()).collect();
    if matches.len() != 1 {
        return Err("candidate archive must contain exactly one Legion release root".to_string());
    }
    Ok(matches.into_iter().next().unwrap())
}

fn executable_records(root: &Path) -> Result<Vec<Value>, String> {
    EXECUTABLES
        .iter()
        .map(|name| {
            let path = root.join("bin").join(name);
            let meta = fs::symlink_metadata(&path).map_err(|_| format!("candidate executable missing or unsafe: {name}"))?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(format!("candidate executable missing or unsafe: {name}"));
            }
            Ok(json!({ "file": format!("bin/{name}"), "sha256": sha256_file(&path)?, "sizeBytes": meta.len() }))
        })
        .collect()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

pub struct PrepareArgs {
    pub candidate_root: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub architecture: String,
    pub source_revision: Option<String>,
    pub version: Option<String>,
    pub receipt_path: Option<PathBuf>,
}

pub fn prepare_macos_candidate_finalization(repository_root: &Path, args: PrepareArgs) -> Result<Value, String> {
    prepare_macos_candidate_finalization_with(repository_root, args, &mut MacosFinalizeDeps::default())
}

pub fn prepare_macos_candidate_finalization_with(repository_root: &Path, args: PrepareArgs, deps: &mut MacosFinalizeDeps) -> Result<Value, String> {
    let candidate_root = args.candidate_root.ok_or("LEGION_UNSIGNED_CANDIDATE_ROOT or --candidate is required")?;
    let output_root = args.output_root.ok_or("--output is required")?;
    let output = assert_below(&output_root, &repository_root.join("dist/native"), "candidate extraction output")?;
    let checked = prepare_unsigned_candidate::check_unsigned_candidate(
        repository_root,
        CheckArgs {
            output_root: Some(candidate_root),
            platform: Some("macos".to_string()),
            architecture: Some(args.architecture.clone()),
            source_revision: args.source_revision.clone(),
            version: args.version.clone(),
        },
    )?;
    let archive = PathBuf::from(checked.get("archive").and_then(|v| v.as_str()).unwrap_or_default());
    assert_safe_archive_entries(&archive, deps.run_tar.as_mut())?;

    let pid = std::process::id();
    let staging = PathBuf::from(format!("{}.candidate-extract-{pid}", output.display()));
    let _ = fs::remove_dir_all(&staging);
    let _ = fs::remove_dir_all(&output);
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;

    let result: Result<(), String> = (|| {
        let archive_from_staging = pathdiff_lexical(&staging, &archive);
        let extract_args = vec!["-xzf".to_string(), archive_from_staging];
        let (status, stdout, stderr) = (deps.run_tar)(&extract_args, &staging)?;
        if status != 0 {
            let msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!("candidate extraction failed: {}", msg.trim()));
        }
        assert_safe_tree(&staging, &staging)?;
        let release_root = find_release_root(&staging)?;
        if output.exists() {
            return Err(format!("candidate extraction output already exists: {}", output.display()));
        }
        copy_dir_recursive(&release_root, &output).map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staging);
    result?;

    let files = executable_records(&output)?;
    let mut receipt = json!({
        "schema": 1,
        "kind": "legion-macos-candidate-input",
        "status": "verified",
        "candidateArchive": checked.get("archive"),
        "candidateArchiveSha256": checked.get("archiveSha256"),
        "sourceRevision": checked.get("sourceRevision"),
        "version": checked.get("version"),
        "architecture": checked.get("architecture"),
        "output": output.display().to_string(),
        "files": files,
    });
    if let Some(receipt_path) = &args.receipt_path {
        if let Some(parent) = receipt_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(receipt_path, format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap())).map_err(|e| e.to_string())?;
    }
    receipt["receipt"] = match &args.receipt_path {
        Some(p) => Value::String(p.display().to_string()),
        None => Value::Null,
    };
    Ok(receipt)
}

fn pathdiff_lexical(from: &Path, to: &Path) -> String {
    let from = normalize_lexical(from);
    let to = normalize_lexical(to);
    let from_c: Vec<_> = from.components().collect();
    let to_c: Vec<_> = to.components().collect();
    let common = from_c.iter().zip(to_c.iter()).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<String> = Vec::new();
    for _ in common..from_c.len() {
        parts.push("..".to_string());
    }
    for c in &to_c[common..] {
        parts.push(c.as_os_str().to_string_lossy().to_string());
    }
    parts.join("/")
}

pub struct PackageArgs {
    pub input_root: PathBuf,
    pub output_root: PathBuf,
    pub notarization_archive: PathBuf,
    pub version: String,
    pub architecture: String,
    pub source_revision: String,
}

/// A rebind request equivalent to the `node scripts/assemble-native-release.mjs
/// ... --finalize-signed --provenance <p>` invocation the JS `packageMacosCandidate`
/// spawned. `args` mirrors that spawned argv (minus argv[0]/the script path)
/// so tests can assert on flag positions exactly as
/// `tests/unsigned-release-candidate.test.mjs` does; `out`/`provenance` are
/// broken out for the default implementation, which calls
/// `assemble_native_release::run` in-process instead of spawning Node.
pub struct RebindRequest {
    pub args: Vec<String>,
    pub platform: String,
    pub architecture: String,
    pub target: String,
    pub out: PathBuf,
    pub bin_dir: PathBuf,
    pub provenance: String,
}

/// Minimal seam over `package_macos_candidate`'s three external calls
/// (archive creation, the signed-runtime rebind, and the notarization zip),
/// mirroring the JS test's `createArchive`/`commandRunner` overrides.
pub struct MacosPackageDeps<'a> {
    pub create_archive: Box<dyn Fn(&Path, &Path, &Path) -> Result<Value, String> + 'a>,
    pub rebind: Box<dyn FnMut(&RebindRequest) -> Result<(), String> + 'a>,
    pub run_ditto: Box<dyn FnMut(&Path, &Path) -> Result<(), String> + 'a>,
}

/// Builds the real (non-test) dependency set, bound to `repository_root`
/// (the rebind and ditto closures both need it, so this isn't a plain
/// `Default` impl).
fn real_macos_package_deps(repository_root: &Path) -> MacosPackageDeps<'_> {
    MacosPackageDeps {
        create_archive: Box::new(|root, src, out| rightkit_release_bridge::create_portable_archive(root, src, out)),
        rebind: Box::new(move |req| {
            assemble_native_release::run(
                repository_root,
                AssembleArgs {
                    platform: Some(req.platform.clone()),
                    architecture: Some(req.architecture.clone()),
                    profile: Some("release".to_string()),
                    target: Some(req.target.clone()),
                    bin_dir: Some(req.bin_dir.clone()),
                    out: Some(req.out.clone()),
                    force: false,
                    finalize_signed: true,
                    provenance: Some(req.provenance.clone()),
                },
            )
            .map(|_| ())
            .map_err(|e| format!("signed macOS rebind failed: {e}"))
        }),
        run_ditto: Box::new(move |input, notary_zip| {
            let zipped = Command::new("ditto")
                .args(["-c", "-k", "--keepParent"])
                .arg(input)
                .arg(notary_zip)
                .current_dir(repository_root)
                .output()
                .map_err(|e| e.to_string())?;
            if !zipped.status.success() {
                let msg = if !zipped.stderr.is_empty() { zipped.stderr } else { zipped.stdout };
                return Err(format!("notarization archive failed: {}", String::from_utf8_lossy(&msg).trim()));
            }
            Ok(())
        }),
    }
}

pub fn package_macos_candidate(repository_root: &Path, args: PackageArgs) -> Result<Value, String> {
    let mut deps = real_macos_package_deps(repository_root);
    package_macos_candidate_with(repository_root, args, &mut deps)
}

pub fn package_macos_candidate_with(repository_root: &Path, args: PackageArgs, deps: &mut MacosPackageDeps) -> Result<Value, String> {
    let input = assert_below(&args.input_root, &repository_root.join("dist/native"), "signed macOS input")?;
    let output = assert_below(&args.output_root, &repository_root.join("dist/releases/mac"), "signed macOS output")?;
    let notary_zip = assert_below(&args.notarization_archive, &repository_root.join(".right-release/notary"), "notarization archive")?;
    if !Regex::new(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$").unwrap().is_match(&args.version) {
        return Err("stable version is required".to_string());
    }
    if !Regex::new(r"(?i)^[a-f0-9]{40,64}$").unwrap().is_match(&args.source_revision) {
        return Err("source revision is required".to_string());
    }
    executable_records(&input)?;

    // codesign rewrote bin/legion after assembly, so release.json and
    // composition.json still bind the unsigned digest and `legion setup
    // repair` refuses the install. Rebind them to the signed runtime, as
    // Windows does through nativeAssembly.finalizer, before anything is
    // archived.
    let signed_runtime = sha256_file(&input.join("bin/legion"))?;
    let target = if args.architecture == "arm64" { "aarch64-apple-darwin".to_string() } else { "x86_64-apple-darwin".to_string() };
    let provenance = format!("rightkit-release://macos-{}/{signed_runtime}", args.architecture);
    let bin_dir = input.join("bin");
    let rebind_request = RebindRequest {
        args: vec![
            "--profile".to_string(), "release".to_string(),
            "--platform".to_string(), "macos".to_string(),
            "--architecture".to_string(), args.architecture.clone(),
            "--target".to_string(), target.clone(),
            "--out".to_string(), input.display().to_string(),
            "--bin-dir".to_string(), bin_dir.display().to_string(),
            "--finalize-signed".to_string(),
            "--provenance".to_string(), provenance.clone(),
        ],
        platform: "macos".to_string(),
        architecture: args.architecture.clone(),
        target,
        out: input.clone(),
        bin_dir,
        provenance,
    };
    (deps.rebind)(&rebind_request)?;

    let bound: Value = serde_json::from_str(&fs::read_to_string(input.join("share/legion/release.json")).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let bound_runtime = bound.get("runtime").and_then(|r| r.get("sha256")).and_then(|v| v.as_str()).unwrap_or_default();
    if bound_runtime != signed_runtime {
        return Err(format!("signed macOS release.json binds {bound_runtime}, runtime is {signed_runtime}"));
    }

    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    fs::create_dir_all(notary_zip.parent().unwrap()).map_err(|e| e.to_string())?;
    let stem = format!("legion-{}-macos-{}", args.version, args.architecture);
    let archive = output.join(format!("{stem}.tar.gz"));
    let sbom = output.join(format!("{stem}.cdx.json"));
    let provenance = output.join(format!("{stem}.intoto.jsonl"));

    (deps.create_archive)(repository_root, &input, &archive)?;

    (deps.run_ditto)(&input, &notary_zip)?;
    if !notary_zip.is_file() {
        return Err(format!("notarization archive missing: {}", notary_zip.display()));
    }

    let created_at = std::time::SystemTime::now();
    let created_at_iso = {
        let dur = created_at.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        crate::prepare_unsigned_candidate::iso8601_utc_millis(dur.as_secs() as i64, dur.subsec_millis())
    };
    let signed_archive = json!({
        "name": archive.file_name().unwrap().to_string_lossy(),
        "size": fs::metadata(&archive).map_err(|e| e.to_string())?.len(),
        "sha256": sha256_file(&archive)?,
    });
    rightkit_release_bridge::materialize_cyclonedx_sbom(
        repository_root,
        &json!({
            "outputPath": sbom.to_string_lossy(),
            "product": "legion",
            "version": args.version,
            "target": format!("macos-{}", args.architecture),
            "sourceCommit": args.source_revision,
            "files": [signed_archive],
            "createdAt": created_at_iso,
        }),
    )?;
    rightkit_release_bridge::materialize_in_toto_slsa_provenance(
        repository_root,
        &json!({
            "outputPath": provenance.to_string_lossy(),
            "product": "legion",
            "version": args.version,
            "target": format!("macos-{}", args.architecture),
            "sourceCommit": args.source_revision,
            "sourceRepository": "https://github.com/Orthic-Labs/legion",
            "subjects": [signed_archive],
            "startedAt": created_at_iso,
            "finishedAt": created_at_iso,
        }),
    )?;

    Ok(json!({
        "archive": archive.display().to_string(),
        "archiveSha256": signed_archive.get("sha256"),
        "sbom": sbom.display().to_string(),
        "provenance": provenance.display().to_string(),
        "notarizationArchive": notary_zip.display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the path-safety guard exercised by
    /// "protected finalization requires an exact candidate source identity
    /// before any work" in `tests/release-artifacts.test.mjs` / the macOS
    /// finalization test in `tests/unsigned-release-candidate.test.mjs`.
    #[test]
    fn assert_below_rejects_output_outside_dist_native() {
        let root = Path::new("/tmp/legion-repo");
        let err = assert_below(Path::new("/tmp/elsewhere"), &root.join("dist/native"), "candidate extraction output").unwrap_err();
        assert!(err.contains("must be below"));
    }

    #[test]
    fn assert_below_accepts_nested_output() {
        let root = Path::new("/tmp/legion-repo");
        let ok = assert_below(&root.join("dist/native/macos-arm64/legion-0.1.0"), &root.join("dist/native"), "candidate extraction output");
        assert!(ok.is_ok());
    }
}
