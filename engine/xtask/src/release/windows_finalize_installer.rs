//! Rust port of `scripts/release/windows/finalize-installer.mjs`: renders the
//! Inno Setup script from the signed payload, builds it with `iscc.exe`, and
//! (unless `unsigned`) signs + verifies it via the external `right-release`
//! CLI (`@rightkit/release`, kept as a subprocess call per the packet brief).

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::paths::{assert_file, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult};
use crate::process_boundary::command_diagnostic;

const REQUIRED_DIRECTORIES: &[&str] = &["bin", "plugin", "share"];
const REQUIRED_BINARIES: &[&str] = &["legion.exe", "legion-hook.exe", "legion-mcp.exe"];

fn fail(message: impl Into<String>) -> String {
    format!("windows-installer: {}", message.into())
}

fn is_architecture(value: &str) -> bool {
    value == "x86_64" || value == "arm64"
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallerIdentity {
    pub version: String,
    pub architecture: String,
    pub name: String,
}

pub fn installer_identity(version: &str, architecture: &str) -> ReleaseResult<InstallerIdentity> {
    if !is_stable_semver(version) {
        return Err(fail("version must be stable SemVer"));
    }
    if !is_architecture(architecture) {
        return Err(fail("architecture must be x86_64 or arm64"));
    }
    Ok(InstallerIdentity {
        version: version.to_string(),
        architecture: architecture.to_string(),
        name: format!("Legion-{version}-windows-{architecture}-setup.exe"),
    })
}

fn assert_regular(path: &Path, label: &str) -> ReleaseResult<()> {
    assert_file(path, label)
}

fn release_metadata(root: &Path, version: &str, architecture: &str) -> ReleaseResult<Value> {
    let path = root.join("share").join("legion").join("release.json");
    assert_regular(&path, "release metadata")?;
    let text = fs::read_to_string(&path).map_err(|e| fail(format!("release metadata could not be read: {e}")))?;
    let value: Value = serde_json::from_str(&text).map_err(|_| fail("release metadata is invalid JSON"))?;
    let ok = value.get("releaseVersion").and_then(Value::as_str) == Some(version)
        && value.get("runtime").and_then(|r| r.get("platform")).and_then(Value::as_str) == Some("windows")
        && value.get("runtime").and_then(|r| r.get("architecture")).and_then(Value::as_str) == Some(architecture);
    if !ok {
        return Err(fail("release metadata does not match requested Windows identity"));
    }
    let runtime = root.join("bin").join("legion.exe");
    let declared = value.get("runtime").and_then(|r| r.get("sha256")).and_then(Value::as_str).unwrap_or("");
    let declared = declared.strip_prefix("sha256:").unwrap_or(declared).to_lowercase();
    if declared != sha256_file(&runtime)? {
        return Err(fail("release runtime digest mismatch"));
    }
    Ok(value)
}

fn assert_safe_tree(root: &Path, dir: &Path) -> ReleaseResult<()> {
    for entry in fs::read_dir(dir).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| fail(e.to_string()))?;
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        if meta.is_symlink() {
            return Err(fail(format!("payload contains symlink: {rel}")));
        } else if meta.is_dir() {
            assert_safe_tree(root, &path)?;
        } else if !meta.is_file() {
            return Err(fail(format!("payload contains non-file: {rel}")));
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct FinalizeWindowsInstallerInput {
    pub input_root: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub version: String,
    pub architecture: String,
    pub receipt_path: Option<PathBuf>,
    pub rendered_script_path: Option<PathBuf>,
    pub unsigned: bool,
    pub inno_setup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizeWindowsInstallerResult {
    pub status: &'static str,
    pub installer: PathBuf,
    pub sha256: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub receipt: Option<PathBuf>,
    pub identity: InstallerIdentity,
    #[serde(rename = "runtimeSha256")]
    pub runtime_sha256: String,
}

/// Renders `legion.iss` with `@@...@@` placeholders substituted; template
/// text is read from disk by the caller so this stays free of the
/// `resolve(import.meta.url)` machinery the JS used only to find the file.
pub fn render_inno_template(template: &str, activation_script: &Path, source_root: &Path, output_root: &Path, version: &str, architecture: &str) -> ReleaseResult<String> {
    for (label, value) in [("source", source_root), ("output", output_root)] {
        if !value.is_absolute() {
            return Err(fail(format!("{label} root must be absolute")));
        }
        let s = value.to_string_lossy();
        if s.contains('\r') || s.contains('\n') || s.contains('"') {
            return Err(fail(format!("{label} root contains unsafe Inno directive characters")));
        }
    }
    let identity = installer_identity(version, architecture)?;
    let setup_name = identity.name.trim_end_matches(".exe").to_string();
    let mut out = template.to_string();
    for (needle, value) in [
        ("@@VERSION@@", version.to_string()),
        ("@@ACTIVATION_SCRIPT@@", activation_script.to_string_lossy().to_string()),
        ("@@SOURCE_ROOT@@", source_root.to_string_lossy().to_string()),
        ("@@OUTPUT_ROOT@@", output_root.to_string_lossy().to_string()),
        ("@@SETUP_NAME@@", setup_name),
    ] {
        out = out.replace(needle, &value);
    }
    Ok(out)
}

pub fn inno_command(script_path: &Path, iscc_path: &str) -> ReleaseResult<(String, Vec<String>)> {
    if !script_path.is_absolute() {
        return Err(fail("rendered Inno script path must be absolute"));
    }
    Ok((iscc_path.to_string(), vec!["/Qp".to_string(), script_path.to_string_lossy().to_string()]))
}

/// The `right-release` CLI path this crate delegates signing to, resolved
/// relative to the repository root (`node_modules/@rightkit/release/...`) —
/// kept as an external Node subprocess call per the porting brief.
fn right_release_cli(repository_root: &Path) -> PathBuf {
    repository_root.join("node_modules").join("@rightkit").join("release").join("cli").join("right-release.mjs")
}

pub fn outer_signing_command(repository_root: &Path, installer: &Path, receipt: &Path) -> ReleaseResult<(String, Vec<String>)> {
    if !installer.is_absolute() || !receipt.is_absolute() {
        return Err(fail("installer & receipt paths must be absolute"));
    }
    Ok((
        "node".to_string(),
        vec![
            right_release_cli(repository_root).to_string_lossy().to_string(),
            "sign-windows".to_string(),
            "--receipt".to_string(),
            receipt.to_string_lossy().to_string(),
            installer.to_string_lossy().to_string(),
        ],
    ))
}

pub fn verify_signing_command(repository_root: &Path, installer: &Path) -> ReleaseResult<(String, Vec<String>)> {
    if !installer.is_absolute() {
        return Err(fail("installer path must be absolute"));
    }
    Ok((
        "node".to_string(),
        vec![right_release_cli(repository_root).to_string_lossy().to_string(), "sign-windows".to_string(), "--verify-only".to_string(), installer.to_string_lossy().to_string()],
    ))
}

fn execute(runner: CommandRunner, repository_root: &Path, command: &str, args: &[String], cwd: &Path) -> ReleaseResult<()> {
    let options = CommandOptions { cwd: Some(cwd.to_path_buf()), env: None };
    let result = runner(command, args, &options);
    if result.error_message.is_some() || (result.status != Some(0)) {
        let base = std::path::Path::new(command).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| command.to_string());
        let _ = repository_root;
        return Err(fail(format!("{base} failed: {}", command_diagnostic(&result))));
    }
    Ok(())
}

pub fn finalize_windows_installer(runner: CommandRunner, repository_root: &Path, template: &str, activation_script: &Path, input: FinalizeWindowsInstallerInput) -> ReleaseResult<FinalizeWindowsInstallerResult> {
    let Some(input_root) = input.input_root.as_ref() else { return Err(fail("--input-root & --output are required")) };
    let Some(output_root) = input.output_root.as_ref() else { return Err(fail("--input-root & --output are required")) };
    // realpath() spelling: Inno Setup rejects the `\\?\` prefix canonicalize() adds on Windows.
    let source = input_root.canonicalize().map(crate::windows_release_support::strip_verbatim).unwrap_or_else(|_| input_root.clone());
    let output = if output_root.is_absolute() { output_root.clone() } else { std::env::current_dir().unwrap().join(output_root) };
    let meta = fs::symlink_metadata(&source).map_err(|_| fail("input root must be a real directory"))?;
    if meta.is_symlink() || !meta.is_dir() {
        return Err(fail("input root must be a real directory"));
    }
    // The output must not be inside the signed payload root.
    if output.starts_with(&source) {
        return Err(fail("output must not be inside signed payload root"));
    }
    for dir in REQUIRED_DIRECTORIES {
        let path = source.join(dir);
        let m = fs::symlink_metadata(&path).map_err(|_| fail(format!("payload directory missing or unsafe: {dir}")))?;
        if m.is_symlink() || !m.is_dir() {
            return Err(fail(format!("payload directory missing or unsafe: {dir}")));
        }
    }
    for binary in REQUIRED_BINARIES {
        assert_regular(&source.join("bin").join(binary), &format!("payload binary {binary}"))?;
    }
    assert_safe_tree(&source, &source)?;
    let metadata = release_metadata(&source, &input.version, &input.architecture)?;
    let identity = installer_identity(&input.version, &input.architecture)?;
    fs::create_dir_all(&output).map_err(|e| fail(e.to_string()))?;
    let script_path = input.rendered_script_path.clone().unwrap_or_else(|| output.join(format!("{}.iss", identity.name)));
    if !script_path.starts_with(&output) {
        return Err(fail("rendered Inno script must be below output root"));
    }
    let rendered = render_inno_template(template, activation_script, &source, &output, &input.version, &input.architecture)?;
    fs::write(&script_path, rendered).map_err(|e| fail(e.to_string()))?;
    let installer = output.join(&identity.name);
    let iscc = input.inno_setup_path.unwrap_or_else(|| "iscc.exe".to_string());
    let (command, args) = inno_command(&script_path, &iscc)?;
    execute(runner, repository_root, &command, &args, &output)?;
    assert_regular(&installer, "Inno setup executable")?;
    let runtime_sha256 = {
        let v = metadata.get("runtime").and_then(|r| r.get("sha256")).and_then(Value::as_str).unwrap_or("");
        v.strip_prefix("sha256:").unwrap_or(v).to_lowercase()
    };
    if input.unsigned {
        return Ok(FinalizeWindowsInstallerResult {
            status: "unsigned",
            sha256: sha256_file(&installer)?,
            size_bytes: fs::metadata(&installer).map_err(|e| fail(e.to_string()))?.len(),
            installer,
            receipt: None,
            identity,
            runtime_sha256,
        });
    }
    let receipt = input.receipt_path.clone().unwrap_or_else(|| output.join(format!("{}.signing.json", identity.name)));
    let (sign_cmd, sign_args) = outer_signing_command(repository_root, &installer, &receipt)?;
    execute(runner, repository_root, &sign_cmd, &sign_args, &output)?;
    let (verify_cmd, verify_args) = verify_signing_command(repository_root, &installer)?;
    execute(runner, repository_root, &verify_cmd, &verify_args, &output)?;
    assert_regular(&receipt, "installer signing receipt")?;
    Ok(FinalizeWindowsInstallerResult {
        status: "signed",
        sha256: sha256_file(&installer)?,
        size_bytes: fs::metadata(&installer).map_err(|e| fail(e.to_string()))?.len(),
        installer,
        receipt: Some(receipt),
        identity,
        runtime_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_identity_rejects_bad_version() {
        assert!(installer_identity("1.2", "x86_64").is_err());
        assert!(installer_identity("1.2.3", "sparc").is_err());
        let ok = installer_identity("1.2.3", "x86_64").unwrap();
        assert_eq!(ok.name, "Legion-1.2.3-windows-x86_64-setup.exe");
    }

    #[test]
    fn inno_command_requires_absolute_script() {
        assert!(inno_command(Path::new("relative.iss"), "iscc.exe").is_err());
        let script = std::env::temp_dir().join("script.iss");
        let (cmd, args) = inno_command(&script, "iscc.exe").unwrap();
        assert_eq!(cmd, "iscc.exe");
        assert_eq!(args, vec!["/Qp".to_string(), script.to_string_lossy().to_string()]);
    }
}
