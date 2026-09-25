//! Rust port of `scripts/release/macos/build-installer.mjs`: builds the
//! `.app`/DMG installer wrapper around a finalized portable macOS release,
//! codesigns and notarizes it via `codesign`/`hdiutil`/`xcrun` (kept as
//! subprocess calls — these are Apple platform tools, not `right-release`,
//! but still external to this crate).

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;

use super::paths::{is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult};
use crate::process_boundary::command_diagnostic;

const EXECUTABLES: &[&str] = &["legion", "legion-hook", "legion-mcp"];
const APP_NAME: &str = "Legion Installer.app";
const APP_IDENTIFIER: &str = "com.orthiclabs.legion.installer";

fn fail(message: impl Into<String>) -> String {
    message.into()
}

fn safe_tree(root: &Path, dir: &Path) -> ReleaseResult<()> {
    for entry in fs::read_dir(dir).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| fail(e.to_string()))?;
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        if meta.is_symlink() {
            return Err(fail(format!("portable release contains symlink: {rel}")));
        } else if meta.is_dir() {
            safe_tree(root, &path)?;
        } else if !meta.is_file() {
            return Err(fail(format!("portable release contains non-file: {rel}")));
        }
    }
    Ok(())
}

pub fn assert_finalized_portable_release(input_root: Option<&Path>, version: &str) -> ReleaseResult<PathBuf> {
    let root = input_root.ok_or_else(|| fail("RIGHT_GIT_FINALIZED_MACOS_ROOT is required"))?;
    if !root.is_dir() {
        return Err(fail(format!("finalized macOS release root missing: {}", root.display())));
    }
    if !is_stable_semver(version) {
        return Err(fail("stable version is required"));
    }
    safe_tree(root, root)?;
    for dir in ["bin", "plugin", "share"] {
        if !root.join(dir).is_dir() {
            return Err(fail(format!("finalized macOS release missing {dir}/")));
        }
    }
    for executable in EXECUTABLES {
        let path = root.join("bin").join(executable);
        let meta = fs::symlink_metadata(&path).map_err(|_| fail(format!("finalized macOS release missing safe bin/{executable}")))?;
        if meta.is_symlink() || !meta.is_file() {
            return Err(fail(format!("finalized macOS release missing safe bin/{executable}")));
        }
    }
    Ok(root.to_path_buf())
}

pub struct MacosCommand {
    pub file: &'static str,
    pub args: Vec<String>,
}

pub struct MacosInstallerPlan {
    pub input: PathBuf,
    pub output: PathBuf,
    pub version: String,
    pub app: PathBuf,
    pub dmg: PathBuf,
    pub receipt: PathBuf,
    pub commands: Vec<MacosCommand>,
}

#[allow(clippy::too_many_arguments)]
pub fn macos_installer_plan(
    swift_source: &Path,
    input_root: Option<&Path>,
    output_root: Option<&Path>,
    version: &str,
    developer_id: Option<&str>,
    api_key_path: Option<&str>,
    api_key: Option<&str>,
    api_issuer: Option<&str>,
) -> ReleaseResult<MacosInstallerPlan> {
    let input = assert_finalized_portable_release(input_root, version)?;
    let output = output_root.ok_or_else(|| fail("RIGHT_GIT_FINALIZED_MACOS_ROOT output is required"))?.to_path_buf();
    let app = output.join(APP_NAME);
    let dmg = output.join(format!("legion-{version}-macos-installer.dmg"));
    let receipt = output.join(format!("legion-{version}-macos-installer-finalization.json"));
    let developer_id = developer_id.filter(|s| !s.is_empty()).ok_or_else(|| fail("APPLE_DEVELOPER_ID is required"))?;
    if api_key_path.unwrap_or("").is_empty() || api_key.unwrap_or("").is_empty() || api_issuer.unwrap_or("").is_empty() {
        return Err(fail("APPLE_API_KEY_PATH, APPLE_API_KEY, & APPLE_API_ISSUER are required"));
    }
    let executable_out = app.join("Contents").join("MacOS").join("Legion Installer");
    let commands = vec![
        MacosCommand { file: "swiftc", args: vec!["-parse-as-library".into(), swift_source.to_string_lossy().into(), "-framework".into(), "Cocoa".into(), "-o".into(), executable_out.to_string_lossy().into()] },
        MacosCommand { file: "codesign", args: vec!["--force".into(), "--options".into(), "runtime".into(), "--timestamp".into(), "--sign".into(), developer_id.into(), app.to_string_lossy().into()] },
        MacosCommand { file: "hdiutil", args: vec!["create".into(), "-ov".into(), "-fs".into(), "HFS+".into(), "-volname".into(), "Legion Installer".into(), "-srcfolder".into(), app.to_string_lossy().into(), dmg.to_string_lossy().into()] },
        MacosCommand { file: "codesign", args: vec!["--force".into(), "--options".into(), "runtime".into(), "--timestamp".into(), "--sign".into(), developer_id.into(), dmg.to_string_lossy().into()] },
        MacosCommand { file: "xcrun", args: vec!["notarytool".into(), "submit".into(), dmg.to_string_lossy().into(), "--key".into(), api_key_path.unwrap().into(), "--key-id".into(), api_key.unwrap().into(), "--issuer".into(), api_issuer.unwrap().into(), "--wait".into(), "--output-format".into(), "json".into()] },
        MacosCommand { file: "xcrun", args: vec!["stapler".into(), "staple".into(), dmg.to_string_lossy().into()] },
        MacosCommand { file: "spctl", args: vec!["--assess".into(), "--type".into(), "open".into(), "--context".into(), "context:primary-signature".into(), "--verbose=4".into(), dmg.to_string_lossy().into()] },
    ];
    Ok(MacosInstallerPlan { input, output, version: version.to_string(), app, dmg, receipt, commands })
}

fn invoke(runner: CommandRunner, command: &MacosCommand) -> ReleaseResult<()> {
    let options = CommandOptions::default();
    let result = runner(command.file, &command.args, &options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!("{} failed: {}", command.file, command_diagnostic(&result))));
    }
    Ok(())
}

fn copy_dir_recursive(from: &Path, to: &Path) -> ReleaseResult<()> {
    fs::create_dir_all(to).map_err(|e| fail(e.to_string()))?;
    for entry in fs::read_dir(from).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let target = to.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| fail(e.to_string()))?;
        if meta.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target).map_err(|e| fail(e.to_string()))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct MaterializedMacosInstaller {
    pub schema: u32,
    pub kind: &'static str,
    pub status: &'static str,
    pub version: String,
    pub installer: PathBuf,
    #[serde(rename = "installerSha256")]
    pub installer_sha256: String,
    pub app: PathBuf,
    #[serde(rename = "portableRelease")]
    pub portable_release: PathBuf,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub receipt: PathBuf,
}

pub fn materialize_macos_installer(runner: CommandRunner, plan: &MacosInstallerPlan, now: impl Fn() -> String) -> ReleaseResult<MaterializedMacosInstaller> {
    let _ = fs::remove_dir_all(&plan.app);
    let _ = fs::remove_file(&plan.dmg);
    fs::create_dir_all(plan.app.join("Contents").join("MacOS")).map_err(|e| fail(e.to_string()))?;
    fs::create_dir_all(plan.app.join("Contents").join("Resources")).map_err(|e| fail(e.to_string()))?;
    let info_plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>CFBundleDisplayName</key><string>Legion Installer</string><key>CFBundleExecutable</key><string>Legion Installer</string><key>CFBundleIdentifier</key><string>{APP_IDENTIFIER}</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>{}</string></dict></plist>\n",
        plan.version
    );
    fs::write(plan.app.join("Contents").join("Info.plist"), info_plist).map_err(|e| fail(e.to_string()))?;
    fs::write(plan.app.join("Contents").join("Resources").join("version.txt"), format!("{}\n", plan.version)).map_err(|e| fail(e.to_string()))?;
    copy_dir_recursive(&plan.input, &plan.app.join("Contents").join("Resources").join("payload"))?;
    for command in &plan.commands {
        invoke(runner, command)?;
    }
    if !plan.dmg.is_file() {
        return Err(fail(format!("DMG missing after finalization: {}", plan.dmg.display())));
    }
    let installer_sha256 = sha256_file(&plan.dmg)?;
    let created_at = now();
    let receipt = json!({
        "schema": 1, "kind": "legion-macos-installer-finalization", "status": "verified",
        "version": plan.version, "installer": plan.dmg, "installerSha256": installer_sha256,
        "app": plan.app, "portableRelease": plan.input, "createdAt": created_at,
        "notarization": { "tool": "xcrun notarytool", "status": "accepted" },
    });
    fs::write(&plan.receipt, format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap())).map_err(|e| fail(e.to_string()))?;
    Ok(MaterializedMacosInstaller {
        schema: 1,
        kind: "legion-macos-installer-finalization",
        status: "verified",
        version: plan.version.clone(),
        installer: plan.dmg.clone(),
        installer_sha256,
        app: plan.app.clone(),
        portable_release: plan.input.clone(),
        created_at,
        receipt: plan.receipt.clone(),
    })
}
