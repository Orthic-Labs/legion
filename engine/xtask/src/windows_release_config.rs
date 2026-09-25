//! Rust port of the Windows-relevant constants in `right-release.config.mjs`
//! (`WINDOWS_ARCHITECTURES` and `WINDOWS_INSTALL_CONTRACT`).
//!
//! The JS module also computes a whole release-config object with
//! environment-dependent side effects (reads `release/version.json`, reads
//! `LEGION_WINDOWS_ARCH`, builds the `right-release` pipeline config used by
//! other, unported scripts). None of that is needed by
//! `qualify-windows-release.mjs` or `package-windows-release.mjs`'s package
//! mode, so only the two frozen constant tables are ported here.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsArchitecture {
    pub platform: &'static str,
    pub architecture: &'static str,
    pub native_architecture: &'static str,
    pub target_triple: &'static str,
    pub artifact_id: &'static str,
}

pub const WINDOWS_X86_64: WindowsArchitecture = WindowsArchitecture {
    platform: "windows",
    architecture: "x86_64",
    native_architecture: "x64",
    target_triple: "x86_64-pc-windows-msvc",
    artifact_id: "windows-x86_64",
};

pub const WINDOWS_ARM64: WindowsArchitecture = WindowsArchitecture {
    platform: "windows",
    architecture: "arm64",
    native_architecture: "arm64",
    target_triple: "aarch64-pc-windows-msvc",
    artifact_id: "windows-arm64",
};

/// Mirrors `WINDOWS_ARCHITECTURES[normalized]` lookups.
pub fn windows_architecture(normalized: &str) -> Option<WindowsArchitecture> {
    match normalized {
        "x86_64" => Some(WINDOWS_X86_64),
        "arm64" => Some(WINDOWS_ARM64),
        _ => None,
    }
}

/// `assembleRoot` / `archive` file-name fragments live in the JS config next
/// to the architecture table but depend on `releaseVersion`; callers build
/// those strings themselves (see `package_windows_release`).
pub fn windows_assembly_root(version: &str, architecture: &str) -> String {
    format!("dist/native/windows-{architecture}/legion-{version}")
}

pub fn windows_archive_name(version: &str, architecture: &str) -> String {
    format!("legion-{version}-windows-{architecture}.zip")
}

/// Mirrors `normalizeWindowsArchitecture` (identical in both scripts).
pub fn normalize_windows_architecture(value: &str) -> Result<String, String> {
    let trimmed = value.trim().to_lowercase();
    let stripped = trimmed.strip_prefix("windows-").unwrap_or(&trimmed);
    let normalized = match stripped {
        "x64" | "amd64" => "x86_64",
        "aarch64" => "arm64",
        other => other,
    };
    if windows_architecture(normalized).is_none() {
        return Err(format!(
            "unsupported Windows architecture: {value}; expected x86_64 or arm64"
        ));
    }
    Ok(normalized.to_string())
}

pub struct WindowsInstallContract;

impl WindowsInstallContract {
    pub const ORIGIN: &'static str = "installed";
    pub const LOCAL_APP_DATA_SUBDIR: [&'static str; 2] = ["Orthic Labs", "Legion"];
    pub const INSTALL_ROOT_SUBDIR: &'static str = "Orthic Labs/Legion";
    pub const STABLE_CURRENT_NAME: &'static str = "current";
    pub const PREVIOUS_CURRENT_NAME: &'static str = ".current-previous";
    pub const NEXT_CURRENT_NAME: &'static str = ".current-next";
    pub const INTEGRATION_JOURNAL_NAME: &'static str = "integration-journal.json";
    pub const EXECUTABLE_PATH: &'static str = "bin/legion.exe";
    pub const GENERATION_FORMAT: &'static str = "release-version:declarative-assets-sha256";
    pub const FORBIDDEN_BINDING_SEGMENTS: [&'static str; 4] = ["repo", "dist", "target", "node_modules"];
}

/// Mirrors `FORBIDDEN_BINDING_SEGMENTS` in both scripts (the contract's set
/// plus `.git`).
pub fn forbidden_binding_segments() -> [&'static str; 5] {
    ["repo", "dist", "target", "node_modules", ".git"]
}

pub fn executable_path_for(current_path: &Path) -> std::path::PathBuf {
    current_path.join("bin").join("legion.exe")
}
