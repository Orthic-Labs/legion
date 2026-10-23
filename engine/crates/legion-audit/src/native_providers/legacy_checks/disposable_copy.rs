//! Bounded test execution over an owner-only byte copy of Audit's frozen
//! materialized inventory. This is an explicit source-integrity assurance; it
//! does not claim an OS filesystem or network sandbox.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use super::attested_runs::{self, AdapterEnrollment, AttestedRunsEnrollment};
use legion_contracts::{Coverage, FindingId, FindingRef, ProviderStatus};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    inventory::{InventoryEntry, InventoryEnvelope},
    plan::AuditProvider,
};

use super::{
    audit_environment, empty_output, test_declaration_location, AuditScratch, LegacyCheckExecution,
    LegacyCheckInput, LegacyCheckOutput, LegacyCheckProcessState, ResolvedCommand,
};

const MAX_FILES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATH_LIST_BYTES: usize = 64 * 1024 * 1024;
const CANCEL_ON_DISCONNECT: &str = "RIGHTKIT_CANCEL_ON_DISCONNECT";
static COPY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct PreparedCopy {
    path: PathBuf,
    cwd: PathBuf,
    workspace_root: PathBuf,
    input_modes: BTreeMap<String, u32>,
    source_digest: String,
    copy_digest: String,
    file_count: usize,
    total_bytes: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum CopyError {
    UnsafePath(String),
    UnsupportedCargoBoundary(String),
    SourceDrift(String),
    Limit(String),
    Io(String),
    Cancelled,
    Deadline,
}

impl CopyError {
    fn code(&self) -> &'static str {
        match self {
            Self::UnsafePath(_) => "unsafe-source-path",
            Self::UnsupportedCargoBoundary(_) => "unsupported-local-cargo-boundary",
            Self::SourceDrift(_) => "source-digest-drift",
            Self::Limit(_) => "copy-bound-exceeded",
            Self::Io(_) => "copy-io-failed",
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline-expired",
        }
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn file_mode(path: &Path) -> Result<u32, CopyError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| CopyError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CopyError::UnsafePath(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        Ok(0)
    }
}

fn safe_relative(path: &str) -> Result<PathBuf, CopyError> {
    if path.is_empty() || path.contains('\\') || path.contains(':') || path.contains('\0') {
        return Err(CopyError::UnsafePath(path.to_owned()));
    }
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(CopyError::UnsafePath(path.to_owned()));
    }
    Ok(relative.to_path_buf())
}

fn current_bytes(root: &Path, entry: &InventoryEntry) -> Result<Vec<u8>, CopyError> {
    let relative = safe_relative(&entry.path)?;
    let source = root.join(relative);
    let mut cursor = root.to_path_buf();
    for part in Path::new(&entry.path).components() {
        cursor.push(part);
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|error| CopyError::Io(format!("{}: {error}", entry.path)))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir() && cursor != source && !metadata.is_file()
        {
            return Err(CopyError::UnsafePath(entry.path.clone()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(CopyError::UnsafePath(entry.path.clone()));
            }
        }
    }
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| CopyError::Io(format!("{}: {error}", entry.path)))?;
    if !metadata.is_file() {
        return Err(CopyError::UnsafePath(entry.path.clone()));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(CopyError::Limit(format!("file too large: {}", entry.path)));
    }
    let bytes =
        fs::read(&source).map_err(|error| CopyError::Io(format!("{}: {error}", entry.path)))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CopyError::SourceDrift(entry.path.clone()));
    }
    if entry.digest.as_deref() != Some(sha(&bytes).as_str()) {
        return Err(CopyError::SourceDrift(entry.path.clone()));
    }
    Ok(bytes)
}

fn inventory_digest(entries: &[(String, String, u64)]) -> String {
    let mut hash = Sha256::new();
    for (path, digest, bytes) in entries {
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update((digest.len() as u64).to_be_bytes());
        hash.update(digest.as_bytes());
        hash.update(bytes.to_be_bytes());
    }
    format!("sha256:{}", hex::encode(hash.finalize()))
}

fn check_cargo_boundaries(root: &Path, inventory: &InventoryEnvelope) -> Result<(), CopyError> {
    for entry in inventory
        .entries
        .iter()
        .filter(|entry| entry.path.ends_with("Cargo.toml"))
    {
        let metadata = fs::metadata(root.join(&entry.path))
            .map_err(|error| CopyError::Io(format!("{}: {error}", entry.path)))?;
        if metadata.len() > 1024 * 1024 {
            return Err(CopyError::Limit(format!(
                "Cargo manifest too large: {}",
                entry.path
            )));
        }
        let bytes = current_bytes(root, entry)?;
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            CopyError::UnsupportedCargoBoundary(format!("{}: {error}", entry.path))
        })?;
        let value: toml::Value = toml::from_str(text).map_err(|error| {
            CopyError::UnsupportedCargoBoundary(format!("{}: {error}", entry.path))
        })?;
        let manifest_dir = Path::new(&entry.path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let mut paths = Vec::new();
        collect_dependency_paths(&value, &mut paths);
        collect_target_paths(&value, &mut paths);
        for local in paths {
            validate_local_path(root, inventory, manifest_dir, local)?;
        }
        if let Some(workspace) = value
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|package| package.get("workspace"))
            .and_then(toml::Value::as_str)
        {
            validate_local_path(root, inventory, manifest_dir, workspace)?;
        }
        for field in ["readme", "license-file", "build"] {
            if let Some(path) = value
                .get("package")
                .and_then(toml::Value::as_table)
                .and_then(|package| package.get(field))
                .and_then(toml::Value::as_str)
            {
                validate_local_path(root, inventory, manifest_dir, path)?;
            }
        }
        if let Some(workspace) = value.get("workspace").and_then(toml::Value::as_table) {
            for key in ["members", "default-members", "exclude"] {
                if let Some(values) = workspace.get(key).and_then(toml::Value::as_array) {
                    for member in values {
                        let Some(member) = member.as_str() else {
                            return Err(CopyError::UnsupportedCargoBoundary(format!(
                                "{}: non-string workspace {key}",
                                entry.path
                            )));
                        };
                        if member.contains('*') || member.contains('?') || member.contains('[') {
                            return Err(CopyError::UnsupportedCargoBoundary(format!(
                                "{}: workspace glob {member}",
                                entry.path
                            )));
                        }
                        validate_local_path(root, inventory, manifest_dir, member)?;
                        if matches!(key, "members" | "default-members") {
                            validate_local_path(
                                root,
                                inventory,
                                manifest_dir,
                                &format!("{member}/Cargo.toml"),
                            )?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn collect_dependency_paths<'a>(value: &'a toml::Value, output: &mut Vec<&'a str>) {
    fn dependencies<'a>(value: &'a toml::Value, output: &mut Vec<&'a str>) {
        let Some(table) = value.as_table() else {
            return;
        };
        for dependency in table.values() {
            if let Some(path) = dependency.as_table().and_then(|table| table.get("path")) {
                output.push(path.as_str().unwrap_or(""));
            }
        }
    }
    fn dependency_sections<'a>(value: &'a toml::Value, output: &mut Vec<&'a str>) {
        for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(section) = value.get(key) {
                dependencies(section, output);
            }
        }
    }

    dependency_sections(value, output);
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            dependency_sections(target, output);
        }
    }
    if let Some(workspace_dependencies) = value
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
    {
        dependencies(workspace_dependencies, output);
    }
    if let Some(patches) = value.get("patch").and_then(toml::Value::as_table) {
        for source in patches.values() {
            dependencies(source, output);
        }
    }
    if let Some(replacements) = value.get("replace").and_then(toml::Value::as_table) {
        for replacement in replacements.values() {
            if let Some(path) = replacement.as_table().and_then(|table| table.get("path")) {
                output.push(path.as_str().unwrap_or(""));
            }
        }
    }
}

fn collect_target_paths<'a>(value: &'a toml::Value, output: &mut Vec<&'a str>) {
    let mut push_target = |target: &'a toml::Value| {
        if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
            output.push(path);
        }
    };
    if let Some(target) = value.get("lib") {
        push_target(target);
    }
    for key in ["bin", "test", "example", "bench"] {
        if let Some(targets) = value.get(key).and_then(toml::Value::as_array) {
            for target in targets {
                push_target(target);
            }
        }
    }
}

fn validate_local_path(
    root: &Path,
    inventory: &InventoryEnvelope,
    base: &Path,
    path: &str,
) -> Result<(), CopyError> {
    if path.is_empty() || Path::new(path).is_absolute() || path.contains('$') {
        return Err(CopyError::UnsupportedCargoBoundary(format!(
            "external or unresolved local path: {path}"
        )));
    }
    let joined = base.join(path);
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(CopyError::UnsupportedCargoBoundary(format!(
                        "path escapes repository: {path}"
                    )));
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => {
                return Err(CopyError::UnsupportedCargoBoundary(format!(
                    "absolute local path: {path}"
                )));
            }
        }
    }
    let target = root.join(&normalized);
    if !target.exists() {
        return Err(CopyError::UnsupportedCargoBoundary(format!(
            "missing local input: {path}"
        )));
    }
    if target.is_dir() {
        let prefix = normalized.to_string_lossy().replace('\\', "/");
        let manifest_path = if prefix.is_empty() {
            "Cargo.toml".to_owned()
        } else {
            format!("{prefix}/Cargo.toml")
        };
        if !inventory
            .entries
            .iter()
            .any(|entry| entry.path == manifest_path)
        {
            return Err(CopyError::UnsupportedCargoBoundary(format!(
                "unmaterialized local input: {path}"
            )));
        }
    } else {
        let relative = normalized.to_string_lossy().replace('\\', "/");
        if !inventory.entries.iter().any(|entry| entry.path == relative) {
            return Err(CopyError::UnsupportedCargoBoundary(format!(
                "unmaterialized local input: {path}"
            )));
        }
    }
    Ok(())
}

fn prepare_copy(
    root: &Path,
    inventory: &InventoryEnvelope,
    scratch: &AuditScratch,
    test_declaration: &str,
    deadline: std::time::Instant,
    cancellation: &CancellationToken,
) -> Result<PreparedCopy, CopyError> {
    if inventory.entries.is_empty() || inventory.entries.len() > MAX_FILES {
        return Err(CopyError::Limit(
            "inventory file count is empty or exceeds 100000".into(),
        ));
    }
    let source_root = fs::canonicalize(root).map_err(|error| CopyError::Io(error.to_string()))?;
    let git_marker = source_root.join(".git");
    if fs::symlink_metadata(&git_marker).is_ok_and(|meta| !meta.is_dir()) {
        return Err(CopyError::UnsafePath(
            "git-file-worktree-or-submodule".into(),
        ));
    }
    for entry in &inventory.entries {
        let relative = safe_relative(&entry.path)?;
        let mut ancestor = source_root.clone();
        for component in relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .components()
        {
            ancestor.push(component);
            if fs::symlink_metadata(ancestor.join(".git")).is_ok() {
                return Err(CopyError::UnsafePath(format!(
                    "nested-repository:{}",
                    entry.path
                )));
            }
        }
    }
    check_cargo_boundaries(&source_root, inventory)?;

    let sequence = COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let copy_root = scratch.root().join(format!("test-copy-{sequence}"));
    super::make_private_dir(&copy_root).map_err(|error| CopyError::Io(error.to_string()))?;
    let copy_root = fs::canonicalize(&copy_root).map_err(|error| {
        let suffix = fs::remove_dir_all(&copy_root)
            .err()
            .map(|cleanup_error| format!("; cleanup failed: {cleanup_error}"))
            .unwrap_or_default();
        CopyError::Io(format!(
            "copy root canonicalization failed: {error}{suffix}"
        ))
    })?;
    let mut source_records = Vec::with_capacity(inventory.entries.len());
    let mut copied_records = Vec::with_capacity(inventory.entries.len());
    let mut input_modes = BTreeMap::new();
    let mut total = 0_u64;
    let mut sorted = inventory.entries.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    for entry in sorted {
        if cancellation.is_cancelled() {
            return Err(CopyError::Cancelled);
        }
        if std::time::Instant::now() >= deadline {
            return Err(CopyError::Deadline);
        }
        let bytes = current_bytes(&source_root, entry)?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_TOTAL_BYTES {
            return Err(CopyError::Limit("inventory exceeds 4 GiB".into()));
        }
        let relative = safe_relative(&entry.path)?;
        let mode = file_mode(&source_root.join(&relative))?;
        input_modes.insert(entry.path.clone(), mode);
        let destination = copy_root.join(&relative);
        let parent = destination
            .parent()
            .ok_or_else(|| CopyError::UnsafePath(entry.path.clone()))?;
        super::make_private_dir(parent).map_err(|error| CopyError::Io(error.to_string()))?;
        fs::write(&destination, &bytes)
            .map_err(|error| CopyError::Io(format!("{}: {error}", entry.path)))?;
        let source_digest = sha(&bytes);
        let copied = fs::read(&destination).map_err(|error| CopyError::Io(error.to_string()))?;
        let copied_digest = sha(&copied);
        if copied_digest != source_digest {
            return Err(CopyError::SourceDrift(entry.path.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::metadata(source_root.join(&relative))
                .map_err(|error| CopyError::Io(error.to_string()))?;
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(metadata.mode() & 0o7777),
            )
            .map_err(|error| CopyError::Io(error.to_string()))?;
            let src = fs::metadata(source_root.join(&relative))
                .map_err(|error| CopyError::Io(error.to_string()))?;
            let dst =
                fs::metadata(&destination).map_err(|error| CopyError::Io(error.to_string()))?;
            if src.dev() == dst.dev() && src.ino() == dst.ino() {
                return Err(CopyError::Io(
                    "copy unexpectedly shares source inode".into(),
                ));
            }
        }
        source_records.push((entry.path.clone(), source_digest, bytes.len() as u64));
        copied_records.push((entry.path.clone(), copied_digest, copied.len() as u64));
    }
    if source_records != copied_records {
        return Err(CopyError::SourceDrift("copy inventory differs".into()));
    }
    let source_digest = inventory_digest(&source_records);
    let copy_digest = inventory_digest(&copied_records);
    let declaration = copy_root.join(test_declaration);
    let cwd = if test_declaration.ends_with("Cargo.toml") {
        declaration.parent().unwrap_or(&copy_root).to_path_buf()
    } else {
        copy_root.clone()
    };
    Ok(PreparedCopy {
        path: copy_root.clone(),
        cwd,
        workspace_root: copy_root,
        input_modes,
        source_digest,
        copy_digest,
        file_count: source_records.len(),
        total_bytes: total,
    })
}

fn bind_copy_workspace_root(
    source_root: &Path,
    source: &Value,
    copy: &mut PreparedCopy,
) -> Result<(), String> {
    let source_workspace = source
        .get("workspaceRoot")
        .and_then(Value::as_str)
        .ok_or("resolver-workspace-root-missing")?;
    let source_root = fs::canonicalize(source_root).map_err(|error| error.to_string())?;
    let source_workspace = fs::canonicalize(source_workspace).map_err(|error| error.to_string())?;
    let relative = source_workspace
        .strip_prefix(&source_root)
        .map_err(|_| "resolver-workspace-root-outside-source")?;
    let copy_root = fs::canonicalize(&copy.path).map_err(|error| error.to_string())?;
    let copy_workspace =
        fs::canonicalize(copy_root.join(relative)).map_err(|error| error.to_string())?;
    if !copy_workspace.starts_with(&copy_root) {
        return Err("resolver-workspace-root-outside-copy".into());
    }
    copy.workspace_root = copy_workspace;
    Ok(())
}

const BROKER_SOCKET_ENV: &str = "RIGHTKIT_BUILD_BROKER_SOCKET";

/// The broker endpoint is a locator, not a secret. Windows never discovers it
/// implicitly, so pass it through only when the host sets a non-empty
/// single-line value; nothing else widens the allowlist.
fn pass_broker_socket(
    value: Option<String>,
    environment: &mut BTreeMap<String, String>,
    allowlist: &mut BTreeSet<String>,
) {
    let Some(value) = value.filter(|v| !v.is_empty() && !v.contains(['\n', '\r', '\0'])) else {
        return;
    };
    environment.insert(BROKER_SOCKET_ENV.into(), value);
    allowlist.insert(BROKER_SOCKET_ENV.into());
}

fn request_id(stderr: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(stderr).map_err(|_| "request-id-stderr-not-utf8".to_owned())?;
    let ids = text
        .lines()
        .filter_map(|line| line.strip_prefix("rightkit: request "))
        .collect::<Vec<_>>();
    if ids.len() != 1 {
        if ids.is_empty() && text.contains("RK_BROKER_UNAVAILABLE") {
            return Err("rustright-broker-unavailable".into());
        }
        return Err("request-id-line-missing-or-ambiguous".into());
    }
    let id = ids[0];
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("request-id-invalid".into());
    }
    Ok(id.into())
}

fn id_suffix(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn array_empty(receipt: &Value, key: &str) -> bool {
    receipt
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn no_survivors(receipt: &Value) -> bool {
    match receipt.get("survivors") {
        None => true,
        Some(Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    }
}

fn valid_broker_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_expected_test_command(value: Option<&str>, expected: &str) -> bool {
    value == Some(expected)
}

fn is_known_cargo_argv_normalization(
    receipt: &Value,
    expected_command: &str,
    expected_argv: &[String],
    actual_argv: &[String],
) -> bool {
    if expected_command != "cargo test"
        || expected_argv.len() != 1
        || expected_argv[0] != "test"
        || actual_argv.len() != 5
        || actual_argv[0] != "test"
        || actual_argv[1] != "--target"
        || actual_argv[2].is_empty()
        || actual_argv[3] != "--target-dir"
        || !Path::new(&actual_argv[4]).is_absolute()
        || receipt.get("targetTriple").and_then(Value::as_str) != Some(actual_argv[2].as_str())
        || receipt.pointer("/target/path").and_then(Value::as_str) != Some(actual_argv[4].as_str())
    {
        return false;
    }
    let expected_effective_command = format!("cargo {}", actual_argv.join(" "));
    receipt.get("command").and_then(Value::as_str) == Some(&expected_effective_command)
}

fn validate_status(
    status: &Value,
    id: &str,
    copy: &PreparedCopy,
    expected_command: &str,
    expected_argv: &[String],
) -> Result<i32, String> {
    let receipt = status
        .get("receipt")
        .filter(|value| value.is_object())
        .ok_or("status-receipt-missing")?;
    if status.get("id").and_then(Value::as_str) != Some(id)
        || receipt.get("id").and_then(Value::as_str) != Some(id)
    {
        return Err("status-request-id-mismatch".into());
    }
    let workspace = receipt
        .get("workspace")
        .and_then(Value::as_str)
        .ok_or("receipt-workspace-missing")?;
    let repository = receipt
        .get("repository")
        .and_then(Value::as_str)
        .ok_or("receipt-repository-missing")?;
    let resolved_workspace = fs::canonicalize(workspace).ok();
    let resolved_repository = fs::canonicalize(repository).ok();
    let repository_bound = resolved_repository
        .as_ref()
        .is_some_and(|path| path == &copy.path || path == &copy.cwd);
    if resolved_workspace.as_deref() != Some(copy.cwd.as_path()) || !repository_bound {
        return Err("receipt-copy-binding-mismatch".into());
    }
    let argv = receipt
        .get("argv")
        .and_then(Value::as_array)
        .ok_or("receipt-argv-missing")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or("receipt-argv-invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let command = receipt.get("command").and_then(Value::as_str);
    if argv != expected_argv || !is_expected_test_command(command, expected_command) {
        if is_known_cargo_argv_normalization(receipt, expected_command, expected_argv, &argv) {
            return Err(
                "managed-test-request-provenance-unavailable:cargo-target-normalization".into(),
            );
        }
        return Err("receipt-argv-mismatch".into());
    }
    let input = receipt
        .get("inputClosure")
        .filter(|value| value.is_object())
        .ok_or("input-closure-missing")?;
    if input.get("status").and_then(Value::as_str) != Some("verified")
        || !valid_broker_digest(input.get("preDigest"))
        || !valid_broker_digest(input.get("postDigest"))
        || input.get("preDigest") != input.get("postDigest")
        || !["changed", "added", "removed", "extrasChanged"]
            .iter()
            .all(|key| array_empty(input, key))
    {
        return Err("input-closure-unverified-or-changed".into());
    }
    let reap = receipt
        .get("reap")
        .filter(|value| value.is_object())
        .ok_or("reap-proof-missing")?;
    if reap.get("status").and_then(Value::as_str) != Some("REAPED")
        || reap.get("reaped").and_then(Value::as_bool) != Some(true)
        || !no_survivors(receipt)
    {
        return Err("broker-reap-unconfirmed".into());
    }
    let outer_status = status
        .get("state")
        .or_else(|| status.get("status"))
        .and_then(Value::as_str)
        .ok_or("terminal-state-missing")?;
    if !matches!(outer_status, "SUCCEEDED" | "FAILED") {
        return Err("broker-job-not-terminal".into());
    }
    let exit = receipt
        .get("exitCode")
        .and_then(Value::as_i64)
        .ok_or("test-exit-code-missing")?;
    if status
        .get("exitCode")
        .and_then(Value::as_i64)
        .is_some_and(|outer| outer != exit)
    {
        return Err("terminal-exit-code-mismatch".into());
    }
    if receipt
        .get("signal")
        .is_some_and(|signal| !signal.is_null())
    {
        return Err("test-terminated-by-signal".into());
    }
    Ok(exit as i32)
}

fn valid_hex_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_attested_payload(
    payload: &Value,
    status: &Value,
    id: &str,
    nonce: &str,
    request_digest: &str,
    copy: &PreparedCopy,
    enrollment: &AttestedRunsEnrollment,
    family: &str,
    runner: &str,
    adapter: Option<&super::attested_runs::AdapterEnrollment>,
    requested_argv: &[String],
    outputs: &[PathBuf],
    submitted_exit: i32,
) -> Result<i32, String> {
    let request = payload
        .get("request")
        .filter(|value| value.is_object())
        .ok_or("provenance-request-missing")?;
    let shim = if family == "rust-rightkit" {
        "cargo"
    } else {
        "adapter"
    };
    let expected_kind = if shim == "cargo" { "cargo" } else { "adapter" };
    let expected_adapter = adapter.map(|item| item.broker_adapter_id.as_str());
    if payload.get("host").and_then(Value::as_str) != Some(enrollment.host.as_str())
        || payload.get("keyId").and_then(Value::as_str) != Some(enrollment.key_id.as_str())
        || payload
            .pointer("/broker/brokerDigest")
            .and_then(Value::as_str)
            != Some(enrollment.broker_digest.as_str())
        || payload.get("jobId").and_then(Value::as_str) != Some(id)
        || payload.get("nonce").and_then(Value::as_str) != Some(nonce)
        || payload.get("requestDigest").and_then(Value::as_str) != Some(request_digest)
    {
        return Err("provenance-top-level-binding-mismatch".into());
    }
    if request.get("kind").and_then(Value::as_str) != Some(expected_kind)
        || request.get("shim").and_then(Value::as_str) != Some(shim)
        || request.get("adapter").and_then(Value::as_str) != expected_adapter
        || request
            .get("requestedArgv")
            .and_then(Value::as_array)
            .is_none_or(|values| {
                values
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .is_none_or(|values| {
                        values
                            != requested_argv
                                .iter()
                                .map(String::as_str)
                                .collect::<Vec<_>>()
                    })
            })
        || request.get("workspace").and_then(Value::as_str)
            != Some(copy.cwd.to_string_lossy().as_ref())
        || request.get("workspaceRoot").and_then(Value::as_str)
            != Some(copy.workspace_root.to_string_lossy().as_ref())
        || payload
            .pointer("/broker/clientDigest")
            .and_then(Value::as_str)
            != Some(enrollment.client_digest.as_str())
    {
        return Err("provenance-request-binding-mismatch".into());
    }
    let expected_outputs = outputs
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if request
        .get("outputs")
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .is_none_or(|values| {
                    values
                        != expected_outputs
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                })
        })
        || !valid_hex_digest(request.get("manifestDigest"))
        || request
            .get("effectiveArgv")
            .and_then(Value::as_array)
            .is_none()
        || request
            .get("transformations")
            .and_then(Value::as_array)
            .is_none()
    {
        return Err("provenance-effective-request-evidence-invalid".into());
    }
    let executable = payload
        .get("executable")
        .filter(|value| value.is_object())
        .ok_or("provenance-executable-missing")?;
    if executable
        .get("path")
        .and_then(Value::as_str)
        .is_none_or(|path| !Path::new(path).is_absolute())
        || !valid_hex_digest(executable.get("sha256"))
        || !matches!(
            executable.get("kind").and_then(Value::as_str),
            Some("native" | "interpreter")
        )
    {
        return Err("provenance-executable-identity-invalid".into());
    }
    if let Some(script) = executable.get("script") {
        if script
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(|path| !Path::new(path).is_absolute())
            || !valid_hex_digest(script.get("sha256"))
        {
            return Err("provenance-script-identity-invalid".into());
        }
        if executable
            .get("argsPrefix")
            .and_then(Value::as_array)
            .is_some_and(|prefix| !prefix.is_empty())
        {
            return Err("provenance-script-combined-with-prefix".into());
        }
    } else if executable.get("argsPrefix").is_some() {
        if executable.get("prefixAttested").and_then(Value::as_bool) != Some(false)
            || executable
                .get("argsPrefix")
                .and_then(Value::as_array)
                .is_none()
        {
            return Err("provenance-native-prefix-invalid".into());
        }
    }
    let descendants = payload
        .get("descendants")
        .filter(|value| value.is_object())
        .ok_or("provenance-descendants-missing")?;
    if descendants.get("status").and_then(Value::as_str) != Some("tree-contained") {
        return Err("broker-descendants-not-contained".into());
    }
    if descendants
        .get("survivors")
        .is_some_and(|survivors| !survivors.as_array().is_some_and(Vec::is_empty))
    {
        return Err("broker-known-survivors".into());
    }
    let result = payload
        .get("result")
        .filter(|value| value.is_object())
        .ok_or("provenance-result-missing")?;
    if !matches!(
        result.get("status").and_then(Value::as_str),
        Some("SUCCEEDED" | "FAILED")
    ) || result.pointer("/reap/status").and_then(Value::as_str) != Some("REAPED")
        || result.pointer("/reap/reaped").and_then(Value::as_bool) != Some(true)
        || result.get("signal").is_some_and(|signal| !signal.is_null())
    {
        return Err("broker-terminal-result-unconfirmed".into());
    }
    let boundary = payload
        .get("inputBoundary")
        .filter(|value| value.is_object())
        .ok_or("provenance-input-boundary-missing")?;
    if boundary.get("status").and_then(Value::as_str) != Some("intact")
        || !["changed", "deleted", "added"]
            .iter()
            .all(|key| array_empty(boundary, key))
    {
        return Err("broker-input-boundary-not-intact".into());
    }
    let exit = result
        .get("exitCode")
        .and_then(Value::as_i64)
        .ok_or("provenance-exit-code-missing")?;
    if status
        .get("exitCode")
        .and_then(Value::as_i64)
        .is_some_and(|outer| outer != exit)
        || status.get("id").and_then(Value::as_str) != Some(id)
        || status
            .get("state")
            .or_else(|| status.get("status"))
            .and_then(Value::as_str)
            != result.get("status").and_then(Value::as_str)
        || (exit == 0 && result.get("status").and_then(Value::as_str) != Some("SUCCEEDED"))
        || (exit != 0 && result.get("status").and_then(Value::as_str) != Some("FAILED"))
        || !valid_hex_digest(payload.get("outputDigest"))
    {
        return Err("status-provenance-terminal-mismatch".into());
    }
    match_submit_to_attested_exit(submitted_exit, exit)?;
    let _ = runner;
    Ok(exit as i32)
}

fn cleanup_proven(
    status: &Value,
    id: &str,
    copy: &PreparedCopy,
    expected_command: &str,
    expected_argv: &[String],
) -> bool {
    let _ = (status, id, copy, expected_command, expected_argv);
    false
}

pub(super) fn incomplete(
    input: &LegacyCheckInput,
    message: String,
    details: Value,
) -> LegacyCheckExecution {
    let reason = format!("disposable-copy-incomplete:{message}");
    let mut output = empty_output(vec![reason.clone()]);
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![reason],
    });
    output.details.insert(
        "testCommandResolution".into(),
        json!({"status":"incomplete","reason":message}),
    );
    output.details.insert("disposableCopy".into(), details);
    let mut execution = super::terminal_execution(
        input,
        super::CommandShape::Named {
            tool: "cargo",
            args: &[],
        },
        LegacyCheckProcessState::CleanupUnconfirmed,
        None,
        Vec::new(),
        Vec::new(),
        output,
        vec![format!("preflight-incomplete:{message}")],
        super::now_ms(),
        false,
        None,
    );
    // Keep legacy cleanup state separate from canonical terminal state. With
    // no observation, the full receipt records internal/unknown plus explicit
    // process-state uncertainty instead of asserting launch or reap facts.
    if let Some(receipt) = execution
        .output
        .as_mut()
        .and_then(|output| output.details.get_mut("executionReceipt"))
    {
        if let Some(object) = receipt.as_object_mut() {
            object.remove("kind");
        }
        receipt["state"] = Value::String("internal".into());
        receipt["complete"] = Value::Bool(false);
        receipt["executable"] = Value::Null;
        receipt["command"] = Value::Null;
        receipt["gaps"] = json!([format!("preflight-incomplete:{message}")]);
        receipt["processTree"]["detail"] =
            Value::String("launch and cleanup state unobserved".into());
    }
    execution
}

fn canonical_receipt_json(receipt: &ExecutionReceipt) -> Value {
    json!({
        "schemaVersion": receipt.schema_version,
        "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id,
        "providerId": receipt.provider_id,
        "planId": receipt.plan_id,
        "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id,
        "state": receipt.state.as_str(),
        "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}", e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}", e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd,
        "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code,
        "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
        "gaps": receipt.gaps,
    })
}

fn validate_runner_binding(
    source: &Value,
    family: &str,
    invocation: &[String],
    enrollment: &AttestedRunsEnrollment,
) -> Result<(), String> {
    let runner = source.get("runner").and_then(Value::as_str);
    match family {
        "rust-rightkit" if invocation.iter().map(String::as_str).eq(["cargo", "test"]) => Ok(()),
        "registered-adapter" => {
            let runner = runner.ok_or("test-runner-name-missing")?;
            if invocation.first().map(String::as_str) != Some(runner) {
                return Err("test-runner-name-or-argv-mismatch".into());
            }
            if enrollment.adapter(runner).is_none() {
                return Err(format!("managed-test-runner-not-registered:{runner}"));
            }
            Ok(())
        }
        _ => Err("test-runner-family-not-allowlisted".into()),
    }
}

fn validate_required_runner_version(
    runner: &str,
    required: Option<&str>,
    adapter: Option<&AdapterEnrollment>,
) -> Result<(), String> {
    let Some(required) = required else {
        return Ok(());
    };
    match adapter.and_then(|item| item.qualified_version.as_deref()) {
        Some(qualified) if qualified == required => Ok(()),
        Some(_) => Err(format!("managed-test-runner-version-mismatch:{runner}")),
        None => Err(format!("managed-test-runner-version-unqualified:{runner}")),
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct InputFile {
    path: String,
    kind: &'static str,
    sha256: String,
    mode: u32,
    size: u64,
}

fn input_manifest(root: &Path) -> Result<Value, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    let mut total = 0u64;
    for item in walkdir::WalkDir::new(&root).follow_links(false) {
        let item = item.map_err(|error| error.to_string())?;
        if item.path() == root {
            continue;
        }
        let metadata = fs::symlink_metadata(item.path()).map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "input-manifest-unsupported-entry:{}",
                item.path().display()
            ));
        }
        total = total.saturating_add(metadata.len());
        if entries.len() >= MAX_FILES || total > MAX_TOTAL_BYTES {
            return Err("input-manifest-bound-exceeded".into());
        }
        let relative = item
            .path()
            .strip_prefix(&root)
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or("input-manifest-path-not-utf8")?
            .replace('\\', "/");
        let bytes = fs::read(item.path()).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o7777
        };
        #[cfg(windows)]
        let mode = 0;
        entries.push(InputFile {
            path: relative,
            kind: "file",
            sha256: hex::encode(Sha256::digest(&bytes)),
            mode,
            size: bytes.len() as u64,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(json!({"root":root,"entries":entries}))
}

fn approved_outputs(copy: &PreparedCopy, family: &str, runner: &str) -> Vec<PathBuf> {
    let names: &[&str] = match (family, runner) {
        ("rust-rightkit", _) => &[],
        ("registered-adapter", "npm" | "pnpm" | "yarn" | "bun") => &["node_modules"],
        ("registered-adapter", "pytest") => &[".pytest_cache"],
        ("registered-adapter", "swift") => &[".build"],
        ("registered-adapter", "mvn") => &["target"],
        ("registered-adapter", "gradle") => &[".gradle", "build"],
        ("registered-adapter", "dotnet") => &["bin", "obj"],
        ("registered-adapter", "flutter") => &[".dart_tool", "build"],
        ("registered-adapter", "mix") => &["_build", "deps"],
        _ => &[],
    };
    if family == "rust-rightkit" {
        vec![copy.workspace_root.join("target")]
    } else {
        names.iter().map(|name| copy.path.join(name)).collect()
    }
}

fn observed_rust_environment(environment: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    const KEYS: &[&str] = &[
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INSTALL_ROOT",
        "RUSTUP_HOME",
        "RUSTC",
        "RUSTDOC",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ];
    environment
        .iter()
        .filter(|(key, _)| KEYS.iter().any(|managed| key.eq_ignore_ascii_case(managed)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn artifact_bytes(
    receipt: &ExecutionReceipt,
    stderr: bool,
    scratch: &AuditScratch,
) -> Option<Vec<u8>> {
    super::readable_artifact(
        &[&scratch.artifacts_dir()],
        if stderr {
            receipt.stderr.as_ref()?
        } else {
            receipt.stdout.as_ref()?
        },
    )
}

fn trusted_cli_response<'a>(receipt: &ExecutionReceipt, response: &'a Value) -> Option<&'a Value> {
    (receipt.complete
        && receipt.state == ExecutionState::Completed
        && receipt.exit_code == Some(0)
        && receipt.process_tree.reaped)
        .then_some(response)
}

fn submit_process_exit(receipt: &ExecutionReceipt) -> Option<i32> {
    if receipt.complete && receipt.state == ExecutionState::Completed && receipt.process_tree.reaped
    {
        receipt.exit_code
    } else {
        None
    }
}

fn match_submit_to_attested_exit(submitted_exit: i32, attested_exit: i64) -> Result<(), String> {
    if i64::from(submitted_exit) == attested_exit {
        Ok(())
    } else {
        Err("submit-exit-does-not-match-attested-job-exit".into())
    }
}

/// Classify a failed request-digest probe by what the receipt shows.
/// `...-unreaped` only when the process started and was not reaped; a probe
/// that never launched reports its real state instead of an unreaped process.
fn request_digest_process_gap(receipt: &ExecutionReceipt) -> Option<String> {
    if receipt.process_tree.started && !receipt.process_tree.reaped {
        Some("request-digest-process-unreaped".into())
    } else if !receipt.process_tree.started {
        Some(format!(
            "request-digest-process-not-started:{}",
            receipt.state.as_str()
        ))
    } else {
        None
    }
}

fn external_request(
    base: &ExternalToolRequest,
    command: &[String],
    cwd: &Path,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    timeout_ms: u64,
) -> ExternalToolRequest {
    let mut request = base.clone();
    let operation = match command.first().map(String::as_str) {
        Some("cancel") => "cancel",
        Some("status") => "status",
        _ => "submit",
    };
    request.request_id = format!(
        "{}-{operation}-{}",
        base.request_id,
        COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    request.args = command.to_vec();
    request.cwd = cwd.to_string_lossy().into_owned();
    request.environment = environment;
    request.environment_allowlist = allowlist;
    request.expected_digest = base.expected_digest.clone();
    request.timeout_ms = timeout_ms;
    request.accepted_exit_codes = (0..=255).collect();
    request.requires_network_sandbox = false;
    request.sandbox = None;
    request
}

fn id_request(
    base: &ExternalToolRequest,
    operation: &str,
    id: &str,
    cwd: &Path,
    timeout_ms: u64,
) -> ExternalToolRequest {
    let (environment, allowlist) = audit_environment_for_request(base);
    external_request(
        base,
        &[operation.to_owned(), id.to_owned()],
        cwd,
        environment,
        allowlist,
        timeout_ms,
    )
}

fn audit_environment_for_request(
    base: &ExternalToolRequest,
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let mut environment = base.environment.clone();
    let mut allowlist = base.environment_allowlist.clone();
    environment.insert(CANCEL_ON_DISCONNECT.into(), "1".into());
    allowlist.insert(CANCEL_ON_DISCONNECT.into());
    (environment, allowlist)
}

fn copied_request(
    base: &ExternalToolRequest,
    copy: &PreparedCopy,
    timeout_ms: u64,
    request_id: String,
    command: &[String],
) -> ExternalToolRequest {
    let (mut environment, mut allowlist) =
        (base.environment.clone(), base.environment_allowlist.clone());
    environment.insert(CANCEL_ON_DISCONNECT.into(), "1".into());
    allowlist.insert(CANCEL_ON_DISCONNECT.into());
    let mut request =
        external_request(base, command, &copy.cwd, environment, allowlist, timeout_ms);
    request.request_id = request_id;
    request
}

/// Run a frozen Rust test declaration on a materialized copy. Only terminal,
/// source-unchanged broker receipts produce a pass or failing-test finding.
pub(super) async fn execute(
    tool: &dyn ExternalProjectTool,
    plan_digest: &str,
    preparation_authorizer: Option<&dyn legion_effects::PolicyAuthorizer>,
    root: &Path,
    command: &ResolvedCommand,
    source: &Value,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    input: &LegacyCheckInput,
    scratch: &AuditScratch,
    cancellation: CancellationToken,
    timeout_ms: u64,
    enrollment: Option<&AttestedRunsEnrollment>,
) -> LegacyCheckExecution {
    if let Some(enrollment) = enrollment {
        if let Err(error) = enrollment.validate() {
            let command_shape = super::spec(&input.provider_id)
                .expect("managed test input has a frozen provider contract")
                .command;
            return super::invalid_test_enrollment(input, command_shape, &error.to_string());
        }
    }
    let Some(enrollment) = enrollment else {
        return super::unavailable_test_refusal(
            input,
            "managed-test-trust-not-configured",
            json!({"assurance":"attested-runs-required"}),
        );
    };
    let test_declaration = source
        .get("testDeclarationPath")
        .and_then(Value::as_str)
        .or_else(|| {
            source
                .get("sources")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items.iter().find_map(|item| {
                        let path = item.get("path")?.as_str()?;
                        path.ends_with("Cargo.toml").then_some(path)
                    })
                })
        })
        .map(ToOwned::to_owned);
    let Some(test_declaration) = test_declaration else {
        return incomplete(
            input,
            "frozen-test-declaration-missing".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
    };
    let family = source.get("family").and_then(Value::as_str).unwrap_or("");
    if !matches!(family, "rust-rightkit" | "registered-adapter") {
        return incomplete(
            input,
            "test-runner-family-not-supported-in-disposable-copy".into(),
            json!({"assurance":"disposable-copy-before-after","family":family}),
        );
    }
    let invocation = command.args.clone();
    if invocation.is_empty() {
        return incomplete(
            input,
            "frozen-test-argv-empty".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
    }
    if let Err(message) = validate_runner_binding(source, family, &invocation, enrollment) {
        if message.starts_with("managed-test-runner-") {
            return super::unavailable_test_refusal(
                input,
                &message,
                json!({"assurance":"attested-runs-required","family":family}),
            );
        }
        return incomplete(
            input,
            message,
            json!({"assurance":"disposable-copy-before-after","family":family}),
        );
    }
    let runner_label = if family == "rust-rightkit" {
        "cargo"
    } else {
        source.get("runner").and_then(Value::as_str).unwrap_or("")
    };
    let adapter = enrollment.adapter(runner_label);
    let required_runner_version = source.get("requiredRunnerVersion").and_then(Value::as_str);
    if let Err(reason) =
        validate_required_runner_version(runner_label, required_runner_version, adapter)
    {
        if reason.starts_with("managed-test-runner-version-") {
            return super::unavailable_test_refusal(
                input,
                &reason,
                json!({"assurance":"attested-runs-required","requiredVersion":required_runner_version}),
            );
        }
        return incomplete(
            input,
            reason,
            json!({"assurance":"attested-runs-required","requiredVersion":required_runner_version}),
        );
    }
    let pinned_client = fs::canonicalize(&enrollment.client_executable).ok();
    let enrollment_meta = fs::symlink_metadata(&enrollment.client_executable).ok();
    let selected_client = fs::canonicalize(&command.executable).ok();
    let selected_bytes = selected_client
        .as_ref()
        .and_then(|path| fs::read(path).ok());
    let selected_digest = selected_bytes
        .as_ref()
        .map(|bytes| hex::encode(Sha256::digest(bytes)));
    if pinned_client.is_none()
        || enrollment_meta
            .as_ref()
            .is_none_or(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        || selected_client != pinned_client
        || selected_digest.as_deref() != Some(enrollment.client_digest.as_str())
        || command.digest != format!("sha256:{}", enrollment.client_digest)
    {
        return super::unavailable_test_refusal(
            input,
            "managed-test-attestation-cli-unavailable",
            json!({"assurance":"attested-runs-required","reason":"pinned-client-unavailable-or-mismatched"}),
        );
    }
    // Enrollment authenticates the broker; it does not admit Git inventory,
    // disposable-copy preparation, or the managed test operation itself.
    let mut preparation = ExternalToolRequest {
        request_id: format!(
            "audit:{}:{}:managed-test-preparation",
            provider.id, plan_digest
        ),
        provider_id: provider.id.clone(),
        plan_id: plan_digest.into(),
        policy_id: crate::execution_policy::POLICY_ID.into(),
        task_id: Some("managed-test-disposable-copy".into()),
        executable: command.executable.to_string_lossy().into_owned(),
        args: command.args.clone(),
        cwd: root.to_string_lossy().into_owned(),
        timeout_ms,
        ..ExternalToolRequest::default()
    };
    let decision = super::owner_request::authorize_preparation(
        scratch.owner_context().as_deref(),
        scratch.owner_authorizer().as_deref(),
        preparation_authorizer,
        &mut preparation,
    );
    if !decision.allowed {
        #[cfg(unix)]
        let process = legion_effects::platform::unix::UnixProcess::new();
        #[cfg(windows)]
        let process = legion_effects::platform::windows::WindowsProcess::default();
        let effects = legion_effects::EffectExecutor::new(
            process,
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            legion_effects::StaticPolicy { decision },
        );
        let receipt = effects
            .execute_with_cancellation(&preparation, cancellation)
            .await;
        return super::execution_from_receipt(
            input,
            super::spec(&provider.id)
                .expect("managed test contract")
                .command,
            &[root],
            receipt,
            super::ReportSource::Stdout,
            None,
            Some(source.clone()),
        );
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut copy = match prepare_copy(
        root,
        inventory,
        scratch,
        &test_declaration,
        deadline,
        &cancellation,
    ) {
        Ok(copy) => copy,
        Err(error) => {
            let code = error.code();
            let detail = match &error {
                CopyError::UnsafePath(value)
                | CopyError::UnsupportedCargoBoundary(value)
                | CopyError::SourceDrift(value)
                | CopyError::Limit(value)
                | CopyError::Io(value) => value.clone(),
                CopyError::Cancelled => "cancelled".into(),
                CopyError::Deadline => "deadline-expired".into(),
            };
            let message = format!("{code}:{detail}");
            return incomplete(
                input,
                message,
                json!({"assurance":"disposable-copy-before-after","osSandbox":false,"networkIsolation":"not-enforced"}),
            );
        }
    };
    if let Err(message) = bind_copy_workspace_root(root, source, &mut copy) {
        return retain_incomplete(scratch, &copy, input, &message);
    }
    if !verify_source_unchanged(root, inventory, &copy.input_modes, deadline, &cancellation)
        || !verify_copy_unchanged(&copy, inventory, &[], deadline, &cancellation)
    {
        let _ = fs::remove_dir_all(&copy.path);
        return incomplete(
            input,
            "source-or-copy-drift-before-submit".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
    }
    let remaining_ms = || {
        deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64
    };
    let request_material = format!(
        "{}:{}:{}",
        provider.id,
        inventory.digest,
        COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let base = ExternalToolRequest {
        request_id: format!(
            "audit-{}",
            hex::encode(Sha256::digest(request_material.as_bytes()))
        ),
        provider_id: provider.id.clone(),
        plan_id: plan_digest.into(),
        policy_id: provider
            .configuration
            .get("policyId")
            .and_then(Value::as_str)
            .unwrap_or("audit")
            .into(),
        task_id: Some("test".into()),
        executable: command.executable.to_string_lossy().into_owned(),
        cwd: copy.cwd.to_string_lossy().into_owned(),
        expected_digest: Some(command.digest.clone()),
        // Never probe a test runner with `--version`: that runs project code
        // outside an attested request. The pinned rightkit CLI itself is
        // checked against enrollment above and sealed by `expected_digest`
        // (still verified by the executor). It is a multicall binary, so a
        // bare probe exits 125 and could never qualify; the executor records
        // the skip as policy. Every request below derives from this base.
        skip_version_probe: true,
        version_requirement: None,
        ..ExternalToolRequest::default()
    };
    let (mut environment, mut allowlist) = audit_environment(scratch);
    pass_broker_socket(
        std::env::var(BROKER_SOCKET_ENV).ok(),
        &mut environment,
        &mut allowlist,
    );
    environment.insert(CANCEL_ON_DISCONNECT.into(), "1".into());
    allowlist.insert(CANCEL_ON_DISCONNECT.into());
    let outputs = approved_outputs(&copy, family, runner_label);
    let manifest_paths = match input_manifest(&copy.path) {
        Ok(value) => value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                entry
                    .get("path")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>(),
        Err(message) => return retain_incomplete(scratch, &copy, input, &message),
    };
    let mut output_relatives = Vec::new();
    for output in &outputs {
        let Ok(relative) = output.strip_prefix(&copy.path) else {
            return retain_incomplete(scratch, &copy, input, "approved-output-root-invalid");
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.is_empty()
            || manifest_paths.iter().any(|path| {
                path == &relative
                    || path.starts_with(&format!("{relative}/"))
                    || relative.starts_with(&format!("{path}/"))
            })
            || output_relatives.iter().any(|prior: &String| {
                prior == &relative
                    || prior.starts_with(&format!("{relative}/"))
                    || relative.starts_with(&format!("{prior}/"))
            })
        {
            return retain_incomplete(
                scratch,
                &copy,
                input,
                "approved-output-overlaps-frozen-input",
            );
        }
        output_relatives.push(relative);
        if let Err(error) = fs::create_dir_all(output) {
            return retain_incomplete(
                scratch,
                &copy,
                input,
                &format!("output-root-create-failed:{error}"),
            );
        }
    }
    let nonce = match attested_runs::fresh_nonce() {
        Ok(nonce) => nonce,
        Err(message) => return retain_incomplete(scratch, &copy, input, &message),
    };
    let manifest = match input_manifest(&copy.path) {
        Ok(manifest) => manifest,
        Err(message) => return retain_incomplete(scratch, &copy, input, &message),
    };
    let manifest_path = scratch
        .root()
        .join(format!("attested-manifest-{}", id_suffix(&base.request_id)));
    let core_path = scratch
        .root()
        .join(format!("attested-core-{}", id_suffix(&base.request_id)));
    let output_strings = outputs
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let requested_argv = invocation.iter().skip(1).cloned().collect::<Vec<_>>();
    let shim = if family == "rust-rightkit" {
        "cargo"
    } else {
        "adapter"
    };
    let core = json!({
        "adapter":adapter.map(|item| item.broker_adapter_id.as_str()),
        "env":{},
        "inputManifest":manifest.clone(),
        "nonce":nonce,
        "observedEnv":if shim == "cargo" { json!(observed_rust_environment(&environment)) } else { json!({}) },
        "outputs":output_strings,
        "requestedArgv":requested_argv,
        "shim":shim,
        "workspace":copy.cwd.to_string_lossy(),
    });
    if fs::write(&core_path, serde_json::to_vec(&core).unwrap_or_default()).is_err() {
        return retain_incomplete(scratch, &copy, input, "request-core-write-failed");
    }
    if remaining_ms() == 0 {
        return retain_incomplete(scratch, &copy, input, "deadline-expired-before-cli-probe");
    }
    let probe_env = environment.clone();
    let probe_allowlist = allowlist.clone();
    let probe = external_request(
        &base,
        &[
            "request-digest".into(),
            "--core".into(),
            core_path.to_string_lossy().into_owned(),
        ],
        &copy.cwd,
        probe_env,
        probe_allowlist,
        remaining_ms(),
    );
    let probe_receipt = tokio::select! {
        _ = cancellation.cancelled() => return retain_incomplete(scratch, &copy, input, "cancelled-before-cli-probe"),
        result = tool.execute(probe, cancellation.clone()) => result,
    };
    let probe_bytes = artifact_bytes(&probe_receipt, false, scratch).unwrap_or_default();
    let probe_json: Value = serde_json::from_slice(&probe_bytes).unwrap_or(Value::Null);
    let request_digest = probe_json
        .get("requestDigest")
        .and_then(Value::as_str)
        .unwrap_or("");
    if trusted_cli_response(&probe_receipt, &probe_json).is_none()
        || !request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || request_digest.len() != 64
    {
        if let Some(gap) = request_digest_process_gap(&probe_receipt) {
            let mut execution = retain_incomplete(scratch, &copy, input, &gap);
            attach_execution_receipt(&mut execution, &probe_receipt);
            return execution;
        }
        let mut execution = incomplete(
            input,
            "managed-test-attestation-cli-unavailable".into(),
            json!({"assurance":"attested-runs-required","phase":"request-digest","clientState":format!("{:?}", probe_receipt.state)}),
        );
        attach_execution_receipt(&mut execution, &probe_receipt);
        return execution;
    }
    let manifest_envelope = json!({"root":manifest["root"],"entries":manifest["entries"]});
    if fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest_envelope).unwrap_or_default(),
    )
    .is_err()
    {
        let mut execution = retain_incomplete(scratch, &copy, input, "input-manifest-write-failed");
        attach_execution_receipt(&mut execution, &probe_receipt);
        return execution;
    }
    environment.insert("RIGHTKIT_ATTEST_NONCE".into(), nonce.clone());
    environment.insert(
        "RIGHTKIT_INPUT_MANIFEST".into(),
        manifest_path.to_string_lossy().into_owned(),
    );
    environment.insert(
        "RIGHTKIT_OUTPUT_ROOTS".into(),
        output_strings.join(if cfg!(windows) { ";" } else { ":" }),
    );
    allowlist.extend([
        "RIGHTKIT_ATTEST_NONCE".into(),
        "RIGHTKIT_INPUT_MANIFEST".into(),
        "RIGHTKIT_OUTPUT_ROOTS".into(),
    ]);
    if remaining_ms() == 0 {
        let _ = fs::remove_dir_all(&copy.path);
        let mut execution = incomplete(
            input,
            "deadline-expired-before-submit".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
        attach_execution_receipt(&mut execution, &probe_receipt);
        return execution;
    }
    let submit = copied_request(
        &ExternalToolRequest {
            environment,
            environment_allowlist: allowlist,
            ..base.clone()
        },
        &copy,
        remaining_ms(),
        base.request_id.clone(),
        &{
            if family == "rust-rightkit" {
                invocation.clone()
            } else {
                let mut args = vec![
                    "run".into(),
                    adapter.unwrap().broker_adapter_id.clone(),
                    "--".into(),
                ];
                args.extend(invocation.iter().skip(1).cloned());
                args
            }
        },
    );
    // From launch onward, scratch survives unless authenticated terminal
    // evidence and local integrity checks prove cleanup is safe.
    scratch.begin_attested_request();
    let submitted = tokio::select! {
        _ = cancellation.cancelled() => {
            // execute may already have launched the broker request. Without a
            // parsed request ID and terminal reap receipt, preserve the copy.
            return retain_incomplete(scratch, &copy, input, "cancelled-after-submit-launch");
        },
        result = tool.execute(submit.clone(), cancellation.clone()) => result,
    };
    let raw_stderr = artifact_bytes(&submitted, true, scratch).unwrap_or_default();
    let id = match request_id(&raw_stderr) {
        Ok(id) => id,
        Err(message) => {
            let mut execution = retain_incomplete(scratch, &copy, input, &message);
            attach_execution_receipt(&mut execution, &submitted);
            return execution;
        }
    };
    if cancellation.is_cancelled()
        || remaining_ms() == 0
        || matches!(
            submitted.state,
            ExecutionState::Timeout | ExecutionState::Cancelled
        )
    {
        let cancel = id_request(&submit, "cancel", &id, &copy.cwd, remaining_ms().max(1));
        let cleanup_token = CancellationToken::new();
        let _ = tool.execute(cancel, cleanup_token.clone()).await;
        let status = id_request(&submit, "status", &id, &copy.cwd, remaining_ms().max(1));
        let _final_status = tool.execute(status, cleanup_token).await;
        // Unsigned cleanup/status fields cannot authorize deleting the copy.
        scratch.retain_after_drop();
        let mut execution = retain_incomplete(scratch, &copy, input, "cancelled-or-timed-out");
        attach_execution_receipt(&mut execution, &submitted);
        return execution;
    }
    let Some(submitted_exit) = submit_process_exit(&submitted) else {
        let mut execution =
            retain_incomplete(scratch, &copy, input, "rightkit-submit-process-unconfirmed");
        attach_execution_receipt(&mut execution, &submitted);
        return execution;
    };
    let status_request = id_request(&submit, "status", &id, &copy.cwd, remaining_ms());
    let status_receipt = tokio::select! {
        _ = cancellation.cancelled() => {
            let cancel = id_request(&submit, "cancel", &id, &copy.cwd, remaining_ms().max(1));
            let cleanup_token = CancellationToken::new();
            let _ = tool.execute(cancel, cleanup_token.clone()).await;
            let _ = tool.execute(id_request(&submit, "status", &id, &copy.cwd, remaining_ms().max(1)), cleanup_token).await;
            scratch.retain_after_drop();
            let mut execution =
                retain_incomplete(scratch, &copy, input, "cancelled-during-status");
            attach_execution_receipt(&mut execution, &submitted);
            return execution;
        },
        result = tool.execute(status_request, CancellationToken::new()) => result,
    };
    if trusted_cli_response(&status_receipt, &Value::Null).is_none() {
        let mut execution =
            retain_incomplete(scratch, &copy, input, "broker-status-process-unconfirmed");
        attach_execution_receipt(&mut execution, &submitted);
        attach_auxiliary_receipt(&mut execution, "rustRightStatusReceipt", &status_receipt);
        return execution;
    }
    let Some(status_json) = status_json(&status_receipt, scratch) else {
        scratch.retain_after_drop();
        let mut execution =
            retain_incomplete(scratch, &copy, input, "broker-status-artifact-unavailable");
        attach_execution_receipt(&mut execution, &submitted);
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    };
    let receipt_path = scratch
        .root()
        .join(format!("attested-receipt-{}", id_suffix(&id)));
    if fs::write(
        &receipt_path,
        serde_json::to_vec(&status_json).unwrap_or_default(),
    )
    .is_err()
    {
        let mut execution = retain_incomplete(
            scratch,
            &copy,
            input,
            "receipt-copy-for-verification-failed",
        );
        attach_execution_receipt(&mut execution, &submitted);
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    }
    let verify_args = vec![
        "verify-receipt".into(),
        "--receipt".into(),
        receipt_path.to_string_lossy().into_owned(),
        "--public-key".into(),
        enrollment.public_key.clone(),
        "--key-id".into(),
        enrollment.key_id.clone(),
        "--host".into(),
        enrollment.host.clone(),
        "--broker-digest".into(),
        enrollment.broker_digest.clone(),
        "--nonce".into(),
        nonce.clone(),
        "--request-digest".into(),
        request_digest.to_owned(),
        "--job-id".into(),
        id.clone(),
    ];
    let verify_request = external_request(
        &submit,
        &verify_args,
        &copy.cwd,
        submit.environment.clone(),
        submit.environment_allowlist.clone(),
        remaining_ms(),
    );
    let verified = tokio::select! {
        _ = cancellation.cancelled() => {
            let mut execution = retain_incomplete(scratch, &copy, input, "cancelled-during-receipt-verification");
            attach_execution_receipt(&mut execution, &submitted);
            attach_status_artifact(&mut execution, &status_receipt);
            return execution;
        },
        result = tool.execute(verify_request, CancellationToken::new()) => result,
    };
    let verify_bytes = artifact_bytes(&verified, false, scratch).unwrap_or_default();
    let verify_json: Value = serde_json::from_slice(&verify_bytes).unwrap_or(Value::Null);
    let Some(verify_json) = trusted_cli_response(&verified, &verify_json) else {
        let mut execution = retain_incomplete(
            scratch,
            &copy,
            input,
            "receipt-verifier-process-unconfirmed",
        );
        attach_execution_receipt(&mut execution, &submitted);
        attach_auxiliary_receipt(&mut execution, "rustRightVerifyReceipt", &verified);
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    };
    let Some(payload) = verify_json
        .get("payload")
        .filter(|_| verify_json.get("ok").and_then(Value::as_bool) == Some(true))
    else {
        let mut execution = retain_incomplete(
            scratch,
            &copy,
            input,
            "managed-test-attestation-verification-failed",
        );
        attach_execution_receipt(&mut execution, &submitted);
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    };
    let expected_adapter = adapter;
    let exit = match validate_attested_payload(
        payload,
        &status_json,
        &id,
        &nonce,
        request_digest,
        &copy,
        enrollment,
        family,
        runner_label,
        expected_adapter,
        &requested_argv,
        &outputs,
        submitted_exit,
    ) {
        Ok(exit) => exit,
        Err(message) => {
            let source_unchanged = verify_source_unchanged(
                root,
                inventory,
                &copy.input_modes,
                deadline,
                &cancellation,
            );
            let copy_unchanged =
                verify_copy_unchanged(&copy, inventory, &outputs, deadline, &cancellation);
            let mut execution = retain_incomplete(scratch, &copy, input, &message);
            attach_execution_receipt(&mut execution, &submitted);
            attach_status_artifact(&mut execution, &status_receipt);
            if let Some(output) = execution.output.as_mut() {
                output.details.insert(
                    "sourceIntegrityAfterReceipt".into(),
                    json!({"sourceUnchanged":source_unchanged,"copyUnchanged":copy_unchanged}),
                );
            }
            return execution;
        }
    };
    let final_source =
        verify_source_unchanged(root, inventory, &copy.input_modes, deadline, &cancellation);
    let final_copy = verify_copy_unchanged(&copy, inventory, &outputs, deadline, &cancellation);
    if !final_source || !final_copy {
        let mut execution =
            retain_incomplete(scratch, &copy, input, "source-or-copy-drift-after-test");
        if let Some(output) = execution.output.as_mut() {
            output.details.insert(
                "integrityCheck".into(),
                json!({"requestId":id,"sourceUnchanged":final_source,"copyUnchanged":final_copy}),
            );
        }
        attach_execution_receipt(&mut execution, &submitted);
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    }
    let _ = fs::remove_dir_all(&copy.path);
    scratch.finish_attested_request();
    let mut output = empty_output(Vec::new());
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: input.denominator.entries.len() as u64,
        gaps: Vec::new(),
    });
    output
        .details
        .insert("testCommandSource".into(), source.clone());
    output.details.insert("disposableCopy".into(), json!({"assurance":"disposable-copy-before-after","osSandbox":false,"networkIsolation":"not-enforced","sourceDigest":copy.source_digest,"copyDigest":copy.copy_digest,"fileCount":copy.file_count,"bytes":copy.total_bytes,"sourceUnchanged":true,"copyUnchanged":true,"requestId":id}));
    output.details.insert(
        "attestedRuns".into(),
        json!({"verified":true,"host":enrollment.host,"keyId":enrollment.key_id,"qualifiedRunnerVersion":adapter.and_then(|item| item.qualified_version.as_deref()),"trustScope":"trusted local-key provenance; same-user hostile code is outside this boundary"}),
    );
    output.status = ProviderStatus::Ok;
    output.complete = true;
    if exit == 0 {
        output.details.insert(
            "testOutcome".into(),
            json!({"passed":true,"exitCode":0,"complete":true}),
        );
    }
    if exit != 0 {
        add_failure_finding(input, source, exit, &mut output);
        if test_declaration_location(Some(source), input).is_none() {
            output
                .coverage_gaps
                .push("test-command-declaration-outside-denominator".into());
            output.complete = false;
            output.status = ProviderStatus::Partial;
        } else {
            output.status = ProviderStatus::Complete;
        }
    }
    output.details.insert(
        "executionReceipt".into(),
        canonical_receipt_json(&submitted),
    );
    output.details.insert(
        "rustRightVerifiedResult".into(),
        json!({"jobId":id,"status":if exit == 0 {"SUCCEEDED"} else {"FAILED"},"exitCode":exit,"verified":true,"host":enrollment.host,"keyId":enrollment.key_id}),
    );
    if let Some(artifact) = status_receipt.stdout.as_ref() {
        output.details.insert(
            "rustRightBrokerStatus".into(),
            json!({"path":artifact.path,"digest":artifact.digest,"bytes":artifact.bytes,"immutable":artifact.immutable}),
        );
    }
    LegacyCheckExecution {
        state: LegacyCheckProcessState::Completed,
        exit_code: Some(exit),
        stdout: artifact_bytes(&submitted, false, scratch).unwrap_or_default(),
        stderr: artifact_bytes(&submitted, true, scratch).unwrap_or_default(),
        receipt_id: Some(submitted.receipt_id.clone()),
        output: Some(output),
        error: None,
    }
}

fn retain_incomplete(
    scratch: &AuditScratch,
    copy: &PreparedCopy,
    input: &LegacyCheckInput,
    message: &str,
) -> LegacyCheckExecution {
    scratch.retain_after_drop();
    incomplete(
        input,
        message.into(),
        json!({"assurance":"disposable-copy-before-after","osSandbox":false,"networkIsolation":"not-enforced","copyPath":copy.path,"sourceDigest":copy.source_digest,"copyDigest":copy.copy_digest,"fileCount":copy.file_count,"bytes":copy.total_bytes}),
    )
}

fn status_json(receipt: &ExecutionReceipt, scratch: &AuditScratch) -> Option<Value> {
    let bytes = artifact_bytes(receipt, false, scratch)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn attach_status_artifact(execution: &mut LegacyCheckExecution, receipt: &ExecutionReceipt) {
    if let Some(output) = execution.output.as_mut() {
        if let Some(artifact) = receipt.stdout.as_ref() {
            output.details.insert(
                "rustRightBrokerStatus".into(),
                json!({"path":artifact.path,"digest":artifact.digest,"bytes":artifact.bytes,"immutable":artifact.immutable}),
            );
        }
    }
}

/// Attach the canonical terminal receipt: the request-digest probe before a
/// submit exists, the submit process afterward. Its exit is bound to the
/// attested job exit, so it is the receipt consumers read. The legacy cleanup
/// state and absent exit code stay on the execution; the receipt records only
/// what that process actually did, and broker attestation stays in separate
/// details.
fn attach_execution_receipt(execution: &mut LegacyCheckExecution, receipt: &ExecutionReceipt) {
    if let Some(output) = execution.output.as_mut() {
        output
            .details
            .insert("executionReceipt".into(), canonical_receipt_json(receipt));
    }
    execution.receipt_id = Some(receipt.receipt_id.clone());
}

/// Preserve an auxiliary CLI process receipt whose own confirmation failed,
/// under its own key, so its terminal facts are not discarded without
/// changing which process the canonical receipt describes.
fn attach_auxiliary_receipt(
    execution: &mut LegacyCheckExecution,
    key: &'static str,
    receipt: &ExecutionReceipt,
) {
    if let Some(output) = execution.output.as_mut() {
        output
            .details
            .insert(key.into(), canonical_receipt_json(receipt));
    }
}

fn source_inventory_paths(
    root: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<String>, CopyError> {
    let mut child = crate::trusted_git::std_command(root).and_then(|mut command| {
        hide_process_console(&mut command);
        command
            .arg("-C")
            .arg(root)
            .args([
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    });
    let git_bytes = if let Some(process) = child.as_mut() {
        let Some(mut stdout) = process.stdout.take() else {
            let _ = process.kill();
            let _ = process.wait();
            return Err(CopyError::Io("git inventory stdout unavailable".into()));
        };
        let (sender, receiver) = mpsc::sync_channel::<Result<Vec<u8>, String>>(2);
        let reader = thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if sender.send(Ok(buffer[..count].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let mut bytes = Vec::new();
        let mut eof = false;
        let mut exit_status = None;
        let mut exited_at = None;
        loop {
            if cancellation.is_cancelled() {
                let _ = process.kill();
                let _ = process.wait();
                drop(receiver);
                drop(reader);
                return Err(CopyError::Cancelled);
            }
            if Instant::now() >= deadline {
                let _ = process.kill();
                let _ = process.wait();
                drop(receiver);
                drop(reader);
                return Err(CopyError::Deadline);
            }
            if !eof {
                match receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(Ok(chunk)) => {
                        if bytes.len().saturating_add(chunk.len()) > MAX_PATH_LIST_BYTES {
                            let _ = process.kill();
                            let _ = process.wait();
                            drop(receiver);
                            drop(reader);
                            return Err(CopyError::Limit(
                                "inventory path list exceeds bound".into(),
                            ));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok(Err(error)) => {
                        let _ = process.kill();
                        let _ = process.wait();
                        drop(receiver);
                        drop(reader);
                        return Err(CopyError::Io(format!("git inventory: {error}")));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => eof = true,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            if exit_status.is_none() {
                match process.try_wait() {
                    Ok(status) => {
                        let has_exited = status.is_some();
                        exit_status = status;
                        if has_exited {
                            exited_at = Some(Instant::now());
                        }
                    }
                    Err(error) => {
                        let _ = process.kill();
                        let _ = process.wait();
                        drop(receiver);
                        drop(reader);
                        return Err(CopyError::Io(format!("git inventory: {error}")));
                    }
                }
            }
            if eof && exit_status.is_some() {
                break;
            }
            if exited_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(200)) {
                drop(receiver);
                drop(reader);
                return Err(CopyError::Io(
                    "git inventory pipe remained open after child exit".into(),
                ));
            }
        }
        let _ = reader.join();
        if exit_status.is_some_and(|status| status.success()) {
            Some(bytes)
        } else {
            None
        }
    } else {
        None
    };
    let mut paths = if let Some(bytes) = git_bytes {
        let mut paths = Vec::new();
        for path in bytes
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let path = String::from_utf8_lossy(path).replace('\\', "/");
            if crate::inventory::path_in_excluded_directory(&path) {
                continue;
            }
            paths.push(path);
            if paths.len() > MAX_FILES {
                return Err(CopyError::Limit("inventory exceeds 100000 files".into()));
            }
        }
        paths
    } else {
        let mut paths = Vec::new();
        let mut path_bytes = 0_usize;
        for item in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(crate::inventory::included_entry)
        {
            if cancellation.is_cancelled() {
                return Err(CopyError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(CopyError::Deadline);
            }
            let item = item.map_err(|error| CopyError::Io(error.to_string()))?;
            if item.depth() == 0 || !(item.file_type().is_file() || item.file_type().is_symlink()) {
                continue;
            }
            let relative = item
                .path()
                .strip_prefix(root)
                .map_err(|error| CopyError::Io(error.to_string()))?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            path_bytes = path_bytes.saturating_add(relative.len());
            if paths.len() >= MAX_FILES || path_bytes > MAX_PATH_LIST_BYTES {
                return Err(CopyError::Limit("inventory exceeds path-list bound".into()));
            }
            paths.push(relative);
        }
        paths
    };
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_FILES {
        return Err(CopyError::Limit("inventory exceeds 100000 files".into()));
    }
    Ok(paths)
}

fn hide_process_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    let _ = command;
}

fn bounded_file_metadata(root: &Path, relative: &str) -> Result<u64, CopyError> {
    let relative_path = safe_relative(relative)?;
    let mut cursor = root.to_path_buf();
    let components = relative_path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|error| CopyError::Io(format!("{relative}: {error}")))?;
        if metadata.file_type().is_symlink()
            || (index + 1 == components.len() && !metadata.is_file())
            || (index + 1 < components.len() && !metadata.is_dir())
        {
            return Err(CopyError::UnsafePath(relative.into()));
        }
        if index + 1 == components.len() {
            if metadata.len() > MAX_FILE_BYTES {
                return Err(CopyError::Limit(format!("file too large: {relative}")));
            }
            return Ok(metadata.len());
        }
    }
    Err(CopyError::UnsafePath(relative.into()))
}

fn bounded_digest(
    path: &Path,
    relative: &str,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(String, u64), CopyError> {
    let mut file =
        fs::File::open(path).map_err(|error| CopyError::Io(format!("{relative}: {error}")))?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if cancellation.is_cancelled() {
            return Err(CopyError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(CopyError::Deadline);
        }
        let count = file
            .read(&mut buffer)
            .map_err(|error| CopyError::Io(format!("{relative}: {error}")))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_FILE_BYTES {
            return Err(CopyError::Limit(format!("file too large: {relative}")));
        }
        hash.update(&buffer[..count]);
    }
    Ok((format!("sha256:{}", hex::encode(hash.finalize())), total))
}

fn verify_source_unchanged(
    root: &Path,
    inventory: &InventoryEnvelope,
    input_modes: &BTreeMap<String, u32>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> bool {
    let paths = match source_inventory_paths(root, deadline, cancellation) {
        Ok(paths) => paths,
        Err(_) => return false,
    };
    let mut expected = inventory
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    expected.sort();
    if paths != expected || cancellation.is_cancelled() || Instant::now() >= deadline {
        return false;
    }
    let mut total = 0_u64;
    for path in &paths {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let length = match bounded_file_metadata(root, path) {
            Ok(length) => length,
            Err(_) => return false,
        };
        total = total.saturating_add(length);
        if total > MAX_TOTAL_BYTES {
            return false;
        }
    }
    let mut hashed_total = 0_u64;
    for entry in &inventory.entries {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let Some(expected) = entry.digest.as_deref() else {
            return false;
        };
        let Ok((digest, bytes)) =
            bounded_digest(&root.join(&entry.path), &entry.path, deadline, cancellation)
        else {
            return false;
        };
        hashed_total = hashed_total.saturating_add(bytes);
        if digest != expected
            || file_mode(&root.join(&entry.path)).ok() != input_modes.get(&entry.path).copied()
            || hashed_total > MAX_TOTAL_BYTES
        {
            return false;
        }
    }
    true
}

fn verify_copy_unchanged(
    copy: &PreparedCopy,
    inventory: &InventoryEnvelope,
    outputs: &[PathBuf],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> bool {
    let expected = inventory
        .entries
        .iter()
        .filter_map(|entry| {
            entry.digest.as_deref().map(|digest| {
                (
                    entry.path.clone(),
                    (
                        digest.to_owned(),
                        copy.input_modes.get(&entry.path).copied(),
                    ),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    if expected.len() != inventory.entries.len() {
        return false;
    }
    let mut frozen_directories = BTreeSet::new();
    for path in expected.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent.filter(|path| !path.as_os_str().is_empty()) {
            frozen_directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    if outputs.iter().any(|path| {
        path.strip_prefix(&copy.path).is_err()
            || fs::symlink_metadata(path)
                .map_or(true, |meta| meta.file_type().is_symlink() || !meta.is_dir())
    }) {
        return false;
    }
    let allowed_output = |path: &Path| outputs.iter().any(|root| path.starts_with(root));
    let mut actual_paths = Vec::new();
    let mut visited = 0_usize;
    for item in walkdir::WalkDir::new(&copy.path).follow_links(false) {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let Ok(item) = item else { return false };
        if item.depth() == 0 {
            continue;
        }
        visited = visited.saturating_add(1);
        if visited > MAX_FILES {
            return false;
        }
        let Ok(relative) = item.path().strip_prefix(&copy.path) else {
            return false;
        };
        if item.file_type().is_symlink() {
            // Generated output contents are outside the attested input
            // comparison. WalkDir never follows links; links anywhere else
            // could redirect a frozen input or workspace boundary.
            if allowed_output(item.path()) {
                continue;
            }
            return false;
        }
        if item.file_type().is_dir() {
            if !frozen_directories.contains(relative) && !allowed_output(item.path()) {
                return false;
            }
            continue;
        }
        if !item.file_type().is_file() {
            return false;
        }
        actual_paths.push(relative.to_string_lossy().replace('\\', "/"));
        if actual_paths.len() > MAX_FILES {
            return false;
        }
    }
    actual_paths.sort();
    if !expected.keys().all(|path| {
        actual_paths
            .binary_search_by(|item| item.as_str().cmp(path.as_str()))
            .is_ok()
    }) || cancellation.is_cancelled()
        || Instant::now() >= deadline
    {
        return false;
    }
    let mut total = 0_u64;
    let mut hashed_total = 0_u64;
    for path in &actual_paths {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let length = match bounded_file_metadata(&copy.path, path) {
            Ok(length) => length,
            Err(_) => return false,
        };
        total = total.saturating_add(length);
        if total > MAX_TOTAL_BYTES {
            return false;
        }
    }
    for path in &actual_paths {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let Ok((digest, bytes)) =
            bounded_digest(&copy.path.join(path), path, deadline, cancellation)
        else {
            return false;
        };
        hashed_total = hashed_total.saturating_add(bytes);
        if hashed_total > MAX_TOTAL_BYTES {
            return false;
        }
        let file = copy.path.join(path);
        if let Some((expected_digest, expected_mode)) = expected.get(path) {
            if expected_digest != &digest
                || expected_mode.is_none()
                || file_mode(&file).ok() != *expected_mode
            {
                return false;
            }
        } else if !allowed_output(&file) {
            return false;
        }
    }
    true
}

fn add_failure_finding(
    input: &LegacyCheckInput,
    source: &Value,
    exit: i32,
    output: &mut LegacyCheckOutput,
) {
    let material = format!(
        "{}\0{}\0test-run-failed\0{}",
        input.provider_id, input.inventory_digest, exit
    );
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    );
    output.findings.push(FindingRef {
        id: FindingId::new(id.clone()).expect("derived finding id is valid"),
        severity: "medium".into(),
    });
    output.details.insert("findingEvidence".into(), json!({(id.clone()):{"kind":"project-test-failure","exitCode":exit,"inventoryDigest":input.inventory_digest,"testCommandSource":source}}));
    output.details.insert(
        "findingTitles".into(),
        json!({(id.clone()):"Test command exited nonzero"}),
    );
    output.details.insert("findingMessages".into(), json!({(id.clone()):format!("Declared test command exited with code {exit}; failure cause is unclassified")}));
    output.details.insert("findingLocations".into(), json!({(id):test_declaration_location(Some(source), input).into_iter().collect::<Vec<_>>()}));
    output.details.insert(
        "testOutcome".into(),
        json!({"passed":false,"exitCode":exit,"complete":true}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input() -> LegacyCheckInput {
        LegacyCheckInput {
            provider_id: "legacy.quality.test".into(),
            check: "test".into(),
            root: std::env::temp_dir(),
            inventory_generation: "fixture-generation".into(),
            inventory_digest: format!("sha256:{}", "a".repeat(64)),
            denominator: crate::inventory::InventoryDenominator {
                entries: Vec::new(),
                digest: format!("sha256:{}", "b".repeat(64)),
            },
            binding: None,
            projection: None,
            artifacts: Value::Null,
        }
    }

    fn test_request() -> ExternalToolRequest {
        ExternalToolRequest {
            request_id: "audit-fixture".into(),
            provider_id: "legacy.quality.test".into(),
            plan_id: format!("sha256:{}", "a".repeat(64)),
            policy_id: "attested-runs-fixture".into(),
            executable: "/usr/bin/true".into(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
            ..ExternalToolRequest::default()
        }
    }

    #[test]
    fn preflight_incomplete_receipt_is_full_unknown_and_gapful() {
        let execution = incomplete(&test_input(), "fixture-no-launch".into(), json!({}));
        let output = execution.output.unwrap();
        let receipt = &output.details["executionReceipt"];
        assert_eq!(receipt["state"], "internal");
        assert_eq!(receipt["complete"], false);
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["processTree"]["reaped"], false);
        assert_eq!(
            receipt["processTree"]["detail"],
            "launch and cleanup state unobserved"
        );
        assert!(!receipt["gaps"].as_array().unwrap().is_empty());
        assert_eq!(execution.state, LegacyCheckProcessState::CleanupUnconfirmed);
        assert!(
            crate::execution::validate_external_receipt_projection(
                "legacy.quality.test",
                &output.details,
                false,
            )
            .is_ok(),
            "synthetic preflight receipt must satisfy the external receipt schema"
        );
    }

    #[test]
    fn unconfirmed_postlaunch_receipt_keeps_observed_process_facts() {
        let mut receipt = ExecutionReceipt::failure(
            &test_request(),
            ExecutionState::KillFailed,
            "process-tree-cleanup-unconfirmed",
        );
        receipt.process_tree.started = true;
        receipt.process_tree.detail = Some("termination and reap unconfirmed".into());
        let projected = canonical_receipt_json(&receipt);
        assert_eq!(projected["state"], "kill_failed");
        assert_eq!(projected["complete"], false);
        assert_eq!(projected["processTree"]["started"], true);
        assert_eq!(projected["processTree"]["terminated"], false);
        assert_eq!(projected["processTree"]["reaped"], false);
        assert!(!projected["gaps"].as_array().unwrap().is_empty());
        let details = BTreeMap::from([("executionReceipt".into(), projected)]);
        assert!(
            crate::execution::validate_external_receipt_projection(
                "legacy.quality.test",
                &details,
                false,
            )
            .is_ok(),
            "canonical projection must satisfy the external receipt schema"
        );
    }

    #[test]
    fn verified_success_and_real_test_failure_remain_distinct() {
        let mut receipt =
            ExecutionReceipt::failure(&test_request(), ExecutionState::Completed, "fixture");
        receipt.complete = true;
        receipt.gaps.clear();
        receipt.exit_code = Some(0);
        receipt.process_tree.started = true;
        receipt.process_tree.terminated = true;
        receipt.process_tree.reaped = true;
        receipt.parser.attempted = true;
        receipt.parser.succeeded = true;
        let success = canonical_receipt_json(&receipt);
        assert_eq!(success["state"], "completed");
        assert_eq!(success["complete"], true);
        assert!(success["gaps"].as_array().unwrap().is_empty());
        let details = BTreeMap::from([("executionReceipt".into(), success)]);
        assert!(
            crate::execution::validate_external_receipt_projection(
                "legacy.quality.test",
                &details,
                true,
            )
            .is_ok(),
            "completed canonical projection must support a complete result"
        );

        let mut output = empty_output(Vec::new());
        add_failure_finding(&test_input(), &json!({}), 101, &mut output);
        assert_eq!(output.details["testOutcome"]["passed"], false);
        assert_eq!(output.details["testOutcome"]["exitCode"], 101);
        assert_eq!(output.findings.len(), 1);
    }

    fn receipt(path: &Path, id: &str, state: &str, exit: i64) -> Value {
        let path = path.to_string_lossy();
        json!({"id":id,"state":state,"receipt":{
            "id":id,"workspace":path,"repository":path,"command":"cargo test","argv":["test"],"exitCode":exit,"signal":null,
            "inputClosure":{"status":"verified","preDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","postDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","changed":[],"added":[],"removed":[],"extrasChanged":[]},
            "reap":{"status":"REAPED","reaped":true},"survivors":[]
        }})
    }

    #[test]
    fn broker_socket_passes_through_only_when_set() {
        let (mut env, mut allow) = (BTreeMap::new(), BTreeSet::new());
        pass_broker_socket(None, &mut env, &mut allow);
        pass_broker_socket(Some(String::new()), &mut env, &mut allow);
        pass_broker_socket(Some("a\nb".into()), &mut env, &mut allow);
        assert!(env.is_empty() && allow.is_empty());
        pass_broker_socket(
            Some(r"\\.\pipe\rightkit-build-control".into()),
            &mut env,
            &mut allow,
        );
        assert_eq!(env.len(), 1);
        assert_eq!(allow.len(), 1);
        assert!(allow.contains("RIGHTKIT_BUILD_BROKER_SOCKET"));
    }

    #[test]
    fn broker_unavailable_stderr_maps_to_precise_gap() {
        assert_eq!(
            request_id(b"rightkit: RK_BROKER_UNAVAILABLE: endpoint is not configured\n")
                .unwrap_err(),
            "rustright-broker-unavailable"
        );
        assert_eq!(
            request_id(b"garbage\n").unwrap_err(),
            "request-id-line-missing-or-ambiguous"
        );
    }

    #[test]
    fn request_id_requires_one_exact_valid_line() {
        assert_eq!(
            request_id(b"rightkit: request abc-123\n").unwrap(),
            "abc-123"
        );
        assert!(request_id(b"rightkit: request abc\nrightkit: request def\n").is_err());
        assert!(request_id(b"rightkit: request ../bad\n").is_err());
    }

    #[test]
    fn effect_artifact_request_ids_are_portable_and_unique() {
        let base = ExternalToolRequest {
            request_id: "audit-safe".into(),
            ..ExternalToolRequest::default()
        };
        let cwd = std::env::temp_dir();
        let first = id_request(&base, "status", "job-1", &cwd, 100);
        let second = id_request(&base, "status", "job-1", &cwd, 100);
        assert_ne!(first.request_id, second.request_id);
        assert!(first
            .request_id
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }));
    }

    fn cli_receipt(
        complete: bool,
        state: ExecutionState,
        exit_code: Option<i32>,
        reaped: bool,
    ) -> ExecutionReceipt {
        let mut receipt =
            ExecutionReceipt::failure(&ExternalToolRequest::default(), state, "fixture");
        receipt.complete = complete;
        receipt.exit_code = exit_code;
        receipt.process_tree.reaped = reaped;
        receipt
    }

    #[test]
    fn structured_cli_json_cannot_replace_successful_reaped_process_receipt() {
        let response = json!({"ok":true,"requestDigest":"a".repeat(64),"payload":{}});
        assert!(trusted_cli_response(
            &cli_receipt(true, ExecutionState::Completed, Some(0), true),
            &response
        )
        .is_some());
        for receipt in [
            cli_receipt(true, ExecutionState::Completed, Some(9), true),
            cli_receipt(false, ExecutionState::Completed, Some(0), true),
            cli_receipt(true, ExecutionState::Failed, Some(0), true),
            cli_receipt(true, ExecutionState::Completed, Some(0), false),
        ] {
            assert!(trusted_cli_response(&receipt, &response).is_none());
        }
    }

    #[test]
    fn request_digest_gap_separates_not_started_from_unreaped() {
        let mut not_started = cli_receipt(false, ExecutionState::UnsealedExecutable, None, false);
        not_started.process_tree.started = false;
        assert_eq!(
            request_digest_process_gap(&not_started).as_deref(),
            Some("request-digest-process-not-started:unsealed_executable")
        );
        let mut unreaped = cli_receipt(false, ExecutionState::KillFailed, None, false);
        unreaped.process_tree.started = true;
        assert_eq!(
            request_digest_process_gap(&unreaped).as_deref(),
            Some("request-digest-process-unreaped")
        );
        let mut reaped = cli_receipt(true, ExecutionState::Completed, Some(0), true);
        reaped.process_tree.started = true;
        assert_eq!(request_digest_process_gap(&reaped), None);
    }

    #[test]
    fn derived_requests_inherit_the_pinned_client_probe_skip() {
        let base = ExternalToolRequest {
            request_id: "audit-safe".into(),
            skip_version_probe: true,
            ..ExternalToolRequest::default()
        };
        let cwd = std::env::temp_dir();
        assert!(id_request(&base, "status", "job-1", &cwd, 100).skip_version_probe);
        assert!(
            external_request(
                &base,
                &["request-digest".into()],
                &cwd,
                BTreeMap::new(),
                BTreeSet::new(),
                100
            )
            .skip_version_probe
        );
    }

    #[test]
    fn nonzero_submit_exit_requires_matching_attested_job_exit() {
        let submitted = cli_receipt(true, ExecutionState::Completed, Some(1), true);
        assert_eq!(submit_process_exit(&submitted), Some(1));
        assert!(match_submit_to_attested_exit(1, 1).is_ok());
        assert!(match_submit_to_attested_exit(1, 0).is_err());
        assert_eq!(
            submit_process_exit(&cli_receipt(true, ExecutionState::Completed, None, true)),
            None
        );
        assert_eq!(
            submit_process_exit(&cli_receipt(
                false,
                ExecutionState::Completed,
                Some(1),
                true
            )),
            None
        );
        assert_eq!(
            submit_process_exit(&cli_receipt(
                true,
                ExecutionState::Completed,
                Some(1),
                false
            )),
            None
        );
    }

    #[test]
    fn package_manager_pin_requires_exact_enrolled_runner_qualification() {
        let matching = AdapterEnrollment {
            broker_adapter_id: "npm-adapter".into(),
            qualified_version: Some("10.2.0".into()),
        };
        let unqualified = AdapterEnrollment {
            broker_adapter_id: "npm-adapter".into(),
            qualified_version: None,
        };
        let mismatch = AdapterEnrollment {
            broker_adapter_id: "npm-adapter".into(),
            qualified_version: Some("10.1.0".into()),
        };
        assert!(validate_required_runner_version("npm", Some("10.2.0"), Some(&matching)).is_ok());
        assert_eq!(
            validate_required_runner_version("npm", Some("10.2.0"), Some(&unqualified)),
            Err("managed-test-runner-version-unqualified:npm".into())
        );
        assert_eq!(
            validate_required_runner_version("npm", Some("10.2.0"), Some(&mismatch)),
            Err("managed-test-runner-version-mismatch:npm".into())
        );
    }

    #[test]
    fn only_bound_verified_reaped_receipts_are_terminal() {
        let temp = std::env::temp_dir().join(format!(
            "audit-copy-test-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp).unwrap();
        let temp = fs::canonicalize(&temp).unwrap();
        let copy = PreparedCopy {
            path: temp.clone(),
            cwd: temp.clone(),
            workspace_root: temp.clone(),
            input_modes: BTreeMap::new(),
            source_digest: String::new(),
            copy_digest: String::new(),
            file_count: 0,
            total_bytes: 0,
        };
        assert_eq!(
            validate_status(
                &receipt(&temp, "id-1", "SUCCEEDED", 0),
                "id-1",
                &copy,
                "cargo test",
                &["test".into()]
            )
            .unwrap(),
            0
        );
        let mut targeted = receipt(&temp, "id-1", "SUCCEEDED", 0);
        targeted["receipt"]["command"] = json!("cargo test");
        assert_eq!(
            validate_status(&targeted, "id-1", &copy, "cargo test", &["test".into()]).unwrap(),
            0
        );
        let failed = receipt(&temp, "id-1", "FAILED", 101);
        assert_eq!(
            validate_status(&failed, "id-1", &copy, "cargo test", &["test".into()]).unwrap(),
            101
        );
        let target_dir = temp.join("target");
        let mut normalized = receipt(&temp, "id-1", "SUCCEEDED", 0);
        normalized["receipt"]["argv"] = json!([
            "test",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--target-dir",
            target_dir
        ]);
        normalized["receipt"]["command"] = json!(format!(
            "cargo test --target x86_64-unknown-linux-gnu --target-dir {}",
            target_dir.display()
        ));
        normalized["receipt"]["targetTriple"] = json!("x86_64-unknown-linux-gnu");
        normalized["receipt"]["target"] = json!({"path":target_dir});
        assert_eq!(
            validate_status(&normalized, "id-1", &copy, "cargo test", &["test".into()])
                .unwrap_err(),
            "managed-test-request-provenance-unavailable:cargo-target-normalization"
        );
        normalized["receipt"]["targetTriple"] = json!("a-different-triple");
        assert_eq!(
            validate_status(&normalized, "id-1", &copy, "cargo test", &["test".into()])
                .unwrap_err(),
            "receipt-argv-mismatch"
        );
        let mut foreign = receipt(&temp, "foreign", "SUCCEEDED", 0);
        assert!(validate_status(&foreign, "id-1", &copy, "cargo test", &["test".into()]).is_err());
        foreign["receipt"]["inputClosure"]["changed"] = json!(["Cargo.toml"]);
        assert!(
            validate_status(&foreign, "foreign", &copy, "cargo test", &["test".into()]).is_err()
        );
        let mut unverified = receipt(&temp, "id-1", "SUCCEEDED", 0);
        unverified["receipt"]["inputClosure"]["status"] = json!("unverified");
        assert!(
            validate_status(&unverified, "id-1", &copy, "cargo test", &["test".into()]).is_err()
        );
        assert!(!cleanup_proven(
            &unverified,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        ));
        let mut changed_closure = receipt(&temp, "id-1", "SUCCEEDED", 0);
        changed_closure["receipt"]["inputClosure"]["changed"] = json!(["Cargo.toml"]);
        assert!(validate_status(
            &changed_closure,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        )
        .is_err());
        assert!(!cleanup_proven(
            &changed_closure,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        ));
        let mut prefixed_digest = receipt(&temp, "id-1", "SUCCEEDED", 0);
        prefixed_digest["receipt"]["inputClosure"]["preDigest"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(validate_status(
            &prefixed_digest,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        )
        .is_err());
        let mut survivors_missing = receipt(&temp, "id-1", "SUCCEEDED", 0);
        survivors_missing["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("survivors");
        assert_eq!(
            validate_status(
                &survivors_missing,
                "id-1",
                &copy,
                "cargo test",
                &["test".into()]
            )
            .unwrap(),
            0
        );
        assert!(!cleanup_proven(
            &survivors_missing,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        ));
        survivors_missing["receipt"]["survivors"] = json!(null);
        assert!(validate_status(
            &survivors_missing,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        )
        .is_err());
        assert!(!cleanup_proven(
            &survivors_missing,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        ));
        unverified["receipt"]["reap"]["status"] = json!("REAP_PENDING");
        assert!(!cleanup_proven(
            &unverified,
            "id-1",
            &copy,
            "cargo test",
            &["test".into()]
        ));
        let mut unreaped = receipt(&temp, "id-1", "FAILED", 101);
        unreaped["receipt"]["reap"]["status"] = json!("REAP_PENDING");
        unreaped["receipt"]["survivors"] = json!([{"pid":42}]);
        assert!(validate_status(&unreaped, "id-1", &copy, "cargo test", &["test".into()]).is_err());
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn copied_inventory_has_frozen_bytes_and_separate_inodes() {
        let root = std::env::temp_dir().join(format!(
            "audit-copy-src-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let scratch_root = std::env::temp_dir().join(format!(
            "audit-copy-scratch-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&scratch_root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            b"pub fn current() {} // dirty tracked bytes\n",
        )
        .unwrap();
        fs::write(root.join("untracked.rs"), b"pub fn untracked() {}\n").unwrap();
        let entries = ["Cargo.toml", "src/lib.rs", "untracked.rs"]
            .into_iter()
            .map(|path| {
                let bytes = fs::read(root.join(path)).unwrap();
                InventoryEntry {
                    path: path.into(),
                    symbols: vec![],
                    dependencies: vec![],
                    package_scripts: vec![],
                    source_file: true,
                    digest: Some(sha(&bytes)),
                }
            })
            .collect::<Vec<_>>();
        let inventory = InventoryEnvelope::new("fixture", "test", entries).unwrap();
        let scratch = AuditScratch::with_scratch_dir(&root, scratch_root.join("audit")).unwrap();
        let copy = prepare_copy(
            &root,
            &inventory,
            &scratch,
            "Cargo.toml",
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            fs::read(copy.path.join("src/lib.rs")).unwrap(),
            b"pub fn current() {} // dirty tracked bytes\n"
        );
        assert_eq!(
            fs::read(copy.path.join("untracked.rs")).unwrap(),
            b"pub fn untracked() {}\n"
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let cancellation = CancellationToken::new();
        fs::write(root.join("added.rs"), b"pub fn added() {}\n").unwrap();
        assert!(!verify_source_unchanged(
            &root,
            &inventory,
            &copy.input_modes,
            deadline,
            &cancellation
        ));
        fs::write(copy.path.join("added.rs"), b"pub fn added() {}\n").unwrap();
        assert!(!verify_copy_unchanged(
            &copy,
            &inventory,
            &[],
            deadline,
            &cancellation
        ));
        fs::remove_file(copy.path.join("added.rs")).unwrap();
        let generated_root = copy.path.join("target");
        fs::create_dir_all(&generated_root).unwrap();
        fs::write(generated_root.join("generated.bin"), b"approved output").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(
                "/outside-approved-output",
                generated_root.join("generated-link"),
            )
            .unwrap();
            assert!(verify_copy_unchanged(
                &copy,
                &inventory,
                &[generated_root.clone()],
                deadline,
                &cancellation
            ));
            fs::remove_file(generated_root.join("generated-link")).unwrap();
            symlink(
                "/outside-frozen-input",
                copy.path.join("src/generated-link"),
            )
            .unwrap();
            assert!(!verify_copy_unchanged(
                &copy,
                &inventory,
                &[generated_root.clone()],
                deadline,
                &cancellation
            ));
            fs::remove_file(copy.path.join("src/generated-link")).unwrap();
        }
        assert!(verify_copy_unchanged(
            &copy,
            &inventory,
            &[generated_root.clone()],
            deadline,
            &cancellation
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let source = fs::metadata(root.join("src/lib.rs")).unwrap();
            let copied = fs::metadata(copy.path.join("src/lib.rs")).unwrap();
            assert_ne!((source.dev(), source.ino()), (copied.dev(), copied.ino()));
            let original_mode = source.permissions().mode() & 0o7777;
            fs::set_permissions(
                root.join("src/lib.rs"),
                fs::Permissions::from_mode(original_mode ^ 0o100),
            )
            .unwrap();
            assert!(!verify_source_unchanged(
                &root,
                &inventory,
                &copy.input_modes,
                deadline,
                &cancellation
            ));
            fs::set_permissions(
                root.join("src/lib.rs"),
                fs::Permissions::from_mode(original_mode),
            )
            .unwrap();
            fs::set_permissions(
                copy.path.join("src/lib.rs"),
                fs::Permissions::from_mode((copied.permissions().mode() & 0o7777) ^ 0o100),
            )
            .unwrap();
            assert!(!verify_copy_unchanged(
                &copy,
                &inventory,
                &[generated_root],
                deadline,
                &cancellation
            ));
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(scratch_root).unwrap();
    }

    #[test]
    fn cargo_path_dependency_outside_frozen_root_refuses_copy() {
        let root = std::env::temp_dir().join(format!(
            "audit-copy-boundary-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let scratch_root = std::env::temp_dir().join(format!(
            "audit-copy-boundary-scratch-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&scratch_root).unwrap();
        fs::write(root.join("Cargo.toml"), b"[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n[dependencies]\noutside={path='../other'}\n").unwrap();
        let bytes = fs::read(root.join("Cargo.toml")).unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "test",
            vec![InventoryEntry {
                path: "Cargo.toml".into(),
                symbols: vec![],
                dependencies: vec![],
                package_scripts: vec![],
                source_file: false,
                digest: Some(sha(&bytes)),
            }],
        )
        .unwrap();
        let scratch = AuditScratch::with_scratch_dir(&root, scratch_root.join("audit")).unwrap();
        assert!(prepare_copy(
            &root,
            &inventory,
            &scratch,
            "Cargo.toml",
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            &CancellationToken::new()
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(scratch_root).unwrap();
    }

    #[test]
    fn cargo_path_inspection_ignores_opaque_metadata_path() {
        let manifest: toml::Value = toml::from_str(
            r#"
                [package.metadata.vendor]
                path = "external/vendor-cache"

                [dependencies.local]
                path = "../local"
            "#,
        )
        .unwrap();
        let mut paths = Vec::new();
        collect_dependency_paths(&manifest, &mut paths);
        assert_eq!(paths, vec!["../local"]);
    }

    #[test]
    fn local_workspace_path_can_resolve_to_inventory_root() {
        let root = std::env::temp_dir().join(format!(
            "audit-copy-root-workspace-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let bytes = b"[workspace]\nmembers = []\n";
        fs::write(root.join("Cargo.toml"), bytes).unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "test",
            vec![InventoryEntry {
                path: "Cargo.toml".into(),
                symbols: vec![],
                dependencies: vec![],
                package_scripts: vec![],
                source_file: false,
                digest: Some(sha(bytes)),
            }],
        )
        .unwrap();
        validate_local_path(&root, &inventory, Path::new("crates/member"), "../..").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_post_launch_cancellation_retains_copy_for_possible_writer() {
        let source_root = std::env::temp_dir().join(format!(
            "audit-copy-cancel-source-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&source_root).unwrap();
        let scratch = AuditScratch::create(&source_root).unwrap();
        let scratch_root = scratch.root().to_path_buf();
        let copy = scratch_root.join("disposable-copy");
        fs::create_dir(&copy).unwrap();
        fs::write(copy.join("Cargo.toml"), b"broker may still be writing").unwrap();

        // Cancellation can drop execute before its request ID reaches us;
        // keep both scratch root and copy until broker reap is proven.
        scratch.retain_after_drop();
        drop(scratch);

        assert!(copy.join("Cargo.toml").is_file());
        fs::remove_dir_all(scratch_root).unwrap();
        fs::remove_dir_all(source_root).unwrap();
    }

    fn git_fixture() -> PathBuf {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "audit-git-src-{}-{}",
                std::process::id(),
                COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("Cargo.toml"), b"[package]\nname='f'\n").unwrap();
        fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").unwrap();
        fs::write(root.join(".gitignore"), b"ignored.log\n").unwrap();
        let init = crate::trusted_git::std_command(&root)
            .expect("trusted git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status()
            .unwrap();
        assert!(init.success());
        let add = crate::trusted_git::std_command(&root)
            .expect("trusted git")
            .arg("-C")
            .arg(&root)
            .args(["add", "Cargo.toml", "src/lib.rs", ".gitignore"])
            .status()
            .unwrap();
        assert!(add.success());
        root
    }

    fn fixture_inventory(root: &Path) -> (InventoryEnvelope, BTreeMap<String, u32>) {
        use crate::inventory::{FilesystemInventorySource, InventorySource};
        let inventory = FilesystemInventorySource::new(root)
            .unwrap()
            .inventory("fixture")
            .unwrap();
        let modes = inventory
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.path.clone(),
                    file_mode(&root.join(&entry.path)).unwrap(),
                )
            })
            .collect();
        (inventory, modes)
    }

    #[test]
    fn source_inventory_matches_audit_inventory_with_out_dir_under_root() {
        let root = git_fixture();
        // Audit output under the repo root, generated and vendored trees, and a
        // gitignored file: none belong to the audit inventory.
        fs::create_dir_all(root.join(".audit")).unwrap();
        fs::write(root.join(".audit/x.json"), b"{}").unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("target/gen.bin"), b"gen").unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), b"x").unwrap();
        fs::write(root.join("ignored.log"), b"log").unwrap();
        let (inventory, modes) = fixture_inventory(&root);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let cancellation = CancellationToken::new();
        let mut expected = inventory
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            source_inventory_paths(&root, deadline, &cancellation).unwrap(),
            expected
        );
        assert!(verify_source_unchanged(
            &root,
            &inventory,
            &modes,
            deadline,
            &cancellation
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn untracked_input_file_still_counts_as_source_drift() {
        let root = git_fixture();
        let (inventory, modes) = fixture_inventory(&root);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let cancellation = CancellationToken::new();
        assert!(verify_source_unchanged(
            &root,
            &inventory,
            &modes,
            deadline,
            &cancellation
        ));
        fs::write(root.join("src/new_input.rs"), b"pub fn n() {}\n").unwrap();
        assert!(!verify_source_unchanged(
            &root,
            &inventory,
            &modes,
            deadline,
            &cancellation
        ));
        let _ = fs::remove_dir_all(root);
    }
}
