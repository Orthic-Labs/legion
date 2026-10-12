//! Bounded Cargo test execution over an owner-only byte copy of Audit's frozen
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

use legion_contracts::{Coverage, FindingId, FindingRef, ProviderStatus};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    inventory::{InventoryEntry, InventoryEnvelope},
    plan::AuditProvider,
};

use super::{
    AuditScratch, LegacyCheckExecution, LegacyCheckInput, LegacyCheckOutput,
    LegacyCheckProcessState, ResolvedCommand, audit_environment, empty_output,
    test_declaration_location,
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

fn safe_relative(path: &str) -> Result<PathBuf, CopyError> {
    if path.is_empty() || path.contains('\\') || path.contains(':') || path.contains('\0') {
        return Err(CopyError::UnsafePath(path.to_owned()));
    }
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative.components().any(|part| {
            !matches!(part, Component::Normal(_))
                || part.as_os_str() == ".git"
                || part.as_os_str() == "target"
                || part.as_os_str() == "node_modules"
        })
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
    cargo_manifest: &str,
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
    let copy_root = scratch.root().join(format!("cargo-copy-{sequence}"));
    super::make_private_dir(&copy_root).map_err(|error| CopyError::Io(error.to_string()))?;
    let mut source_records = Vec::with_capacity(inventory.entries.len());
    let mut copied_records = Vec::with_capacity(inventory.entries.len());
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
                fs::Permissions::from_mode(metadata.mode() & 0o777),
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
    let manifest = copy_root.join(cargo_manifest);
    let cwd = manifest.parent().unwrap_or(&copy_root).to_path_buf();
    Ok(PreparedCopy {
        path: copy_root,
        cwd,
        source_digest,
        copy_digest,
        file_count: source_records.len(),
        total_bytes: total,
    })
}

fn request_id(stderr: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(stderr).map_err(|_| "request-id-stderr-not-utf8".to_owned())?;
    let ids = text
        .lines()
        .filter_map(|line| line.strip_prefix("rightkit: request "))
        .collect::<Vec<_>>();
    if ids.len() != 1 {
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

fn is_cargo_test_command(value: Option<&str>) -> bool {
    value.is_some_and(|command| command == "cargo test" || command.starts_with("cargo test "))
}

fn validate_status(
    status: &Value,
    id: &str,
    copy: &PreparedCopy,
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
    if argv != expected_argv
        || !is_cargo_test_command(receipt.get("command").and_then(Value::as_str))
    {
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

fn cleanup_proven(status: &Value, id: &str, copy: &PreparedCopy) -> bool {
    let Some(receipt) = status.get("receipt").filter(|value| value.is_object()) else {
        return false;
    };
    if status.get("id").and_then(Value::as_str) != Some(id)
        || receipt.get("id").and_then(Value::as_str) != Some(id)
    {
        return false;
    }
    let workspace_bound = receipt
        .get("workspace")
        .and_then(Value::as_str)
        .and_then(|path| fs::canonicalize(path).ok())
        .as_deref()
        == Some(copy.cwd.as_path());
    let repository_bound = receipt
        .get("repository")
        .and_then(Value::as_str)
        .and_then(|path| fs::canonicalize(path).ok())
        .is_some_and(|path| path == copy.cwd || path == copy.path);
    let terminal = status
        .get("state")
        .or_else(|| status.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|state| matches!(state, "SUCCEEDED" | "FAILED"));
    let invocation_bound = is_cargo_test_command(receipt.get("command").and_then(Value::as_str))
        && receipt
            .get("argv")
            .and_then(Value::as_array)
            .is_some_and(|argv| argv.len() == 1 && argv[0].as_str() == Some("test"))
        && receipt.get("exitCode").and_then(Value::as_i64).is_some()
        && status
            .get("exitCode")
            .and_then(Value::as_i64)
            .is_none_or(|outer| Some(outer) == receipt.get("exitCode").and_then(Value::as_i64));
    terminal
        && invocation_bound
        && workspace_bound
        && repository_bound
        && receipt.pointer("/reap/status").and_then(Value::as_str) == Some("REAPED")
        && receipt.pointer("/reap/reaped").and_then(Value::as_bool) == Some(true)
        && no_survivors(receipt)
}

fn incomplete(input: &LegacyCheckInput, message: String, details: Value) -> LegacyCheckExecution {
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
    LegacyCheckExecution {
        state: LegacyCheckProcessState::CleanupUnconfirmed,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        receipt_id: None,
        output: Some(output),
        error: None,
    }
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

fn external_request(
    base: &ExternalToolRequest,
    command: &[&str],
    cwd: &Path,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    timeout_ms: u64,
) -> ExternalToolRequest {
    let mut request = base.clone();
    let operation = match command {
        ["cargo", "test"] => "submit",
        ["cancel", _] => "cancel",
        ["status", _] => "status",
        _ => "control",
    };
    request.request_id = format!(
        "{}-{operation}-{}",
        base.request_id,
        COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    request.args = command.iter().map(|item| (*item).to_owned()).collect();
    request.cwd = cwd.to_string_lossy().into_owned();
    request.environment = environment;
    request.environment_allowlist = allowlist;
    request.expected_digest = base.expected_digest.clone();
    request.version_args = vec!["cargo".into(), "--version".into()];
    request.version_requirement = None;
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
        &[operation, id],
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
) -> ExternalToolRequest {
    let (mut environment, mut allowlist) =
        (base.environment.clone(), base.environment_allowlist.clone());
    environment.insert(CANCEL_ON_DISCONNECT.into(), "1".into());
    allowlist.insert(CANCEL_ON_DISCONNECT.into());
    let mut request = external_request(
        base,
        &["cargo", "test"],
        &copy.cwd,
        environment,
        allowlist,
        timeout_ms,
    );
    request.request_id = request_id;
    request
}

/// Run a frozen Rust test declaration on a materialized copy. Only terminal,
/// source-unchanged broker receipts produce a pass or failing-test finding.
pub(super) async fn execute(
    tool: &dyn ExternalProjectTool,
    root: &Path,
    command: &ResolvedCommand,
    source: &Value,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    input: &LegacyCheckInput,
    scratch: &AuditScratch,
    cancellation: CancellationToken,
    timeout_ms: u64,
) -> LegacyCheckExecution {
    let cargo_manifest = source
        .get("sources")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                let path = item.get("path")?.as_str()?;
                path.ends_with("Cargo.toml").then(|| path.to_owned())
            })
        });
    let Some(cargo_manifest) = cargo_manifest else {
        return incomplete(
            input,
            "frozen-cargo-manifest-missing".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let copy = match prepare_copy(
        root,
        inventory,
        scratch,
        &cargo_manifest,
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
    if !verify_source_unchanged(root, inventory, deadline, &cancellation)
        || !verify_copy_unchanged(&copy, inventory, deadline, &cancellation)
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
        plan_id: input.inventory_digest.clone(),
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
        ..ExternalToolRequest::default()
    };
    let (mut environment, mut allowlist) = audit_environment(scratch);
    environment.insert(CANCEL_ON_DISCONNECT.into(), "1".into());
    allowlist.insert(CANCEL_ON_DISCONNECT.into());
    if remaining_ms() == 0 {
        let _ = fs::remove_dir_all(&copy.path);
        return incomplete(
            input,
            "deadline-expired-before-submit".into(),
            json!({"assurance":"disposable-copy-before-after"}),
        );
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
    );
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
        Err(message) => return retain_incomplete(scratch, &copy, input, message),
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
        let final_status = tool.execute(status, cleanup_token).await;
        if status_json(&final_status, scratch).is_some_and(|raw| cleanup_proven(&raw, &id, &copy)) {
            let _ = fs::remove_dir_all(&copy.path);
            let mut execution = incomplete(
                input,
                "cancelled-or-timed-out-after-confirmed-reap".into(),
                json!({"requestId":id}),
            );
            attach_status_artifact(&mut execution, &final_status);
            return execution;
        } else {
            scratch.retain_after_drop();
        }
        return retain_incomplete(scratch, &copy, input, "cancelled-or-timed-out");
    }
    if !submitted.complete
        || submitted.state != ExecutionState::Completed
        || !submitted.process_tree.reaped
    {
        return retain_incomplete(scratch, &copy, input, "rightkit-submit-process-unconfirmed");
    }
    let status_request = id_request(&submit, "status", &id, &copy.cwd, remaining_ms());
    let status_receipt = tokio::select! {
        _ = cancellation.cancelled() => {
            let cancel = id_request(&submit, "cancel", &id, &copy.cwd, remaining_ms().max(1));
            let cleanup_token = CancellationToken::new();
            let _ = tool.execute(cancel, cleanup_token.clone()).await;
            let final_status = tool.execute(id_request(&submit, "status", &id, &copy.cwd, remaining_ms().max(1)), cleanup_token).await;
            if status_json(&final_status, scratch).is_some_and(|raw| cleanup_proven(&raw, &id, &copy)) {
                let _ = fs::remove_dir_all(&copy.path);
                let mut execution = incomplete(input, "cancelled-during-status-after-confirmed-reap".into(), json!({"requestId":id}));
                attach_status_artifact(&mut execution, &final_status);
                return execution;
            }
            scratch.retain_after_drop();
            return retain_incomplete(scratch, &copy, input, "cancelled-during-status");
        },
        result = tool.execute(status_request, CancellationToken::new()) => result,
    };
    let Some(status_json) = status_json(&status_receipt, scratch) else {
        scratch.retain_after_drop();
        let mut execution =
            retain_incomplete(scratch, &copy, input, "broker-status-artifact-unavailable");
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    };
    let exit = match validate_status(&status_json, &id, &copy, &["test".into()]) {
        Ok(exit) => exit,
        Err(message) => {
            let cleanup_proven = cleanup_proven(&status_json, &id, &copy);
            let source_unchanged =
                verify_source_unchanged(root, inventory, deadline, &cancellation);
            let copy_unchanged = verify_copy_unchanged(&copy, inventory, deadline, &cancellation);
            let mut execution = if cleanup_proven {
                let _ = fs::remove_dir_all(&copy.path);
                incomplete(
                    input,
                    message.into(),
                    json!({"assurance":"disposable-copy-before-after","osSandbox":false,"networkIsolation":"not-enforced","requestId":id,"sourceDigest":copy.source_digest,"copyDigest":copy.copy_digest,"fileCount":copy.file_count,"bytes":copy.total_bytes,"copyRemovedAfterReap":true,"sourceUnchanged":source_unchanged,"copyUnchanged":copy_unchanged}),
                )
            } else {
                retain_incomplete(scratch, &copy, input, &message)
            };
            attach_status_artifact(&mut execution, &status_receipt);
            return execution;
        }
    };
    if submitted.exit_code != Some(exit) {
        scratch.retain_after_drop();
        let mut execution = retain_incomplete(
            scratch,
            &copy,
            input,
            "submit-exit-does-not-match-broker-receipt",
        );
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    }
    let final_source = verify_source_unchanged(root, inventory, deadline, &cancellation);
    let final_copy = verify_copy_unchanged(&copy, inventory, deadline, &cancellation);
    if !final_source || !final_copy {
        let _ = fs::remove_dir_all(&copy.path);
        let mut execution = incomplete(
            input,
            "source-or-copy-drift-after-test".into(),
            json!({"requestId":id,"sourceUnchanged":final_source,"copyUnchanged":final_copy}),
        );
        attach_status_artifact(&mut execution, &status_receipt);
        return execution;
    }
    let _ = fs::remove_dir_all(&copy.path);
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
    let broker_artifact = status_receipt.stdout.as_ref().map(|artifact| json!({"path":artifact.path,"digest":artifact.digest,"bytes":artifact.bytes,"immutable":artifact.immutable}));
    output.details.insert("executionReceipt".into(), json!({"schemaVersion":1,"requestId":id,"providerId":provider.id,"state":"completed","complete":true,"exitCode":exit,"processTree":{"started":true,"terminated":true,"hardKilled":false,"reaped":true},"brokerStatus":broker_artifact}));
    LegacyCheckExecution {
        state: LegacyCheckProcessState::Completed,
        exit_code: Some(exit),
        stdout: Vec::new(),
        stderr: Vec::new(),
        receipt_id: Some(id),
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
    let Some(artifact) = receipt.stdout.as_ref() else {
        return;
    };
    if let Some(output) = execution.output.as_mut() {
        output.details.insert(
            "executionReceipt".into(),
            json!({
                "schemaVersion": 1,
                "state": "cleanup_unconfirmed",
                "complete": false,
                "brokerStatus": {
                    "path": artifact.path,
                    "digest": artifact.digest,
                    "bytes": artifact.bytes,
                    "immutable": artifact.immutable
                }
            }),
        );
    }
}

fn excluded_inventory_directory(path: &Path) -> bool {
    path.components()
        .take(path.components().count().saturating_sub(1))
        .any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some(".git" | ".audit" | ".legion-cache" | "node_modules" | "target")
            )
        })
}

fn source_inventory_paths(
    root: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<String>, CopyError> {
    let mut command = Command::new("git");
    hide_process_console(&mut command);
    let mut child = command
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
        .ok();
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
            if !excluded_inventory_directory(Path::new(&path)) {
                paths.push(path);
            }
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
            .filter_entry(|entry| {
                entry.depth() == 0
                    || !entry.file_type().is_dir()
                    || !matches!(
                        entry.file_name().to_str(),
                        Some(".git" | ".audit" | ".legion-cache" | "node_modules" | "target")
                    )
            })
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
        if digest != expected || hashed_total > MAX_TOTAL_BYTES {
            return false;
        }
    }
    true
}

fn verify_copy_unchanged(
    copy: &PreparedCopy,
    inventory: &InventoryEnvelope,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> bool {
    let expected = inventory
        .entries
        .iter()
        .filter_map(|entry| {
            entry
                .digest
                .as_deref()
                .map(|digest| (entry.path.clone(), digest.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut actual_paths = Vec::new();
    for item in walkdir::WalkDir::new(&copy.path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | ".audit" | ".legion-cache" | "node_modules" | "target")
                )
        })
    {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return false;
        }
        let Ok(item) = item else { return false };
        if item.depth() == 0 || item.file_type().is_dir() {
            continue;
        }
        if !item.file_type().is_file() {
            return false;
        }
        let Ok(relative) = item.path().strip_prefix(&copy.path) else {
            return false;
        };
        actual_paths.push(relative.to_string_lossy().replace('\\', "/"));
        if actual_paths.len() > MAX_FILES {
            return false;
        }
    }
    actual_paths.sort();
    if actual_paths.len() != expected.len()
        || !expected.keys().all(|path| {
            actual_paths
                .binary_search_by(|item| item.as_str().cmp(path.as_str()))
                .is_ok()
        })
        || cancellation.is_cancelled()
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
        if hashed_total > MAX_TOTAL_BYTES
            || expected
                .get(path)
                .is_none_or(|expected| expected != &digest)
        {
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

    fn receipt(path: &Path, id: &str, state: &str, exit: i64) -> Value {
        let path = path.to_string_lossy();
        json!({"id":id,"state":state,"receipt":{
            "id":id,"workspace":path,"repository":path,"command":"cargo test","argv":["test"],"exitCode":exit,"signal":null,
            "inputClosure":{"status":"verified","preDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","postDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","changed":[],"added":[],"removed":[],"extrasChanged":[]},
            "reap":{"status":"REAPED","reaped":true},"survivors":[]
        }})
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
        assert!(
            first
                .request_id
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') })
        );
    }

    #[test]
    fn only_bound_verified_reaped_receipts_are_terminal() {
        let temp = std::env::temp_dir().join(format!(
            "audit-copy-test-{}",
            COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp).unwrap();
        let copy = PreparedCopy {
            path: temp.clone(),
            cwd: temp.clone(),
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
                &["test".into()]
            )
            .unwrap(),
            0
        );
        let mut targeted = receipt(&temp, "id-1", "SUCCEEDED", 0);
        targeted["receipt"]["command"] =
            json!("cargo test --target x86_64-unknown-linux-gnu --target-dir target");
        assert_eq!(
            validate_status(&targeted, "id-1", &copy, &["test".into()]).unwrap(),
            0
        );
        let failed = receipt(&temp, "id-1", "FAILED", 101);
        assert_eq!(
            validate_status(&failed, "id-1", &copy, &["test".into()]).unwrap(),
            101
        );
        let mut foreign = receipt(&temp, "foreign", "SUCCEEDED", 0);
        assert!(validate_status(&foreign, "id-1", &copy, &["test".into()]).is_err());
        foreign["receipt"]["inputClosure"]["changed"] = json!(["Cargo.toml"]);
        assert!(validate_status(&foreign, "foreign", &copy, &["test".into()]).is_err());
        let mut unverified = receipt(&temp, "id-1", "SUCCEEDED", 0);
        unverified["receipt"]["inputClosure"]["status"] = json!("unverified");
        assert!(validate_status(&unverified, "id-1", &copy, &["test".into()]).is_err());
        assert!(cleanup_proven(&unverified, "id-1", &copy));
        let mut changed_closure = receipt(&temp, "id-1", "SUCCEEDED", 0);
        changed_closure["receipt"]["inputClosure"]["changed"] = json!(["Cargo.toml"]);
        assert!(validate_status(&changed_closure, "id-1", &copy, &["test".into()]).is_err());
        assert!(cleanup_proven(&changed_closure, "id-1", &copy));
        let mut prefixed_digest = receipt(&temp, "id-1", "SUCCEEDED", 0);
        prefixed_digest["receipt"]["inputClosure"]["preDigest"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(validate_status(&prefixed_digest, "id-1", &copy, &["test".into()]).is_err());
        let mut survivors_missing = receipt(&temp, "id-1", "SUCCEEDED", 0);
        survivors_missing["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("survivors");
        assert_eq!(
            validate_status(&survivors_missing, "id-1", &copy, &["test".into()]).unwrap(),
            0
        );
        assert!(cleanup_proven(&survivors_missing, "id-1", &copy));
        survivors_missing["receipt"]["survivors"] = json!(null);
        assert!(validate_status(&survivors_missing, "id-1", &copy, &["test".into()]).is_err());
        assert!(!cleanup_proven(&survivors_missing, "id-1", &copy));
        unverified["receipt"]["reap"]["status"] = json!("REAP_PENDING");
        assert!(!cleanup_proven(&unverified, "id-1", &copy));
        let mut unreaped = receipt(&temp, "id-1", "FAILED", 101);
        unreaped["receipt"]["reap"]["status"] = json!("REAP_PENDING");
        unreaped["receipt"]["survivors"] = json!([{"pid":42}]);
        assert!(validate_status(&unreaped, "id-1", &copy, &["test".into()]).is_err());
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
            deadline,
            &cancellation
        ));
        fs::write(copy.path.join("added.rs"), b"pub fn added() {}\n").unwrap();
        assert!(!verify_copy_unchanged(
            &copy,
            &inventory,
            deadline,
            &cancellation
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let source = fs::metadata(root.join("src/lib.rs")).unwrap();
            let copied = fs::metadata(copy.path.join("src/lib.rs")).unwrap();
            assert_ne!((source.dev(), source.ino()), (copied.dev(), copied.ino()));
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
        assert!(
            prepare_copy(
                &root,
                &inventory,
                &scratch,
                "Cargo.toml",
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                &CancellationToken::new()
            )
            .is_err()
        );
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
}
