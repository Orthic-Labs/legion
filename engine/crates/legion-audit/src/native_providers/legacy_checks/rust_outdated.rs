//! Bind cargo-outdated's one executed root package to its selected frozen lockfile.
use super::{AuditScratch, LegacyCheckExecution, LegacyCheckInput, LegacyCheckProcessState};
use crate::inventory::InventoryEnvelope;
use legion_contracts::{Coverage, ProviderStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const MAX_FILES: usize = 100_000;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn relative_path(value: &str) -> Result<&Path, String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains(['\\', ':', '\0'])
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe-copy-path:{value}"));
    }
    Ok(path)
}

fn regular_bytes(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let relative = relative_path(relative)?;
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|_| "copy-input-unavailable")?;
        if metadata.file_type().is_symlink() {
            return Err("copy-input-symlink".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("copy-input-reparse-point".into());
            }
        }
    }
    let metadata = fs::metadata(&path).map_err(|_| "copy-input-unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("copy-input-size-or-type".into());
    }
    let bytes = fs::read(&path).map_err(|_| "copy-input-unreadable")?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("copy-input-size-drift".into());
    }
    Ok(bytes)
}

fn native_bytes(path: &Path) -> Result<Vec<u8>, String> {
    regular_bytes(
        path.parent().ok_or("native-runtime-parent-unavailable")?,
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("native-runtime-name-unavailable")?,
    )
}

// Local manifest paths must resolve lexically inside the copied repository.
// Registry/git resolution remains cargo-outdated's existing network operation.
fn manifest_paths_inside(value: &toml::Value, directory: &Path) -> bool {
    fn local_path(directory: &Path, value: &str) -> bool {
        if value.contains(['\\', ':', '\0']) || Path::new(value).is_absolute() {
            return false;
        }
        let mut depth = directory.components().count();
        for part in Path::new(value).components() {
            match part {
                Component::Normal(_) => depth += 1,
                Component::CurDir => (),
                Component::ParentDir if depth > 0 => depth -= 1,
                _ => return false,
            }
        }
        true
    }
    match value {
        toml::Value::Table(table) => table.iter().all(|(key, value)| {
            let local = matches!(
                key.as_str(),
                "path" | "workspace" | "readme" | "license-file" | "build"
            );
            let members = matches!(key.as_str(), "members" | "default-members" | "exclude");
            let local_git =
                key == "git" && value.as_str().is_some_and(|git| git.starts_with("file:"));
            !local_git
                && (!local
                    || value
                        .as_str()
                        .is_none_or(|path| local_path(directory, path)))
                && (!members
                    || value.as_array().is_none_or(|paths| {
                        paths.iter().all(|path| {
                            path.as_str()
                                .is_some_and(|path| local_path(directory, path))
                        })
                    }))
                && manifest_paths_inside(value, directory)
        }),
        toml::Value::Array(values) => values
            .iter()
            .all(|value| manifest_paths_inside(value, directory)),
        _ => true,
    }
}

fn cargo_config_absent(cwd: &Path) -> Result<(), String> {
    for ancestor in cwd.ancestors() {
        for name in ["config", "config.toml"] {
            match fs::symlink_metadata(ancestor.join(".cargo").join(name)) {
                Ok(_) => return Err("copy-cargo-config-unproven".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err("copy-cargo-config-unavailable".into()),
            }
        }
    }
    Ok(())
}

pub(super) struct Prepared {
    source_root: PathBuf,
    source_cwd: PathBuf,
    execution_root: PathBuf,
    pub cwd: PathBuf,
    preimage: BTreeMap<String, String>,
    lock_path: String,
    before: Result<Value, String>,
    runtime: BTreeMap<String, Value>,
    cancellation: CancellationToken,
}

impl Prepared {
    pub(super) fn bind_runtime(&mut self) -> Result<BTreeMap<String, String>, String> {
        let mut environment = BTreeMap::new();
        for (name, variable) in [("cargo", "CARGO"), ("rustc", "RUSTC")] {
            let command = super::resolve_request(&self.source_root, name, &[])
                .map_err(|_| format!("native-runtime-unavailable:{name}"))?;
            // A rustup proxy becomes the `rustup` canonical path. Do not move
            // its toolchain installation into a new HOME or acquire one.
            let bytes = native_bytes(&command.executable)?;
            if command
                .executable
                .file_stem()
                .and_then(|name| name.to_str())
                != Some(name)
                || bytes.starts_with(b"#!")
                || digest(&bytes) != command.digest
            {
                return Err(format!("native-runtime-proxy-or-script:{name}"));
            }
            environment.insert(
                variable.into(),
                command.executable.to_string_lossy().into_owned(),
            );
            self.runtime.insert(
                name.into(),
                json!({"path":command.executable,"digest":command.digest}),
            );
        }
        let cargo = Path::new(environment.get("CARGO").ok_or("native-cargo-unavailable")?);
        let rustc = Path::new(environment.get("RUSTC").ok_or("native-rustc-unavailable")?);
        if cargo.parent() != rustc.parent()
            || self.runtime["cargo"]["digest"] == self.runtime["rustc"]["digest"]
        {
            return Err("native-runtime-toolchain-unproven".into());
        }
        Ok(environment)
    }

    pub(super) fn before(&self) -> Result<Value, String> {
        self.before.clone()
    }

    fn evidence(&self, inventory: &InventoryEnvelope) -> Value {
        let deadline = Instant::now() + std::time::Duration::from_secs(120);
        let source_unchanged = self.preimage.iter().all(|(path, hash)| {
            !self.cancellation.is_cancelled()
                && Instant::now() < deadline
                && regular_bytes(&self.source_root, path).is_ok_and(|bytes| digest(&bytes) == *hash)
        });
        let postimage = copied_files(&self.execution_root, deadline, &self.cancellation);
        let runtime_unchanged = self.runtime.values().all(|identity| {
            identity["path"]
                .as_str()
                .zip(identity["digest"].as_str())
                .is_some_and(|(path, hash)| {
                    !self.cancellation.is_cancelled()
                        && Instant::now() < deadline
                        && native_bytes(Path::new(path)).is_ok_and(|bytes| digest(&bytes) == hash)
                })
        });
        let valid = source_unchanged
            && runtime_unchanged
            && !self.cancellation.is_cancelled()
            && Instant::now() < deadline
            && cargo_config_absent(&self.cwd).is_ok()
            && postimage.as_ref().is_ok_and(|files| {
                files.len() == self.preimage.len()
                    && self.preimage.iter().all(|(path, hash)| {
                        files
                            .get(path)
                            .is_some_and(|after| path == &self.lock_path || after == hash)
                    })
            });
        let deltas = postimage
            .as_ref()
            .map(|files| {
                self.preimage
                    .iter()
                    .filter_map(|(path, before)| {
                        files.get(path).filter(|after| *after != before).map(
                            |after| json!({"path":path,"beforeDigest":before,"afterDigest":after}),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        json!({"sourceRoot":self.source_root,"sourceCwd":self.source_cwd,
            "executionRoot":self.execution_root,"executionCwd":self.cwd,
            "inventoryDigest":inventory.digest,"preimage":self.preimage,
            "preimageDigest":digest(&serde_json::to_vec(&self.preimage).expect("string map")),
            "postimage":postimage.as_ref().ok(),"postimageError":postimage.as_ref().err(),
            "allowedChangedPath":self.lock_path,"deltas":deltas,
            "sourceUnchanged":source_unchanged,"runtime":self.runtime,"runtimeUnchanged":runtime_unchanged,"valid":valid})
    }
}

pub(super) fn refusal(
    input: &LegacyCheckInput,
    command: super::CommandShape,
    reason: &str,
) -> LegacyCheckExecution {
    let reason = format!("cargo-outdated-resolution-unavailable:{reason}");
    let gap = crate::native_providers::availability::unavailable_gap(&reason);
    let mut output = super::empty_output(vec![gap.clone()]);
    output.details.insert(
        "rustOutdatedResolution".into(),
        json!({"status":"unavailable","reason":reason}),
    );
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    super::terminal_execution(
        input,
        command,
        LegacyCheckProcessState::Failed,
        None,
        vec![],
        vec![],
        output,
        vec![gap],
        super::now_ms(),
        false,
        Some(&reason),
    )
}

pub(super) fn prepare(
    input: &LegacyCheckInput,
    inventory: &InventoryEnvelope,
    source_cwd: &Path,
    scratch: &AuditScratch,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Prepared, String> {
    let source_root = fs::canonicalize(&input.root).map_err(|_| "copy-root-unavailable")?;
    let source_cwd = fs::canonicalize(source_cwd).map_err(|_| "copy-cwd-unavailable")?;
    let relative_cwd = source_cwd
        .strip_prefix(&source_root)
        .map_err(|_| "copy-cwd-outside-source")?;
    if inventory.entries.is_empty() || inventory.entries.len() > MAX_FILES {
        return Err("copy-file-count-limit".into());
    }
    let container = scratch.root().join("rust-outdated-resolution");
    // Exclusive creation inside this unique AuditScratch refuses stale copies.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&container)
            .map_err(|_| "copy-root-not-exclusive")?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&container).map_err(|_| "copy-root-not-exclusive")?;
    let execution_root = container.join("source");
    super::make_private_dir(&execution_root).map_err(|_| "copy-root-unavailable")?;
    let execution_root = fs::canonicalize(execution_root).map_err(|_| "copy-root-unavailable")?;
    if execution_root.starts_with(&source_root) {
        return Err("copy-root-inside-source".into());
    }
    let cwd = execution_root.join(relative_cwd);
    // Cargo merges ancestor configuration. An unsealed configuration can
    // redirect caches, runtime tools or local sources outside this copy.
    cargo_config_absent(&cwd)?;
    let lock_path = relative_cwd
        .join("Cargo.lock")
        .to_string_lossy()
        .replace('\\', "/");
    let before = capture(input, inventory, &source_cwd);
    let mut preimage = BTreeMap::new();
    let mut total = 0_u64;
    for entry in &inventory.entries {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err("copy-cancelled-or-deadline".into());
        }
        if matches!(
            Path::new(&entry.path)
                .file_name()
                .and_then(|name| name.to_str()),
            Some("config" | "config.toml")
        ) && Path::new(&entry.path)
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".cargo")
        {
            return Err("copy-cargo-config-unproven".into());
        }
        let bytes = regular_bytes(&source_root, &entry.path)?;
        let hash = digest(&bytes);
        if entry.digest.as_deref() != Some(hash.as_str())
            || preimage.insert(entry.path.clone(), hash.clone()).is_some()
        {
            return Err(format!("copy-source-digest-unproven:{}", entry.path));
        }
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_TOTAL_BYTES {
            return Err("copy-total-size-limit".into());
        }
        if Path::new(&entry.path)
            .file_name()
            .is_some_and(|name| name == "Cargo.toml")
        {
            // Malformed TOML still reaches the real tool's error control.
            if let Some(manifest) = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| toml::from_str::<toml::Value>(text).ok())
            {
                if !manifest_paths_inside(
                    &manifest,
                    Path::new(&entry.path).parent().unwrap_or(Path::new("")),
                ) {
                    return Err("copy-local-cargo-path-outside-source".into());
                }
            }
        }
        let destination = execution_root.join(relative_path(&entry.path)?);
        super::make_private_dir(destination.parent().ok_or("copy-parent-unavailable")?)
            .map_err(|_| "copy-parent-unavailable")?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&destination)
            .and_then(|mut file| file.write_all(&bytes))
            .map_err(|_| "copy-write-failed")?;
        if digest(&regular_bytes(&execution_root, &entry.path)?) != hash {
            return Err("copy-preimage-drift".into());
        }
    }
    if cancellation.is_cancelled() || Instant::now() >= deadline {
        return Err("copy-cancelled-or-deadline".into());
    }
    if !preimage.contains_key(&lock_path) || !cwd.is_dir() {
        return Err("copy-executed-lock-unavailable".into());
    }
    Ok(Prepared {
        source_root,
        source_cwd,
        execution_root,
        cwd,
        preimage,
        lock_path,
        before,
        runtime: BTreeMap::new(),
        cancellation: cancellation.clone(),
    })
}

fn copied_files(
    root: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<BTreeMap<String, String>, String> {
    fn walk(
        root: &Path,
        path: &Path,
        files: &mut BTreeMap<String, String>,
        visited: &mut usize,
        total: &mut u64,
        depth: usize,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), String> {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err("copy-postimage-cancelled-or-deadline".into());
        }
        *visited += 1;
        if *visited > MAX_FILES * 2 || depth > 128 {
            return Err("copy-postimage-tree-limit".into());
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| "copy-postimage-unavailable")?;
        if metadata.file_type().is_symlink() {
            return Err("copy-postimage-symlink".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("copy-postimage-reparse-point".into());
            }
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "copy-postimage-unreadable")? {
                walk(
                    root,
                    &entry.map_err(|_| "copy-postimage-unreadable")?.path(),
                    files,
                    visited,
                    total,
                    depth + 1,
                    deadline,
                    cancellation,
                )?;
            }
        } else if metadata.is_file() && files.len() < MAX_FILES {
            *total = total.saturating_add(metadata.len());
            if *total > MAX_TOTAL_BYTES {
                return Err("copy-postimage-total-size-limit".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "copy-postimage-outside-root")?
                .to_str()
                .ok_or("copy-postimage-non-utf8")?
                .replace('\\', "/");
            files.insert(relative.clone(), digest(&regular_bytes(root, &relative)?));
        } else {
            return Err("copy-postimage-size-or-type".into());
        }
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err("copy-postimage-cancelled-or-deadline".into());
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    walk(
        root,
        root,
        &mut files,
        &mut 0,
        &mut 0,
        0,
        deadline,
        cancellation,
    )?;
    Ok(files)
}

pub(super) fn capture(
    input: &LegacyCheckInput,
    inventory: &InventoryEnvelope,
    cwd: &Path,
) -> Result<Value, String> {
    let root = std::fs::canonicalize(&input.root).map_err(|_| "root-unavailable")?;
    let resolved = std::fs::canonicalize(cwd).map_err(|_| "cwd-unavailable")?;
    let relative = resolved
        .strip_prefix(&root)
        .map_err(|_| "cwd-outside-root")?;
    let read = |name: &str| -> Result<(String, String, Vec<u8>), String> {
        let relative = relative.join(name).to_string_lossy().replace('\\', "/");
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == relative)
            .ok_or_else(|| format!("source-outside-inventory:{relative}"))?;
        let mut path = root.clone();
        for part in Path::new(&relative).components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err("unsafe-source-path".into());
            }
            path.push(part);
            if std::fs::symlink_metadata(&path)
                .map_err(|_| "source-unavailable")?
                .file_type()
                .is_symlink()
            {
                return Err("source-symlink".into());
            }
        }
        if std::fs::canonicalize(&path).map_err(|_| "source-unavailable")? != path {
            return Err("source-alias-or-reparse-point".into());
        }
        let metadata = std::fs::metadata(&path).map_err(|_| "source-unavailable")?;
        if !metadata.is_file() || metadata.len() > 1_048_576 {
            return Err("source-size-or-type".into());
        }
        let bytes = std::fs::read(&path).map_err(|_| "source-unreadable")?;
        if bytes.len() > 1_048_576 {
            return Err("source-size-limit".into());
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if entry.digest.as_deref() != Some(digest.as_str()) {
            return Err(format!("source-digest-unproven:{relative}"));
        }
        Ok((relative, digest, bytes))
    };
    let (manifest_path, manifest_digest, manifest_bytes) = read("Cargo.toml")?;
    let (lock_path, lock_digest, _) = read("Cargo.lock")?;
    if !input.denominator.entries.iter().any(|entry| {
        entry.path == lock_path && entry.digest.as_deref() == Some(lock_digest.as_str())
    }) {
        return Err("executed-lock-outside-denominator".into());
    }
    let manifest: toml::Value = std::str::from_utf8(&manifest_bytes)
        .ok()
        .and_then(|text| toml::from_str(text).ok())
        .ok_or("manifest-unparseable")?;
    let name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or("root-package-unproven")?;
    Ok(
        json!({"cwd":resolved,"manifest":{"path":manifest_path,"digest":manifest_digest,"name":name},"lock":{"path":lock_path,"digest":lock_digest},"denominatorDigest":input.denominator.digest,"analysisScope":"executed-root-package-direct-dependencies"}),
    )
}

pub(super) fn reconcile(
    input: &LegacyCheckInput,
    inventory: &InventoryEnvelope,
    before: Result<Value, String>,
    prepared: Option<Prepared>,
    execution: &mut LegacyCheckExecution,
) {
    let Some(output) = execution.output.as_mut() else {
        return;
    };
    let copy_evidence = prepared.as_ref().map(|copy| copy.evidence(inventory));
    let mut proven_lock = None;
    match before {
        Ok(binding) => {
            let receipt_cwd = output
                .details
                .get("executionReceipt")
                .and_then(|receipt| receipt.get("cwd"))
                .and_then(Value::as_str);
            let matches_after = prepared.as_ref().is_some_and(|copy| {
                receipt_cwd == copy.cwd.to_str()
                    && copy_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence["valid"] == true)
                    && capture(input, inventory, &copy.source_cwd)
                        .is_ok_and(|after| after == binding)
            });
            let document = serde_json::from_slice::<Value>(&execution.stdout).ok();
            let root_matches = document.as_ref().and_then(|value| value.get("crate_name"))
                == binding
                    .get("manifest")
                    .and_then(|manifest| manifest.get("name"));
            if matches_after
                && root_matches
                && execution.state == LegacyCheckProcessState::Completed
                && execution.exit_code == Some(0)
                && output.complete
            {
                proven_lock = binding["lock"]["path"].as_str().map(str::to_owned);
            } else {
                output
                    .coverage_gaps
                    .push("cargo-outdated-input-or-report-unproven".into());
            }
            // Retain actual pre-execution source identity even if the run failed.
            output.details.insert("rustOutdatedInput".into(), binding);
        }
        Err(reason) => output
            .coverage_gaps
            .push(format!("cargo-outdated-input-unproven:{reason}")),
    }
    if let Some(evidence) = copy_evidence {
        if evidence["valid"] != true {
            output
                .coverage_gaps
                .push("cargo-outdated-resolution-copy-unproven".into());
        }
        output
            .details
            .insert("rustOutdatedResolution".into(), evidence);
    }
    if proven_lock.is_none() {
        output.findings.clear();
        output.details.remove("findingEvidence");
        output.details.remove("findingLocations");
    }
    for entry in &input.denominator.entries {
        if proven_lock.as_deref() != Some(entry.path.as_str()) {
            output
                .coverage_gaps
                .push(format!("cargo-outdated-lock-uncovered:{}", entry.path));
        }
    }
    if let Some(path) = proven_lock.as_ref() {
        // Recreate aggregate evidence against the executed lock, rather than
        // the first (possibly unrelated) selected lock. Raw report is retained.
        if let Some(count) = output
            .details
            .get("findingsCount")
            .and_then(Value::as_u64)
            .filter(|count| *count > 0)
        {
            output.findings.clear();
            output.details.remove("findingEvidence");
            output.details.remove("findingLocations");
            super::push_finding(
                output,
                "legacy.cargo_outdated.cargo-outdated",
                "low",
                path,
                1,
                &format!("cargo_outdated reported {count} finding(s)"),
            );
            if let Some(locations) = output
                .details
                .get_mut("findingLocations")
                .and_then(Value::as_object_mut)
            {
                for locations in locations.values_mut() {
                    *locations = json!([path]);
                }
            }
        }
    }
    output.coverage_gaps.sort();
    output.coverage_gaps.dedup();
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: u64::from(proven_lock.is_some()),
        gaps: output.coverage_gaps.clone(),
    });
    if !output.coverage_gaps.is_empty() {
        output.complete = false;
        output.status = ProviderStatus::Partial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{FilesystemInventorySource, InventoryDenominator, InventorySource};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::var_os("RUNNER_TEMP")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
            let path = base.join(format!(
                "rust-outdated-copy-control-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(path.join("source/src")).unwrap();
            fs::write(
                path.join("source/Cargo.toml"),
                "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
            )
            .unwrap();
            fs::write(path.join("source/Cargo.lock"), "version = 4\n").unwrap();
            fs::write(path.join("source/src/lib.rs"), "pub fn value() {}\n").unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        fn prepare(&self) -> (Prepared, InventoryEnvelope) {
            self.prepare_result().unwrap()
        }

        fn prepare_result(&self) -> Result<(Prepared, InventoryEnvelope), String> {
            let root = self.0.join("source");
            let inventory = FilesystemInventorySource::new(&root)
                .unwrap()
                .inventory("copy-control")
                .unwrap();
            let input = LegacyCheckInput {
                provider_id: "legacy.stack.rust-outdated".into(),
                check: "cargo_outdated".into(),
                root: root.clone(),
                inventory_generation: inventory.generation.clone(),
                inventory_digest: inventory.digest.clone(),
                denominator: InventoryDenominator {
                    entries: inventory
                        .entries
                        .iter()
                        .filter(|entry| entry.path == "Cargo.lock")
                        .cloned()
                        .collect(),
                    digest: "test-denominator".into(),
                },
                binding: None,
                projection: None,
                artifacts: Value::Null,
            };
            let scratch = AuditScratch::with_scratch_dir(&root, self.0.join("run")).unwrap();
            let prepared = prepare(
                &input,
                &inventory,
                &root,
                &scratch,
                Instant::now() + std::time::Duration::from_secs(120),
                &CancellationToken::new(),
            )?;
            Ok((prepared, inventory))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolution_copy_preserves_original_and_allows_only_executed_lock_delta() {
        let fixture = Fixture::new();
        let (copy, inventory) = fixture.prepare();
        assert_eq!(copy.evidence(&inventory)["valid"], true);
        assert_ne!(copy.cwd, copy.source_cwd);
        fs::write(
            copy.cwd.join("Cargo.lock"),
            "version = 4\n# resolved copy\n",
        )
        .unwrap();
        let evidence = copy.evidence(&inventory);
        assert_eq!(evidence["valid"], true);
        assert_eq!(evidence["deltas"].as_array().unwrap().len(), 1);
        assert_eq!(evidence["deltas"][0]["path"], "Cargo.lock");
        assert_eq!(
            fs::read_to_string(copy.source_cwd.join("Cargo.lock")).unwrap(),
            "version = 4\n"
        );
        fs::write(copy.cwd.join("src/lib.rs"), "changed\n").unwrap();
        assert_eq!(copy.evidence(&inventory)["valid"], false);
    }

    #[test]
    fn resolution_copy_rejects_extra_files_and_original_source_drift() {
        let fixture = Fixture::new();
        let (copy, inventory) = fixture.prepare();
        fs::write(copy.cwd.join("unexpected"), "extra\n").unwrap();
        assert_eq!(copy.evidence(&inventory)["valid"], false);
        fs::remove_file(copy.cwd.join("unexpected")).unwrap();
        fs::write(copy.source_cwd.join("Cargo.lock"), "changed source\n").unwrap();
        assert_eq!(copy.evidence(&inventory)["sourceUnchanged"], false);
        assert_eq!(copy.evidence(&inventory)["valid"], false);
    }

    #[test]
    fn resolution_copy_refuses_unsealed_cargo_configuration() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join("source/.cargo")).unwrap();
        fs::write(
            fixture.0.join("source/.cargo/config.toml"),
            "[build]\ntarget-dir = \"/outside\"\n",
        )
        .unwrap();
        assert!(
            matches!(fixture.prepare_result(), Err(reason) if reason == "copy-cargo-config-unproven")
        );
    }

    #[test]
    fn resolution_copy_keeps_local_paths_inside_frozen_repository() {
        let local: toml::Value =
            toml::from_str("[dependencies.local]\npath = \"../shared\"\n").unwrap();
        assert!(manifest_paths_inside(&local, Path::new("engine")));
        assert!(!manifest_paths_inside(&local, Path::new("")));
        for path in ["/outside", "../../outside", "C:\\outside"] {
            let manifest =
                toml::from_str(&format!("[dependencies.local]\npath = {path:?}\n")).unwrap();
            assert!(!manifest_paths_inside(&manifest, Path::new("engine")));
        }
    }
}
