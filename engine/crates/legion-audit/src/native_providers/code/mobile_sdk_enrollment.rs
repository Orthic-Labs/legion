//! Source-only enrollment of installed native macOS compiler/test runtime trees.
//! No discovery commands, downloads, installers or qualification claims.
use super::*;
use std::io::Read;

pub(super) const ENV: &str = "LEGION_MOBILE_SDK_ENROLLMENT";
const MAX_NODES: usize = 500_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;

fn canonical_digest(value: &impl serde::Serialize, error: &'static str) -> Result<String, String> {
    let bytes = legion_contracts::canonical_json_bytes(value).map_err(|_| error)?;
    Ok(sha256_text(&bytes))
}

fn file_digest(path: &Path, total: &mut u64) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|_| "native-closure-metadata")?
        .len();
    *total = total
        .checked_add(size)
        .filter(|total| *total <= MAX_BYTES)
        .ok_or("native-closure-byte-budget")?;
    let mut file = std::fs::File::open(path).map_err(|_| "native-closure-unreadable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "native-closure-read-failed")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn walk(
    root: &Path,
    path: &Path,
    rows: &mut BTreeMap<String, Value>,
    total: &mut u64,
) -> Result<(), String> {
    if rows.len() >= MAX_NODES {
        return Err("native-closure-node-budget".into());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "native-closure-metadata")?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "native-closure-path")?
        .to_string_lossy()
        .into_owned();
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path).map_err(|_| "native-closure-link-unreadable")?;
        // Symlink contents are enrolled. Internal targets are independently
        // visited at their real location. External system dylibs stay inside
        // the explicit OS build boundary, never counted as SDK-owned files.
        rows.insert(relative, json!({"kind":"symlink","target":target}));
    } else if metadata.is_dir() {
        rows.insert(relative, json!({"kind":"directory"}));
        let mut children = std::fs::read_dir(path)
            .map_err(|_| "native-closure-directory")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "native-closure-directory")?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            walk(root, &child.path(), rows, total)?;
        }
    } else if metadata.is_file() {
        rows.insert(
            relative,
            json!({"kind":"file","bytes":metadata.len(),"digest":file_digest(path, total)?}),
        );
    } else {
        return Err("native-closure-special-file".into());
    }
    Ok(())
}

fn roots(sdk: &Path, swiftlint: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let developer = sdk
        .ancestors()
        .find(|parent| parent.join("Toolchains/XcodeDefault.xctoolchain").is_dir())
        .ok_or("native-closure-full-xcode-required")?;
    let contents = developer.parent().ok_or("native-closure-xcode-contents")?;
    let swiftlint = swiftlint
        .canonicalize()
        .map_err(|_| "native-closure-swiftlint")?;
    let swiftlint_root = if swiftlint.to_string_lossy().contains("/Cellar/swiftlint/") {
        swiftlint
            .parent()
            .and_then(Path::parent)
            .ok_or("native-closure-swiftlint")?
            .to_path_buf()
    } else {
        swiftlint
    };
    let paths = [
        (
            "toolchain",
            developer.join("Toolchains/XcodeDefault.xctoolchain"),
        ),
        ("macosSdk", sdk.to_path_buf()),
        (
            "macosTestRuntime",
            developer.join("Platforms/MacOSX.platform/Developer/Library"),
        ),
        ("developerTools", developer.join("usr")),
        ("developerLibrary", developer.join("Library")),
        ("xcodeSharedFrameworks", contents.join("SharedFrameworks")),
        ("xcodeVersion", contents.join("version.plist")),
        ("swiftlintRuntime", swiftlint_root),
        (
            "osBuild",
            PathBuf::from("/System/Library/CoreServices/SystemVersion.plist"),
        ),
        ("xcrun", PathBuf::from("/usr/bin/xcrun")),
        ("xcodeSelect", PathBuf::from("/usr/bin/xcode-select")),
        ("sandboxExec", PathBuf::from("/usr/bin/sandbox-exec")),
    ];
    paths
        .into_iter()
        .map(|(name, path)| {
            path.canonicalize()
                .map(|path| (name.into(), path))
                .map_err(|_| format!("native-closure-root-missing:{name}"))
        })
        .collect()
}

pub(super) fn capture(sdk: &Path, swiftlint: &Path, audited_root: &Path) -> Result<Value, String> {
    let roots = roots(sdk, swiftlint)?;
    let audited_root = audited_root
        .canonicalize()
        .map_err(|_| "native-closure-audited-root")?;
    let mut total = 0u64;
    let mut trees = BTreeMap::new();
    for (name, path) in &roots {
        if path.starts_with(&audited_root) {
            return Err("native-closure-root-inside-project".into());
        }
        let mut files = BTreeMap::new();
        walk(path, path, &mut files, &mut total)?;
        let digest = canonical_digest(&files, "native-closure-serialization")?;
        trees.insert(name, json!({"root":path,"files":files,"digest":digest}));
    }
    // Refuse dangling/out-of-enrollment links unless target belongs to Apple's
    // system runtime boundary, which is identified by enrolled osBuild bytes.
    for tree in trees.values() {
        let root = Path::new(tree["root"].as_str().ok_or("native-closure-root")?);
        for (relative, row) in tree["files"].as_object().ok_or("native-closure-files")? {
            if row["kind"] != "symlink" {
                continue;
            }
            let path = root.join(relative);
            let target = path
                .canonicalize()
                .map_err(|_| format!("native-closure-dangling-link:{}", path.display()))?;
            let managed = roots.values().any(|root| target.starts_with(root));
            let os_runtime = ["/System/Library", "/usr/lib", "/System/Volumes/Preboot"]
                .iter()
                .any(|prefix| target.starts_with(prefix));
            if !managed && !os_runtime {
                return Err(format!("native-closure-unenrolled-link:{}", path.display()));
            }
        }
    }
    Ok(
        json!({"schema":"legion-mobile-native-enrollment/1", "host":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},
        "sdkRoot":sdk,"sdkSettingsRawBytes":std::fs::read(sdk.join("SDKSettings.json")).map_err(|_| "native-sdk-settings-unreadable")?,"swiftlintExecutable":swiftlint.canonicalize().ok(),
        "swiftlintInvocation":{"path":swiftlint,"canonicalPath":swiftlint.canonicalize().ok(),"linkTarget":std::fs::read_link(swiftlint).ok()},"roots":trees,"fileBytes":total,
        "osRuntimeBoundary":"Apple system dynamic runtime identified by enrolled macOS build; no system-library completeness claim",
        "scope":"installed macOS Xcode toolchain + selected SDK + XCTest/runtime support + SwiftLint"}),
    )
}

pub(super) fn descriptor(audited_root: &Path) -> Result<Option<Value>, String> {
    let Some(path) = std::env::var_os(ENV).map(PathBuf::from) else {
        return Ok(None);
    };
    let path = path
        .canonicalize()
        .map_err(|_| "native-enrollment-file-missing")?;
    if path.starts_with(
        audited_root
            .canonicalize()
            .map_err(|_| "native-enrollment-root")?,
    ) {
        return Err("native-enrollment-inside-project".into());
    }
    let bytes = std::fs::read(&path).map_err(|_| "native-enrollment-file-unreadable")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "native-enrollment-malformed")?;
    if value["schema"] != "legion-mobile-native-enrollment/1"
        || value["host"]["os"] != std::env::consts::OS
        || value["host"]["arch"] != std::env::consts::ARCH
    {
        return Err("native-enrollment-platform-mismatch".into());
    }
    Ok(Some(
        json!({"path":path,"digest":sha256_text(&bytes),"fileBytes":value["fileBytes"],"sdkRoot":value["sdkRoot"],"swiftlintExecutable":value["swiftlintExecutable"],"swiftlintInvocation":value["swiftlintInvocation"],
        "roots":value["roots"].as_object().ok_or("native-enrollment-roots")?.iter().map(|(name, tree)|
            (name.clone(), json!({"root":tree["root"],"digest":tree["digest"],"entries":tree["files"].as_object().map(|files| files.len())}))).collect::<BTreeMap<_, _>>() }),
    ))
}

pub(super) fn verify(audited_root: &Path, sdk: &Path) -> Result<Option<Value>, String> {
    let Some(descriptor) = descriptor(audited_root)? else {
        return Ok(None);
    };
    let value: Value = serde_json::from_slice(
        &std::fs::read(
            descriptor["path"]
                .as_str()
                .ok_or("native-enrollment-path")?,
        )
        .map_err(|_| "native-enrollment-file-unreadable")?,
    )
    .map_err(|_| "native-enrollment-malformed")?;
    if value["sdkRoot"].as_str() != sdk.to_str() {
        return Err("native-enrollment-sdk-mismatch".into());
    }
    let swiftlint = Path::new(
        value["swiftlintInvocation"]["path"]
            .as_str()
            .ok_or("native-enrollment-swiftlint")?,
    );
    if capture(sdk, swiftlint, audited_root)? != value {
        return Err("native-enrollment-tree-changed".into());
    }
    Ok(Some(descriptor))
}

/// Independently read full compiler/executor/registry/pipeline source closure.
/// Prepared JSON is compared with actual bytes; it supplies no trusted hashes.
#[cfg(test)]
pub(super) fn source_snapshot(root: &Path) -> Result<Value, String> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "source-enrollment-metadata")?;
        if metadata.file_type().is_symlink() {
            return Err("source-enrollment-symlink".into());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "source-enrollment-path")?
            .to_str()
            .ok_or("source-enrollment-utf8")?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|_| "source-enrollment-directory")? {
                visit(
                    root,
                    &entry.map_err(|_| "source-enrollment-directory")?.path(),
                    files,
                )?;
            }
        } else if metadata.is_file() {
            let generated = Regex::new(r"^engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json$").expect("source exclusion");
            if !generated.is_match(relative) {
                if files.len() >= MAX_NODES {
                    return Err("source-enrollment-node-budget".into());
                }
                let raw = std::fs::read(path).map_err(|_| "source-enrollment-read")?;
                let source_digest = if relative == "src/registry/providers.json" {
                    let mut value: Value =
                        serde_json::from_slice(&raw).map_err(|_| "source-registry-malformed")?;
                    for provider in value["providers"]
                        .as_array_mut()
                        .ok_or("source-registry-providers")?
                    {
                        let benchmark = provider["benchmark"]
                            .as_object_mut()
                            .ok_or("source-registry-benchmark")?;
                        for name in ["status", "qualificationDigest", "qualification"] {
                            benchmark.remove(name);
                        }
                    }
                    sha256_text(
                        &serde_json::to_vec(&value).map_err(|_| "source-registry-serialization")?,
                    )
                } else {
                    sha256_text(&raw)
                };
                files.insert(relative.into(), source_digest);
            }
        } else {
            return Err("source-enrollment-special-file".into());
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    for name in [
        "legion-audit",
        "legion-effects",
        "legion-provider-sdk",
        "legion-contracts",
        "legion-rules",
    ] {
        visit(
            root,
            &root.join(format!("engine/crates/{name}/src")),
            &mut files,
        )?;
        visit(
            root,
            &root.join(format!("engine/crates/{name}/Cargo.toml")),
            &mut files,
        )?;
    }
    for name in [
        "src/registry/rules",
        "src/registry/controls",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        "scripts/ci/audit-mobile-native-enrollment.py",
        "scripts/ci/audit-mobile-sdk-accuracy.py",
        "scripts/ci/tests/test_audit_mobile_sdk_accuracy.py",
        "scripts/ci/audit-qualification-records.py",
        "scripts/ci/tests/test_audit_qualification_records.py",
        "scripts/ci/tests/test_python_code_sdk_adapter.py",
        "qualification/provider-accuracy/schema.json",
        "bench/provider-accuracy-plan.json",
        "src/registry/providers.json",
        ".github/workflows/ci.yml",
        "scripts/ci/right-git-ci.sh",
        ".rightgit.json",
        "package.json",
        "pnpm-lock.yaml",
    ] {
        visit(root, &root.join(name), &mut files)?;
    }
    Ok(
        json!({"schema":"legion-mobile-source-enrollment/1", "root":root,
        "registryRawDigest":sha256_text(&std::fs::read(root.join("src/registry/providers.json")).map_err(|_| "source-registry-read")?),
        "digest":canonical_digest(&files, "source-enrollment-serialization")?, "files":files}),
    )
}

#[cfg(test)]
mod canonical_digest_tests {
    use super::*;

    #[test]
    fn canonical_digest_ignores_nested_object_insertion_order() {
        let first: Value = serde_json::from_str(r#"{"outer":{"b":2,"a":1}}"#).unwrap();
        let reordered: Value = serde_json::from_str(r#"{"outer":{"a":1,"b":2}}"#).unwrap();
        assert_ne!(
            sha256_text(&serde_json::to_vec(&first).unwrap()),
            sha256_text(&serde_json::to_vec(&reordered).unwrap())
        );
        assert_eq!(
            canonical_digest(&first, "test-canonicalization").unwrap(),
            canonical_digest(&reordered, "test-canonicalization").unwrap()
        );
    }
}
