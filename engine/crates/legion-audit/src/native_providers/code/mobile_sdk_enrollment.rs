//! Source-only enrollment of installed native macOS compiler/test runtime trees.
//! No discovery commands, downloads, installers or qualification claims.
use super::*;
use std::io::Read;

pub(super) const ENV: &str = "LEGION_MOBILE_SDK_ENROLLMENT";
const MAX_NODES: usize = 500_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;

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
        let raw = serde_json::to_vec(&files).map_err(|_| "native-closure-serialization")?;
        trees.insert(
            name,
            json!({"root":path,"files":files,"digest":sha256_text(&raw)}),
        );
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
        "sdkRoot":sdk,"swiftlintExecutable":swiftlint.canonicalize().ok(),"roots":trees,"fileBytes":total,
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
        json!({"path":path,"digest":sha256_text(&bytes),"fileBytes":value["fileBytes"],"sdkRoot":value["sdkRoot"],"swiftlintExecutable":value["swiftlintExecutable"],
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
        value["swiftlintExecutable"]
            .as_str()
            .ok_or("native-enrollment-swiftlint")?,
    );
    if capture(sdk, swiftlint, audited_root)? != value {
        return Err("native-enrollment-tree-changed".into());
    }
    Ok(Some(descriptor))
}
