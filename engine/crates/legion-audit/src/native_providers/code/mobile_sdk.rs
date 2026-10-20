//! Native macOS SDK slice. Commands use the existing admitted SDK executor;
//! neither tool discovery nor these plans authorize target-project execution.
//! Apple SDKSettings.json, frozen inventory & staged bytes bind every receipt.
//! iOS/simulator/Xcode target configurations remain explicit unqualified gaps.
use super::*;
#[path = "mobile_sdk_enrollment.rs"]
mod enrollment;

const MAX_FILES: usize = 512;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const BINDING_DIGEST_ENV: &str = "LEGION_MOBILE_FROZEN_BINDING_DIGEST";
const BINDING: &str = ".legion-mobile-inputs.json";
const LINT_CONFIG: &str = "only_rules:\n  - force_cast\n  - force_try\n  - trailing_whitespace\n";

fn fail(plan: &mut Plan, reason: &'static str) {
    for tool in ["compiler", "analyzer", "test"] {
        plan.not_planned.insert(tool, reason);
    }
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && !path.contains(['\n', '\r', '\\'])
        && path != BINDING
}

/// No process-based SDK discovery: caller selects SDKROOT, otherwise established
/// Xcode/CLT installation roots are inspected. Ambiguity never picks another SDK.
fn sdk(root: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("SDKROOT") {
        candidates.push(PathBuf::from(path));
    } else if let Some(path) = std::env::var_os("DEVELOPER_DIR") {
        candidates
            .push(PathBuf::from(path).join("Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"));
    } else {
        candidates.push(PathBuf::from("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"));
        candidates.push(PathBuf::from(
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
        ));
    }
    candidates.into_iter().find_map(|path| {
        let path = path.canonicalize().ok()?;
        let root = root.canonicalize().ok()?;
        if path.starts_with(root) {
            return None;
        }
        let settings: Value =
            serde_json::from_slice(&std::fs::read(path.join("SDKSettings.json")).ok()?).ok()?;
        (settings
            .get("CanonicalName")?
            .as_str()?
            .starts_with("macosx")
            && settings.get("Version")?.as_str().is_some())
        .then_some(path)
    })
}

fn command(
    tool: &'static str,
    programs: &'static [&'static str],
    stage: &Path,
    args: Vec<String>,
    parser: Parser,
    accepted: &'static [i32],
) -> Planned {
    let home = stage.parent().expect("scratch tmp").join("mobile-home");
    Planned {
        tool,
        programs,
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: stage.to_string_lossy().into_owned(),
        args,
        parser,
        accepted,
        env: vec![
            ("HOME", home.to_string_lossy().into_owned()),
            ("CFFIXED_USER_HOME", home.to_string_lossy().into_owned()),
        ],
        diagnostics_on_stderr: false,
        source_path: None,
        source_digest: None,
    }
}

pub(super) fn is_mobile(parser: Parser) -> bool {
    matches!(
        parser,
        Parser::MobileCompiler | Parser::MobileLint | Parser::MobileProcess
    )
}

/// Resolve real compiler executables rather than /usr/bin Xcode selector shims.
pub(super) fn resolve(ctx: &ToolContext<'_>, command: &Planned, name: &str) -> Option<PathBuf> {
    let inputs = snapshot(command).ok()?;
    let sdk = Path::new(inputs["inputs"]["platform"]["sdkRoot"].as_str()?);
    let dirs = if let Some(dirs) = ctx.search_path {
        dirs.to_vec()
    } else if name == "swiftlint" {
        std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default()
    } else {
        sdk.ancestors()
            .flat_map(|parent| {
                [
                    parent.join("Toolchains/XcodeDefault.xctoolchain/usr/bin"),
                    parent.join("usr/bin"),
                ]
            })
            .collect()
    };
    dirs.iter().find_map(|dir| {
        let invocation = in_dir(dir, name)?;
        if !invocation.is_absolute() {
            return None;
        }
        let path = invocation.canonicalize().ok()?;
        if !path.is_absolute() || path.starts_with(ctx.root.canonicalize().ok()?) {
            return None;
        }
        let text = path.to_str()?;
        let enrolled = &inputs["inputs"]["nativeEnrollment"];
        if !enrolled.is_null() {
            let expected = if name == "swiftlint" {
                path == Path::new(enrolled["swiftlintExecutable"].as_str()?)
            } else {
                path.starts_with(Path::new(enrolled["roots"]["toolchain"]["root"].as_str()?))
            };
            if !expected {
                return None;
            }
        }
        // Swift's real swift/swiftc aliases select driver mode through argv[0].
        // Seal canonical bytes while preserving native toolchain invocation name.
        (name == "swiftlint"
            || text.contains(".xctoolchain/usr/bin/")
            || text.contains("CommandLineTools/usr/bin/"))
        .then_some(invocation)
    })
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if !cfg!(target_os = "macos") {
        fail(plan, "mobile-native-macos-sdk-required");
        return;
    }
    let Some(sdk) = sdk(root) else {
        fail(plan, "mobile-macos-sdk-unbound");
        return;
    };
    let stage = scratch.tmp_dir().join("mobile-sdk");
    if std::fs::create_dir(&stage).is_err() {
        fail(plan, "scratch-unwritable");
        return;
    }
    if std::fs::create_dir_all(scratch.tmp_dir().join("mobile-home")).is_err() {
        fail(plan, "scratch-unwritable");
        return;
    }
    let mut sources = BTreeMap::new();
    let mut bytes = 0usize;
    // Stage the entire frozen inventory, including headers/manifests/resources.
    // An omitted/unreadable entry invalidates closure; never shrink denominator.
    for entry in entries {
        if entries.len() > MAX_FILES || !safe_relative(&entry.path) {
            fail(plan, "mobile-input-budget-or-unsafe-path");
            return;
        }
        let Some(source) = super::super::evidence::syntax_source(root, entry) else {
            fail(plan, "mobile-frozen-input-unreadable");
            return;
        };
        bytes += source.len();
        if bytes > MAX_BYTES {
            fail(plan, "mobile-input-budget");
            return;
        }
        let target = stage.join(&entry.path);
        if std::fs::create_dir_all(target.parent().expect("staged parent")).is_err()
            || std::fs::write(&target, source.as_bytes()).is_err()
        {
            fail(plan, "scratch-unwritable");
            return;
        }
        sources.insert(entry.path.clone(), sha256_text(source.as_bytes()));
        plan.cleanup.push(target);
    }
    if !selected.iter().all(|path| sources.contains_key(path)) {
        fail(plan, "mobile-selected-input-missing");
        return;
    }
    let settings = sdk.join("SDKSettings.json");
    let Ok(settings_bytes) = std::fs::read(&settings) else {
        fail(plan, "mobile-macos-sdk-unbound");
        return;
    };
    let enrollment = match enrollment::descriptor(root) {
        Ok(value) => value,
        Err(_) => {
            fail(plan, "mobile-native-enrollment-invalid");
            return;
        }
    };
    let binding = json!({"nativeEnrollment":enrollment,"schema":"legion-mobile-inputs/1", "root":root.canonicalize().ok(),
        "stage":stage,"sources":sources,"selected":selected,
        "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
            "sdkRoot":sdk,"sdkSettings":settings,"sdkSettingsDigest":sha256_text(&settings_bytes),
            "sdkSettingsValue":serde_json::from_slice::<Value>(&settings_bytes).ok()}});
    let binding_bytes = serde_json::to_vec(&binding).expect("binding JSON");
    let binding_digest = sha256_text(&binding_bytes);
    let binding_path = stage.join(BINDING);
    let config = stage.join(".legion-swiftlint.yml");
    if std::fs::write(&binding_path, &binding_bytes).is_err()
        || std::fs::write(&config, LINT_CONFIG).is_err()
    {
        fail(plan, "scratch-unwritable");
        return;
    }
    plan.cleanup.extend([binding_path, config.clone()]);
    if enrollment.is_none() {
        plan.notes
            .push("mobile-sdk-closure-gap:installed-native-enrollment-required".into());
    }
    plan.notes
        .push("mobile-context-scope:macos-host-swiftpm-and-explicit-clang-source-checks".into());
    plan.notes.push(
        "mobile-platform-gap:ios-ipados-tvos-watchos-visionos-catalyst-simulator-unqualified"
            .into(),
    );
    if entries
        .iter()
        .any(|entry| entry.path.ends_with("project.pbxproj"))
    {
        plan.notes
            .push("mobile-xcode-gap:scheme-destination-build-settings-test-plan-required".into());
    }
    // SwiftPM build/test executes project code only through injected admission.
    let packages = cap_roots(
        dirs_named(entries, &["Package.swift"])
            .into_iter()
            .collect(),
        "swift",
        &mut plan.notes,
    );
    if packages.is_empty() {
        plan.not_planned
            .insert("test", "mobile-test-manifest-or-xcode-context-required");
        let swift: Vec<_> = selected
            .iter()
            .filter(|path| path.ends_with(".swift"))
            .cloned()
            .collect();
        if !swift.is_empty() {
            let mut args = vec![
                "-typecheck".into(),
                "-sdk".into(),
                sdk.to_string_lossy().into_owned(),
                "-module-cache-path".into(),
                scratch
                    .cache_dir()
                    .join("mobile-modules")
                    .to_string_lossy()
                    .into_owned(),
            ];
            args.extend(
                swift
                    .iter()
                    .map(|path| stage.join(path).to_string_lossy().into_owned()),
            );
            plan.commands.push(command(
                "compiler",
                &["swiftc"],
                &stage,
                args,
                Parser::MobileCompiler,
                &[0, 1],
            ));
            plan.notes
                .push("mobile-swift-context-gap:standalone-host-typecheck-not-target-build".into());
        }
    }
    for (index, package) in packages.iter().enumerate() {
        for (tool, action) in [("compiler", "build"), ("test", "test")] {
            let args = vec![
                action.into(),
                "--package-path".into(),
                stage.join(package).to_string_lossy().into_owned(),
                "--skip-update".into(),
                "--disable-automatic-resolution".into(),
                // SwiftPM cannot nest its subprocess sandbox inside authenticated
                // outer confinement; required outer network denial stays intact.
                "--disable-sandbox".into(),
                "--cache-path".into(),
                scratch
                    .cache_dir()
                    .join("mobile-spm-cache")
                    .to_string_lossy()
                    .into_owned(),
                "--config-path".into(),
                scratch
                    .cache_dir()
                    .join("mobile-spm-config")
                    .to_string_lossy()
                    .into_owned(),
                "--security-path".into(),
                scratch
                    .cache_dir()
                    .join("mobile-spm-security")
                    .to_string_lossy()
                    .into_owned(),
                "--disable-netrc".into(),
                "--disable-keychain".into(),
                "--scratch-path".into(),
                scratch
                    .cache_dir()
                    .join(format!("mobile-package-{index}"))
                    .to_string_lossy()
                    .into_owned(),
            ];
            let item = command(tool, &["swift"], &stage, args, Parser::MobileProcess, &[0]);
            plan.commands.push(item);
        }
    }
    for path in selected {
        let extension = Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        if extension == "swift" {
            let args = vec![
                "lint".into(),
                "--quiet".into(),
                "--no-cache".into(),
                "--config".into(),
                config.to_string_lossy().into_owned(),
                "--reporter".into(),
                "json".into(),
                "--strict".into(),
                stage.join(path).to_string_lossy().into_owned(),
            ];
            let mut item = command(
                "analyzer",
                &["swiftlint"],
                &stage,
                args,
                Parser::MobileLint,
                &[0, 2],
            );
            item.source_path = Some(path.clone());
            item.source_digest = sources.get(path).cloned();
            plan.commands.push(item);
        } else if matches!(extension, "m" | "mm") {
            for (tool, mode) in [("compiler", "-fsyntax-only"), ("analyzer", "--analyze")] {
                let mut args = vec![
                    mode.into(),
                    "-x".into(),
                    if extension == "mm" {
                        "objective-c++".into()
                    } else {
                        "objective-c".into()
                    },
                    "-isysroot".into(),
                    sdk.to_string_lossy().into_owned(),
                    "-fno-color-diagnostics".into(),
                    "-fno-caret-diagnostics".into(),
                    format!(
                        "-fmodules-cache-path={}",
                        scratch.cache_dir().join("mobile-clang-modules").display()
                    ),
                ];
                if tool == "analyzer" {
                    args.extend(["-Xanalyzer".into(), "-analyzer-output=text".into()]);
                }
                args.push(stage.join(path).to_string_lossy().into_owned());
                let mut item = command(
                    tool,
                    &["clang"],
                    &stage,
                    args,
                    Parser::MobileCompiler,
                    &[0, 1],
                );
                item.source_path = Some(path.clone());
                item.source_digest = sources.get(path).cloned();
                plan.commands.push(item);
            }
            plan.notes
                .push(format!("mobile-objc-context-gap:default-host-flags:{path}"));
        }
    }
    let developer = sdk
        .ancestors()
        .find(|parent| parent.join("Toolchains/XcodeDefault.xctoolchain").is_dir());
    for item in plan
        .commands
        .iter_mut()
        .filter(|item| is_mobile(item.parser))
    {
        item.env.push((BINDING_DIGEST_ENV, binding_digest.clone()));
        item.env
            .push(("SDKROOT", sdk.to_string_lossy().into_owned()));
        if let Some(developer) = developer {
            item.env
                .push(("DEVELOPER_DIR", developer.to_string_lossy().into_owned()));
            let toolchain = developer.join("Toolchains/XcodeDefault.xctoolchain");
            item.env
                .push(("TOOLCHAIN_DIR", toolchain.to_string_lossy().into_owned()));
            item.env.push((
                "XCODE_DEFAULT_TOOLCHAIN_OVERRIDE",
                toolchain.to_string_lossy().into_owned(),
            ));
        }
    }
    for tool in ["compiler", "analyzer"] {
        if !plan.commands.iter().any(|item| item.tool == tool) {
            plan.not_planned
                .insert(tool, "mobile-no-applicable-sources");
        }
    }
}

/// Full tree verification at provider/matrix boundaries. Per-command snapshots
/// additionally seal enrollment artifact identity without repeatedly scanning SDK.
pub(super) fn closure_snapshot(root: &Path) -> Result<Option<Value>, String> {
    let Some(sdk) = sdk(root) else {
        return Err("mobile-macos-sdk-unbound".into());
    };
    enrollment::verify(root, &sdk)
}

/// Re-read original & staged closures before/after every execution, even refusal.
pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let stage = Path::new(&command.cwd_rel);
    let raw = std::fs::read(stage.join(BINDING)).map_err(|_| "mobile-binding-unreadable")?;
    if command
        .env
        .iter()
        .find(|(name, _)| *name == BINDING_DIGEST_ENV)
        .map(|(_, digest)| digest.as_str())
        != Some(sha256_text(&raw).as_str())
    {
        return Err("mobile-frozen-binding-changed".into());
    }
    let binding: Value = serde_json::from_slice(&raw).map_err(|_| "mobile-binding-malformed")?;
    if binding["schema"] != "legion-mobile-inputs/1" || binding["stage"].as_str() != stage.to_str()
    {
        return Err("mobile-binding-invalid".into());
    }
    let root = Path::new(binding["root"].as_str().ok_or("mobile-root-unbound")?);
    if binding
        .get("nativeEnrollment")
        .is_some_and(|value| !value.is_null())
        && enrollment::descriptor(root)?.as_ref() != binding.get("nativeEnrollment")
    {
        return Err("mobile-native-enrollment-changed".into());
    }
    let sources = binding["sources"]
        .as_object()
        .ok_or("mobile-sources-unbound")?;
    for (path, expected) in sources {
        if !safe_relative(path) {
            return Err("mobile-unsafe-source".into());
        }
        for parent in [root, stage] {
            let source = parent.join(path);
            let mut component_path = parent.to_path_buf();
            for component in Path::new(path).components() {
                component_path.push(component);
                if std::fs::symlink_metadata(&component_path)
                    .map_err(|_| "mobile-source-missing")?
                    .file_type()
                    .is_symlink()
                {
                    return Err("mobile-source-symlink".into());
                }
            }
            let resolved = source.canonicalize().map_err(|_| "mobile-source-missing")?;
            if !resolved.starts_with(parent)
                || std::fs::symlink_metadata(&source)
                    .map_err(|_| "mobile-source-missing")?
                    .file_type()
                    .is_symlink()
                || std::fs::read(&source)
                    .ok()
                    .map(|bytes| sha256_text(&bytes))
                    .as_deref()
                    != expected.as_str()
            {
                return Err("mobile-source-changed".into());
            }
        }
    }
    let settings = Path::new(
        binding["platform"]["sdkSettings"]
            .as_str()
            .ok_or("mobile-sdk-unbound")?,
    );
    if std::fs::read(settings)
        .ok()
        .map(|bytes| sha256_text(&bytes))
        .as_deref()
        != binding["platform"]["sdkSettingsDigest"].as_str()
    {
        return Err("mobile-sdk-settings-changed".into());
    }
    if std::fs::read_to_string(stage.join(".legion-swiftlint.yml"))
        .ok()
        .as_deref()
        != Some(LINT_CONFIG)
    {
        return Err("mobile-owned-config-changed".into());
    }
    Ok(json!({"bindingDigest":sha256_text(&raw), "inputs":binding}))
}

pub(super) fn parse(
    bytes: &[u8],
    stderr: Option<&[u8]>,
    exit: Option<i32>,
    command: &Planned,
) -> Result<Vec<Diag>, String> {
    let snapshot = snapshot(command)?;
    let inputs = &snapshot["inputs"];
    let sources = inputs["sources"]
        .as_object()
        .ok_or("mobile-sources-unbound")?;
    let stage = Path::new(&command.cwd_rel);
    let map_path = |raw: &str| -> Result<String, String> {
        let path = Path::new(raw);
        let relative = if path.is_absolute() {
            path.strip_prefix(stage)
                .map_err(|_| "mobile-diagnostic-outside-stage")?
        } else {
            path
        };
        let relative = relative.to_str().ok_or("mobile-invalid-diagnostic-path")?;
        if !safe_relative(relative)
            || !sources.contains_key(relative)
            || !inputs["selected"]
                .as_array()
                .is_some_and(|paths| paths.iter().any(|path| path.as_str() == Some(relative)))
        {
            return Err("mobile-diagnostic-outside-denominator".into());
        }
        Ok(relative.into())
    };
    let valid_line = |path: &str, line: usize| -> bool {
        std::fs::read_to_string(stage.join(path))
            .ok()
            .is_some_and(|source| line > 0 && line <= source.lines().count().max(1) + 1)
    };
    if command.parser == Parser::MobileProcess {
        return if exit == Some(0) {
            Ok(Vec::new())
        } else {
            Err("mobile-project-command-failed".into())
        };
    }
    if command.parser == Parser::MobileLint {
        if stderr.is_none_or(|bytes| !bytes.is_empty()) {
            return Err("mobile-swiftlint-stderr-or-missing-stream".into());
        }
        let records: Vec<Value> =
            serde_json::from_slice(bytes).map_err(|_| "mobile-swiftlint-malformed")?;
        if !matches!(exit, Some(0 | 2)) || (exit == Some(0)) != records.is_empty() {
            return Err("mobile-swiftlint-inconsistent-exit".into());
        }
        return records
            .iter()
            .map(|record| {
                let path = map_path(record["file"].as_str().ok_or("mobile-swiftlint-path")?)?;
                if Some(path.as_str()) != command.source_path.as_deref() {
                    return Err("mobile-swiftlint-wrong-source".into());
                }
                let rule = record["rule_id"]
                    .as_str()
                    .filter(|rule| !rule.is_empty())
                    .ok_or("mobile-swiftlint-rule")?;
                let severity = match record["severity"].as_str() {
                    Some("Warning") => "warning",
                    Some("Error") => "error",
                    _ => return Err("mobile-swiftlint-severity".into()),
                };
                let line = record["line"]
                    .as_u64()
                    .filter(|line| *line > 0)
                    .ok_or("mobile-swiftlint-line")? as usize;
                if !valid_line(&path, line) {
                    return Err("mobile-swiftlint-line-out-of-range".into());
                }
                let message = record["reason"]
                    .as_str()
                    .filter(|text| !text.trim().is_empty())
                    .ok_or("mobile-swiftlint-message")?;
                Ok(Diag {
                    rule: format!("swiftlint:{rule}"),
                    severity,
                    path,
                    line,
                    message: shorten(message),
                })
            })
            .collect();
    }
    let stderr = stderr.ok_or("mobile-stderr-unreadable")?;
    let text = std::str::from_utf8(stderr).map_err(|_| "mobile-diagnostic-utf8")?;
    let regex = Regex::new(r"^(.+):([0-9]+):([0-9]+): (warning|error|fatal error): (.+)$")
        .expect("diagnostic regex");
    let mut diagnostics = Vec::new();
    for line in text.lines() {
        if let Some(captures) = regex.captures(line) {
            let path = map_path(&captures[1])?;
            if command
                .source_path
                .as_ref()
                .is_some_and(|source| source != &path)
            {
                return Err("mobile-diagnostic-wrong-source".into());
            }
            let source_line = captures[2]
                .parse::<usize>()
                .ok()
                .filter(|line| valid_line(&path, *line))
                .ok_or("mobile-diagnostic-line")?;
            diagnostics.push(Diag {
                rule: if command.programs.contains(&"clang") {
                    "clang".into()
                } else {
                    "swiftc".into()
                },
                path,
                line: source_line,
                severity: if &captures[4] == "warning" {
                    "warning"
                } else {
                    "error"
                },
                message: shorten(&captures[5]),
            });
        } else if line.contains("error:") || line.contains("warning:") {
            return Err("mobile-unmapped-diagnostic".into());
        } else if !line.trim().is_empty()
            && !line.contains(": note:")
            && !line.contains('|')
            && !line.ends_with(" generated.")
        {
            return Err("mobile-unrecognized-diagnostic-output".into());
        }
    }
    if !matches!(exit, Some(0 | 1))
        || (exit == Some(1) && !diagnostics.iter().any(|diag| diag.severity == "error"))
        || (exit == Some(0) && diagnostics.iter().any(|diag| diag.severity == "error"))
        || !bytes.is_empty()
    {
        return Err("mobile-compiler-inconsistent-output-or-exit".into());
    }
    Ok(diagnostics)
}

#[cfg(test)]
#[path = "mobile_sdk_tests.rs"]
mod tests;
