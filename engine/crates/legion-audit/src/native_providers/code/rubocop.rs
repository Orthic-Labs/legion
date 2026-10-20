//! RuboCop runs against frozen Ruby snapshots, never repository configuration.
//! Flag/schema reference: rubocop/rubocop v1.80.2 `lib/rubocop/options.rb`,
//! `arguments_{file,env}.rb` & `formatter/json_formatter.rb`.
use super::*;
use std::io::Read;

const MAX_FILES: usize = 200;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const OWNED_CONFIG: &str =
    "AllCops:\n  NewCops: enable\n  SuggestExtensions: false\n  UseCache: false\n  Exclude: []\n";

pub(super) fn trusted_path(root: &Path, path: &Path) -> bool {
    path.is_absolute()
        && path.canonicalize().ok().is_some_and(|path| {
            root.canonicalize()
                .ok()
                .is_some_and(|root| !path.starts_with(root))
        })
}

pub(super) fn search_dirs(ctx: &ToolContext<'_>) -> Vec<PathBuf> {
    let dirs = ctx.search_path.map(<[PathBuf]>::to_vec).unwrap_or_else(|| {
        std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default()
    });
    dirs.into_iter()
        .filter(|path| trusted_path(ctx.root, path))
        .collect()
}

/// Preserve a user-installed scanner's gem dependencies after replacing HOME,
/// deriving their root from the sealed executable rather than GEM_* input.
pub(super) fn gem_home(root: &Path, executable: &Path) -> Option<String> {
    let executable = executable.canonicalize().ok()?;
    executable
        .ancestors()
        .skip(1)
        .take(5)
        .find(|path| {
            trusted_path(root, path)
                && path.join("specifications").is_dir()
                && path.join("gems").is_dir()
                && trusted_path(root, &path.join("specifications"))
                && trusted_path(root, &path.join("gems"))
        })
        .map(|path| path.to_string_lossy().into_owned())
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    let mut ruby = entries
        .iter()
        .filter(|entry| {
            selected.contains(&entry.path)
                && Path::new(&entry.path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("rb"))
        })
        .peekable();
    if ruby.peek().is_none() {
        plan.not_planned.insert("ruby-lint", "no-ruby-sources");
        return;
    }
    // A private cwd also prevents `.rubocop` argv-file loading. The explicit
    // YAML has no ERB, plugins, requires, inheritance, or repository paths.
    let cwd = scratch.tmp_dir().join("ruby-lint");
    let config = cwd.join("audit.yml");
    if std::fs::create_dir(&cwd).is_err() || std::fs::write(&config, OWNED_CONFIG).is_err() {
        plan.not_planned.insert("ruby-lint", "scratch-unwritable");
        return;
    }
    plan.cleanup.push(config.clone());
    let cwd_text = cwd.to_string_lossy().into_owned();
    let mut bytes = 0usize;
    for (index, entry) in ruby.enumerate() {
        if index >= MAX_FILES || bytes >= MAX_BYTES {
            plan.notes
                .push(format!("rubocop-input-budget:ruby-lint:{}", entry.path));
            plan.not_planned.insert("ruby-lint", "rubocop-input-budget");
            continue;
        }
        let Some(source) = super::super::evidence::syntax_source(root, entry) else {
            plan.notes
                .push(format!("rubocop-input-unreadable:ruby-lint:{}", entry.path));
            plan.not_planned
                .insert("ruby-lint", "rubocop-input-unreadable");
            continue;
        };
        bytes += source.len();
        if bytes > MAX_BYTES {
            plan.notes
                .push(format!("rubocop-input-budget:ruby-lint:{}", entry.path));
            plan.not_planned.insert("ruby-lint", "rubocop-input-budget");
            continue;
        }
        let staged = cwd.join(format!("source-{index}.rb"));
        if std::fs::write(&staged, &source).is_err() {
            plan.not_planned.insert("ruby-lint", "scratch-unwritable");
            continue;
        }
        plan.cleanup.push(staged.clone());
        plan.commands.push(Planned {
            tool: "ruby-lint",
            programs: &["rubocop"],
            local_bin: false,
            sibling_of: None,
            requires: None,
            cwd_rel: cwd_text.clone(),
            args: vec![
                "--config".into(),
                config.to_string_lossy().into_owned(),
                "--format".into(),
                "json".into(),
                "--lint".into(),
                // Cache stays disabled in OWNED_CONFIG. Passing --cache false
                // with --no-parallel prints non-JSON compatibility text in
                // v1.80.2, even though the parallel option is false.
                "--no-server".into(),
                "--no-parallel".into(),
                "--no-color".into(),
                "--ignore-parent-exclusion".into(),
                "--ignore-disable-comments".into(),
                "--raise-cop-error".into(),
                "--fail-level".into(),
                "info".into(),
                "--".into(),
                staged.to_string_lossy().into_owned(),
            ],
            parser: Parser::Rubocop,
            accepted: &[0, 1],
            env: vec![
                ("HOME", cwd_text.clone()),
                ("USERPROFILE", cwd_text.clone()),
                ("XDG_CONFIG_HOME", cwd_text.clone()),
                ("RUBOCOP_OPTS", String::new()),
                ("RUBYOPT", String::new()),
                ("RUBYLIB", String::new()),
            ],
            diagnostics_on_stderr: false,
            source_path: Some(entry.path.clone()),
            source_digest: Some(sha256_text(source.as_bytes())),
        });
    }
}

fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= limit).then_some(bytes)
}

pub(super) fn staged_input_valid(command: &Planned) -> bool {
    let Some(staged) = command.args.last().map(Path::new) else {
        return false;
    };
    let Some(config) = command.args.get(1).map(Path::new) else {
        return false;
    };
    [staged, config].into_iter().all(|path| {
        path.parent() == Some(Path::new(&command.cwd_rel))
            && std::fs::symlink_metadata(path)
                .ok()
                .is_some_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
    }) && read_bounded(staged, 1024 * 1024)
        .is_some_and(|bytes| command.source_digest.as_deref() == Some(sha256_text(&bytes).as_str()))
        && read_bounded(config, OWNED_CONFIG.len()).as_deref() == Some(OWNED_CONFIG.as_bytes())
}

pub(super) fn parse(
    bytes: &[u8],
    stderr: Option<&[u8]>,
    exit: Option<i32>,
    command: &Planned,
) -> Result<Vec<Diag>, String> {
    // Runner errors may share exit 1 with offenses. Never call their partial
    // JSON clean; --raise-cop-error & stderr validation preserve this gap.
    if !matches!(exit, Some(0 | 1)) {
        return Err("rubocop-inconsistent-exit".into());
    }
    if stderr.is_none_or(|bytes| bytes.iter().any(|byte| !byte.is_ascii_whitespace())) {
        return Err("rubocop-stderr-or-unreadable".into());
    }
    let report: Value = serde_json::from_slice(bytes).map_err(|_| "rubocop-invalid-json")?;
    let version = report
        .pointer("/metadata/rubocop_version")
        .and_then(Value::as_str);
    if version.is_none_or(|value| value.trim().is_empty()) {
        return Err("rubocop-invalid-metadata".into());
    }
    let files = report
        .get("files")
        .and_then(Value::as_array)
        .ok_or("rubocop-invalid-files")?;
    if files.len() != 1
        || report
            .pointer("/summary/target_file_count")
            .and_then(Value::as_u64)
            != Some(1)
        || report
            .pointer("/summary/inspected_file_count")
            .and_then(Value::as_u64)
            != Some(1)
    {
        return Err("rubocop-incomplete-file-count".into());
    }
    let staged = command
        .args
        .last()
        .ok_or("rubocop-source-binding-required")?;
    let filename = Path::new(staged)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("rubocop-source-binding-required")?;
    let path = files[0]
        .get("path")
        .and_then(Value::as_str)
        .ok_or("rubocop-invalid-path")?;
    if path != staged && path != filename && path != format!("./{filename}") {
        return Err("rubocop-unmapped-path".into());
    }
    let original = command
        .source_path
        .as_ref()
        .ok_or("rubocop-source-binding-required")?;
    let source = read_bounded(Path::new(staged), 1024 * 1024)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or("rubocop-source-unreadable")?;
    if command.source_digest.as_deref() != Some(sha256_text(source.as_bytes()).as_str()) {
        return Err("rubocop-source-changed".into());
    }
    let offenses = files[0]
        .get("offenses")
        .and_then(Value::as_array)
        .ok_or("rubocop-invalid-offenses")?;
    if report
        .pointer("/summary/offense_count")
        .and_then(Value::as_u64)
        != Some(offenses.len() as u64)
        || exit != Some(i32::from(!offenses.is_empty()))
    {
        return Err("rubocop-inconsistent-offense-count-or-exit".into());
    }
    let mut diagnostics = Vec::new();
    let max_line = source.lines().count().max(1) + 1;
    for offense in offenses {
        let rule = offense
            .get("cop_name")
            .and_then(Value::as_str)
            .filter(|rule| {
                !rule.is_empty()
                    && rule
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_'))
            })
            .ok_or("rubocop-invalid-cop-name")?;
        let message = offense
            .get("message")
            .and_then(Value::as_str)
            .filter(|message| !message.trim().is_empty())
            .ok_or("rubocop-invalid-message")?;
        let severity = match offense.get("severity").and_then(Value::as_str) {
            Some("fatal" | "error") => "error",
            Some("warning" | "convention" | "refactor" | "info") => "warning",
            _ => return Err("rubocop-invalid-severity".into()),
        };
        if offense.get("corrected").and_then(Value::as_bool) != Some(false)
            || offense
                .get("correctable")
                .and_then(Value::as_bool)
                .is_none()
        {
            return Err("rubocop-invalid-correction-state".into());
        }
        let line = offense
            .pointer("/location/start_line")
            .and_then(Value::as_u64)
            .and_then(|line| usize::try_from(line).ok())
            .filter(|line| *line > 0 && *line <= max_line)
            .ok_or("rubocop-invalid-location")?;
        diagnostics.push(Diag {
            rule: format!("rubocop:{rule}"),
            severity,
            path: original.clone(),
            line,
            message: shorten(message),
        });
    }
    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, AuditScratch, Plan) {
        let root = std::env::temp_dir().join(format!(
            "rubocop-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let scratch = AuditScratch::create(&root).unwrap();
        let source = "def example\n  value = 1\n  nil\nend\n";
        std::fs::write(root.join("app.rb"), source).unwrap();
        std::fs::write(root.join("app.php"), "<?php echo 1;\n").unwrap();
        std::fs::write(root.join(".rubocop"), "--require ./evil.rb --autocorrect").unwrap();
        std::fs::write(
            root.join(".rubocop.yml"),
            "inherit_from: https://example.invalid/config.yml\nrequire: ./evil.rb\n",
        )
        .unwrap();
        let entries = ["app.rb", "app.php"].map(|path| InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(sha256_text(&std::fs::read(root.join(path)).unwrap())),
        });
        let selected = entries.iter().map(|entry| entry.path.clone()).collect();
        let mut planned = Plan::default();
        plan(&root, &entries, &selected, &scratch, &mut planned);
        (root, scratch, planned)
    }

    fn report(command: &Planned, offenses: Value) -> Value {
        json!({
            "metadata": {"rubocop_version": "1.80.2"},
            "files": [{"path": Path::new(command.args.last().unwrap()).file_name().unwrap().to_str().unwrap(), "offenses": offenses}],
            "summary": {"target_file_count": 1, "inspected_file_count": 1, "offense_count": offenses.as_array().unwrap().len()},
        })
    }

    fn offense() -> Value {
        json!({
            "cop_name": "Lint/UselessAssignment", "severity": "warning",
            "message": "Useless assignment to variable - value.",
            "corrected": false, "correctable": true,
            "location": {"start_line": 2, "start_column": 3},
        })
    }

    fn parse_report(report: &Value, exit: i32, command: &Planned) -> Result<Vec<Diag>, String> {
        parse(
            &serde_json::to_vec(report).unwrap(),
            Some(b""),
            Some(exit),
            command,
        )
    }

    #[test]
    fn rubocop_plan_contains_config_sources_and_environment() {
        let (root, scratch, planned) = fixture();
        assert_eq!(planned.commands.len(), 1);
        let command = &planned.commands[0];
        assert_eq!(command.tool, "ruby-lint");
        assert_eq!(command.source_path.as_deref(), Some("app.rb"));
        assert!(staged_input_valid(command));
        assert!(Path::new(&command.cwd_rel).starts_with(scratch.tmp_dir()));
        assert!(!Path::new(&command.cwd_rel).starts_with(&root));
        assert!(!Path::new(&command.cwd_rel).join(".rubocop").exists());
        assert_eq!(
            std::fs::read_to_string(&command.args[1]).unwrap(),
            OWNED_CONFIG
        );
        for flag in [
            "--no-server",
            "--no-parallel",
            "--ignore-parent-exclusion",
            "--ignore-disable-comments",
            "--raise-cop-error",
        ] {
            assert!(command.args.iter().any(|arg| arg == flag));
        }
        assert!(!command
            .args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--autocorrect" | "--require" | "--plugin")));
        for name in ["RUBOCOP_OPTS", "RUBYOPT", "RUBYLIB"] {
            assert!(command
                .env
                .iter()
                .any(|(key, value)| *key == name && value.is_empty()));
        }
        assert!(!trusted_path(&root, Path::new(".")));
        assert!(!trusted_path(&root, &root.join("app.rb")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rubocop_clean_and_offense_output_bind_original_file_line_and_rule() {
        let (root, _scratch, planned) = fixture();
        let command = &planned.commands[0];
        assert!(parse_report(&report(command, json!([])), 0, command)
            .unwrap()
            .is_empty());
        let mut absolute = report(command, json!([]));
        absolute["files"][0]["path"] = json!(command.args.last().unwrap());
        assert!(parse_report(&absolute, 0, command).unwrap().is_empty());
        let diagnostics = parse_report(&report(command, json!([offense()])), 1, command).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path, "app.rb");
        assert_eq!(diagnostics[0].line, 2);
        assert_eq!(diagnostics[0].rule, "rubocop:Lint/UselessAssignment");
        assert_eq!(diagnostics[0].severity, "warning");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rubocop_rejects_partial_wrong_shape_and_inconsistent_exit_reports() {
        let (root, _scratch, planned) = fixture();
        let command = &planned.commands[0];
        for bytes in [
            b"".as_slice(),
            b"{}",
            b"[]",
            b"{\"files\":[]}",
            b"{\"files\":",
        ] {
            assert!(parse(bytes, Some(b""), Some(0), command).is_err());
        }
        let clean = report(command, json!([]));
        assert!(parse_report(&clean, 1, command).is_err());
        assert!(parse_report(&clean, 2, command).is_err());
        assert!(parse_report(&report(command, json!([offense()])), 0, command).is_err());
        assert!(parse(
            &serde_json::to_vec(&clean).unwrap(),
            Some(b"An error occurred in Lint/Cop"),
            Some(0),
            command
        )
        .is_err());
        assert!(parse(&serde_json::to_vec(&clean).unwrap(), None, Some(0), command).is_err());
        for pointer in [
            "/summary/target_file_count",
            "/summary/inspected_file_count",
            "/summary/offense_count",
        ] {
            let mut bad = clean.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(99);
            assert!(parse_report(&bad, 0, command).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rubocop_rejects_unmapped_clean_files_and_malformed_offenses() {
        let (root, _scratch, planned) = fixture();
        let command = &planned.commands[0];
        for path in ["../../app.rb", "/outside/app.rb", "app.php", "other.rb"] {
            let mut bad = report(command, json!([]));
            bad["files"][0]["path"] = json!(path);
            assert!(parse_report(&bad, 0, command).is_err());
        }
        for (pointer, value) in [
            ("/corrected", json!(true)),
            ("/severity", json!("unknown")),
            ("/location/start_line", json!(0)),
            ("/location/start_line", json!(1000)),
            ("/message", json!("")),
            ("/cop_name", json!("")),
        ] {
            let mut bad = offense();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(parse_report(&report(command, json!([bad])), 1, command).is_err());
        }
        std::fs::write(command.args.last().unwrap(), "changed").unwrap();
        assert!(!staged_input_valid(command));
        assert!(parse_report(&report(command, json!([])), 0, command).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rubocop_file_cap_and_changed_frozen_sources_remain_gaps() {
        let (root, _scratch, _planned) = fixture();
        let entry = InventoryEntry {
            path: "app.rb".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(sha256_text(&std::fs::read(root.join("app.rb")).unwrap())),
        };
        let selected = BTreeSet::from(["app.rb".into()]);
        let scratch = AuditScratch::create(&root).unwrap();
        let mut planned = Plan::default();
        plan(
            &root,
            &vec![entry.clone(); MAX_FILES + 1],
            &selected,
            &scratch,
            &mut planned,
        );
        assert_eq!(planned.commands.len(), MAX_FILES);
        assert_eq!(
            planned.not_planned.get("ruby-lint"),
            Some(&"rubocop-input-budget")
        );
        std::fs::write(root.join("app.rb"), "changed after inventory\n").unwrap();
        let scratch = AuditScratch::create(&root).unwrap();
        let mut changed = Plan::default();
        plan(&root, &[entry], &selected, &scratch, &mut changed);
        assert!(changed.commands.is_empty());
        assert_eq!(
            changed.not_planned.get("ruby-lint"),
            Some(&"rubocop-input-unreadable")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Clone, Copy)]
    enum MockReport {
        Clean,
        Offense,
        Unmapped,
    }

    struct MockRuboCop(MockReport);

    #[async_trait::async_trait]
    impl ExternalProjectTool for MockRuboCop {
        async fn execute(
            &self,
            request: ExternalToolRequest,
            _cancellation: CancellationToken,
        ) -> ExecutionReceipt {
            assert_eq!(request.task_id.as_deref(), Some("ruby-lint"));
            assert!(request.requires_network_sandbox);
            // Mock command orchestration only: authenticated macOS wrapping,
            // when available, must not change the original scanner arguments.
            let arguments = if request.sandbox.is_some() {
                assert_eq!(request.executable, "/usr/bin/sandbox-exec");
                assert_eq!(request.args.first().map(String::as_str), Some("-f"));
                assert_eq!(request.args.get(2).map(String::as_str), Some("--"));
                &request.args[4..]
            } else {
                &request.args[..]
            };
            assert!(arguments.iter().any(|arg| arg == "--no-parallel"));
            // v1.80.2 OptionsValidator prints a warning to stdout for the
            // cache:false + parallel:false CLI combination. Config-only
            // UseCache:false keeps both caching & parallelism disabled.
            assert!(!arguments.iter().any(|arg| arg == "--cache"));
            assert_eq!(
                std::fs::read_to_string(&arguments[1]).unwrap(),
                OWNED_CONFIG
            );
            let offenses = match self.0 {
                MockReport::Offense => json!([offense()]),
                _ => json!([]),
            };
            let path = match self.0 {
                MockReport::Unmapped => "../../outside.rb".to_owned(),
                _ => Path::new(arguments.last().unwrap())
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            };
            let stdout = serde_json::to_vec(&json!({
                "metadata": {"rubocop_version": "1.80.2"},
                "files": [{"path": path, "offenses": offenses}],
                "summary": {
                    "target_file_count": 1, "inspected_file_count": 1,
                    "offense_count": usize::from(matches!(self.0, MockReport::Offense)),
                },
            }))
            .unwrap();
            let artifact = |name: &str, bytes: &[u8]| {
                let path = Path::new(&request.cwd).join(name);
                std::fs::write(&path, bytes).unwrap();
                legion_effects::ArtifactRecord {
                    path: path.to_string_lossy().into_owned(),
                    digest: sha256_text(bytes),
                    bytes: bytes.len(),
                    immutable: true,
                }
            };
            let mut receipt =
                ExecutionReceipt::failure(&request, ExecutionState::Completed, "mock");
            receipt.complete = true;
            receipt.gaps.clear();
            receipt.exit_code = Some(i32::from(matches!(self.0, MockReport::Offense)));
            let mut identity = legion_effects::ExecutableIdentity::resolve(
                &request.executable,
                request.expected_digest.as_deref(),
            )
            .unwrap();
            identity.version.output = Some("1.80.2".into());
            receipt.executable = Some(identity);
            receipt.stdout = Some(artifact("mock-stdout.json", &stdout));
            receipt.stderr = Some(artifact("mock-stderr.txt", b""));
            receipt
        }
    }

    // Command-unit regression through production run_one + path normalization.
    // Mock SDK bytes do not qualify the full provider's native enrollment.
    #[tokio::test]
    async fn rubocop_command_keeps_original_paths_diagnostics_and_receipts() {
        let (root, _fixture_scratch, _planned) = fixture();
        let digest = sha256_text(&std::fs::read(root.join("app.rb")).unwrap());
        let entries = [InventoryEntry {
            path: "app.rb".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(digest.clone()),
        }];
        let selected = BTreeSet::from(["app.rb".into()]);
        for mode in [MockReport::Clean, MockReport::Offense, MockReport::Unmapped] {
            let scratch = AuditScratch::create(&root).unwrap();
            let mut planned = Plan::default();
            plan(&root, &entries, &selected, &scratch, &mut planned);
            assert_eq!(planned.commands.len(), 1);
            let bin = scratch.root().join("mock-bin");
            std::fs::create_dir(&bin).unwrap();
            let executable = bin.join("rubocop");
            std::fs::write(&executable, "mock scanner, never launched").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            let search_path = [bin];
            let tool = MockRuboCop(mode);
            let context = ToolContext {
                root: &root,
                tool: &tool,
                scratch: &scratch,
                sandbox: SandboxPolicy::Required,
                #[cfg(all(test, target_os = "macos"))]
                dotnet_qualification_loopback: false,
                search_path: Some(&search_path),
                plan_digest: "sha256:plan",
                inventory_digest: "sha256:inventory",
                provider_id: "code.php-ruby",
                per_tool_timeout_ms: 1000,
                total_budget_ms: 10_000,
                output_limit: 64 * 1024,
            };
            let mut resolver = super::super::Resolver::new(&context);
            let output = super::super::run_one(
                &context,
                &mut resolver,
                &planned.commands[0],
                None,
                0,
                1000,
                CancellationToken::new(),
            )
            .await;
            let receipt = output.receipt.as_ref().expect("RuboCop command receipt");
            assert_eq!(receipt["tool"], "ruby-lint");
            assert!(receipt["sdkReceipt"].is_object());
            assert_eq!(receipt["sourcePath"], "app.rb");
            assert_eq!(receipt["sourceDigest"], digest);
            assert_eq!(
                receipt["cwd"],
                scratch
                    .tmp_dir()
                    .join("ruby-lint")
                    .to_string_lossy()
                    .into_owned()
            );
            let canonical_root = root.canonicalize().unwrap();
            for diagnostic in &output.diagnostics {
                // Isolated lint diagnostics already refer to original sources;
                // production finding normalization therefore uses an empty cwd.
                let path =
                    super::super::repo_relative(&root, &canonical_root, "", &diagnostic.path)
                        .expect("diagnostic must remain inside repository");
                assert_eq!(path, "app.rb");
                assert!(selected.contains(&path));
            }
            match mode {
                MockReport::Unmapped => {
                    assert!(
                        matches!(&output.outcome, Outcome::Failed(reason) if reason.contains("rubocop-unmapped-path"))
                    );
                    assert!(output.diagnostics.is_empty());
                }
                MockReport::Clean => {
                    assert_eq!(output.outcome, Outcome::Ran);
                    assert!(output.diagnostics.is_empty());
                }
                MockReport::Offense => {
                    assert_eq!(output.outcome, Outcome::Ran);
                    assert_eq!(output.diagnostics.len(), 1);
                    assert_eq!(output.diagnostics[0].path, "app.rb");
                    assert_eq!(output.diagnostics[0].line, 2);
                    assert_eq!(output.diagnostics[0].rule, "rubocop:Lint/UselessAssignment");
                }
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rubocop_full_provider_without_enrollment_never_submits() {
        // Isolate environment removal in this exact test's child process;
        // changing process-global enrollment would race parallel native tests.
        const CHILD: &str = "LEGION_RUBOCOP_MISSING_ENROLLMENT_TEST_CHILD";
        const ENROLLMENT: &str = "LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON";
        const EXECUTED: &str = "rubocop-missing-enrollment-control-executed";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_providers::code::tools::rubocop::tests::rubocop_full_provider_without_enrollment_never_submits",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env_remove(ENROLLMENT)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated missing-enrollment control failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.trim() == EXECUTED),
                "isolated missing-enrollment control must execute its assertions"
            );
            return;
        }
        assert!(std::env::var_os(ENROLLMENT).is_none());
        struct NeverSubmit;
        #[async_trait::async_trait]
        impl ExternalProjectTool for NeverSubmit {
            async fn execute(
                &self,
                _request: ExternalToolRequest,
                _cancellation: CancellationToken,
            ) -> ExecutionReceipt {
                panic!("missing genuine enrollment must refuse before SDK submission");
            }
        }
        let (root, _fixture_scratch, _planned) = fixture();
        let scratch = AuditScratch::create(&root).unwrap();
        let entries = [InventoryEntry {
            path: "app.rb".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(sha256_text(&std::fs::read(root.join("app.rb")).unwrap())),
        }];
        let search_path = [];
        let context = ToolContext {
            root: &root,
            tool: &NeverSubmit,
            scratch: &scratch,
            sandbox: SandboxPolicy::Required,
            #[cfg(all(test, target_os = "macos"))]
            dotnet_qualification_loopback: false,
            search_path: Some(&search_path),
            plan_digest: "sha256:plan",
            inventory_digest: "sha256:inventory",
            provider_id: "code.php-ruby",
            per_tool_timeout_ms: 1000,
            total_budget_ms: 10_000,
            output_limit: 64 * 1024,
        };
        let evidence = super::super::run(
            &context,
            &["ruby-lint"],
            &entries,
            &BTreeSet::from(["app.rb".into()]),
            CancellationToken::new(),
        )
        .await;
        assert!(evidence.findings.is_empty());
        // The first enrollment refusal survives the later same-rank boundary failure.
        assert_eq!(
            evidence.outcomes.get("ruby-lint"),
            Some(&Outcome::Failed("php-ruby-enrollment-unavailable".into()))
        );
        assert_eq!(evidence.receipts.len(), 1);
        let boundary = &evidence.receipts[0];
        assert_eq!(boundary["kind"], "php-ruby-native-enrollment-boundary");
        assert!(boundary["before"].is_null() && boundary["after"].is_null());
        assert_eq!(boundary["beforeError"], "php-ruby-enrollment-unavailable");
        assert_eq!(boundary["afterError"], "php-ruby-enrollment-unavailable");
        std::fs::remove_dir_all(root).unwrap();
        println!("{EXECUTED}");
    }
}
