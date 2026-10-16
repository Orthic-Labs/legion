//! Native-family applicability & isolated syntax adapters. Project commands
//! remain behind the runner's existing no-project-code policy. Keeping their
//! exact argv separate from receipts makes missing historical execution visible.
use super::*;

const MAX_SYNTAX_FILES: usize = 200;
const MAX_SYNTAX_BYTES: usize = 16 * 1024 * 1024;

fn command(
    tool: &'static str,
    programs: &'static [&'static str],
    dir: &str,
    args: Vec<String>,
) -> Planned {
    Planned {
        tool,
        programs,
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: dir.into(),
        args,
        parser: Parser::Syntax,
        accepted: &[0, 1, 2, 255],
        env: Vec::new(),
        diagnostics_on_stderr: false,
        source_path: None,
        source_digest: None,
    }
}

fn defer(
    plan: &mut Plan,
    entries: &[InventoryEntry],
    manifests: &[&str],
    programs: &'static [&'static str],
    tool: &'static str,
    args: &[&str],
) {
    let dirs = cap_roots(
        dirs_named(entries, manifests).into_iter().collect(),
        programs[0],
        &mut plan.notes,
    );
    for dir in dirs {
        plan.deferred.push(command(
            tool,
            programs,
            &dir,
            args.iter().map(|arg| (*arg).into()).collect(),
        ));
    }
}

pub(super) fn plan(
    provider: &str,
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    match provider {
        "code.go" => defer(
            plan,
            entries,
            &["go.mod"],
            &["go"],
            "test",
            &["test", "./..."],
        ),
        "code.mobile" => {
            defer(
                plan,
                entries,
                &["Package.swift"],
                &["swift"],
                "compiler",
                &["build", "--skip-update"],
            );
            defer(
                plan,
                entries,
                &["Package.swift"],
                &["swift"],
                "test",
                &["test", "--skip-update"],
            );
            if dirs_named(entries, &["Package.swift"]).is_empty() {
                let files: Vec<String> = selected
                    .iter()
                    .filter(|path| path.ends_with(".swift"))
                    .cloned()
                    .collect();
                if !files.is_empty() {
                    let mut args = vec!["-typecheck".into()];
                    args.extend(files);
                    plan.deferred
                        .push(command("compiler", &["swiftc"], "", args));
                }
            }
        }
        "code.jvm" => {
            for (tool, args) in [
                (
                    "compile",
                    &["--offline", "--no-daemon", "build", "-x", "test"][..],
                ),
                ("test", &["--offline", "--no-daemon", "test"][..]),
            ] {
                defer(
                    plan,
                    entries,
                    &[
                        "build.gradle",
                        "build.gradle.kts",
                        "settings.gradle",
                        "settings.gradle.kts",
                    ],
                    &["gradle"],
                    tool,
                    args,
                );
            }
            for (tool, args) in [
                (
                    "compile",
                    &["--offline", "--batch-mode", "-DskipTests", "verify"][..],
                ),
                ("test", &["--offline", "--batch-mode", "test"][..]),
            ] {
                defer(plan, entries, &["pom.xml"], &["mvn"], tool, args);
            }
        }
        "code.dotnet" => {
            // Restore is deliberately not attempted: it can acquire dependencies.
            plan.not_planned
                .insert("restore", "policy-no-dependency-install");
            let dirs = cap_roots(
                entries
                    .iter()
                    .filter(|e| {
                        [".csproj", ".fsproj", ".vbproj", ".sln"]
                            .iter()
                            .any(|suffix| e.path.ends_with(suffix))
                    })
                    .map(|e| dir_of(&e.path))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                "dotnet",
                &mut plan.notes,
            );
            for dir in dirs {
                for tool in ["build", "test"] {
                    plan.deferred.push(command(
                        tool,
                        &["dotnet"],
                        &dir,
                        vec![tool.into(), "--no-restore".into(), "--nologo".into()],
                    ));
                }
            }
        }
        "code.c-family" => {
            // Both configuration & make -n may execute project code.
            for dir in cap_roots(
                dirs_named(entries, &["CMakeLists.txt"])
                    .into_iter()
                    .collect(),
                "cmake",
                &mut plan.notes,
            ) {
                let target = scratch
                    .cache_dir()
                    .join(format!("cmake-{}", plan.deferred.len()))
                    .to_string_lossy()
                    .into_owned();
                plan.deferred.push(command(
                    "compiler",
                    &["cmake"],
                    &dir,
                    vec!["-S".into(), ".".into(), "-B".into(), target.clone()],
                ));
                plan.deferred.push(command(
                    "compiler",
                    &["cmake"],
                    &dir,
                    vec!["--build".into(), target],
                ));
            }
            defer(
                plan,
                entries,
                &["Makefile", "makefile", "GNUmakefile"],
                &["make"],
                "compiler",
                &["-n"],
            );
        }
        "code.php-ruby" => {
            // Composer may activate project plugins even for validate.
            defer(
                plan,
                entries,
                &["composer.json"],
                &["composer"],
                "package",
                &[
                    "--no-plugins",
                    "--no-scripts",
                    "validate",
                    "--no-check-publish",
                ],
            );
            defer(
                plan,
                entries,
                &["Gemfile", "Rakefile"],
                &["bundle"],
                "test",
                &["exec", "rake", "test"],
            );
        }
        "code.long-tail" => {
            defer(
                plan,
                entries,
                &["pubspec.yaml"],
                &["dart"],
                "dart-analyze",
                &["analyze", "--no-fatal-infos"],
            );
            defer(
                plan,
                entries,
                &["pubspec.yaml"],
                &["dart"],
                "dart-test",
                &["test"],
            );
            defer(
                plan,
                entries,
                &["mix.exs"],
                &["mix"],
                "elixir-compile",
                &["compile", "--no-deps-check"],
            );
            defer(
                plan,
                entries,
                &["mix.exs"],
                &["mix"],
                "elixir-test",
                &["test", "--no-deps-check"],
            );
            defer(
                plan,
                entries,
                &["rebar.config"],
                &["rebar3"],
                "erlang-test",
                &["eunit"],
            );
        }
        _ => {}
    }
    syntax(provider, root, entries, selected, scratch, plan);
}

fn syntax(
    provider: &str,
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    if !matches!(provider, "code.php-ruby" | "code.long-tail") {
        return;
    }
    let mut count = 0;
    let mut bytes = 0;
    for entry in entries
        .iter()
        .filter(|entry| selected.contains(&entry.path))
    {
        let extension = entry
            .path
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let (tool, programs): (&'static str, &'static [&'static str]) = match extension.as_str() {
            "php" => ("lint", &["php"]),
            "rb" => ("ruby-syntax", &["ruby"]),
            "sh" | "bash" => ("shell-syntax", &["bash"]),
            "zsh" => ("zsh-syntax", &["zsh"]),
            "ps1" | "psm1" => ("powershell-syntax", &["pwsh", "powershell"]),
            _ => continue,
        };
        if count >= MAX_SYNTAX_FILES || bytes >= MAX_SYNTAX_BYTES {
            plan.notes
                .push(format!("syntax-input-budget:{tool}:{}", entry.path));
            plan.not_planned.insert(tool, "syntax-input-budget");
            continue;
        }
        let Some(source) = super::super::evidence::syntax_source(root, entry) else {
            plan.notes
                .push(format!("syntax-input-unreadable:{tool}:{}", entry.path));
            plan.not_planned.insert(tool, "syntax-input-unreadable");
            continue;
        };
        bytes += source.len();
        if bytes > MAX_SYNTAX_BYTES {
            plan.notes
                .push(format!("syntax-input-budget:{tool}:{}", entry.path));
            plan.not_planned.insert(tool, "syntax-input-budget");
            continue;
        }
        let staged = scratch
            .tmp_dir()
            .join(format!("native-syntax-{count}.{extension}"));
        count += 1;
        let source_digest = sha256_text(source.as_bytes());
        if std::fs::write(&staged, source).is_err() {
            plan.not_planned.insert(tool, "scratch-unwritable");
            continue;
        }
        let staged_arg = staged.to_string_lossy().into_owned();
        let mut item = command(tool, programs, "", Vec::new());
        item.source_path = Some(entry.path.clone());
        item.source_digest = Some(source_digest);
        item.args = match extension.as_str() {
            "php" => vec!["-n".into(), "-l".into(), staged_arg],
            // Ripper parses without evaluating BEGIN blocks or project code.
            "rb" => vec!["--disable-gems".into(), "-rripper".into(), "-e".into(), "unless Ripper.sexp(File.read(ARGV.fetch(0))); STDERR.puts 'Ruby syntax error'; exit 1; end; puts 'Syntax OK'".into(), staged_arg],
            "zsh" => vec!["-f".into(), "-n".into(), staged_arg],
            "ps1" | "psm1" => {
                item.env.push(("LEGION_AUDIT_SYNTAX_SOURCE", staged_arg));
                vec!["-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:LEGION_AUDIT_SYNTAX_SOURCE,[ref]$t,[ref]$e); if ($e.Count) { [Console]::Error.WriteLine(($e | ForEach-Object { $_.Message }) -join [Environment]::NewLine); exit 1 }; exit 0".into()]
            }
            _ => vec!["--noprofile".into(), "--norc".into(), "-n".into(), staged_arg],
        };
        plan.cleanup.push(staged);
        plan.commands.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> InventoryEntry {
        InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: false,
            digest: None,
        }
    }

    fn fixture() -> (PathBuf, AuditScratch) {
        let root = std::env::temp_dir().join(format!(
            "native-command-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let scratch = AuditScratch::create(&root).unwrap();
        (root, scratch)
    }

    #[test]
    fn native_manifest_contracts_never_enter_executable_plan() {
        let (root, scratch) = fixture();
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("code.go", &["go.mod"], &["go"]),
            ("code.mobile", &["Package.swift"], &["swift"]),
            (
                "code.jvm",
                &["build.gradle.kts", "pom.xml"],
                &["gradle", "mvn"],
            ),
            ("code.dotnet", &["App.csproj"], &["dotnet"]),
            (
                "code.c-family",
                &["CMakeLists.txt", "Makefile"],
                &["cmake", "make"],
            ),
            (
                "code.php-ruby",
                &["composer.json", "Gemfile"],
                &["composer", "bundle"],
            ),
            (
                "code.long-tail",
                &["pubspec.yaml", "mix.exs", "rebar.config"],
                &["dart", "mix", "rebar3"],
            ),
        ];
        for (provider, manifests, programs) in cases {
            let entries = manifests.iter().map(|path| entry(path)).collect::<Vec<_>>();
            let mut planned = Plan::default();
            plan(
                provider,
                &root,
                &entries,
                &BTreeSet::new(),
                &scratch,
                &mut planned,
            );
            assert!(
                planned.commands.is_empty(),
                "{provider} must not execute project code"
            );
            for program in *programs {
                assert!(
                    planned
                        .deferred
                        .iter()
                        .any(|item| item.programs.contains(program)),
                    "missing {program} contract"
                );
            }
            assert!(planned
                .deferred
                .iter()
                .all(|item| !item.args.iter().any(|arg| arg == "--disable-sandbox")));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn syntax_adapters_parse_isolated_snapshots_without_loading_project_config() {
        let (root, scratch) = fixture();
        let paths = [
            "app.php", "app.rb", "app.sh", "app.bash", "app.zsh", "app.ps1", "app.psm1",
        ];
        let entries = paths
            .iter()
            .map(|path| {
                std::fs::write(root.join(path), "# source fixture\n").unwrap();
                entry(path)
            })
            .collect::<Vec<_>>();
        let mut planned = Plan::default();
        let selected = paths.iter().map(|path| (*path).into()).collect();
        syntax(
            "code.long-tail",
            &root,
            &entries,
            &selected,
            &scratch,
            &mut planned,
        );
        assert_eq!(planned.commands.len(), paths.len());
        assert!(planned
            .commands
            .iter()
            .all(|item| item.source_path.is_some() && item.parser == Parser::Syntax));
        assert!(planned
            .commands
            .iter()
            .find(|item| item.tool == "lint")
            .unwrap()
            .args
            .starts_with(&["-n".into(), "-l".into()]));
        let ruby = planned
            .commands
            .iter()
            .find(|item| item.tool == "ruby-syntax")
            .unwrap();
        assert!(ruby.args.iter().any(|arg| arg.contains("Ripper.sexp")));
        let powershell = planned
            .commands
            .iter()
            .find(|item| item.tool == "powershell-syntax")
            .unwrap();
        assert!(powershell.args.contains(&"-NoProfile".into()));
        assert!(powershell
            .env
            .iter()
            .any(|(key, value)| *key == "LEGION_AUDIT_SYNTAX_SOURCE"
                && Path::new(value).starts_with(scratch.tmp_dir())));
        for staged in &planned.cleanup {
            assert!(staged.starts_with(scratch.tmp_dir()));
            assert_eq!(
                std::fs::read_to_string(staged).unwrap(),
                "# source fixture\n"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn syntax_staging_rejects_symlinked_source_ancestors() {
        let (root, scratch) = fixture();
        let outside = scratch.tmp_dir().join("external");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("bad.sh"), "echo not audited\n").unwrap();
        std::os::unix::fs::symlink(outside, root.join("link")).unwrap();
        let mut planned = Plan::default();
        syntax(
            "code.long-tail",
            &root,
            &[entry("link/bad.sh")],
            &BTreeSet::from(["link/bad.sh".into()]),
            &scratch,
            &mut planned,
        );
        assert!(planned.commands.is_empty());
        assert_eq!(
            planned.not_planned.get("shell-syntax"),
            Some(&"syntax-input-unreadable")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
