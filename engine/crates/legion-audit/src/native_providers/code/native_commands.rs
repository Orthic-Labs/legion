//! Native-family applicability & isolated syntax adapters. Project commands
//! use enrolled offline SDK plans where supported, through the existing
//! policy-bound runner. Plans never substitute for actual execution receipts.
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
            super::dotnet_sdk::plan(root, entries, scratch, plan);
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
    if provider != "code.long-tail" {
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
