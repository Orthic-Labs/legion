//! Single trusted launcher for every audit-owned `git` process.
//!
//! The audited repository is attacker-controlled: it can ship a `git` binary
//! (or script) in the tree, on a relative PATH entry, or rely on repository
//! config (`core.fsmonitor`, hooks, external diff/textconv, pager). Every audit
//! git launch therefore uses an absolute git resolved from fixed system
//! locations outside the audited root, a cleared environment, and explicit
//! denial of config-driven execution. When no trusted git exists callers fail
//! closed exactly as they do when git is unavailable.

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const ENV_ALLOWLIST: [&str; 4] = ["SystemRoot", "TEMP", "TMP", "TMPDIR"];

fn null_path() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

/// Absolute, trusted `git`: resolved once from fixed system locations, never
/// from the audited tree. Only when none exists are absolute PATH entries
/// considered, and any candidate inside the audited root (or a relative PATH
/// entry such as `.`) is rejected.
pub(crate) fn trusted_git_path(root: &Path) -> Option<PathBuf> {
    static FIXED: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    if let Some(found) = FIXED.get_or_init(|| {
        let candidates: &[&str] = if cfg!(windows) {
            &[
                "C:\\Program Files\\Git\\cmd\\git.exe",
                "C:\\Program Files (x86)\\Git\\cmd\\git.exe",
            ]
        } else {
            &[
                "/usr/bin/git",
                "/opt/homebrew/bin/git",
                "/usr/local/bin/git",
                "/bin/git",
            ]
        };
        candidates
            .iter()
            .map(PathBuf::from)
            .find_map(|path| std::fs::canonicalize(path).ok().filter(|p| p.is_file()))
    }) {
        return Some(found.clone());
    }
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let name = if cfg!(windows) { "git.exe" } else { "git" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .filter(|dir| dir.is_absolute())
        .filter_map(|dir| std::fs::canonicalize(dir.join(name)).ok())
        .find(|path| {
            path.is_file() && !path.starts_with(&canonical_root) && !path.starts_with(root)
        })
}

/// Absolute, trusted helper tool (for example `gh`) by bare name: fixed system
/// locations first, then absolute PATH entries; anything inside the audited
/// root or on a relative PATH entry (such as `.`) is never executed. `None`
/// when no trusted binary exists (callers fail closed).
pub(crate) fn trusted_tool_path(root: &Path, name: &str) -> Option<PathBuf> {
    trusted_tool_path_in(root, name, std::env::var_os("PATH"))
}

/// `trusted_tool_path` with an explicit PATH value (tests pass a hostile PATH
/// without mutating process state).
fn trusted_tool_path_in(
    root: &Path,
    name: &str,
    path_var: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return None;
    }
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let outside = |path: &Path| !path.starts_with(&canonical_root) && !path.starts_with(root);
    let fixed: &[&str] = if cfg!(windows) {
        &[
            "C:\\Program Files\\GitHub CLI",
            "C:\\Program Files (x86)\\GitHub CLI",
        ]
    } else {
        &["/usr/bin", "/opt/homebrew/bin", "/usr/local/bin", "/bin"]
    };
    if let Some(found) = fixed
        .iter()
        .filter_map(|dir| std::fs::canonicalize(Path::new(dir).join(&file)).ok())
        .find(|path| path.is_file() && outside(path))
    {
        return Some(found);
    }
    std::env::split_paths(&path_var?)
        .filter(|dir| dir.is_absolute())
        .filter_map(|dir| std::fs::canonicalize(dir.join(&file)).ok())
        .find(|path| path.is_file() && outside(path))
}

/// RightKit-owned command for a trusted helper tool: absolute binary outside the
/// audited root, environment cleared down to `env_allowlist` (plus a PATH made
/// only of the trusted tool's and trusted git's directories), no prompts.
pub(crate) fn owned_tool_command(
    root: &Path,
    name: &str,
    env_allowlist: &[&str],
) -> Option<rightkit_child_process::OwnedCommand> {
    let tool = trusted_tool_path(root, name)?;
    let mut command = rightkit_child_process::OwnedCommand::new(&tool);
    command.env_allowlist(env_allowlist.iter().copied());
    command.windows_hide();
    let mut dirs: Vec<PathBuf> = tool.parent().map(Path::to_path_buf).into_iter().collect();
    if let Some(dir) = trusted_git_path(root).and_then(|git| git.parent().map(Path::to_path_buf)) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    if let Ok(path) = std::env::join_paths(dirs) {
        command.command_mut().env("PATH", path);
    }
    command
        .command_mut()
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_PAGER", "cat")
        .env("NO_COLOR", "1");
    Some(command)
}

fn base_harden(command: &mut std::process::Command) {
    let null = null_path();
    command
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["--no-optional-locks", "-c", "core.fsmonitor=false", "-c"])
        .arg(format!("core.hooksPath={null}"))
        .args(["-c"])
        .arg(format!("core.attributesFile={null}"))
        .args([
            "-c",
            "core.pager=cat",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "gc.auto=0",
            "-c",
            "diff.external=",
            "-c",
            "core.quotePath=false",
            "-c",
            "core.sshCommand=",
            "-c",
            "core.askPass=",
            "-c",
            "core.gitProxy=",
            "-c",
            "credential.helper=",
            "-c",
            "uploadpack.packObjectsHook=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.ext.allow=never",
            // Never descend into submodules: their own configs (filters,
            // drivers) are not enumerated or neutralized below.
            "-c",
            "submodule.recurse=false",
            "-c",
            "diff.ignoreSubmodules=all",
            "-c",
            "status.submoduleSummary=false",
            // Signature verification runs external programs on read paths
            // (`git log` with `log.showSignature`): keep them inert.
            "-c",
            "log.showSignature=false",
            "-c",
            "gpg.program=",
            "-c",
            "gpg.ssh.program=",
            "-c",
            "gpg.x509.program=",
            "-c",
            "gpg.ssh.allowedSignersFile=",
            "-c",
            "core.alternateRefsCommand=",
            "-c",
            "core.alternateRefsPrefixes=",
        ]);
}

/// Configuration keys naming repository-configured drivers that git would
/// execute (`filter.<n>.*`, `diff.<n>.*`, `merge.<n>.*`), enumerated without
/// executing anything: `git config --list` follows includes and reads only
/// config files. Returns `-c key=` overrides; `None` (fail closed) when the
/// enumeration cannot be trusted.
fn driver_overrides(git: &Path, root: &Path) -> Option<Vec<String>> {
    let mut list = std::process::Command::new(git);
    list.env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            list.env(key, value);
        }
    }
    base_harden(&mut list);
    let output = list
        .args(["config", "--null", "--list"])
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut overrides = std::collections::BTreeSet::new();
    for entry in output.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let key_bytes = entry.split(|b| *b == b'\n').next()?;
        let key = std::str::from_utf8(key_bytes).ok()?;
        let Some((section, rest)) = key.split_once('.') else {
            continue;
        };
        let section = section.to_ascii_lowercase();
        if !matches!(section.as_str(), "filter" | "diff" | "merge") {
            continue;
        }
        let Some((name, _var)) = rest.rsplit_once('.') else {
            continue;
        };
        if name.is_empty() || name.contains(['=', '\n', '\0']) {
            return None;
        }
        let vars: &[&str] = match section.as_str() {
            "filter" => &["clean", "smudge", "process"],
            "diff" => &["textconv", "command"],
            _ => &["driver"],
        };
        for var in vars {
            overrides.insert(format!("{section}.{name}.{var}="));
        }
        if section == "filter" {
            overrides.insert(format!("filter.{name}.required=false"));
        }
    }
    Some(overrides.into_iter().collect())
}

fn harden(command: &mut std::process::Command, git: &Path, root: &Path) -> Option<()> {
    base_harden(command);
    for item in driver_overrides(git, root)? {
        command.arg("-c").arg(item);
    }
    Some(())
}

/// A RightKit-owned git command: absolute trusted binary, scrubbed environment,
/// hardened config prefix. Callers append their own args, cwd and stdio.
/// `None` when no trusted git exists or config cannot be enumerated (fail closed).
pub(crate) fn owned_command(root: &Path) -> Option<rightkit_child_process::OwnedCommand> {
    let git = trusted_git_path(root)?;
    let mut command = rightkit_child_process::OwnedCommand::new(&git);
    command.env_allowlist(ENV_ALLOWLIST);
    command.windows_hide();
    harden(command.command_mut(), &git, root)?;
    Some(command)
}

/// Plain `std::process::Command` variant for call sites that own their own
/// process supervision. Environment is cleared down to OS essentials.
pub(crate) fn std_command(root: &Path) -> Option<std::process::Command> {
    let git = trusted_git_path(root)?;
    let mut command = std::process::Command::new(&git);
    command.env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    harden(&mut command, &git, root)?;
    Some(command)
}

/// Run trusted git in `root` with a deadline and bounded stdout. `None` on
/// unavailable git, spawn failure, timeout, non-zero exit or oversized output.
pub(crate) fn run_stdout(
    root: &Path,
    args: &[&str],
    timeout: Duration,
    max_output: u64,
) -> Option<Vec<u8>> {
    let mut command = owned_command(root)?;
    command
        .command_mut()
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().ok()?;
    let mut stdout = child.take_stdout()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let result = (&mut stdout).take(max_output + 1).read_to_end(&mut kept);
        let _ = tx.send((result.is_ok() && kept.len() as u64 <= max_output, kept));
    });
    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        _ => {
            // Timeout or wait failure: kill the whole child tree.
            let _ = child.terminate_tree_bounded(Duration::from_secs(2));
            return None;
        }
    };
    let (complete, stdout) = rx.recv_timeout(Duration::from_secs(5)).ok()?;
    if !status.success() || !complete {
        return None;
    }
    Some(stdout)
}

#[cfg(all(test, unix))]
mod tool_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn repo_local_fake_tool_on_path_is_never_resolved_or_executed() {
        static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("legion-fake-gh-{}", std::process::id()));
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let marker = root.join("EXECUTED");
        for name in ["gh", "legionfaketool"] {
            let script = bin.join(name);
            std::fs::write(
                &script,
                format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var_os("PATH");
        let mut entries = vec![bin.clone(), PathBuf::from("bin"), PathBuf::from(".")];
        if let Some(saved) = &saved {
            entries.extend(std::env::split_paths(saved));
        }
        let poisoned = std::env::join_paths(entries).unwrap();
        let gh = trusted_tool_path_in(&root, "gh", Some(poisoned.clone()));
        let fake = trusted_tool_path_in(&root, "legionfaketool", Some(poisoned));
        assert!(gh.is_none_or(|path| !path.starts_with(&root)));
        assert!(fake.is_none(), "repo-local tool must not resolve");
        assert!(trusted_tool_path(&root, "../gh").is_none());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(all(test, unix))]
mod exploit_tests {
    //! Regression tests for repository-configured execution reproduced by the
    //! adversarial review: submodule filter drivers and signature programs.
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn system_git() -> PathBuf {
        [
            "/usr/bin/git",
            "/opt/homebrew/bin/git",
            "/usr/local/bin/git",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("system git for fixtures")
    }

    fn setup_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new(system_git())
            .args(["-c", "protocol.file.allow=always"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .expect("fixture git");
        assert!(status.success(), "fixture git {args:?}");
    }

    fn scratch(tag: &str) -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir =
            std::env::temp_dir().join(format!("legion-git-exploit-{tag}-{}", hex::encode(nonce)));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn marker_script(dir: &Path, marker: &Path) -> PathBuf {
        let script = dir.join("payload.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[test]
    fn submodule_filter_driver_never_runs() {
        let base = scratch("submodule");
        let marker = base.join("PWNED");
        let script = marker_script(&base, &marker);
        let sub_src = base.join("sub-src");
        std::fs::create_dir_all(&sub_src).unwrap();
        setup_git(&sub_src, &["init", "-q"]);
        std::fs::write(sub_src.join("a.txt"), b"a\n").unwrap();
        setup_git(&sub_src, &["add", "."]);
        setup_git(&sub_src, &["commit", "-qm", "s"]);
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        setup_git(&repo, &["init", "-q"]);
        setup_git(
            &repo,
            &["submodule", "add", "-q", sub_src.to_str().unwrap(), "s"],
        );
        setup_git(&repo, &["commit", "-qm", "with submodule"]);
        let sub_config = repo.join(".git/modules/s/config");
        let mut config = std::fs::read_to_string(&sub_config).unwrap();
        config.push_str(&format!(
            "[filter \"evil\"]\n\tclean = {}\n",
            script.display()
        ));
        std::fs::write(&sub_config, config).unwrap();
        std::fs::write(repo.join("s/.gitattributes"), b"* filter=evil\n").unwrap();
        std::fs::write(repo.join("s/a.txt"), b"changed\n").unwrap();
        let _ = run_stdout(
            &repo,
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
            ],
            Duration::from_secs(30),
            1 << 20,
        );
        let _ = run_stdout(
            &repo,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=all",
            ],
            Duration::from_secs(30),
            1 << 20,
        );
        assert!(!marker.exists(), "submodule filter driver executed");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn signature_program_never_runs_on_log() {
        let base = scratch("gpg");
        let marker = base.join("PWNED");
        let script = marker_script(&base, &marker);
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        setup_git(&repo, &["init", "-q"]);
        std::fs::write(repo.join("a.txt"), b"a\n").unwrap();
        setup_git(&repo, &["add", "."]);
        setup_git(&repo, &["commit", "-qm", "base"]);
        // Hand-written signed commit on top of HEAD.
        let out = std::process::Command::new(system_git())
            .args(["cat-file", "commit", "HEAD"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let body = String::from_utf8(out.stdout).unwrap();
        let (headers, message) = body.split_once("\n\n").unwrap();
        let signed = format!(
            "{headers}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n =AAAA\n -----END PGP SIGNATURE-----\n\n{message}"
        );
        let object = base.join("commit.txt");
        std::fs::write(&object, signed).unwrap();
        let hashed = std::process::Command::new(system_git())
            .args(["hash-object", "-t", "commit", "-w"])
            .arg(&object)
            .current_dir(&repo)
            .output()
            .unwrap();
        let oid = String::from_utf8(hashed.stdout).unwrap().trim().to_owned();
        setup_git(&repo, &["update-ref", "HEAD", &oid]);
        setup_git(&repo, &["config", "log.showSignature", "true"]);
        setup_git(&repo, &["config", "gpg.program", script.to_str().unwrap()]);
        let _ = run_stdout(
            &repo,
            &["log", "--numstat", "--format=%H", "-n", "5"],
            Duration::from_secs(30),
            1 << 20,
        );
        assert!(!marker.exists(), "signature program executed");
        let _ = std::fs::remove_dir_all(&base);
    }
}
