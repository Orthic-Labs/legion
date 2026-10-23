//! Audit-owned git launches never execute a repo-controlled or PATH-injected
//! `git`, and ignore environment-injected git configuration.
#![cfg(unix)]

use legion_audit::{
    scope::{ResolvedScope, ScopeSpec},
    snapshot::FrozenSnapshot,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

/// Tests mutate process-wide PATH/GIT_* env; serialize them so fixture setup in
/// one test never observes another test's hostile environment.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn test_git() -> &'static str {
    [
        "/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ]
    .into_iter()
    .find(|p| Path::new(p).is_file())
    .expect("system git for fixtures")
}

fn real_git(root: &Path, args: &[&str]) {
    let status = Command::new(test_git())
        .env_remove("GIT_DIR")
        .env_remove("GIT_CONFIG_COUNT")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .expect("git available for fixture");
    assert!(status.success(), "git {args:?}");
}

fn script(path: &Path, marker: &Path) {
    fs::write(
        path,
        format!(
            "#!/bin/sh\necho executed >> '{}'\nexit 1\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn snapshot_capture_never_executes_fake_git_or_injected_config() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "legion-trusted-git-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let marker = base.join("marker");
    real_git(&repo, &["init", "-q"]);
    real_git(&repo, &["config", "user.name", "Audit Test"]);
    real_git(&repo, &["config", "user.email", "audit@example.invalid"]);
    fs::write(repo.join("file.rs"), b"base\n").unwrap();
    real_git(&repo, &["add", "."]);
    real_git(&repo, &["commit", "-qm", "base"]);
    fs::write(repo.join("file.rs"), b"changed\n").unwrap();

    // Repo-controlled `git` and a hostile relative/absolute PATH.
    script(&repo.join("git"), &marker);
    let evil_bin = base.join("bin");
    fs::create_dir_all(&evil_bin).unwrap();
    script(&evil_bin.join("git"), &marker);
    let fsmonitor = base.join("fsmonitor.sh");
    script(&fsmonitor, &marker);
    // Repository config execution vector.
    real_git(
        &repo,
        &["config", "core.fsmonitor", fsmonitor.to_str().unwrap()],
    );

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path = std::ffi::OsString::new();
    path.push(&evil_bin);
    path.push(":");
    path.push(&repo);
    path.push(":.:");
    path.push(&original_path);
    std::env::set_var("PATH", &path);
    // Environment injection: bogus GIT_DIR and config-count fsmonitor.
    std::env::set_var("GIT_DIR", base.join("does-not-exist"));
    std::env::set_var("GIT_CONFIG_COUNT", "1");
    std::env::set_var("GIT_CONFIG_KEY_0", "core.fsmonitor");
    std::env::set_var("GIT_CONFIG_VALUE_0", &fsmonitor);

    let result =
        ResolvedScope::resolve(&repo, ScopeSpec::Local, None).and_then(FrozenSnapshot::capture);

    std::env::set_var("PATH", &original_path);
    std::env::remove_var("GIT_DIR");
    std::env::remove_var("GIT_CONFIG_COUNT");
    std::env::remove_var("GIT_CONFIG_KEY_0");
    std::env::remove_var("GIT_CONFIG_VALUE_0");

    let executed = marker.exists();
    let _ = fs::remove_dir_all(&base);
    assert!(!executed, "an attacker-controlled git or hook was executed");
    result.expect("snapshot capture ignores injected environment");
}

#[test]
fn repository_filter_drivers_are_never_executed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "legion-trusted-git-filters-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    let marker = base.join("marker");
    let driver = base.join("driver.sh");
    script(&driver, &marker);
    real_git(&repo, &["init", "-q"]);
    real_git(&repo, &["config", "user.name", "Audit Test"]);
    real_git(&repo, &["config", "user.email", "audit@example.invalid"]);
    fs::write(
        repo.join(".gitattributes"),
        "*.rs filter=x\n*.txt filter=p diff=t\n*.md filter=inc\n",
    )
    .unwrap();
    for name in ["a.rs", "b.txt", "c.md"] {
        fs::write(repo.join(name), b"base\n").unwrap();
    }
    real_git(&repo, &["add", "."]);
    real_git(&repo, &["commit", "-qm", "base"]);
    let d = driver.to_str().unwrap();
    let included = base.join("included.cfg");
    fs::write(
        &included,
        format!("[filter \"inc\"]\n\tclean = {d}\n\tsmudge = {d}\n"),
    )
    .unwrap();
    real_git(&repo, &["config", "filter.x.clean", d]);
    real_git(&repo, &["config", "filter.x.smudge", d]);
    real_git(&repo, &["config", "filter.p.process", d]);
    real_git(&repo, &["config", "diff.t.textconv", d]);
    real_git(
        &repo,
        &["config", "include.path", included.to_str().unwrap()],
    );
    for name in ["a.rs", "b.txt", "c.md"] {
        fs::write(repo.join(name), b"changed content\n").unwrap();
    }

    let result =
        ResolvedScope::resolve(&repo, ScopeSpec::Local, None).and_then(FrozenSnapshot::capture);

    let executed = marker.exists();
    let _ = fs::remove_dir_all(&base);
    assert!(
        !executed,
        "a repository filter/textconv driver was executed"
    );
    let _ = result;
}
