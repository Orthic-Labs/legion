//! Execution-boundary regressions (review finding 4): the `--claude` host
//! executable, no-node-python closure enforcement at process admission, and
//! the inventory `git` launch. Authored for root verification.
#![cfg(unix)]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use legion_audit::{
    execution_policy::OWNER_POLICY_ID,
    owner_admission::{
        OwnerBackedPolicy, OwnerGrant, OwnerIdentity, OwnerPolicyConfig, OwnerProvenance,
        OwnerQuery, OwnerVerdict, TrustedOwner,
    },
    profiles::RuntimeConstraint,
    review_runtime::{probe_host_executable, validate_host_executable, RuntimeOptions},
    FilesystemInventorySource, InventorySource,
};
use legion_effects::{owner_process::InvocationClass, ExternalToolRequest, PolicyAuthorizer};
use sha2::{Digest, Sha256};

static SEQ: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn scratch(label: &str) -> PathBuf {
    let dir = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "legion-runtime-boundary-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn marker_script(marker: &Path) -> Vec<u8> {
    format!("#!/bin/sh\ntouch '{}'\necho --help\n", marker.display()).into_bytes()
}

// ---- --claude host executable ------------------------------------------------

#[test]
fn shebang_script_as_claude_never_runs() {
    let dir = scratch("script");
    let marker = dir.join("marker");
    let claude = dir.join("claude");
    executable(&claude, &marker_script(&marker));
    let cwd = dir.join("cwd");
    fs::create_dir_all(&cwd).unwrap();
    let options = RuntimeOptions {
        claude: Some(claude.clone()),
        ..Default::default()
    };
    let error = probe_host_executable(&options, &cwd, &[]).unwrap_err();
    assert!(error.to_string().contains("script"), "{error}");
    assert!(!marker.exists(), "script was executed by the probe");
    let error = validate_host_executable(&claude, &[]).unwrap_err();
    assert!(error.to_string().contains("script"), "{error}");
    assert!(!marker.exists());
    // An interpreter-less non-native file is refused as well.
    executable(&claude, b"not a native executable\n");
    assert!(validate_host_executable(&claude, &[]).is_err());
}

#[test]
fn claude_inside_audited_root_is_rejected_before_spawn() {
    let root = scratch("audited");
    let marker = root.join("marker");
    let claude = root.join("claude");
    // Native-looking header with a sh payload that would drop the marker if run.
    let mut bytes = vec![0x7f, b'E', b'L', b'F'];
    bytes.extend_from_slice(&marker_script(&marker));
    executable(&claude, &bytes);
    let options = RuntimeOptions {
        claude: Some(claude.clone()),
        ..Default::default()
    };
    let cwd = scratch("audited-cwd");
    let error = probe_host_executable(&options, &cwd, &[root.clone()]).unwrap_err();
    assert!(error.to_string().contains("audited source"), "{error}");
    assert!(!marker.exists());
    // A symlink outside the root that resolves into it is rejected too.
    let outside = scratch("audited-link");
    let link = outside.join("claude");
    symlink(&claude, &link).unwrap();
    let error = validate_host_executable(&link, &[root.clone()]).unwrap_err();
    assert!(error.to_string().contains("audited source"), "{error}");
    assert!(!marker.exists());
}

#[test]
fn claude_in_temp_dir_or_directory_is_rejected() {
    let dir = scratch("temp");
    let claude = dir.join("claude");
    let mut bytes = vec![0x7f, b'E', b'L', b'F'];
    bytes.extend_from_slice(&[0; 32]);
    executable(&claude, &bytes);
    let error = validate_host_executable(&claude, &[]).unwrap_err();
    assert!(error.to_string().contains("temp"), "{error}");
    assert!(validate_host_executable(&dir, &[]).is_err());
}

fn elf_bytes() -> Vec<u8> {
    let mut bytes = vec![0x7f, b'E', b'L', b'F'];
    bytes.extend_from_slice(&[0; 32]);
    bytes
}

#[test]
fn claude_that_is_a_node_or_python_runtime_is_rejected_before_spawn() {
    // Well-known interpreter path: rejected by name, never opened or run.
    let error = validate_host_executable(Path::new("/usr/bin/python3"), &[]).unwrap_err();
    assert!(error.to_string().contains("no-node-python"), "{error}");
    // A symlink named `claude` pointing at a node-named binary.
    let dir = scratch("node-link");
    let marker = dir.join("marker");
    let node = dir.join("node");
    let mut bytes = elf_bytes();
    bytes.extend_from_slice(format!("touch {}", marker.display()).as_bytes());
    executable(&node, &bytes);
    let link = dir.join("claude");
    symlink(&node, &link).unwrap();
    let error = validate_host_executable(&link, &[]).unwrap_err();
    assert!(error.to_string().contains("no-node-python"), "{error}");
    // Version-suffixed and multi-hop names.
    let hop = dir.join("hop");
    symlink(dir.join("python3.12"), &hop).unwrap();
    let outer = dir.join("claude2");
    symlink(&hop, &outer).unwrap();
    assert!(validate_host_executable(&outer, &[])
        .unwrap_err()
        .to_string()
        .contains("no-node-python"));
    let options = RuntimeOptions {
        claude: Some(link),
        ..RuntimeOptions::default()
    };
    let _ = probe_host_executable(&options, &dir, &[]);
    assert!(!marker.exists(), "rejected runtime was spawned");
}

// ---- no-node-python closure at process admission ----------------------------

const PROVIDER: &str = "legacy.quality.lint";
const PLAN: &str = "frozen-plan";
const CONTAINMENT: &str = "owner-containment-1";
const NOW: u64 = 1_000_000;

struct Echo;
impl TrustedOwner for Echo {
    fn identity(&self) -> OwnerIdentity {
        OwnerIdentity {
            owner_id: "test-owner".into(),
            version: "1".into(),
            provenance: OwnerProvenance::Verified {
                key_id: "a".repeat(64),
                receipt_digest: "sha256:r".into(),
            },
        }
    }
    fn admit(&self, query: &OwnerQuery<'_>) -> OwnerVerdict {
        OwnerVerdict::Granted(OwnerGrant {
            owner_id: "test-owner".into(),
            binding_digest: query.binding_digest.into(),
            policy_revision: query.binding.policy_revision.clone(),
            nonce: format!("n-{}", SEQ.fetch_add(1, Ordering::Relaxed)),
            expires_at_ms: NOW + 1000,
        })
    }
}

fn clock() -> u64 {
    NOW
}

struct Admission {
    frozen: PathBuf,
    output: PathBuf,
    tools: PathBuf,
}

fn admission_fixture() -> Admission {
    let base = scratch("admission");
    let (frozen, output, tools) = (base.join("frozen"), base.join("out"), base.join("tools"));
    for dir in [&frozen, &output, &tools] {
        fs::create_dir_all(dir).unwrap();
    }
    Admission {
        frozen,
        output,
        tools,
    }
}

fn policy(f: &Admission, constraint: Option<RuntimeConstraint>) -> OwnerBackedPolicy {
    let mut config = OwnerPolicyConfig::new(
        "rev-1",
        PLAN,
        CONTAINMENT,
        &[f.frozen.clone()],
        &f.output,
        BTreeMap::from([(PROVIDER.to_string(), InvocationClass::ReadOnlyStatic)]),
        BTreeSet::from(["HOME".to_string()]),
        120_000,
        8 * 1024 * 1024,
    )
    .unwrap();
    if let Some(constraint) = constraint {
        config = config.with_runtime_constraint(constraint);
    }
    OwnerBackedPolicy::new(Arc::new(Echo), config)
        .unwrap()
        .with_clock(clock)
}

fn request(
    f: &Admission,
    policy: &OwnerBackedPolicy,
    tool: &Path,
    bytes: &[u8],
    args: &[&str],
) -> ExternalToolRequest {
    ExternalToolRequest {
        request_id: format!("req-{}", SEQ.fetch_add(1, Ordering::Relaxed)),
        provider_id: PROVIDER.into(),
        plan_id: PLAN.into(),
        policy_id: OWNER_POLICY_ID.into(),
        task_id: Some("task-1".into()),
        executable: tool.to_string_lossy().into_owned(),
        args: args.iter().map(|arg| arg.to_string()).collect(),
        cwd: f.frozen.to_string_lossy().into_owned(),
        expected_digest: Some(format!(
            "sha256:{}",
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )),
        skip_version_probe: true,
        requires_network_sandbox: true,
        sandbox: Some(
            policy
                .config()
                .containment_profile(
                    "test-owner",
                    InvocationClass::ReadOnlyStatic,
                    [tool.to_path_buf()].into(),
                )
                .sandbox_receipt(),
        ),
        ..ExternalToolRequest::default()
    }
}

fn denied(decision: &legion_effects::PolicyDecision, code: &str) {
    assert!(!decision.allowed, "expected denial {code}: {decision:?}");
    assert_eq!(
        decision.reason.as_deref(),
        Some(format!("owner-admission-denied:{code}").as_str())
    );
}

#[test]
fn node_shebang_tool_is_denied_by_admission_under_no_node_python() {
    let f = admission_fixture();
    for (name, bytes) in [
        (
            "lint-env",
            b"#!/usr/bin/env node\nconsole.log(1)\n".as_slice(),
        ),
        ("lint-direct", b"#!/usr/local/bin/node\n".as_slice()),
        ("lint-py", b"#!/usr/bin/python3.11\n".as_slice()),
        ("lint-sh", b"#!/bin/sh\nexec node x\n".as_slice()),
    ] {
        let tool = f.tools.join(name);
        executable(&tool, bytes);
        let tool = fs::canonicalize(tool).unwrap();
        // Default frozen constraint is no-node-python.
        let policy = policy(&f, None);
        let decision = policy.authorize(&request(&f, &policy, &tool, bytes, &[]));
        denied(&decision, "runtime-closure-violation");
        // Same request is admissible once the host freezes `unrestricted`:
        // the denial above is the closure check, nothing else.
        let relaxed = self::policy(&f, Some(RuntimeConstraint::Unrestricted));
        let decision = relaxed.authorize(&request(&f, &relaxed, &tool, bytes, &[]));
        assert!(decision.allowed, "{name}: {decision:?}");
    }
}

#[test]
fn node_named_executable_and_launcher_targets_are_denied() {
    let f = admission_fixture();
    let bytes = b"\x7fELF-native-looking".as_slice();
    for (name, args) in [
        ("node", vec![]),
        ("python3.12", vec![]),
        ("npx", vec![]),
        ("env", vec!["node", "x.js"]),
        ("env", vec!["/usr/bin/python3"]),
    ] {
        let dir = f
            .tools
            .join(format!("d{}", SEQ.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&dir).unwrap();
        let tool = dir.join(name);
        executable(&tool, bytes);
        let tool = fs::canonicalize(tool).unwrap();
        let policy = policy(&f, None);
        let decision = policy.authorize(&request(&f, &policy, &tool, bytes, &args));
        denied(&decision, "runtime-closure-violation");
    }
    // A plain native tool is still admitted.
    let tool = f.tools.join("scanner");
    executable(&tool, bytes);
    let tool = fs::canonicalize(tool).unwrap();
    let policy = policy(&f, None);
    let decision = policy.authorize(&request(&f, &policy, &tool, bytes, &["--scan"]));
    assert!(decision.allowed, "{decision:?}");
}

// ---- inventory git launch ----------------------------------------------------

fn host_git() -> Option<&'static str> {
    [
        "/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
}

fn git(git: &str, repo: &Path, args: &[&str]) -> bool {
    std::process::Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn repo_with_ignored_file(git_bin: &str) -> Option<PathBuf> {
    let root = scratch("git-repo");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
    fs::write(root.join("src/lib.rs"), "fn x() {}\n").unwrap();
    fs::write(root.join("ignored.txt"), "secret\n").unwrap();
    git(git_bin, &root, &["init", "-q"]).then_some(root)
}

fn inventory_paths(root: &Path) -> Vec<String> {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("repo")
        .unwrap()
        .paths()
        .map(str::to_owned)
        .collect()
}

#[test]
fn repo_local_fake_git_on_path_is_not_executed() {
    let Some(git_bin) = host_git() else { return };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = repo_with_ignored_file(git_bin) else {
        return;
    };
    let marker = root.join("fake-git-ran");
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    executable(
        &bin.join("git"),
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()).as_bytes(),
    );
    let saved = std::env::var_os("PATH").unwrap_or_default();
    let mut path = std::ffi::OsString::from(&bin);
    path.push(":");
    path.push(&saved);
    std::env::set_var("PATH", &path);
    let paths = inventory_paths(&root);
    std::env::set_var("PATH", &saved);
    assert!(!marker.exists(), "repo-controlled git was executed");
    assert!(paths.iter().any(|p| p == "src/lib.rs"), "{paths:?}");
    assert!(!paths.iter().any(|p| p == "ignored.txt"), "{paths:?}");
}

#[test]
fn git_dir_injection_is_ignored() {
    let Some(git_bin) = host_git() else { return };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = repo_with_ignored_file(git_bin) else {
        return;
    };
    let decoy = scratch("git-decoy");
    assert!(git(git_bin, &decoy, &["init", "-q"]));
    std::env::set_var("GIT_DIR", decoy.join(".git"));
    std::env::set_var("GIT_WORK_TREE", &decoy);
    let paths = inventory_paths(&root);
    std::env::remove_var("GIT_DIR");
    std::env::remove_var("GIT_WORK_TREE");
    // Git ran against `root`'s own repository (the ignore file was honoured),
    // not the injected decoy.
    assert!(paths.iter().any(|p| p == "src/lib.rs"), "{paths:?}");
    assert!(!paths.iter().any(|p| p == "ignored.txt"), "{paths:?}");
}

#[test]
fn repository_fsmonitor_config_is_not_executed() {
    let Some(git_bin) = host_git() else { return };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = repo_with_ignored_file(git_bin) else {
        return;
    };
    let marker = root.join("fsmonitor-ran");
    let hook = root.join("fsmonitor.sh");
    executable(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
    );
    assert!(git(
        git_bin,
        &root,
        &["config", "core.fsmonitor", &hook.to_string_lossy()]
    ));
    let paths = inventory_paths(&root);
    assert!(!marker.exists(), "config-driven fsmonitor executed");
    assert!(paths.iter().any(|p| p == "src/lib.rs"), "{paths:?}");
}
