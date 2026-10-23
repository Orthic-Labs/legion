//! Host-owned trusted owner: admission from a host policy file plus real OS
//! containment via rightkit-sandbox. Authored for root verification (workers do
//! not run it). Confinement tests are macOS-only (Seatbelt).
#![cfg(unix)]
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use legion_audit::{
    execution_policy::OWNER_POLICY_ID,
    host_owner::{HostPolicyOwner, POLICY_FILE},
    owner_admission::{NativeAuthorizer, OwnerPolicyConfig, PlanBinding},
    profiles::RuntimeConstraint,
};
use legion_effects::{
    owner_process::InvocationClass, ArtifactWriter, EffectExecutor, ExecutionReceipt,
    ExecutionState, ExternalToolRequest, PolicyAuthorizer,
};
use sha2::{Digest, Sha256};

static SEQ: AtomicU64 = AtomicU64::new(0);
const PROVIDER: &str = "legacy.quality.lint";

struct Fixture {
    base: PathBuf,
    frozen: PathBuf,
    out: PathBuf,
    artifacts: PathBuf,
    state: PathBuf,
}

fn fixture() -> Fixture {
    let base = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "legion-host-owner-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    let f = Fixture {
        frozen: base.join("frozen"),
        out: base.join("out"),
        artifacts: base.join("artifacts"),
        state: base.join("state"),
        base,
    };
    for dir in [&f.frozen, &f.out, &f.artifacts, &f.state] {
        fs::create_dir_all(dir).unwrap();
    }
    fs::set_permissions(&f.state, fs::Permissions::from_mode(0o700)).unwrap();
    f
}

fn sha256(path: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(fs::read(path).unwrap()))
    )
}

fn write_policy(f: &Fixture, tool: &str, class: &str, digest: &str, mode: u32) -> PathBuf {
    let path = f.state.join(POLICY_FILE);
    let body = serde_json::json!({
        "schemaVersion": 1,
        "policyRevision": "test-r1",
        "tools": [{
            "providers": [PROVIDER], "executable": tool, "sha256": digest,
            "class": class, "environmentNames": []
        }]
    });
    fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn load(f: &Fixture, path: &Path) -> Result<Option<HostPolicyOwner>, String> {
    HostPolicyOwner::load(path, &[f.frozen.clone(), f.out.clone()])
}

fn config(f: &Fixture, owner: &HostPolicyOwner) -> OwnerPolicyConfig {
    owner
        .owner_config("host-plan", &f.frozen, &f.out)
        .unwrap()
        .with_runtime_constraint(RuntimeConstraint::Unrestricted)
}

fn request(
    f: &Fixture,
    cfg: &OwnerPolicyConfig,
    tool: &str,
    class: InvocationClass,
    args: &[&str],
) -> ExternalToolRequest {
    ExternalToolRequest {
        request_id: format!("req-{}", SEQ.fetch_add(1, Ordering::Relaxed)),
        provider_id: PROVIDER.into(),
        plan_id: "host-plan".into(),
        policy_id: OWNER_POLICY_ID.into(),
        task_id: Some("task".into()),
        executable: tool.into(),
        args: args.iter().map(|a| a.to_string()).collect(),
        cwd: f.frozen.to_string_lossy().into_owned(),
        expected_digest: Some(sha256(tool)),
        skip_version_probe: true,
        requires_network_sandbox: true,
        sandbox: Some(
            cfg.containment_profile(
                legion_audit::host_owner::OWNER_ID,
                class,
                [PathBuf::from(tool)].into(),
            )
            .sandbox_receipt(),
        ),
        timeout_ms: 20_000,
        ..ExternalToolRequest::default()
    }
}

async fn run(
    f: &Fixture,
    tool: &str,
    class: &str,
    policy_digest: &str,
    args: &[&str],
    tune: impl FnOnce(&mut ExternalToolRequest),
) -> ExecutionReceipt {
    let path = write_policy(f, tool, class, policy_digest, 0o600);
    let owner = load(f, &path).unwrap().unwrap();
    let cfg = config(f, &owner);
    let class = match class {
        "network-metadata" => InvocationClass::NetworkMetadata,
        "project-executing" => InvocationClass::ProjectExecuting,
        _ => InvocationClass::ReadOnlyStatic,
    };
    let mut req = request(f, &cfg, tool, class, args);
    tune(&mut req);
    let process = owner.process(&cfg).unwrap();
    let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
    assert!(policy.is_owner_backed());
    EffectExecutor::new(process, ArtifactWriter::new(f.artifacts.clone()), policy)
        .execute(&req)
        .await
}

#[test]
fn absent_policy_is_unavailable() {
    let f = fixture();
    assert!(load(&f, &f.state.join(POLICY_FILE)).unwrap().is_none());
}

#[tokio::test]
async fn no_owner_denies_and_never_spawns() {
    let f = fixture();
    let marker = f.out.join("marker");
    let cfg_owner = {
        let path = write_policy(
            &f,
            "/usr/bin/touch",
            "read-only-static",
            &sha256("/usr/bin/touch"),
            0o600,
        );
        load(&f, &path).unwrap().unwrap()
    };
    let cfg = config(&f, &cfg_owner);
    let req = request(
        &f,
        &cfg,
        "/usr/bin/touch",
        InvocationClass::ReadOnlyStatic,
        &[marker.to_str().unwrap()],
    );
    let decision = NativeAuthorizer::resolve(None, None).authorize(&req);
    assert!(!decision.allowed);
    assert!(!marker.exists());
}

#[tokio::test]
async fn wrong_policy_digest_is_denied_before_spawn() {
    let f = fixture();
    let marker = f.out.join("marker");
    let wrong = format!("sha256:{}", "0".repeat(64));
    let receipt = run(
        &f,
        "/usr/bin/touch",
        "read-only-static",
        &wrong,
        &[marker.to_str().unwrap()],
        |_| {},
    )
    .await;
    assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
    assert!(!receipt.process_tree.started);
    assert!(!marker.exists());
}

#[test]
fn policy_file_with_loose_mode_or_inside_audited_root_is_refused() {
    let f = fixture();
    let loose = write_policy(
        &f,
        "/usr/bin/touch",
        "read-only-static",
        &sha256("/usr/bin/touch"),
        0o644,
    );
    assert!(load(&f, &loose).is_err());
    let inside = f.frozen.join(POLICY_FILE);
    fs::copy(&loose, &inside).unwrap();
    fs::set_permissions(&inside, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load(&f, &inside).is_err());
    let _ = &f.base;
}

const FROZEN_PLAN: &str = "sha256:frozen-run-plan";

/// Request shaped exactly as the legacy-check builder shapes it under an active
/// owner: owner policy id, containment receipt from the context, the policy's
/// pin (never a digest of the file about to run) and the bound frozen plan.
fn builder_request(
    f: &Fixture,
    ctx: &legion_audit::host_owner::OwnerRequestContext,
    tool: &str,
    args: &[&str],
) -> Option<ExternalToolRequest> {
    let pin = ctx.pin_for(PROVIDER, Path::new(tool))?;
    Some(ExternalToolRequest {
        request_id: format!("audit:{PROVIDER}:{}", SEQ.fetch_add(1, Ordering::Relaxed)),
        provider_id: PROVIDER.into(),
        plan_id: FROZEN_PLAN.into(),
        policy_id: OWNER_POLICY_ID.into(),
        task_id: Some("lint".into()),
        executable: pin.executable.to_string_lossy().into_owned(),
        args: args.iter().map(|a| a.to_string()).collect(),
        cwd: f.frozen.to_string_lossy().into_owned(),
        expected_digest: Some(pin.digest.clone()),
        skip_version_probe: true,
        requires_network_sandbox: true,
        sandbox: Some(ctx.sandbox_receipt()),
        timeout_ms: 20_000,
        ..ExternalToolRequest::default()
    })
}

fn late_bound(
    f: &Fixture,
    tool: &str,
    policy_digest: &str,
) -> (
    HostPolicyOwner,
    OwnerPolicyConfig,
    legion_audit::host_owner::OwnerRequestContext,
) {
    let path = write_policy(f, tool, "read-only-static", policy_digest, 0o600);
    let owner = load(f, &path).unwrap().unwrap();
    let cfg = owner
        .owner_config_bound(PlanBinding::unbound(), &f.frozen, &f.out)
        .unwrap()
        .with_runtime_constraint(RuntimeConstraint::Unrestricted);
    let ctx = owner.request_context(&cfg);
    (owner, cfg, ctx)
}

#[test]
fn unbound_plan_denies_then_frozen_plan_binds_once() {
    let f = fixture();
    let (owner, cfg, ctx) = late_bound(&f, "/bin/echo", &sha256("/bin/echo"));
    assert_eq!(ctx.sandbox_receipt().id, cfg.containment_id());
    let req = builder_request(&f, &ctx, "/bin/echo", &["hi"]).unwrap();
    let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
    let denied = policy.authorize(&req);
    assert!(!denied.allowed);
    assert!(denied.reason.unwrap().contains("plan-not-bound"));
    ctx.plan().bind(FROZEN_PLAN).unwrap();
    assert!(ctx.plan().bind(FROZEN_PLAN).is_ok());
    assert!(ctx.plan().bind("sha256:other").is_err());
    let allowed = policy.authorize(&req);
    assert!(allowed.allowed, "{allowed:?}");
    let mut other = req.clone();
    other.plan_id = "sha256:other".into();
    assert!(!policy.authorize(&other).allowed);
}

#[test]
fn tool_absent_from_policy_has_no_pin_and_no_request() {
    let f = fixture();
    let (_owner, _cfg, ctx) = late_bound(&f, "/bin/echo", &sha256("/bin/echo"));
    assert!(ctx.pin_for(PROVIDER, Path::new("/bin/ls")).is_none());
    assert!(ctx
        .pin_for("other.provider", Path::new("/bin/echo"))
        .is_none());
    assert!(builder_request(&f, &ctx, "/bin/ls", &[]).is_none());
}

#[test]
fn policy_digest_mismatch_with_the_binary_is_denied() {
    let f = fixture();
    let wrong = format!("sha256:{}", "1".repeat(64));
    let (owner, cfg, ctx) = late_bound(&f, "/bin/echo", &wrong);
    ctx.plan().bind(FROZEN_PLAN).unwrap();
    let req = builder_request(&f, &ctx, "/bin/echo", &["hi"]).unwrap();
    assert_eq!(req.expected_digest.as_deref(), Some(wrong.as_str()));
    let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
    let decision = policy.authorize(&req);
    assert!(!decision.allowed, "{decision:?}");
}

#[test]
fn request_without_pin_or_with_wrong_policy_id_is_denied() {
    let f = fixture();
    let (owner, cfg, ctx) = late_bound(&f, "/bin/echo", &sha256("/bin/echo"));
    ctx.plan().bind(FROZEN_PLAN).unwrap();
    let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
    let mut req = builder_request(&f, &ctx, "/bin/echo", &["hi"]).unwrap();
    req.expected_digest = None;
    assert!(!policy.authorize(&req).allowed);
    let mut req = builder_request(&f, &ctx, "/bin/echo", &["hi"]).unwrap();
    req.policy_id = "audit".into();
    assert!(!policy.authorize(&req).allowed);
}

#[cfg(target_os = "macos")]
mod confined {
    use super::*;

    #[tokio::test]
    async fn legacy_check_style_request_is_admitted_and_runs_confined() {
        let f = fixture();
        let (owner, cfg, ctx) = late_bound(&f, "/bin/echo", &sha256("/bin/echo"));
        ctx.plan().bind(FROZEN_PLAN).unwrap();
        let req = builder_request(&f, &ctx, "/bin/echo", &["confined-ok"]).unwrap();
        let process = owner.process(&cfg).unwrap();
        let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
        let receipt =
            EffectExecutor::new(process, ArtifactWriter::new(f.artifacts.clone()), policy)
                .execute(&req)
                .await;
        assert_eq!(receipt.state, ExecutionState::Completed, "{receipt:?}");
        assert!(receipt.policy.as_ref().is_some_and(|p| p.allowed));
    }

    /// Run `/bin/sh -c script` as an admitted tool under no-node-python.
    async fn run_hardened(class: &str, script: &str) -> (ExecutionReceipt, String, String) {
        let f = fixture();
        let path = write_policy(&f, "/bin/sh", class, &sha256("/bin/sh"), 0o600);
        let owner = load(&f, &path).unwrap().unwrap();
        let cfg = owner
            .owner_config("host-plan", &f.frozen, &f.out)
            .unwrap()
            .with_runtime_constraint(RuntimeConstraint::NoNodePython);
        let ctx = owner.request_context(&cfg);
        let record = ctx.enforced_exec_policy().summary();
        let req = request(
            &f,
            &cfg,
            "/bin/sh",
            match class {
                "project-executing" => InvocationClass::ProjectExecuting,
                _ => InvocationClass::ReadOnlyStatic,
            },
            &["-c", script],
        );
        let process = owner.process(&cfg).unwrap();
        let policy = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
        let receipt =
            EffectExecutor::new(process, ArtifactWriter::new(f.artifacts.clone()), policy)
                .execute(&req)
                .await;
        let out = receipt
            .stdout
            .as_ref()
            .and_then(|a| {
                fs::read_to_string(f.artifacts.join(&a.path))
                    .or_else(|_| fs::read_to_string(&a.path))
                    .ok()
            })
            .unwrap_or_default();
        (receipt, record, out)
    }

    #[tokio::test]
    async fn no_node_python_discloses_that_interpreter_exec_cannot_be_denied() {
        // RightKit#943: deny_read globs are not an exec block, so the sandbox
        // never claims interpreter exec is denied. The honest contract is an
        // explicit, disclosed gap; only the launched executable is admitted.
        let (_receipt, record, _out) = run_hardened(
            "read-only-static",
            "/usr/bin/python3 -c 'print(12345)' 2>/dev/null; echo rc=$?",
        )
        .await;
        assert!(
            record.contains("sandbox-cannot-deny-interpreter-exec"),
            "{record}"
        );
        assert!(record.contains("interpreter-exec-denied=false"), "{record}");
        assert!(!record.contains("interpreter-exec-denied=true"), "{record}");
        assert!(record.contains("audited-root-exec=false"), "{record}");
    }

    #[tokio::test]
    async fn no_node_python_refuses_project_executing_while_unix_sockets_cannot_be_denied() {
        // The sandbox cannot deny AF_UNIX connect, so a project-executing launch
        // must not run at all (explicit gap, never a silent allow).
        let (receipt, record, _out) = run_hardened(
            "project-executing",
            "/usr/bin/nc -U /var/run/mDNSResponder </dev/null >/dev/null 2>&1; echo connected=$?",
        )
        .await;
        assert_ne!(receipt.state, ExecutionState::Completed, "{receipt:?}");
        assert!(
            receipt.stdout.is_none(),
            "tool output produced: {receipt:?}"
        );
        assert!(
            record.contains("sandbox-cannot-deny-unix-sockets"),
            "{record}"
        );
    }

    #[tokio::test]
    async fn writes_only_inside_output_root() {
        let f = fixture();
        let inside = f.out.join("ok");
        let receipt = run(
            &f,
            "/usr/bin/touch",
            "read-only-static",
            &sha256("/usr/bin/touch"),
            &[inside.to_str().unwrap()],
            |_| {},
        )
        .await;
        assert_eq!(receipt.state, ExecutionState::Completed, "{receipt:?}");
        assert!(inside.exists());

        // The path is hidden in the script text so admission's argument-path
        // check passes and only the OS sandbox stands between it and the write.
        let outside = f.base.join("outside");
        let script = format!("/usr/bin/touch {}", outside.display());
        let receipt = run(
            &f,
            "/bin/sh",
            "read-only-static",
            &sha256("/bin/sh"),
            &["-c", &script],
            |_| {},
        )
        .await;
        assert_ne!(receipt.state, ExecutionState::Completed, "{receipt:?}");
        assert!(!outside.exists(), "write outside the output root succeeded");
    }

    #[tokio::test]
    async fn network_is_denied_for_read_only_static_and_allowed_for_metadata() {
        use std::net::TcpListener;
        let curl_args = |port: u16| format!("http://127.0.0.1:{port}/");
        let f = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = curl_args(port);
        let _ = run(
            &f,
            "/usr/bin/curl",
            "read-only-static",
            &sha256("/usr/bin/curl"),
            &["-sS", "-m", "2", &url],
            |_| {},
        )
        .await;
        assert!(
            listener.accept().is_err(),
            "denied class reached the network"
        );

        let _ = run(
            &f,
            "/usr/bin/curl",
            "network-metadata",
            &sha256("/usr/bin/curl"),
            &["-sS", "-m", "2", &url],
            |_| {},
        )
        .await;
        assert!(
            listener.accept().is_ok(),
            "control: metadata class should connect"
        );
    }

    #[tokio::test]
    async fn output_cap_stops_the_tool() {
        let f = fixture();
        let receipt = run(
            &f,
            "/usr/bin/yes",
            "read-only-static",
            &sha256("/usr/bin/yes"),
            &[],
            |req| {
                req.stdout_limit = 1024;
                req.stderr_limit = 1024;
            },
        )
        .await;
        assert_eq!(receipt.state, ExecutionState::OutputLimited, "{receipt:?}");
    }

    #[tokio::test]
    async fn timeout_kills_descendants() {
        let f = fixture();
        let needle = format!("sleep 29.{}", 100 + std::process::id() % 800);
        let script = format!("{needle} & wait");
        let receipt = run(
            &f,
            "/bin/sh",
            "read-only-static",
            &sha256("/bin/sh"),
            &["-c", &script],
            |req| req.timeout_ms = 1_500,
        )
        .await;
        assert_eq!(receipt.state, ExecutionState::Timeout, "{receipt:?}");
        let alive = std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", &needle])
            .status()
            .unwrap()
            .success();
        assert!(!alive, "descendant survived the timeout kill");
    }
}

mod gradle_policy {
    use super::*;

    const ANDROID: &str = "code.android.lint";
    /// Stand-in for a JDK `java`: any canonical file outside the audited roots.
    fn java() -> String {
        fs::canonicalize("/bin/sh")
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn tool(class: &str, provider: &str) -> serde_json::Value {
        serde_json::json!({
            "providers": [provider], "executable": java(), "sha256": sha256(&java()),
            "class": class, "environmentNames": []
        })
    }

    fn write(
        f: &Fixture,
        tools: Vec<serde_json::Value>,
        gradle: Option<serde_json::Value>,
    ) -> PathBuf {
        let path = f.state.join(POLICY_FILE);
        let mut body = serde_json::json!({
            "schemaVersion": 1, "policyRevision": "gradle-r1", "tools": tools
        });
        if let Some(gradle) = gradle {
            body["gradle"] = gradle;
        }
        fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn gradle(f: &Fixture) -> serde_json::Value {
        let cache = f.base.join("cache");
        fs::create_dir_all(&cache).unwrap();
        serde_json::json!({
            "java": java(),
            "wrapperJarSha256": [format!("sha256:{}", "a".repeat(64))],
            "distributionSha256": ["b".repeat(64)],
            "dependencyCacheRoot": cache,
        })
    }

    fn load_err(f: &Fixture, path: &Path) -> String {
        load(f, path).err().expect("policy must be refused")
    }

    #[test]
    fn gradle_section_parses_into_normalised_pins() {
        let f = fixture();
        let path = write(
            &f,
            vec![tool("project-executing", ANDROID)],
            Some(gradle(&f)),
        );
        let owner = load(&f, &path).unwrap().unwrap();
        let pins = owner.gradle_pins().expect("pins");
        assert_eq!(pins.java, PathBuf::from(java()));
        assert!(pins
            .wrapper_jar_sha256
            .contains(&format!("sha256:{}", "a".repeat(64))));
        assert!(pins
            .distribution_sha256
            .contains(&format!("sha256:{}", "b".repeat(64))));
        assert_eq!(
            pins.dependency_cache_root,
            Some(fs::canonicalize(f.base.join("cache")).unwrap())
        );
    }

    #[test]
    fn policy_without_gradle_section_has_no_pins() {
        let f = fixture();
        let path = write(&f, vec![tool("project-executing", ANDROID)], None);
        assert!(load(&f, &path).unwrap().unwrap().gradle_pins().is_none());
    }

    #[test]
    fn invalid_gradle_sections_are_refused() {
        let f = fixture();
        // java is not a tool entry for code.android.lint.
        let path = write(
            &f,
            vec![tool("project-executing", "code.rust")],
            Some(gradle(&f)),
        );
        assert!(load_err(&f, &path).contains("code.android.lint"));
        // java entry is not project-executing.
        let path = write(
            &f,
            vec![tool("read-only-static", ANDROID)],
            Some(gradle(&f)),
        );
        assert!(load_err(&f, &path).contains("project-executing"));
        let tools = || vec![tool("project-executing", ANDROID)];
        // Empty or malformed digest lists.
        for (key, value) in [
            ("wrapperJarSha256", serde_json::json!([])),
            ("distributionSha256", serde_json::json!(["not-hex"])),
        ] {
            let mut section = gradle(&f);
            section[key] = value;
            let path = write(&f, tools(), Some(section));
            assert!(load(&f, &path).is_err(), "{key}");
        }
        // Unknown key, relative java, cache root inside an audited root.
        let mut section = gradle(&f);
        section["extra"] = serde_json::json!(true);
        assert!(load(&f, &write(&f, tools(), Some(section))).is_err());
        let mut section = gradle(&f);
        section["java"] = serde_json::json!("sh");
        assert!(load(&f, &write(&f, tools(), Some(section))).is_err());
        let mut section = gradle(&f);
        let inside = f.frozen.join("cache");
        fs::create_dir_all(&inside).unwrap();
        section["dependencyCacheRoot"] = serde_json::json!(inside);
        assert!(load(&f, &write(&f, tools(), Some(section))).is_err());
    }
}
