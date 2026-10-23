//! Native owner admission: authored for root verification (not run by workers).
//! Requires root to export `legion_audit::owner_admission` and
//! `legion_effects::owner_process`, and to register this test target.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use legion_audit::{
    execution_policy::{ADMISSION_UNAVAILABLE, OWNER_POLICY_ID, POLICY_ID},
    owner_admission::{
        NativeAuthorizer, OwnerGrant, OwnerIdentity, OwnerPolicyConfig, OwnerProvenance,
        OwnerQuery, OwnerVerdict, TrustedOwner,
    },
};
use legion_effects::{
    owner_process::InvocationClass, ArtifactWriter, EffectExecutor, ExecutionState,
    ExternalToolRequest, PlatformProcess, PolicyAuthorizer, ProcessLaunch, ProcessOutput,
    ProcessTreeEvidence,
};
use sha2::{Digest, Sha256};

static SEQ: AtomicU64 = AtomicU64::new(0);
const PROVIDER: &str = "legacy.quality.lint";
const PLAN: &str = "frozen-plan";
const CONTAINMENT: &str = "owner-containment-1";

struct Fixture {
    base: PathBuf,
    frozen: PathBuf,
    output: PathBuf,
    tool: PathBuf,
    tool_digest: String,
}

fn fixture() -> Fixture {
    let base = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("legion-owner-admission-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let (frozen, output, tools) = (base.join("frozen"), base.join("out"), base.join("tools"));
    for dir in [&frozen, &output, &tools] {
        fs::create_dir_all(dir).unwrap();
    }
    let tool = tools.join("scanner");
    fs::write(&tool, b"pinned-scanner-bytes").unwrap();
    let tool_digest = format!("sha256:{}", hex(&Sha256::digest(b"pinned-scanner-bytes")));
    Fixture { base, frozen, output, tool, tool_digest }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn config(f: &Fixture, revision: &str) -> OwnerPolicyConfig {
    OwnerPolicyConfig::new(
        revision,
        PLAN,
        CONTAINMENT,
        &[f.frozen.clone()],
        &f.output,
        BTreeMap::from([(PROVIDER.to_string(), InvocationClass::ReadOnlyStatic)]),
        BTreeSet::from(["HOME".to_string(), "LANG".to_string()]),
        60_000,
        1024 * 1024,
    )
    .unwrap()
}

fn request(f: &Fixture, cfg: &OwnerPolicyConfig) -> ExternalToolRequest {
    ExternalToolRequest {
        request_id: format!("req-{}", SEQ.fetch_add(1, Ordering::Relaxed)),
        provider_id: PROVIDER.into(),
        plan_id: PLAN.into(),
        policy_id: OWNER_POLICY_ID.into(),
        task_id: Some("task-1".into()),
        executable: f.tool.to_string_lossy().into_owned(),
        args: vec!["--scan".into(), format!("--output={}/report.json", f.output.display())],
        cwd: f.frozen.to_string_lossy().into_owned(),
        expected_digest: Some(f.tool_digest.clone()),
        skip_version_probe: true,
        requires_network_sandbox: true,
        sandbox: Some(cfg.containment_profile("test-owner", InvocationClass::ReadOnlyStatic, [f.tool.clone()].into()).sandbox_receipt()),
        ..ExternalToolRequest::default()
    }
}

#[derive(Clone)]
enum Mode {
    Echo,
    FixedDigest(String),
    Replay,
    Deny,
    Unavailable,
    Stale(String),
    WrongOwner,
    Expired,
}

struct FakeOwner {
    mode: Mode,
    verified: bool,
    calls: AtomicUsize,
    last: Mutex<Option<OwnerGrant>>,
}

impl FakeOwner {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self { mode, verified: true, calls: AtomicUsize::new(0), last: Mutex::new(None) })
    }
}

const NOW: u64 = 1_000_000;
fn clock() -> u64 {
    NOW
}

impl TrustedOwner for FakeOwner {
    fn identity(&self) -> OwnerIdentity {
        OwnerIdentity {
            owner_id: "test-owner".into(),
            version: "1".into(),
            provenance: if self.verified {
                OwnerProvenance::Verified { key_id: "a".repeat(64), receipt_digest: "sha256:r".into() }
            } else {
                OwnerProvenance::Unverified("enrollment json only".into())
            },
        }
    }
    fn admit(&self, query: &OwnerQuery<'_>) -> OwnerVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let grant = |digest: &str, revision: &str, owner: &str, nonce: String, exp: u64| OwnerGrant {
            owner_id: owner.into(),
            binding_digest: digest.into(),
            policy_revision: revision.into(),
            nonce,
            expires_at_ms: exp,
        };
        let nonce = format!("n-{}", SEQ.fetch_add(1, Ordering::Relaxed));
        let (d, r) = (query.binding_digest, query.binding.policy_revision.as_str());
        match &self.mode {
            Mode::Echo => OwnerVerdict::Granted(grant(d, r, "test-owner", nonce, NOW + 1000)),
            Mode::FixedDigest(fixed) => OwnerVerdict::Granted(grant(fixed, r, "test-owner", nonce, NOW + 1000)),
            Mode::Replay => {
                let mut last = self.last.lock().unwrap();
                let g = last.get_or_insert_with(|| grant(d, r, "test-owner", "fixed".into(), NOW + 1000));
                OwnerVerdict::Granted(g.clone())
            }
            Mode::Deny => OwnerVerdict::Denied("no".into()),
            Mode::Unavailable => OwnerVerdict::Unavailable("down".into()),
            Mode::Stale(rev) => OwnerVerdict::Granted(grant(d, rev, "test-owner", nonce, NOW + 1000)),
            Mode::WrongOwner => OwnerVerdict::Granted(grant(d, r, "other-owner", nonce, NOW + 1000)),
            Mode::Expired => OwnerVerdict::Granted(grant(d, r, "test-owner", nonce, NOW - 1)),
        }
    }
}

// NativeAuthorizer has no clock hook; grants are minted relative to NOW, so use
// OwnerBackedPolicy directly when time matters.
fn backed(owner: &Arc<FakeOwner>, f: &Fixture) -> legion_audit::owner_admission::OwnerBackedPolicy {
    legion_audit::owner_admission::OwnerBackedPolicy::new(owner.clone(), config(f, "rev-1"))
        .unwrap()
        .with_clock(clock)
}

fn denied_with(decision: &legion_effects::PolicyDecision, code: &str) {
    assert!(!decision.allowed, "expected denial {code}");
    assert_eq!(decision.reason.as_deref(), Some(format!("owner-admission-denied:{code}").as_str()));
}

#[test]
fn matching_request_is_admitted_once_with_bound_evidence() {
    let f = fixture();
    let owner = FakeOwner::new(Mode::Echo);
    let p = backed(&owner, &f);
    let r = request(&f, p.config());
    let d = p.authorize(&r);
    assert!(d.allowed, "{:?}", d.reason);
    assert_eq!(d.policy_id, OWNER_POLICY_ID);
    assert!(d.reason.unwrap().starts_with("owner-admitted:test-owner:sha256:"));
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_or_unverified_owner_falls_back_to_denial_without_owner_call() {
    let f = fixture();
    let none = NativeAuthorizer::resolve(None, Some(config(&f, "rev-1")));
    assert!(!none.is_owner_backed());
    let r = request(&f, &config(&f, "rev-1"));
    let d = none.authorize(&r);
    assert!(!d.allowed);
    assert_eq!(d.policy_id, POLICY_ID);
    assert_eq!(d.reason.as_deref(), Some(ADMISSION_UNAVAILABLE));

    let unverified = Arc::new(FakeOwner { mode: Mode::Echo, verified: false, calls: AtomicUsize::new(0), last: Mutex::new(None) });
    let resolved = NativeAuthorizer::resolve(Some(unverified.clone()), Some(config(&f, "rev-1")));
    assert!(!resolved.is_owner_backed());
    assert!(resolved.unavailable_reason().unwrap().contains("unverified"));
    assert!(!resolved.authorize(&r).allowed);
    assert_eq!(unverified.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn owner_denial_and_unavailability_are_denials() {
    let f = fixture();
    for (mode, code) in [(Mode::Deny, "owner-denied"), (Mode::Unavailable, "owner-unavailable")] {
        let owner = FakeOwner::new(mode);
        let p = backed(&owner, &f);
        denied_with(&p.authorize(&request(&f, p.config())), code);
    }
}

#[test]
fn grant_defects_are_denied() {
    let f = fixture();
    let cases = [
        (Mode::FixedDigest("sha256:stale".into()), "grant-binding-mismatch"),
        (Mode::Stale("rev-0".into()), "grant-policy-stale"),
        (Mode::WrongOwner, "grant-owner-mismatch"),
        (Mode::Expired, "grant-expired-or-unbounded"),
    ];
    for (mode, code) in cases {
        let owner = FakeOwner::new(mode);
        let p = backed(&owner, &f);
        denied_with(&p.authorize(&request(&f, p.config())), code);
    }
}

#[test]
fn replayed_grant_is_denied() {
    let f = fixture();
    let owner = FakeOwner::new(Mode::Replay);
    let p = backed(&owner, &f);
    let r = request(&f, p.config());
    assert!(p.authorize(&r).allowed);
    denied_with(&p.authorize(&r), "grant-replayed");
}

#[test]
fn local_validation_failures_never_reach_the_owner() {
    let f = fixture();
    let owner = FakeOwner::new(Mode::Echo);
    let p = backed(&owner, &f);
    let base = request(&f, p.config());
    let outside = f.base.join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    let cases: Vec<(&str, ExternalToolRequest)> = vec![
        ("plan-mismatch", ExternalToolRequest { plan_id: "other".into(), ..base.clone() }),
        ("policy-id-mismatch", ExternalToolRequest { policy_id: POLICY_ID.into(), ..base.clone() }),
        ("invocation-unclassified", ExternalToolRequest { provider_id: "unlisted".into(), ..base.clone() }),
        ("containment-receipt-mismatch", ExternalToolRequest { sandbox: None, ..base.clone() }),
        ("containment-receipt-mismatch", ExternalToolRequest { requires_network_sandbox: false, ..base.clone() }),
        ("executable-digest-pin-required", ExternalToolRequest { expected_digest: None, ..base.clone() }),
        ("executable-identity-unverified", ExternalToolRequest { expected_digest: Some(format!("sha256:{}", "0".repeat(64))), ..base.clone() }),
        ("cwd-outside-admitted-roots", ExternalToolRequest { cwd: outside.to_string_lossy().into_owned(), ..base.clone() }),
        ("argument-path-outside-admitted-roots", ExternalToolRequest { args: vec!["--out=/etc/passwd".into()], ..base.clone() }),
        ("argument-path-outside-admitted-roots", ExternalToolRequest { args: vec!["../../elsewhere/x".into()], ..base.clone() }),
        ("environment-name-not-admitted", ExternalToolRequest { environment: [("NODE_OPTIONS".to_string(), "--require x".to_string())].into(), ..base.clone() }),
        ("limits-exceed-policy", ExternalToolRequest { timeout_ms: 10_000_000, ..base.clone() }),
        ("request-id-unsafe", ExternalToolRequest { request_id: "../escape".into(), ..base.clone() }),
    ];
    for (code, request) in cases {
        denied_with(&p.authorize(&request), code);
    }
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0, "owner must not be consulted for locally invalid requests");
}

#[test]
fn executable_replacement_after_pinning_is_denied() {
    let f = fixture();
    let owner = FakeOwner::new(Mode::Echo);
    let p = backed(&owner, &f);
    let r = request(&f, p.config());
    fs::write(&f.tool, b"replaced-bytes").unwrap();
    denied_with(&p.authorize(&r), "executable-identity-unverified");
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn executable_inside_frozen_root_is_denied_for_static_class() {
    let f = fixture();
    let inside = f.frozen.join("repo-tool");
    fs::write(&inside, b"pinned-scanner-bytes").unwrap();
    let owner = FakeOwner::new(Mode::Echo);
    let p = backed(&owner, &f);
    let r = ExternalToolRequest { executable: inside.to_string_lossy().into_owned(), ..request(&f, p.config()) };
    denied_with(&p.authorize(&r), "executable-inside-controlled-root");
}

#[cfg(unix)]
#[test]
fn symlink_escapes_are_denied() {
    let f = fixture();
    let owner = FakeOwner::new(Mode::Echo);
    let p = backed(&owner, &f);
    let base = request(&f, p.config());
    let elsewhere = f.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.frozen.join("link")).unwrap();
    let via_cwd = ExternalToolRequest { cwd: f.frozen.join("link").to_string_lossy().into_owned(), ..base.clone() };
    denied_with(&p.authorize(&via_cwd), "cwd-not-canonical");
    let via_arg = ExternalToolRequest { args: vec![format!("--out={}/link/x", f.frozen.display())], ..base.clone() };
    denied_with(&p.authorize(&via_arg), "argument-path-outside-admitted-roots");
    let tool_link = f.base.join("tools").join("scanner-link");
    std::os::unix::fs::symlink(&f.tool, &tool_link).unwrap();
    let via_exe = ExternalToolRequest { executable: tool_link.to_string_lossy().into_owned(), ..base };
    denied_with(&p.authorize(&via_exe), "executable-not-canonical");
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
}

struct CountingPlatform(Arc<AtomicUsize>);
impl PlatformProcess for CountingPlatform {
    fn run<'a>(&'a self, _: ProcessLaunch) -> legion_effects::platform::ProcessFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(ProcessOutput {
                stdout: b"ok".to_vec(),
                stderr: vec![],
                exit_code: Some(0),
                signal: None,
                timed_out: false,
                cancelled: false,
                output_limited: false,
                kill_succeeded: true,
                process_tree: ProcessTreeEvidence { started: true, terminated: true, hard_killed: false, reaped: true, detail: None },
                started_at_ms: 1,
                completed_at_ms: 2,
            })
        })
    }
}

#[tokio::test]
async fn admitted_request_executes_and_denied_request_never_spawns() {
    let f = fixture();
    let spawns = Arc::new(AtomicUsize::new(0));
    let owner = FakeOwner::new(Mode::Echo);
    let authorizer = backed(&owner, &f);
    let r = request(&f, &config(&f, "rev-1"));
    let executor = EffectExecutor::new(CountingPlatform(spawns.clone()), ArtifactWriter::new(&f.output), authorizer);
    let receipt = executor.execute(&r).await;
    // Real-owner completeness is root-observed; here only the policy seam is exercised.
    assert_eq!(receipt.policy.as_ref().unwrap().id, OWNER_POLICY_ID);
    assert!(receipt.policy.as_ref().unwrap().allowed, "{:?}", receipt.gaps);
    assert_eq!(spawns.load(Ordering::SeqCst), 1);

    let denied = ExternalToolRequest { plan_id: "other".into(), request_id: "req-denied".into(), ..r };
    let receipt = executor.execute(&denied).await;
    assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
    assert!(!receipt.complete && !receipt.process_tree.started);
    assert_eq!(spawns.load(Ordering::SeqCst), 1, "denied request must not spawn");
}

#[test]
fn config_rejects_overlapping_roots_and_loader_environment() {
    let f = fixture();
    let ok = |names: BTreeSet<String>, out: &Path| {
        OwnerPolicyConfig::new("r", PLAN, CONTAINMENT, &[f.frozen.clone()], out, BTreeMap::new(), names, 1, 1)
    };
    assert!(ok(BTreeSet::new(), &f.output).is_ok());
    assert!(ok(BTreeSet::new(), &f.frozen).is_err());
    assert!(ok(["LD_PRELOAD".to_string()].into(), &f.output).is_err());
    assert!(ok(["DYLD_INSERT_LIBRARIES".to_string()].into(), &f.output).is_err());
    assert!(ok(["NODE_OPTIONS".to_string()].into(), &f.output).is_err());
}
