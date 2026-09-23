//! Integration tests for wf002's Rust port (see
//! `src/wf_port/wf002/mod.rs`): `policy-inject.mjs`, `minimize.mjs`, and
//! `route-envelope.mjs`.
//!
//! Most parity assertions live as unit tests inside each module (mirroring
//! the JS test suites `tests/arcane-package-policy-inject.test.mjs` and
//! `tests/arcane-package-minimize.test.mjs` line for line where feasible).
//! This file exercises the modules from outside the crate, through
//! `legion_policy::wf_port::wf002`, once the integrator wires
//! `pub mod wf_port;` into `src/lib.rs` — see that module's doc comment.
//!
//! NOTE for the integration owner: until `pub mod wf_port;` is added to
//! `src/lib.rs`, this file will not compile (the path below will not
//! resolve). It is intentionally written against the path the wiring
//! instructions specify.

use std::path::Path;
use std::process::Command;

use legion_policy::wf_port::wf002::minimize::{
    build_review, staged_changes, MinimizeEnv,
};
use legion_policy::wf_port::wf002::policy_inject::{
    build_policy_injection, PolicyEnv, PolicyInjectionInput, PolicyPaths,
};
use legion_policy::wf_port::wf002::route_envelope::{
    compile_arcane_route, route_envelope_context, Availability, RouteInput,
};

fn repo_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = .../engine/crates/legion-policy
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[test]
fn policy_inject_end_to_end_with_real_policy_files() {
    let workspace = std::env::temp_dir().join(format!(
        "legion-wf002-policy-inject-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).unwrap();

    let base = repo_root().join("src/lib/cognitive/arcane/policy");
    let paths = PolicyPaths {
        brief_fallback: base.join("brief-policy.md"),
        minimize_policy: base.join("minimize-policy.md"),
        ccx_directive: base.join("ccx-gateway-directive.md"),
    };

    let injection = build_policy_injection(
        &PolicyInjectionInput {
            workspace: &workspace,
            ..Default::default()
        },
        &paths,
        &PolicyEnv::default(),
    )
    .expect("default env yields brief + minimize");

    assert!(injection.additional_context.contains("Brief is default"));
    assert_eq!(injection.system_message.as_deref(), Some("MINIMIZE:ON"));

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn minimize_review_on_a_real_temp_git_repo() {
    let root = std::env::temp_dir().join(format!(
        "legion-wf002-minimize-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("pkg/src")).unwrap();

    let run = |args: &[&str]| {
        let status = Command::new("git")
            .current_dir(&root)
            .args(args)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    std::fs::write(root.join("pkg/package.json"), "{\"name\":\"pkg\"}\n").unwrap();
    run(&["add", "-A"]);
    run(&["commit", "-qm", "base"]);

    std::fs::write(
        root.join("pkg/src/new.mjs"),
        "export function veryUniqueSymbolName(x) { return x; }\n",
    )
    .unwrap();
    run(&["add", "pkg/src/new.mjs"]);

    let env = MinimizeEnv::default();
    let changes = staged_changes(&root, &env).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "pkg/src/new.mjs");

    let review = build_review(&root, &env).unwrap();
    assert_eq!(review.verdict, "CLEAN");
    assert!(review.findings.is_empty());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn route_envelope_end_to_end_context_string() {
    let input = RouteInput {
        prompt: Some("do the reasonable thing here today".into()),
        ..Default::default()
    };
    let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
    assert_eq!(envelope.mode, "TRIVIAL");
    let context = route_envelope_context(&envelope).unwrap().unwrap();
    assert!(context.starts_with("ARCANE_ROUTE:"));
}
