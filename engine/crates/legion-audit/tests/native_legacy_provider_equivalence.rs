//! Provider-by-provider evidence for the frozen legacy-check surface.
//!
//! Node remains the source of truth for provider identity, selector, role,
//! phase, check name, and historical tool/readiness behavior. Rust's frozen
//! projection is checked against that record, then exercised through its
//! native or authorized external route.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_audit::{
    native_providers::legacy_checks::{
        resolve_request, spec, specs, CommandShape, LegacyCheckDispatcher,
    },
    AuditPlan, AuditProvider, InventoryEntry, InventoryEnvelope, NativeProviderRegistry,
    ProviderExecutor, ProviderKind,
};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::{json, Value};
use sha2::Digest;

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
use tokio_util::sync::CancellationToken;

const NODE_REGISTRY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/registry/providers.json"
);

/// Tool labels and readiness gates are copied from
/// `tools/audit/collect-facts.mjs::buildChecks` and its `doctor` function.
/// `runtime` is the one check owned by `tools/audit/audit-runtime.mjs`.
#[derive(Clone, Copy, Debug)]
struct NodeBehavior {
    id: &'static str,
    check: &'static str,
    tool: &'static str,
    readiness: &'static str,
}

const NODE_BEHAVIOR: &[NodeBehavior] = &[
    NodeBehavior {
        id: "legacy.apple.platform",
        check: "apple_platform",
        tool: "fs",
        readiness: "swift + Apple target",
    },
    NodeBehavior {
        id: "legacy.architecture.decomposition",
        check: "decomposition",
        tool: "loc",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.core.repo",
        check: "repo",
        tool: "git",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.quality.build",
        check: "build",
        tool: "<project build>",
        readiness: "build script or Cargo.toml",
    },
    NodeBehavior {
        id: "legacy.quality.dead-code",
        check: "dead_code",
        tool: "knip",
        readiness: "package.json + knip",
    },
    NodeBehavior {
        id: "legacy.quality.debt-markers",
        check: "debt_markers",
        tool: "git grep",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.quality.duplication",
        check: "duplication",
        tool: "jscpd",
        readiness: "package.json + jscpd",
    },
    NodeBehavior {
        id: "legacy.quality.lint",
        check: "lint",
        tool: "biome|eslint|ruff|clippy",
        readiness: "configured language linter",
    },
    NodeBehavior {
        id: "legacy.quality.negative-space",
        check: "negative_space",
        tool: "fs",
        readiness: "always (+ Node lockfile expectation)",
    },
    NodeBehavior {
        id: "legacy.quality.rust-unused-deps",
        check: "cargo_unused_deps",
        tool: "cargo-machete",
        readiness: "Rust + Cargo.toml",
    },
    NodeBehavior {
        id: "legacy.quality.swift-lint",
        check: "swift_lint",
        tool: "swiftlint",
        readiness: "Swift + swiftlint",
    },
    NodeBehavior {
        id: "legacy.quality.tool-coverage",
        check: "tool_coverage",
        tool: "fs",
        readiness: "always",
    },
    NodeBehavior {
        id: "legacy.quality.types",
        check: "types",
        tool: "tsc|basedpyright|mypy",
        readiness: "typed stack + checker",
    },
    NodeBehavior {
        id: "legacy.react.hooks-config",
        check: "react_hooks",
        tool: "fs",
        readiness: "Node + React dependency",
    },
    NodeBehavior {
        id: "legacy.runtime.app",
        check: "runtime",
        tool: "audit-runtime.mjs",
        readiness: "dev/start/preview/qa:browser script",
    },
    NodeBehavior {
        id: "legacy.security.binary-pins",
        check: "binary_pins",
        tool: "grep+github-api",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.security.dependency-pinning",
        check: "dep_pinning",
        tool: "grep",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.security.docker",
        check: "docker",
        tool: "hadolint",
        readiness: "Dockerfile",
    },
    NodeBehavior {
        id: "legacy.security.github-actions-lint",
        check: "ci_lint",
        tool: "actionlint",
        readiness: ".github/workflows",
    },
    NodeBehavior {
        id: "legacy.security.js-licenses",
        check: "js_licenses",
        tool: "license-checker",
        readiness: "Node + license-checker",
    },
    NodeBehavior {
        id: "legacy.security.node-dependencies",
        check: "deps_cve",
        tool: "npm|pnpm|yarn audit",
        readiness: "Node + package.json + lockfile",
    },
    NodeBehavior {
        id: "legacy.security.python-dependencies",
        check: "py_deps_cve",
        tool: "pip-audit",
        readiness: "Python project",
    },
    NodeBehavior {
        id: "legacy.security.rust-advisories",
        check: "cargo_audit",
        tool: "cargo-audit",
        readiness: "Rust + Cargo.lock",
    },
    NodeBehavior {
        id: "legacy.security.rust-policy",
        check: "cargo_deny",
        tool: "cargo-deny",
        readiness: "Rust",
    },
    NodeBehavior {
        id: "legacy.security.rust-unsafe",
        check: "cargo_unsafe",
        tool: "cargo-geiger",
        readiness: "Rust",
    },
    NodeBehavior {
        id: "legacy.security.sast",
        check: "sast",
        tool: "semgrep",
        readiness: "semgrep",
    },
    NodeBehavior {
        id: "legacy.security.secrets",
        check: "secrets",
        tool: "gitleaks",
        readiness: "gitleaks",
    },
    NodeBehavior {
        id: "legacy.security.vendored-dependencies",
        check: "vendored_deps",
        tool: "fs",
        readiness: "git",
    },
    NodeBehavior {
        id: "legacy.stack.node-outdated",
        check: "outdated",
        tool: "npm|pnpm outdated",
        readiness: "Node + package.json",
    },
    NodeBehavior {
        id: "legacy.stack.rust-outdated",
        check: "cargo_outdated",
        tool: "cargo-outdated",
        readiness: "Rust + Cargo.lock",
    },
    NodeBehavior {
        id: "legacy.tauri.capabilities",
        check: "tauri_capabilities",
        tool: "fs",
        readiness: "Tauri config",
    },
    NodeBehavior {
        id: "legacy.tauri.contract-mirror",
        check: "contract_mirror",
        tool: "grep",
        readiness: "Tauri config + git",
    },
];

const NATIVE_IDS: &[&str] = &[
    "legacy.apple.platform",
    "legacy.architecture.decomposition",
    "legacy.quality.negative-space",
    "legacy.quality.tool-coverage",
    "legacy.react.hooks-config",
    "legacy.security.binary-pins",
    "legacy.security.dependency-pinning",
    "legacy.security.vendored-dependencies",
    "legacy.tauri.capabilities",
    "legacy.tauri.contract-mirror",
];

fn node_registry() -> Vec<Value> {
    let registry: Value =
        serde_json::from_str(&fs::read_to_string(NODE_REGISTRY).unwrap()).unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|provider| provider["runner"]["kind"] == "legacy-check")
        .cloned()
        .collect()
}

fn behavior(id: &str) -> &'static NodeBehavior {
    NODE_BEHAVIOR
        .iter()
        .find(|row| row.id == id)
        .expect("Node behavior table row")
}

fn provider(record: &Value) -> AuditProvider {
    let id = record["id"].as_str().unwrap();
    spec(id).expect("Node record must have frozen Rust contract");
    AuditProvider {
        id: id.into(),
        version: record["providerVersion"].as_str().unwrap().into(),
        role: record["role"].as_str().unwrap().into(),
        phase: record["phase"].as_str().unwrap().into(),
        lens_ids: record["lensIds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        dependencies: Vec::new(),
        kind: ProviderKind::TypedExternalProjectTool,
        configuration: BTreeMap::from([
            ("selector".into(), record["selector"].clone()),
            ("runner".into(), record["runner"].clone()),
        ]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

fn fixture_root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("legion-legacy-equivalence-{suffix}-{id}"));
    fs::create_dir_all(root.join("src-tauri/capabilities")).unwrap();
    for (path, body) in [
        ("src/main.rs", "fn main() {}\n"),
        ("src/main.swift", "import Foundation\n"),
        (
            "src/App.tsx",
            "import React from 'react';\nexport const App = () => <div />;\n",
        ),
        ("src-tauri/frontend.ts", "invoke(\"ping\");\n"),
        (
            "src-tauri/backend.rs",
            "#[tauri::command]\npub fn ping() {}\n",
        ),
        ("src-tauri/tauri.conf.json", "{}\n"),
        (
            "src-tauri/capabilities/default.json",
            "{\"permissions\":[]}",
        ),
        ("package.json", "{}\n"),
        ("package-lock.json", "{}\n"),
        (
            "Cargo.toml",
            "[package]\nname=\"fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        ),
        ("Cargo.lock", "# fixture\n"),
        ("pyproject.toml", "[project]\nname=\"fixture\"\n"),
        ("requirements.txt", ""),
        ("Dockerfile", "FROM scratch\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
        ("vendor/dep/package.json", "{}\n"),
    ] {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }
    root
}

fn write_tool(root: &std::path::Path, name: &str) {
    let path = root.join("node_modules/.bin").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("fixture executable: {name}\n")).unwrap();
}

fn inventory() -> InventoryEnvelope {
    let entries = [
        ("src/main.rs", true, Vec::<&str>::new(), Vec::<&str>::new()),
        ("src/main.swift", true, Vec::new(), Vec::new()),
        ("src/App.tsx", true, vec!["react"], Vec::new()),
        ("src-tauri/frontend.ts", true, Vec::new(), Vec::new()),
        ("src-tauri/backend.rs", true, Vec::new(), Vec::new()),
        ("src-tauri/tauri.conf.json", false, Vec::new(), Vec::new()),
        (
            "src-tauri/capabilities/default.json",
            false,
            Vec::new(),
            Vec::new(),
        ),
        ("package.json", false, Vec::new(), vec!["build", "dev"]),
        ("package-lock.json", false, Vec::new(), Vec::new()),
        ("Cargo.toml", false, Vec::new(), Vec::new()),
        ("Cargo.lock", false, Vec::new(), Vec::new()),
        ("pyproject.toml", false, Vec::new(), Vec::new()),
        ("requirements.txt", false, Vec::new(), Vec::new()),
        ("Dockerfile", false, Vec::new(), Vec::new()),
        (".github/workflows/ci.yml", false, Vec::new(), Vec::new()),
        ("vendor/dep/package.json", false, Vec::new(), Vec::new()),
    ]
    .into_iter()
    .map(
        |(path, source_file, dependencies, package_scripts)| InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: dependencies.into_iter().map(str::to_owned).collect(),
            package_scripts: package_scripts.into_iter().map(str::to_owned).collect(),
            source_file,
            digest: None,
        },
    )
    .collect();
    InventoryEnvelope::new("legacy-equivalence", "generation-1", entries).unwrap()
}

fn plan_for(records: &[Value], inventory: &InventoryEnvelope) -> legion_audit::FrozenPlan {
    let specs = records
        .iter()
        .map(|record| serde_json::from_value(record.clone()).unwrap())
        .collect::<Vec<legion_contracts::ProviderSpec>>();
    AuditPlan::compile(inventory, &specs)
        .unwrap()
        .freeze(Some(b"equivalence-key"))
        .unwrap()
}

struct FakeTool {
    state: ExecutionState,
    body: Option<Vec<u8>>,
}

#[async_trait]
impl ExternalProjectTool for FakeTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        let mut receipt = ExecutionReceipt::failure(&request, self.state, self.state.as_str());
        receipt.process_tree.started = self.state == ExecutionState::Completed;
        receipt.process_tree.terminated = receipt.process_tree.started;
        receipt.process_tree.reaped = receipt.process_tree.started;
        receipt.parser.attempted = self.body.is_some();
        receipt.parser.succeeded = self.body.is_some();
        if self.state == ExecutionState::Completed {
            receipt.gaps.clear();
            receipt.complete = true;
            if let Some(body) = &self.body {
                let path = PathBuf::from(&request.cwd).join("provider-result.json");
                fs::write(&path, body).unwrap();
                receipt.stdout = Some(legion_effects::ArtifactRecord {
                    path: "provider-result.json".into(),
                    digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(body))),
                    bytes: body.len(),
                    immutable: true,
                });
                // `duplication` (jscpd) reads its report from a file under
                // the `--output` dir the real executor passes it
                // (`report_source_for("duplication")` in legacy_checks/mod.rs
                // is `ReportSource::File("_jscpd/jscpd-report.json")`), not
                // from stdout. A generic fixture body only on stdout leaves
                // that file absent, so the production code reports
                // `report-artifact-unreadable`/`artifact-bytes-unreadable`
                // and never completes — reproduce the real tool's on-disk
                // report so this all-providers loop covers file-sourced
                // checks too.
                if let Some(pos) = request.args.iter().position(|a| a == "--output") {
                    if let Some(out_dir) = request.args.get(pos + 1) {
                        let report_dir = PathBuf::from(out_dir).join("_jscpd");
                        fs::create_dir_all(&report_dir).unwrap();
                        fs::write(report_dir.join("jscpd-report.json"), body).unwrap();
                    }
                }
            }
        }
        if cancellation.is_cancelled() {
            receipt.state = ExecutionState::Cancelled;
            receipt.complete = false;
        }
        receipt
    }
}

#[test]
fn all_32_records_match_node_identity_and_explicit_readiness_table() {
    let node = node_registry();
    assert_eq!(node.len(), 32);
    assert_eq!(NODE_BEHAVIOR.len(), 32);
    assert_eq!(specs().len(), 32);
    let node_ids = node
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let rust_ids = specs()
        .iter()
        .map(|contract| contract.provider_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(node_ids, rust_ids);

    for record in node {
        let id = record["id"].as_str().unwrap();
        let row = behavior(id);
        let contract = spec(id).unwrap();
        assert_eq!(
            record["runner"]["check"].as_str(),
            Some(row.check),
            "{id} Node check"
        );
        assert_eq!(
            record["runner"]["check"].as_str(),
            Some(contract.check),
            "{id} Rust check"
        );
        assert_eq!(record["role"].as_str(), Some(contract.role), "{id} role");
        assert_eq!(record["phase"].as_str(), Some(contract.phase), "{id} phase");
        assert_eq!(
            record["selector"],
            serde_json::from_str::<Value>(contract.selector).unwrap(),
            "{id} selector"
        );
        assert_eq!(
            record["providerVersion"].as_str(),
            Some("2.0.0"),
            "{id} version"
        );
        assert!(
            !row.tool.is_empty() && !row.readiness.is_empty(),
            "{id} Node behavior row"
        );
    }
}

#[test]
fn rust_tool_labels_match_node_semantics_without_false_parity() {
    let mismatches = NODE_BEHAVIOR
        .iter()
        .filter_map(|row| {
            let rust = spec(row.id).unwrap().tool;
            (rust != row.tool).then_some((row.id, row.tool, rust))
        })
        .collect::<Vec<_>>();
    assert!(
        mismatches.is_empty(),
        "Rust/Node tool semantics diverge: {mismatches:?}"
    );
}

#[test]
fn symbolic_project_tools_resolve_to_sealed_exact_argv() {
    let root = fixture_root();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@11.18.0","scripts":{"build":"build"},"devDependencies":{"@biomejs/biome":"1","typescript":"1"}}"#,
    )
    .unwrap();
    fs::write(root.join("biome.json"), "{}").unwrap();
    fs::write(root.join("tsconfig.json"), "{}").unwrap();
    for tool in ["pnpm", "biome", "tsc"] {
        write_tool(&root, tool);
    }

    let build = resolve_request(&root, "project-build", &[]).unwrap();
    assert!(build.executable.is_absolute());
    assert_eq!(build.args, ["run", "build"]);
    assert!(build.digest.starts_with("sha256:"));

    let lint = resolve_request(&root, "project-lint", &["--json".into()]).unwrap();
    assert_eq!(
        lint.args,
        ["lint", ".", "--reporter=json", "--max-diagnostics=1000"]
    );

    let types = resolve_request(&root, "project-types", &["--json".into()]).unwrap();
    assert_eq!(types.args, ["--noEmit"]);

    let audit = resolve_request(&root, "package-audit", &["--json".into()]).unwrap();
    assert_eq!(audit.args, ["audit", "--json"]);
    fs::remove_dir_all(root).unwrap();

    let root = fixture_root();
    write_tool(&root, "cargo");
    let build = resolve_request(&root, "project-build", &[]).unwrap();
    assert_eq!(build.args, ["build"]);
    let lint = resolve_request(&root, "project-lint", &["--json".into()]).unwrap();
    assert_eq!(
        lint.args,
        [
            "clippy",
            "--all-targets",
            "--message-format=json",
            "--",
            "-D",
            "warnings"
        ]
    );
    fs::remove_file(root.join("Cargo.toml")).unwrap();
    fs::write(root.join("src-tauri/Cargo.toml"), "[workspace]\n").unwrap();
    let nested = resolve_request(&root, "project-build", &[]).unwrap();
    assert_eq!(nested.cwd, root.join("src-tauri"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_provider_binds_exact_selector_denominator_and_correct_route() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    let dispatcher = LegacyCheckDispatcher::new();
    let registry = NativeProviderRegistry::new(&root);
    let plan = plan_for(&records, &inventory);
    for record in records {
        let id = record["id"].as_str().unwrap();
        let provider = provider(&record);
        let request = dispatcher
            .request_for_path(&provider, &inventory, &root)
            .unwrap();
        let expected = inventory.denominator_entries(&record["selector"]).unwrap();
        assert_eq!(request.provider_id, id);
        assert_eq!(request.check, record["runner"]["check"].as_str().unwrap());
        assert_eq!(request.kind, "legion-named-check");
        assert_eq!(
            request.denominator.digest, expected.digest,
            "{id} denominator digest"
        );
        assert_eq!(
            request.denominator.entries, expected.entries,
            "{id} denominator entries"
        );
        let native_expected = NATIVE_IDS.contains(&id);
        assert_eq!(
            matches!(request.command, CommandShape::Native { .. }),
            native_expected,
            "{id} route"
        );
        assert_eq!(
            plan.provider(id).unwrap().kind,
            if native_expected {
                ProviderKind::RustAlgorithm
            } else {
                ProviderKind::TypedExternalProjectTool
            },
            "{id} planned route kind",
        );
        let result = registry.execute(&provider, &inventory).unwrap();
        assert_eq!(result.provider.to_string(), id);
        assert_eq!(
            result.coverage.as_ref().unwrap().denominator_digest,
            expected.digest,
            "{id} result denominator"
        );
        if native_expected {
            assert!(
                result.complete,
                "{id} deterministic fixture should complete: {:?}",
                result.coverage_gaps
            );
            assert_eq!(
                result.details["implementation"], "native-rust",
                "{id} authority"
            );
            assert_eq!(
                result.details["executionReceipt"]["kind"], "native-legacy-check-receipt",
                "{id} receipt authority"
            );
            assert_eq!(
                result.details["executionReceipt"]["processTree"]["started"], false,
                "{id} no fabricated process"
            );
        } else {
            assert!(
                !result.complete,
                "{id} must not claim external success without capability"
            );
            assert!(
                result
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap == "external-project-tool-capability-unavailable"),
                "{id} unavailable gap"
            );
            assert_eq!(
                result.coverage.as_ref().unwrap().examined,
                0,
                "{id} unavailable denominator"
            );
            assert_eq!(
                result.details["executionReceipt"]["processTree"]["started"], false,
                "{id} no process"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_runner_identity_is_rejected_for_each_frozen_provider() {
    let inventory = inventory();
    let root = fixture_root();
    let dispatcher = LegacyCheckDispatcher::new();
    for record in node_registry() {
        let id = record["id"].as_str().unwrap();
        let mut provider = provider(&record);
        provider.configuration.insert(
            "runner".into(),
            json!({"kind":"legacy-check","check":"not-the-frozen-check"}),
        );
        let error = dispatcher
            .request_for_path(&provider, &inventory, &root)
            .unwrap_err();
        assert_eq!(error.provider_id, id);
        assert_eq!(
            error.state,
            legion_audit::native_providers::legacy_checks::LegacyCheckProcessState::Failed,
            "{id} invalid state"
        );
        assert!(
            error.message.contains("runner check"),
            "{id} invalid detail: {}",
            error.message
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authorized_external_success_is_receipt_and_denominator_bound_for_all_external_providers() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    let plan = plan_for(&records, &inventory);
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(br#"{"complete":true,"status":"ok","coverageGaps":[]}"#.to_vec()),
        }));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut checked = 0;
    for record in records {
        let id = record["id"].as_str().unwrap();
        if NATIVE_IDS.contains(&id) {
            continue;
        }
        checked += 1;
        let provider = plan.provider(id).unwrap();
        assert_eq!(
            provider.kind,
            ProviderKind::TypedExternalProjectTool,
            "{id} route kind"
        );
        let result = runtime
            .block_on(registry.execute_async(&plan, provider, &inventory, CancellationToken::new()))
            .unwrap();
        assert!(
            result.complete,
            "{id} authorized fixture should complete: {:?}",
            result.coverage_gaps
        );
        assert_eq!(
            result.coverage.as_ref().unwrap().examined,
            result.coverage.as_ref().unwrap().expected,
            "{id} examined denominator"
        );
        assert_eq!(
            result.coverage.as_ref().unwrap().denominator_digest,
            provider.configuration["denominatorDigest"]
                .as_str()
                .unwrap(),
            "{id} bound denominator"
        );
        assert_eq!(
            result.details["executionReceipt"]["processTree"]["started"], true,
            "{id} receipt process authority"
        );
    }
    assert_eq!(checked, 22);
    fs::remove_dir_all(root).unwrap();
}

/// Checks whose `parsers::dispatch_text` handler is a plain freeform-text line
/// scan (`legacy_checks::parsers::{build,clippy,tsc,cargo_deny,cargo_machete,
/// debt_markers}`) always return `ParseOutcome::ok` — a count of zero for text
/// containing no matching lines is a legitimate result, not a parse failure,
/// matching the JS check's own tool-output-shape tolerance (these tools emit
/// freeform diagnostics, not a fixed schema). Whitespace-only stdout is
/// therefore *not* invalid output for these checks the way it is for the
/// JSON-schema-validated ones (jscpd, knip, semgrep, ...): `execution_from_
/// receipt` in legacy_checks/mod.rs sets `parsed = true` for them regardless
/// of content, so `output.complete` legitimately stays `true`.
const TEXT_PERMISSIVE_IDS: &[&str] = &[
    "legacy.quality.build",
    "legacy.quality.lint",
    "legacy.quality.types",
    "legacy.security.rust-policy",
    "legacy.quality.rust-unused-deps",
    "legacy.quality.debt-markers",
];

#[test]
fn invalid_external_output_and_terminal_failure_stay_unproven_for_each_external_provider() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    let plan = plan_for(&records, &inventory);
    let invalid_registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            // Whitespace is neither a JSON object nor a parseable text diagnostic.
            body: Some(b" \n".to_vec()),
        }));
    let failed_registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Timeout,
            body: None,
        }));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut checked = 0;
    for record in records {
        let id = record["id"].as_str().unwrap();
        if NATIVE_IDS.contains(&id) {
            continue;
        }
        checked += 1;
        let provider = plan.provider(id).unwrap();
        if !TEXT_PERMISSIVE_IDS.contains(&id) {
            let invalid = runtime
                .block_on(invalid_registry.execute_async(
                    &plan,
                    provider,
                    &inventory,
                    CancellationToken::new(),
                ))
                .unwrap();
            assert!(!invalid.complete, "{id} invalid output");
            assert!(
                invalid
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap == "artifact-bytes-unreadable"),
                "{id} invalid gap"
            );
        }
        let failed = runtime
            .block_on(failed_registry.execute_async(
                &plan,
                provider,
                &inventory,
                CancellationToken::new(),
            ))
            .unwrap();
        assert!(!failed.complete, "{id} timeout");
        assert_eq!(
            failed.details["executionReceipt"]["state"], "timeout",
            "{id} terminal state"
        );
        assert_eq!(
            failed.coverage.as_ref().unwrap().examined,
            0,
            "{id} failed denominator"
        );
    }
    assert_eq!(checked, 22);
    fs::remove_dir_all(root).unwrap();
}
