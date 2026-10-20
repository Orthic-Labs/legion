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
        resolve_request, spec, specs, CommandShape, LegacyCheckDispatcher, ResolveError,
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
const TEST_FIXTURE_PACKAGE_JSON: &str =
    "{\"scripts\":{\"build\":\"build\",\"dev\":\"dev\",\"test\":\"test\"}}\n";
const TEST_FIXTURE_PACKAGE_LOCK: &str = "{}\n";
const TEST_FIXTURE_CARGO_TOML: &str =
    "[package]\nname=\"fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n";
const TEST_FIXTURE_CARGO_LOCK: &str = "# fixture\n";
const TEST_FIXTURE_MACHETE_STDOUT: &[u8] =
    b"cargo-machete didn't find any unused dependencies in this directory. Good job!\n";
const TEST_FIXTURE_MACHETE_STDERR: &[u8] =
    b"Analyzing dependencies of crates in this directory...\nDone!\n";
const TEST_FIXTURE_CARGO_DENY_CLEAN: &[u8] = br#"{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"notes":0,"helps":0},"bans":{"errors":0,"warnings":0,"notes":0,"helps":0},"licenses":{"errors":0,"warnings":0,"notes":0,"helps":0},"sources":{"errors":0,"warnings":0,"notes":0,"helps":0}}}"#;

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
        id: "legacy.quality.test",
        check: "test",
        tool: "project-test",
        readiness: "declared package test script or root/src-tauri Cargo.toml",
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
        ("package.json", TEST_FIXTURE_PACKAGE_JSON),
        ("package-lock.json", TEST_FIXTURE_PACKAGE_LOCK),
        ("Cargo.toml", TEST_FIXTURE_CARGO_TOML),
        ("Cargo.lock", TEST_FIXTURE_CARGO_LOCK),
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

// FakeTool supplies execution; these distinct local bytes provide only the
// sealed identities required before the Cargo resolution copy is prepared.
// They are never launched as a real Cargo toolchain.
fn write_cargo_outdated_fixture_tools(root: &std::path::Path) {
    for name in ["cargo-outdated", "cargo", "rustc"] {
        write_tool(root, name);
        let resolved = resolve_request(root, name, &[]).unwrap();
        assert_eq!(
            resolved.executable,
            fs::canonicalize(root.join("node_modules/.bin").join(name)).unwrap()
        );
    }
}

// Cargo resolution copies every selected file, so only this check receives
// a fully byte-bound inventory. Other checks retain their refusal controls.
fn cargo_outdated_fixture_inventory(root: &std::path::Path) -> InventoryEnvelope {
    let mut entries = inventory().entries;
    for entry in &mut entries {
        entry.digest = Some(format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(
                fs::read(root.join(&entry.path)).unwrap()
            ))
        ));
    }
    InventoryEnvelope::new("legacy-equivalence", "generation-1", entries).unwrap()
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
        (
            "package.json",
            false,
            Vec::new(),
            vec!["build", "dev", "test"],
        ),
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
            digest: match path {
                "package.json" => Some(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(TEST_FIXTURE_PACKAGE_JSON.as_bytes()))
                )),
                "package-lock.json" => Some(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(TEST_FIXTURE_PACKAGE_LOCK.as_bytes()))
                )),
                "Cargo.toml" => Some(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(TEST_FIXTURE_CARGO_TOML.as_bytes()))
                )),
                "Cargo.lock" => Some(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(TEST_FIXTURE_CARGO_LOCK.as_bytes()))
                )),
                _ => None,
            },
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
        if request.task_id.as_deref() == Some("cargo_outdated") {
            let cwd = PathBuf::from(&request.cwd);
            if cwd.file_name().and_then(|name| name.to_str()) != Some("source") {
                if let Err(error) = resolve_request(&cwd, "cargo-outdated", &[]) {
                    // Match the real adapter's missing-tool refusal; successful
                    // fake output must not invent a prepared Cargo copy.
                    let state = match &error {
                        ResolveError::MissingExecutable(_) | ResolveError::NotConfigured(_) => {
                            ExecutionState::MissingExecutable
                        }
                        ResolveError::Unavailable(_) => ExecutionState::Internal,
                    };
                    return ExecutionReceipt::failure(&request, state, error.message());
                }
            }
        }
        let mut receipt = ExecutionReceipt::failure(&request, self.state, self.state.as_str());
        receipt.process_tree.started = self.state == ExecutionState::Completed;
        receipt.process_tree.terminated = receipt.process_tree.started;
        receipt.process_tree.reaped = receipt.process_tree.started;
        // actionlint, hadolint and swiftlint print a top-level JSON array, so
        // an object fixture body is an unexpected shape for them.
        let body_for_tool: Option<Vec<u8>> = match &self.body {
            Some(body)
                if request.task_id.as_deref() == Some("cargo_unused_deps")
                    && serde_json::from_slice::<Value>(body)
                        .is_ok_and(|value| value["complete"] == true) =>
            {
                Some(TEST_FIXTURE_MACHETE_STDOUT.to_vec())
            }
            Some(body)
                if request.task_id.as_deref() == Some("cargo_outdated")
                    && serde_json::from_slice::<Value>(body)
                        .is_ok_and(|value| value["complete"] == true) =>
            {
                // Strict report identity must match the existing executed root package.
                Some(br#"{"crate_name":"fixture","dependencies":[]}"#.to_vec())
            }
            Some(body)
                if request.task_id.as_deref() == Some("cargo_unsafe")
                    && serde_json::from_slice::<Value>(body)
                        .ok()
                        .is_some_and(|v| v["complete"] == true) =>
            {
                Some(include_bytes!("fixtures/legacy_parse/cargo_geiger.json").to_vec())
            }

            Some(body)
                if body.first() == Some(&b'{')
                    && ["actionlint", "hadolint", "swiftlint"]
                        .iter()
                        .any(|tool| request.executable.contains(tool)) =>
            {
                Some(b"[]".to_vec())
            }
            Some(body)
                if request.task_id.as_deref() == Some("cargo_deny")
                    && serde_json::from_slice::<serde_json::Value>(body)
                        .is_ok_and(|value| value["complete"] == true) =>
            {
                // Model cargo-deny's required native all-check summary.
                Some(TEST_FIXTURE_CARGO_DENY_CLEAN.to_vec())
            }
            other => other.clone(),
        };
        receipt.parser.attempted = body_for_tool.is_some();
        receipt.parser.succeeded = body_for_tool.is_some();
        if self.state == ExecutionState::Completed {
            receipt.gaps.clear();
            receipt.complete = true;
            receipt.exit_code = Some(0);
            if let Some(body) = &body_for_tool {
                let cwd = PathBuf::from(&request.cwd);
                // Stream artifacts belong outside the sealed Cargo resolution copy.
                let cargo_resolution = request.task_id.as_deref() == Some("cargo_outdated");
                let artifacts = if cargo_resolution {
                    assert_eq!(cwd.file_name().unwrap(), "source");
                    let parent = cwd.parent().unwrap();
                    assert_eq!(parent.file_name().unwrap(), "rust-outdated-resolution");
                    parent.to_path_buf()
                } else {
                    cwd
                };
                let path = artifacts.join("provider-result.json");
                fs::write(&path, body).unwrap();
                receipt.stdout = Some(legion_effects::ArtifactRecord {
                    path: if cargo_resolution {
                        path.to_string_lossy().into_owned()
                    } else {
                        "provider-result.json".into()
                    },
                    digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(body))),
                    bytes: body.len(),
                    immutable: true,
                });
                // `cargo_deny` reads its JSON from stderr
                // (`report_source_for("cargo_deny")` is `ReportSource::Stderr`),
                // so mirror the body there too, as the real tool would.
                // cargo-machete's completion contract binds both genuine stream shapes.
                // Invalid fixtures keep their original bytes in both streams.
                let stderr = if request.task_id.as_deref() == Some("cargo_unused_deps")
                    && body.as_slice() == TEST_FIXTURE_MACHETE_STDOUT
                {
                    TEST_FIXTURE_MACHETE_STDERR
                } else {
                    body.as_slice()
                };
                let err_path = artifacts.join("provider-result.stderr.json");
                fs::write(&err_path, stderr).unwrap();
                receipt.stderr = Some(legion_effects::ArtifactRecord {
                    path: if cargo_resolution {
                        err_path.to_string_lossy().into_owned()
                    } else {
                        "provider-result.stderr.json".into()
                    },
                    digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(stderr))),
                    bytes: stderr.len(),
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
fn all_33_records_match_node_identity_and_explicit_readiness_table() {
    let node = node_registry();
    assert_eq!(node.len(), 33);
    assert_eq!(NODE_BEHAVIOR.len(), 33);
    assert_eq!(specs().len(), 33);
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
    assert_eq!(
        build.args,
        ["--config.verify-deps-before-run=false", "run", "build"]
    );
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
    fs::remove_file(root.join("package.json")).unwrap();
    fs::remove_file(root.join("package-lock.json")).unwrap();
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
            let unavailable_reason = if id == "legacy.quality.test" {
                "unavailable:managed-test-trust-not-configured"
            } else {
                "external-project-tool-capability-unavailable"
            };
            assert!(
                result
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap == unavailable_reason),
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
            if id == "legacy.quality.test" {
                assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
                assert!(result.coverage.as_ref().unwrap().expected > 0);
                assert_eq!(
                    result.details["executionReceipt"]["state"],
                    "missing_executable"
                );
                assert_eq!(
                    result.details["executionReceipt"]["parser"]["attempted"],
                    false
                );
            }
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

// This mixed fixture deliberately selects unsupported pyproject input as well
// as requirements.txt. Preserve both paths: it must refuse before any tool call.
fn assert_python_input_refused(
    result: &legion_contracts::ProviderResult,
    provider: &AuditProvider,
) {
    assert!(result.applicable && !result.complete);
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, 2);
    assert_eq!(coverage.examined, 0);
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    let reason = "python-requirements-input-unavailable:unsupported-python-input:pyproject.toml";
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == &format!("unavailable:{reason}")));
    assert_eq!(result.details["pythonRequirements"]["reason"], reason);
    assert_eq!(result.details["availability"]["reason"], reason);
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        false
    );
    assert_eq!(
        result.details["executionReceipt"]["parser"]["attempted"],
        false
    );
    assert!(result.findings.is_empty());
}

// This mixed source fixture has no frozen source digests. Preserve all five
// selected paths: SAST must refuse before a tool or parser attempt.
fn assert_sast_source_input_refused(
    result: &legion_contracts::ProviderResult,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
) {
    let denominator = inventory
        .denominator_entries(&provider.configuration["selector"])
        .unwrap();
    assert_eq!(
        denominator
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "src/main.rs",
            "src/main.swift",
            "src/App.tsx",
            "src-tauri/frontend.ts",
            "src-tauri/backend.rs",
        ])
    );
    assert!(denominator
        .entries
        .iter()
        .all(|entry| entry.digest.is_none()));
    assert!(result.applicable && !result.complete);
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, 5);
    assert_eq!(coverage.examined, 0);
    assert_eq!(coverage.denominator_digest, denominator.digest);
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    let reason = "semgrep-selected-source-changed";
    assert!(coverage.gaps.iter().any(|gap| gap == reason));
    assert!(result.coverage_gaps.iter().any(|gap| gap == reason));
    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["state"], "failed");
    assert_eq!(receipt["processTree"]["started"], false);
    assert_eq!(receipt["parser"]["attempted"], false);
    assert_eq!(receipt["parser"]["succeeded"], false);
    assert_eq!(receipt["parser"]["error"], reason);
    assert!(result.findings.is_empty());
}

// Success assertions apply only after input prerequisites admit FakeTool.
// Python/SAST preflight refusals & node-outdated incompleteness stay explicit.
#[test]
fn authorized_external_success_is_receipt_and_denominator_bound_for_all_external_providers() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    write_cargo_outdated_fixture_tools(&root);
    let cargo_inventory = cargo_outdated_fixture_inventory(&root);
    let cargo_plan = plan_for(&records, &cargo_inventory);
    let plan = plan_for(&records, &inventory);
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            // `duplication` (jscpd)'s parser (`legacy_checks::parsers::jscpd`)
            // requires `statistics.total.clones` or an array `duplicates`
            // field — an explicit "malformed output" rule ported from JS
            // (`count === null -> status 'error'`), not a generic
            // complete/status/coverageGaps envelope. Since this fixture body
            // is shared across every external provider (including the
            // on-disk `_jscpd/jscpd-report.json` this FakeTool also writes
            // it to), it needs `duplicates: []` so jscpd's own schema is
            // satisfied without disturbing the other 21 providers' parsers,
            // which ignore the extra key. It also needs a
            // `metadata.vulnerabilities.total` key so `deps_cve`
            // (`legacy_checks::parsers::deps_cve`, mirroring
            // collect-facts.mjs's npm/pnpm-audit parser) finds a proven
            // zero-vulnerability count instead of treating the body as
            // unparseable.
            body: Some(br#"{"complete":true,"status":"ok","coverageGaps":[],"duplicates":[],"metadata":{"vulnerabilities":{"total":0}},"files":[],"diagnostics":[],"summary":{"errorCount":0},"results":[],"vulnerabilities":{"count":0},"packages":[],"dependencies":[]}"#.to_vec()),
        }));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut checked = 0;
    for record in records {
        let id = record["id"].as_str().unwrap();
        let (plan, inventory) = if id == "legacy.stack.rust-outdated" {
            (&cargo_plan, &cargo_inventory)
        } else {
            (&plan, &inventory)
        };
        // `legacy.runtime.app` runs one browser invocation per surface and
        // builds its own evidence; it is covered by
        // `native_legacy_runtime_capture.rs`.
        if NATIVE_IDS.contains(&id) || id == "legacy.runtime.app" {
            continue;
        }
        let provider = plan.provider(id).unwrap();
        if id == "legacy.quality.test" {
            let result = runtime
                .block_on(registry.execute_async(
                    &plan,
                    provider,
                    &inventory,
                    CancellationToken::new(),
                ))
                .unwrap();
            let coverage = result.coverage.as_ref().unwrap();
            assert!(!result.complete, "managed tests need enrolled trust");
            assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
            assert!(coverage.expected > 0);
            assert_eq!(coverage.examined, 0);
            assert_eq!(
                coverage.denominator_digest,
                provider.configuration["denominatorDigest"]
                    .as_str()
                    .unwrap()
            );
            assert!(result
                .coverage_gaps
                .iter()
                .any(|gap| gap == "unavailable:managed-test-trust-not-configured"));
            assert_eq!(
                result.details["availability"]["reason"],
                "managed-test-trust-not-configured"
            );
            assert_eq!(
                result.details["executionReceipt"]["state"],
                "missing_executable"
            );
            assert_eq!(
                result.details["executionReceipt"]["processTree"]["started"],
                false
            );
            assert_eq!(
                result.details["executionReceipt"]["parser"]["attempted"],
                false
            );
            continue;
        }
        if id == "legacy.security.python-dependencies" {
            let result = runtime
                .block_on(registry.execute_async(
                    &plan,
                    provider,
                    &inventory,
                    CancellationToken::new(),
                ))
                .unwrap();
            assert_python_input_refused(&result, provider);
            continue;
        }
        if id == "legacy.security.sast" {
            let result = runtime
                .block_on(registry.execute_async(
                    &plan,
                    provider,
                    &inventory,
                    CancellationToken::new(),
                ))
                .unwrap();
            assert_sast_source_input_refused(&result, provider, &inventory);
            continue;
        }
        if id == "legacy.stack.node-outdated" {
            let result = runtime
                .block_on(registry.execute_async(
                    &plan,
                    provider,
                    &inventory,
                    CancellationToken::new(),
                ))
                .unwrap();
            assert!(
                !result.complete,
                "standalone fake report lacks installed/registry completion evidence"
            );
            assert!(!result.coverage_gaps.is_empty());
            assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
            continue;
        }
        checked += 1;
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
        if id == "legacy.stack.rust-outdated" {
            let resolution = &result.details["rustOutdatedResolution"];
            assert_eq!(resolution["valid"], true);
            assert_eq!(resolution["sourceUnchanged"], true);
            assert_eq!(resolution["runtimeUnchanged"], true);
            assert_eq!(resolution["postimage"], resolution["preimage"]);
            assert_eq!(resolution["deltas"], json!([]));
            assert_ne!(resolution["executionCwd"], resolution["sourceCwd"]);
            assert_eq!(
                resolution["executionCwd"],
                result.details["executionReceipt"]["cwd"]
            );
        }
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
    // Managed tests need enrolled trust; Python/SAST inputs fail preflight.
    // None of these prerequisite refusals can be a successful FakeTool run.
    assert_eq!(checked, 18);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cargo_deny_single_json_and_jsonl_keep_native_summary_contract() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    let plan = plan_for(&records, &inventory);
    let provider = plan.provider("legacy.security.rust-policy").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let info = b"{\"type\":\"log\",\"fields\":{\"level\":\"INFO\",\"message\":\"checked\"}}\n";
    let error =
        b"{\"type\":\"log\",\"fields\":{\"level\":\"ERROR\",\"message\":\"database missing\"}}\n";
    for (label, body, complete) in [
        (
            "single summary",
            TEST_FIXTURE_CARGO_DENY_CLEAN.to_vec(),
            true,
        ),
        (
            "JSONL summary",
            [info.as_slice(), TEST_FIXTURE_CARGO_DENY_CLEAN].concat(),
            true,
        ),
        (
            "incomplete schema",
            br#"{"type":"summary","fields":{}}"#.to_vec(),
            false,
        ),
        (
            "duplicate summary",
            [
                TEST_FIXTURE_CARGO_DENY_CLEAN,
                b"\n",
                TEST_FIXTURE_CARGO_DENY_CLEAN,
            ]
            .concat(),
            false,
        ),
        (
            "operational error",
            [error.as_slice(), TEST_FIXTURE_CARGO_DENY_CLEAN].concat(),
            false,
        ),
    ] {
        let registry =
            NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
                state: ExecutionState::Completed,
                body: Some(body.clone()),
            }));
        let result = runtime
            .block_on(registry.execute_async(&plan, provider, &inventory, CancellationToken::new()))
            .unwrap();
        assert_eq!(
            result.complete, complete,
            "{label}: {:?}",
            result.coverage_gaps
        );
        let receipt = &result.details["executionReceipt"];
        assert_eq!(receipt["state"], "completed", "{label}");
        assert_eq!(receipt["complete"], true, "{label}");
        assert_eq!(receipt["exitCode"], 0, "{label}");
        assert_eq!(receipt["reportSource"], "stderr", "{label}");
        assert_eq!(receipt["stderr"]["immutable"], true, "{label}");
        assert_eq!(
            receipt["stderr"]["digest"],
            format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body))),
            "{label} original stream"
        );
        assert!(result.findings.is_empty(), "{label}");
        assert!(
            result.details["candidates"].as_array().unwrap().is_empty(),
            "{label}"
        );
        if complete {
            assert!(result.coverage_gaps.is_empty(), "{label}");
            assert_eq!(result.details["findingsCount"], 0, "{label}");
            let coverage = result.coverage.as_ref().unwrap();
            assert_eq!(coverage.examined, coverage.expected, "{label}");
            assert_eq!(
                coverage.denominator_digest,
                provider.configuration["denominatorDigest"]
                    .as_str()
                    .unwrap(),
                "{label} denominator"
            );
        } else {
            assert!(
                result
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap == "cargo-deny-completion-unproven"),
                "{label}"
            );
            assert!(result.details["findingsCount"].is_null(), "{label}");
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cargo_deny_reconciled_summary_with_wrong_exit_stays_unproven() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    let plan = plan_for(&records, &inventory);
    // This fixture has a complete summary matching both diagnostic lines,
    // but its bans error requires bitset exit 2. FakeTool returns exit 0.
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(include_bytes!("fixtures/legacy_parse/cargo_deny.jsonl").to_vec()),
        }));
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(registry.execute_async(
            &plan,
            plan.provider("legacy.security.rust-policy").unwrap(),
            &inventory,
            CancellationToken::new(),
        ))
        .unwrap();
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "cargo-deny-completion-unproven"));
    assert!(result.findings.is_empty());
    assert!(result.details["candidates"].as_array().unwrap().is_empty());
    assert!(result.details["findingsCount"].is_null());
    fs::remove_dir_all(root).unwrap();
}

/// Checks whose `parsers::dispatch_text` handler is a plain freeform-text line
/// scan (`legacy_checks::parsers::{build,clippy,tsc,debt_markers}`)
/// always return `ParseOutcome::ok` — a count of zero for text
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
    "legacy.quality.debt-markers",
];

// Invalid-output/timeout assertions apply to launched FakeTool controls;
// Python/SAST retain distinct no-launch prerequisite assertions.
#[test]
fn invalid_external_output_and_terminal_failure_stay_unproven_for_each_external_provider() {
    let records = node_registry();
    let inventory = inventory();
    let root = fixture_root();
    write_cargo_outdated_fixture_tools(&root);
    let cargo_inventory = cargo_outdated_fixture_inventory(&root);
    let cargo_plan = plan_for(&records, &cargo_inventory);
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
        let (plan, inventory) = if id == "legacy.stack.rust-outdated" {
            (&cargo_plan, &cargo_inventory)
        } else {
            (&plan, &inventory)
        };
        // `legacy.runtime.app` runs one browser invocation per surface and
        // builds its own evidence; it is covered by
        // `native_legacy_runtime_capture.rs`.
        if NATIVE_IDS.contains(&id) || id == "legacy.runtime.app" || id == "legacy.quality.test" {
            continue;
        }
        if id == "legacy.security.python-dependencies" {
            let provider = plan.provider(id).unwrap();
            for registry in [&invalid_registry, &failed_registry] {
                let result = runtime
                    .block_on(registry.execute_async(
                        &plan,
                        provider,
                        &inventory,
                        CancellationToken::new(),
                    ))
                    .unwrap();
                assert_python_input_refused(&result, provider);
            }
            continue;
        }
        if id == "legacy.security.sast" {
            let provider = plan.provider(id).unwrap();
            // Both registries are refused before invalid output or timeout
            // can be exercised; these are source-prerequisite controls only.
            for registry in [&invalid_registry, &failed_registry] {
                let result = runtime
                    .block_on(registry.execute_async(
                        &plan,
                        provider,
                        &inventory,
                        CancellationToken::new(),
                    ))
                    .unwrap();
                assert_sast_source_input_refused(&result, provider, &inventory);
            }
            continue;
        }
        if id == "legacy.stack.node-outdated" {
            let provider = plan.provider(id).unwrap();
            for registry in [&invalid_registry, &failed_registry] {
                let result = runtime
                    .block_on(registry.execute_async(
                        &plan,
                        provider,
                        &inventory,
                        CancellationToken::new(),
                    ))
                    .unwrap();
                assert!(!result.complete && !result.coverage_gaps.is_empty());
                assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
            }
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
                    .any(|gap| gap == "artifact-bytes-unreadable"
                        || gap == "cargo-deny-completion-unproven"
                        || gap == "cargo-machete-analysis-unproven"
                        || gap.starts_with("legacy-tool-output-unparseable:")),
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
    // Managed-test & Python/SAST input refusals happen before launch;
    // timeout results here must correspond to a tool that was called.
    assert_eq!(checked, 18);
    fs::remove_dir_all(root).unwrap();
}
