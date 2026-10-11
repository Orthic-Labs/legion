//! The `code.*` providers source their own evidence from the frozen
//! denominator. No test here depends on any external tool being installed.
use legion_audit::{
    native_providers::code::{evidence::EvidenceLimits, ProviderExecutorAdapter},
    AuditProvider, InventoryEntry, InventoryEnvelope, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderStatus};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn fixture(files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-code-evidence-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    for (path, body) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, body).unwrap();
    }
    root
}

fn entry(root: &Path, path: &str) -> InventoryEntry {
    let digest = fs::read(root.join(path))
        .ok()
        .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
        source_file: true,
        digest,
    }
}

fn inventory(root: &Path, paths: &[&str]) -> InventoryEnvelope {
    InventoryEnvelope::new(
        "code-evidence",
        "generation",
        paths.iter().map(|path| entry(root, path)).collect(),
    )
    .unwrap()
}

fn provider(id: &str) -> AuditProvider {
    AuditProvider {
        id: id.into(),
        version: "1.0.0".into(),
        role: "diagnose".into(),
        phase: "p1".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), json!({"op": "always"}))]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

/// `rule@path:line` for every finding, with the authority maps cross-checked.
fn located(result: &ProviderResult) -> BTreeSet<String> {
    let evidence = result.details["findingEvidence"].as_object().unwrap();
    let locations = result.details["findingLocations"].as_object().unwrap();
    assert_eq!(evidence.len(), result.findings.len());
    result
        .findings
        .iter()
        .map(|finding| {
            let item = &evidence[finding.id.as_str()];
            let at = locations[finding.id.as_str()][0].as_str().unwrap();
            assert_eq!(
                at,
                format!("{}:{}", item["path"].as_str().unwrap(), item["line"])
            );
            format!("{}@{at}", item["ruleId"].as_str().unwrap())
        })
        .collect()
}

const DEFECT_FILES: &[(&str, &str)] = &[
    (
        "src/lib.rs",
        "// TODO: remove the shim\nfn run() {\n    compute().ok();\n    dbg!(1);\n}\n",
    ),
    (
        "web/app.js",
        "function load() {\n  try { risky(); } catch (e) {}\n  debugger;\n}\n",
    ),
    (
        "tools/job.py",
        "def job():\n    try:\n        work()\n    except:\n        pass\n",
    ),
    ("svc/main.go", "package main\nfunc f() {\n    _ = g()\n}\n"),
    (
        "a/One.java",
        "class One {\n  int runOne() {\n    int total = computeTotal(order, rates);\n    int tax = computeTax(total, region);\n    int fee = computeFee(total, tax, plan);\n    int sum = total + tax + fee - discount;\n    audit.record(order, sum, region, plan);\n    return finalizeInvoice(order, sum, audit);\n  }\n}\n",
    ),
    (
        "a/Two.java",
        "class Two {\n  int runTwo() {\n    int total = computeTotal(order, rates);\n    int tax = computeTax(total, region);\n    int fee = computeFee(total, tax, plan);\n    int sum = total + tax + fee - discount;\n    audit.record(order, sum, region, plan);\n    return finalizeInvoice(order, sum, audit);\n  }\n}\n",
    ),
    ("README.md", "# readme\n"),
];

const DEFECT_PATHS: &[&str] = &[
    "README.md",
    "a/One.java",
    "a/Two.java",
    "src/lib.rs",
    "svc/main.go",
    "tools/job.py",
    "web/app.js",
];

fn run(root: &Path, paths: &[&str], id: &str) -> ProviderResult {
    ProviderExecutorAdapter::new()
        .with_root(root)
        .execute(&provider(id), &inventory(root, paths))
        .unwrap()
}

#[test]
fn planted_defects_are_found_with_exact_locations_and_counts() {
    let root = fixture(DEFECT_FILES);
    let cases: &[(&str, &[&str], u64)] = &[
        (
            "code.rust",
            &[
                "debt-marker@src/lib.rs:1",
                "error-swallowed@src/lib.rs:3",
                "debug-leftover@src/lib.rs:4",
            ],
            1,
        ),
        (
            "code.javascript",
            &["empty-catch@web/app.js:2", "debug-leftover@web/app.js:3"],
            1,
        ),
        (
            "code.python",
            &[
                "bare-except@tools/job.py:4",
                "swallowed-exception@tools/job.py:4",
            ],
            1,
        ),
        ("code.go", &["ignored-error@svc/main.go:3"], 1),
        ("code.jvm", &["duplicate-block@a/Two.java:3"], 2),
    ];
    for (id, expected, files) in cases {
        let result = run(&root, DEFECT_PATHS, id);
        assert_eq!(
            located(&result),
            expected
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<String>>(),
            "{id}"
        );
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(
            (coverage.expected, coverage.examined),
            (DEFECT_PATHS.len() as u64, *files),
            "{id}: expected is the frozen denominator count"
        );
        assert_eq!(
            coverage.denominator_digest,
            inventory(&root, DEFECT_PATHS).digest
        );
        assert!(
            !result.complete,
            "{id}: no tool receipts, so never complete"
        );
        assert_eq!(result.status, ProviderStatus::Partial);
        assert_eq!(
            result.details["nativeAnalysis"]["denominator"]["examined"],
            json!(files)
        );
        result.validate().unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clean_fixture_yields_no_findings_and_typed_tool_gaps() {
    let root = fixture(&[(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n",
    )]);
    let result = run(&root, &["src/lib.rs"], "code.rust");
    assert!(result.findings.is_empty());
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert!(!result.complete);
    for tool in ["metadata", "check", "lint", "test", "dependency"] {
        let missing = format!("unavailable:tool-missing:{tool}");
        let unrun = format!("unavailable:tool-not-run:{tool}");
        assert!(
            result.coverage_gaps.contains(&missing) || result.coverage_gaps.contains(&unrun),
            "{tool} must be a typed gap, never a pass: {:?}",
            result.coverage_gaps
        );
    }
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap.contains("file-skipped")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unread_files_are_named_gaps_and_never_counted_as_examined() {
    let root = fixture(&[
        ("src/a.rs", "pub fn a() {}\n"),
        (
            "src/big.rs",
            &"// padding line to exceed the cap\n".repeat(40),
        ),
        ("src/b.rs", "pub fn b() {}\n"),
    ]);
    let inv = inventory(
        &root,
        &["src/a.rs", "src/b.rs", "src/big.rs", "src/gone.rs"],
    );
    let adapter = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_limits(EvidenceLimits {
            max_file_bytes: 200,
            ..EvidenceLimits::default()
        });
    let result = adapter.execute(&provider("code.rust"), &inv).unwrap();
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (4, 2));
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:file-size-cap:src/big.rs".to_string()));
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:missing:src/gone.rs".to_string()));
    assert!(!result.complete);

    // Total cap: only the first file fits, the rest are named skips.
    let adapter = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_limits(EvidenceLimits {
            max_total_bytes: 14,
            ..EvidenceLimits::default()
        });
    let result = adapter.execute(&provider("code.rust"), &inv).unwrap();
    assert_eq!(result.coverage.as_ref().unwrap().examined, 1);
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:total-size-cap:src/b.rs".to_string()));

    // A file that changed after inventory is not examined.
    fs::write(root.join("src/a.rs"), "pub fn a() { /* TODO */ }\n").unwrap();
    let result = adapter_for(&root)
        .execute(&provider("code.rust"), &inv)
        .unwrap();
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:changed-since-inventory:src/a.rs".to_string()));
    assert!(result.findings.is_empty());
    fs::remove_dir_all(root).unwrap();
}

fn adapter_for(root: &Path) -> ProviderExecutorAdapter {
    ProviderExecutorAdapter::new().with_root(root)
}

#[test]
fn host_injected_input_takes_precedence_and_is_not_replaced() {
    let root = fixture(DEFECT_FILES);
    let inv = inventory(&root, DEFECT_PATHS);

    let injected = json!({"files": [{"path": "src/lib.rs"}]});
    let via_builder = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_input("code.rust", injected.clone())
        .execute(&provider("code.rust"), &inv)
        .unwrap();
    let mut configured = provider("code.rust");
    configured.configuration.insert("input".into(), injected);
    let via_configuration = adapter_for(&root).execute(&configured, &inv).unwrap();

    for result in [via_builder, via_configuration] {
        assert!(result.findings.is_empty(), "injected input is not re-read");
        assert!(!result.details.contains_key("nativeProducer"));
        assert!(result
            .coverage_gaps
            .contains(&"unavailable:tool-evidence-not-produced:code.rust".to_string()));
        assert_eq!(
            result.coverage.as_ref().unwrap().expected,
            inv.entries.len() as u64
        );
        assert!(!result.complete);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn long_tail_reads_unclaimed_source_files() {
    let root = fixture(&[
        ("lib/tool.lua", "-- helper\n-- TODO: port this\nreturn 1\n"),
        ("src/lib.rs", "pub fn a() {}\n"),
    ]);
    let result = run(&root, &["lib/tool.lua", "src/lib.rs"], "code.long-tail");
    assert_eq!(
        located(&result),
        BTreeSet::from(["debt-marker@lib/tool.lua:2".to_string()])
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (2, 1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn long_tail_with_host_input_and_no_rules_is_not_complete() {
    let root = fixture(&[("lib/tool.lua", "return 1\n")]);
    let inv = inventory(&root, &["lib/tool.lua"]);
    let adapter = ProviderExecutorAdapter::new().with_input(
        "code.long-tail",
        json!({"files": [{"path": "lib/tool.lua"}]}),
    );
    let result = adapter.execute(&provider("code.long-tail"), &inv).unwrap();
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap.ends_with("no-rules-applicable")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn language_with_no_files_is_a_denominator_gap_not_a_pass() {
    let root = fixture(&[("README.md", "# readme\n")]);
    let result = run(&root, &["README.md"], "code.python");
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 0));
    assert!(!result.complete);
    assert!(result.findings.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn frozen_count_differing_from_language_count_is_valid_and_not_complete() {
    let root = fixture(DEFECT_FILES);
    let inv = inventory(&root, DEFECT_PATHS);
    // The plan recorded a denominator count and digest at freeze time.
    let mut planned = provider("code.rust");
    planned
        .configuration
        .insert("denominatorCount".into(), json!(DEFECT_PATHS.len()));
    planned
        .configuration
        .insert("denominatorDigest".into(), json!(inv.digest.clone()));
    let result = adapter_for(&root).execute(&planned, &inv).unwrap();
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, DEFECT_PATHS.len() as u64);
    assert_eq!(coverage.examined, 1, "only the one Rust file was read");
    assert_eq!(coverage.denominator_digest, inv.digest);
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("code.rust:selection-narrower-than-denominator:1of7")));
    assert_eq!(result.findings.len(), 3, "findings are preserved");
    result.validate().unwrap();
    fs::remove_dir_all(root).unwrap();
}

// ---------------------------------------------------------------------------
// Real tool runs through the external-tool route.
//
// Unix-only: the stub "tools" are `#!/bin/sh` scripts placed in a temp
// directory that is the adapter's explicit search path. No real compiler or
// linter is needed, and the OS sandbox is disabled by policy so the tests do
// not depend on a sandbox authenticator being present on the host.
// ---------------------------------------------------------------------------
#[cfg(unix)]
mod real_tools {
    use super::*;
    use async_trait::async_trait;
    use legion_audit::{
        native_providers::{
            legacy_checks::{AuditExternalProjectTool, AuditScratch},
            security::producer::SandboxPolicy,
        },
        AuditPlan, FrozenPlan,
    };
    use legion_provider_sdk::{
        ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
    };
    use std::sync::{Arc, Mutex};
    use tokio_util::sync::CancellationToken;

    const CLEAN_RUST: &str =
        "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n\npub fn one() -> u32 {\n    1\n}\n";

    /// Canned `cargo check --message-format=json` output: an error in the
    /// denominator, a warning in the denominator, and an error in a file that
    /// is not part of it.
    const CARGO_STUB: &str = r#"#!/bin/sh
case "$1" in
  --version) echo "cargo 9.9.9 (stub)"; exit 0;;
  metadata) printf '%s\n' '{"packages":[],"workspace_root":"/stub"}'; exit 0;;
  check)
    printf '%s\n' '{"reason":"compiler-message","message":{"level":"error","message":"mismatched types","code":{"code":"E0308"},"spans":[{"file_name":"src/lib.rs","line_start":3,"is_primary":true}]}}'
    printf '%s\n' '{"reason":"compiler-message","message":{"level":"warning","message":"unused variable","code":{"code":"unused_variables"},"spans":[{"file_name":"src/lib.rs","line_start":6,"is_primary":true}]}}'
    printf '%s\n' '{"reason":"compiler-message","message":{"level":"error","message":"elsewhere","code":{"code":"E0425"},"spans":[{"file_name":"vendor/dep/src/lib.rs","line_start":1,"is_primary":true}]}}'
    printf '%s\n' '{"reason":"build-finished","success":false}'
    exit 101;;
esac
exit 3
"#;

    fn stub_dir(files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-code-stubs-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            let path = dir.join(name);
            fs::write(&path, body).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    fn frozen_plan() -> FrozenPlan {
        let seed = InventoryEnvelope::new(
            "plan",
            "generation",
            vec![InventoryEntry {
                path: "package.json".into(),
                symbols: vec![],
                dependencies: vec![],
                package_scripts: vec![],
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        AuditPlan::compile(&seed, &[serde_json::from_value(json!({
            "schemaVersion":2,"id":"legacy.quality.build","providerVersion":"2.0.0","family":"legacy","role":"deterministic","phase":"source","lensIds":["installer-hygiene"],"dependsOn":[],"consumes":["repository-inventory"],"produces":["provider-result"],"selector":{"op":"always"},"denominatorKind":"repository-inventory","runner":{"kind":"legacy-check","check":"build"},"hostCapabilities":[],"execution":{},"reasoning":{},"benchmark":{"status":"unproven","requiredForCleanClaim":false},"cleanClaim":"evidence-only","controlIds":[],"scopes":[],"selectable":true
        })).unwrap()]).unwrap().freeze(Some(b"test-key")).unwrap()
    }

    /// The production route: sandbox-capable executor behind the audit adapter,
    /// artifacts rooted at the run scratch.
    fn real_tool(scratch: &AuditScratch) -> Arc<dyn ExternalProjectTool> {
        let effects = legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            legion_effects::StaticPolicy {
                decision: legion_effects::PolicyDecision {
                    allowed: true,
                    policy_id: "audit".into(),
                    policy_version: 1,
                    policy_digest: "sha256:audit".into(),
                    reason: None,
                },
            },
        );
        Arc::new(AuditExternalProjectTool::new(effects))
    }

    fn run_async(
        adapter: &ProviderExecutorAdapter,
        root: &Path,
        paths: &[&str],
        tool: Arc<dyn ExternalProjectTool>,
        scratch: Arc<AuditScratch>,
    ) -> ProviderResult {
        let inv = inventory(root, paths);
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(adapter.execute_async(
                &frozen_plan(),
                &provider("code.rust"),
                &inv,
                tool,
                scratch,
                CancellationToken::new(),
            ))
            .unwrap()
    }

    fn adapter(root: &Path, search: Vec<PathBuf>) -> ProviderExecutorAdapter {
        ProviderExecutorAdapter::new()
            .with_root(root)
            .with_search_path(search)
            .with_sandbox(SandboxPolicy::Disabled)
    }

    /// Every file and directory under `root` with its size.
    fn listing(root: &Path) -> BTreeSet<String> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(format!("{relative}:{}", meta.len()));
                if meta.is_dir() {
                    walk(&path, root, out);
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(root, root, &mut out);
        out
    }

    const RUST_FILES: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", CLEAN_RUST),
    ];
    const RUST_PATHS: &[&str] = &["Cargo.toml", "src/lib.rs"];

    #[test]
    fn stub_cargo_diagnostics_become_findings_with_receipts_and_nothing_is_written() {
        let root = fixture(RUST_FILES);
        let stubs = stub_dir(&[("cargo", CARGO_STUB)]);
        let scratch = Arc::new(AuditScratch::create(&root).unwrap());
        let before = listing(&root);

        let result = run_async(
            &adapter(&root, vec![stubs.clone()]),
            &root,
            RUST_PATHS,
            real_tool(&scratch),
            scratch.clone(),
        );

        // Findings: path:line from the primary span; the out-of-denominator
        // diagnostic is dropped and counted.
        assert_eq!(
            located(&result),
            BTreeSet::from([
                "rustc:E0308@src/lib.rs:3".to_string(),
                "rustc:unused_variables@src/lib.rs:6".to_string(),
            ])
        );
        let evidence = result.details["findingEvidence"].as_object().unwrap();
        let severities = result
            .findings
            .iter()
            .map(|finding| {
                (
                    evidence[finding.id.as_str()]["ruleId"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    finding.severity.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(severities["rustc:E0308"], "error");
        assert_eq!(severities["rustc:unused_variables"], "warning");
        assert!(result
            .coverage_gaps
            .contains(&"code.rust:tool-diagnostics-outside-denominator:1".to_string()));

        // Receipts: argv, exit code, version, offline flag, sandbox mode.
        let receipts = result.details["nativeProducer"]["toolReceipts"]
            .as_array()
            .unwrap();
        let check = receipts
            .iter()
            .find(|receipt| receipt["tool"] == "check")
            .expect("check receipt");
        assert_eq!(check["exitCode"], json!(101));
        assert_eq!(check["offline"], json!(true));
        assert_eq!(check["version"], json!("cargo 9.9.9 (stub)"));
        assert_eq!(check["sandbox"]["mode"], json!("disabled"));
        let argv = check["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            [
                "cargo",
                "check",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--message-format=json"
            ]
        );
        assert!(check["artifactDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(check["executableDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));

        // Tool evidence cleared for the tools that ran; typed gaps for the rest.
        let gaps = &result.coverage_gaps;
        for ran in ["metadata", "check"] {
            assert!(
                !gaps
                    .iter()
                    .any(|gap| gap == &format!("code.rust:tool-evidence-gap:{ran}")),
                "{ran} ran with a receipt: {gaps:?}"
            );
            assert!(!gaps
                .iter()
                .any(|gap| gap == &format!("unavailable:tool-missing:{ran}")));
        }
        assert_eq!(
            result.details["nativeAnalysis"]["toolEvidence"][1]["status"],
            "pass"
        );
        assert!(
            gaps.contains(&"unavailable:tool-missing:lint".to_string()),
            "no cargo-clippy: {gaps:?}"
        );
        assert!(gaps.contains(
            &"unavailable:tool-not-run:test:policy-no-project-code-execution".to_string()
        ));
        assert!(!result.complete);
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!((coverage.expected, coverage.examined), (2, 1));
        result.validate().unwrap();

        // Nothing was written into the audited tree.
        assert_eq!(listing(&root), before);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(stubs).unwrap();
    }

    #[test]
    fn missing_tools_are_typed_gaps_and_no_receipt_is_invented() {
        let root = fixture(RUST_FILES);
        let empty = stub_dir(&[]);
        let scratch = Arc::new(AuditScratch::create(&root).unwrap());
        let result = run_async(
            &adapter(&root, vec![empty.clone()]),
            &root,
            RUST_PATHS,
            real_tool(&scratch),
            scratch.clone(),
        );
        assert!(result.findings.is_empty());
        for tool in ["metadata", "check", "lint"] {
            assert!(
                result
                    .coverage_gaps
                    .contains(&format!("unavailable:tool-missing:{tool}")),
                "{tool}: {:?}",
                result.coverage_gaps
            );
            assert!(result
                .coverage_gaps
                .contains(&format!("code.rust:tool-evidence-gap:{tool}")));
        }
        assert!(result.details["nativeProducer"]["toolReceipts"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!result.complete);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(empty).unwrap();
    }

    /// Records every request and answers `Timeout`, so the typed timeout gap
    /// and the request shape can be asserted without running anything.
    struct TimeoutTool {
        requests: Arc<Mutex<Vec<ExternalToolRequest>>>,
    }

    #[async_trait]
    impl ExternalProjectTool for TimeoutTool {
        async fn execute(
            &self,
            request: ExternalToolRequest,
            _cancellation: CancellationToken,
        ) -> ExecutionReceipt {
            self.requests.lock().unwrap().push(request.clone());
            ExecutionReceipt::failure(&request, ExecutionState::Timeout, "timeout")
        }
    }

    #[test]
    fn timeout_is_a_typed_gap_and_requests_are_argv_only_with_scratch_environment() {
        let root = fixture(RUST_FILES);
        let stubs = stub_dir(&[("cargo", CARGO_STUB)]);
        let scratch = Arc::new(AuditScratch::create(&root).unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let before = listing(&root);
        let result = run_async(
            &adapter(&root, vec![stubs.clone()]).with_tool_bounds(777, 60_000),
            &root,
            RUST_PATHS,
            Arc::new(TimeoutTool {
                requests: requests.clone(),
            }),
            scratch.clone(),
        );
        for tool in ["metadata", "check"] {
            assert!(
                result
                    .coverage_gaps
                    .contains(&format!("unavailable:tool-timeout:{tool}")),
                "{tool}: {:?}",
                result.coverage_gaps
            );
        }
        assert!(result.findings.is_empty());
        assert!(!result.complete);

        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "metadata and check; clippy is not installed"
        );
        for request in requests.iter() {
            assert!(!request.shell);
            assert_eq!(request.timeout_ms, 777);
            assert_eq!(request.cwd, root.to_string_lossy());
            assert!(request.args.contains(&"--offline".to_string()));
            assert!(request.args.contains(&"--locked".to_string()));
            // Scratch, caches and temp files live outside the audited tree.
            for name in ["CARGO_TARGET_DIR", "TMPDIR", "XDG_CACHE_HOME"] {
                let value = Path::new(&request.environment[name]);
                assert!(value.starts_with(scratch.root()), "{name}={value:?}");
                assert!(!value.starts_with(&root));
                assert!(request.environment_allowlist.contains(name));
            }
            assert_eq!(request.environment["CARGO_NET_OFFLINE"], "true");
        }
        assert_eq!(listing(&root), before);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(stubs).unwrap();
    }

    #[test]
    fn host_injected_input_never_runs_tools() {
        let root = fixture(RUST_FILES);
        let stubs = stub_dir(&[("cargo", CARGO_STUB)]);
        let scratch = Arc::new(AuditScratch::create(&root).unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut injected = provider("code.rust");
        injected
            .configuration
            .insert("input".into(), json!({"files": [{"path": "src/lib.rs"}]}));
        let inv = inventory(&root, RUST_PATHS);
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(adapter(&root, vec![stubs.clone()]).execute_async(
                &frozen_plan(),
                &injected,
                &inv,
                Arc::new(TimeoutTool {
                    requests: requests.clone(),
                }),
                scratch,
                CancellationToken::new(),
            ))
            .unwrap();
        assert!(requests.lock().unwrap().is_empty());
        assert!(!result.details.contains_key("nativeProducer"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(stubs).unwrap();
    }
}
