//! Private ignored-harness emission. Every observation comes from this process.
//! No registry promotion, CLI admission or production qualification occurs here.
use super::*;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const SELECTOR: &str = "native_providers::security::producer::history_qualification_tests::native_current_history_qualification";
pub(super) const SOURCE_FILES: &[&str] = &[
    "engine/Cargo.lock",
    "engine/Cargo.toml",
    "engine/crates/legion-audit/Cargo.toml",
    "engine/crates/legion-audit/src/continuation.rs",
    "engine/crates/legion-audit/src/dag.rs",
    "engine/crates/legion-audit/src/error.rs",
    "engine/crates/legion-audit/src/execution.rs",
    "engine/crates/legion-audit/src/execution_policy.rs",
    "engine/crates/legion-audit/src/graph_context.rs",
    "engine/crates/legion-audit/src/integrity.rs",
    "engine/crates/legion-audit/src/inventory.rs",
    "engine/crates/legion-audit/src/lib.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/backend.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/common.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/compatibility.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/core.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/data.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/docs.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/docs_contract.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/evidence.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/framework.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/frontend.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/mod.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/producer.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/requirements.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/test_quality.rs",
    "engine/crates/legion-audit/src/native_providers/availability.rs",
    "engine/crates/legion-audit/src/native_providers/code/applicability.rs",
    "engine/crates/legion-audit/src/native_providers/code/c_family.rs",
    "engine/crates/legion-audit/src/native_providers/code/common.rs",
    "engine/crates/legion-audit/src/native_providers/code/dotnet.rs",
    "engine/crates/legion-audit/src/native_providers/code/evidence.rs",
    "engine/crates/legion-audit/src/native_providers/code/go.rs",
    "engine/crates/legion-audit/src/native_providers/code/javascript.rs",
    "engine/crates/legion-audit/src/native_providers/code/jvm.rs",
    "engine/crates/legion-audit/src/native_providers/code/long_tail.rs",
    "engine/crates/legion-audit/src/native_providers/code/mobile.rs",
    "engine/crates/legion-audit/src/native_providers/code/mod.rs",
    "engine/crates/legion-audit/src/native_providers/code/native_commands.rs",
    "engine/crates/legion-audit/src/native_providers/code/php_ruby.rs",
    "engine/crates/legion-audit/src/native_providers/code/python.rs",
    "engine/crates/legion-audit/src/native_providers/code/rubocop.rs",
    "engine/crates/legion-audit/src/native_providers/code/rust.rs",
    "engine/crates/legion-audit/src/native_providers/code/tools.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/accessibility.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/accessibility_internal_suite.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/adapter.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/candidate_suites.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/common.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/framework.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/framework_major_suite.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance_ownership.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance_policy.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/mod.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual_core.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual_png.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/attested_runs.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/contracts.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/disposable_copy.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/mod.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/node_outdated.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/parsers.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/python_requirements.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/registry.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/resolver.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/runtime_capture.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/rust_outdated.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/semgrep.rs",
    "engine/crates/legion-audit/src/native_providers/mod.rs",
    "engine/crates/legion-audit/src/native_providers/p11d_quality/mod.rs",
    "engine/crates/legion-audit/src/native_providers/p11d_quality/security_suite.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/candidate_routing.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/coverage_plan.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/coverage_regressions.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/excerpts.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/followup.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/ingest.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/lens_plan.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/lens_schemas.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/mod.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/packet_context.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/pattern_cards.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/security_adjudication.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/triggers.rs",
    "engine/crates/legion-audit/src/native_providers/security/adapter.rs",
    "engine/crates/legion-audit/src/native_providers/security/ast_grep.rs",
    "engine/crates/legion-audit/src/native_providers/security/common.rs",
    "engine/crates/legion-audit/src/native_providers/security/container_iac.rs",
    "engine/crates/legion-audit/src/native_providers/security/dependency_osv.rs",
    "engine/crates/legion-audit/src/native_providers/security/history.rs",
    "engine/crates/legion-audit/src/native_providers/security/history_qualification_record.rs",
    "engine/crates/legion-audit/src/native_providers/security/history_qualification_tests.rs",
    "engine/crates/legion-audit/src/native_providers/security/imported_sarif.rs",
    "engine/crates/legion-audit/src/native_providers/security/mod.rs",
    "engine/crates/legion-audit/src/native_providers/security/opengrep.rs",
    "engine/crates/legion-audit/src/native_providers/security/packs.rs",
    "engine/crates/legion-audit/src/native_providers/security/producer.rs",
    "engine/crates/legion-audit/src/native_providers/security/scanner_tools.rs",
    "engine/crates/legion-audit/src/native_providers/security/scanners.rs",
    "engine/crates/legion-audit/src/native_providers/security/secrets.rs",
    "engine/crates/legion-audit/src/native_providers/security/supply_chain.rs",
    "engine/crates/legion-audit/src/native_providers/security/suppressions.rs",
    "engine/crates/legion-audit/src/next.rs",
    "engine/crates/legion-audit/src/normalize.rs",
    "engine/crates/legion-audit/src/p12_pipeline/mod.rs",
    "engine/crates/legion-audit/src/p12_pipeline/store.rs",
    "engine/crates/legion-audit/src/plan.rs",
    "engine/crates/legion-audit/src/report.rs",
    "engine/crates/legion-audit/src/review_runtime/batch.rs",
    "engine/crates/legion-audit/src/review_runtime/cost.rs",
    "engine/crates/legion-audit/src/review_runtime/gather.rs",
    "engine/crates/legion-audit/src/review_runtime/mod.rs",
    "engine/crates/legion-audit/src/review_runtime/model.rs",
    "engine/crates/legion-audit/src/review_runtime/native.rs",
    "engine/crates/legion-audit/src/review_runtime/partial.rs",
    "engine/crates/legion-audit/src/review_runtime/projection.rs",
    "engine/crates/legion-audit/src/review_runtime/tools.rs",
    "engine/crates/legion-audit/src/review_runtime/verification.rs",
    "engine/crates/legion-audit/src/scope.rs",
    "engine/crates/legion-audit/src/snapshot.rs",
    "engine/crates/legion-audit/src/source_cache.rs",
    "engine/crates/legion-audit/src/verify.rs",
    "engine/crates/legion-audit/src/wf_port/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/external_process.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/provider_executor.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/provider_registry.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/registry.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/runtime_module.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/tool_identity.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/common.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/complete.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/finalize.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/plan.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/run.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/runtime.rs",
    "engine/crates/legion-audit/src/worktree.rs",
    "engine/crates/legion-contracts/Cargo.toml",
    "engine/crates/legion-contracts/src/agent.rs",
    "engine/crates/legion-contracts/src/canonical.rs",
    "engine/crates/legion-contracts/src/enums.rs",
    "engine/crates/legion-contracts/src/host.rs",
    "engine/crates/legion-contracts/src/id.rs",
    "engine/crates/legion-contracts/src/l2_port/enums.rs",
    "engine/crates/legion-contracts/src/l2_port/executable.rs",
    "engine/crates/legion-contracts/src/l2_port/mod.rs",
    "engine/crates/legion-contracts/src/l2_port/schema_names.rs",
    "engine/crates/legion-contracts/src/lib.rs",
    "engine/crates/legion-contracts/src/plan.rs",
    "engine/crates/legion-contracts/src/policy.rs",
    "engine/crates/legion-contracts/src/provider.rs",
    "engine/crates/legion-contracts/src/provider_result.rs",
    "engine/crates/legion-contracts/src/receipt.rs",
    "engine/crates/legion-contracts/src/report.rs",
    "engine/crates/legion-contracts/src/state_root.rs",
    "engine/crates/legion-contracts/src/task.rs",
    "engine/crates/legion-contracts/src/trace.rs",
    "engine/crates/legion-effects/Cargo.toml",
    "engine/crates/legion-effects/src/artifact.rs",
    "engine/crates/legion-effects/src/credential.rs",
    "engine/crates/legion-effects/src/environment.rs",
    "engine/crates/legion-effects/src/error.rs",
    "engine/crates/legion-effects/src/executable.rs",
    "engine/crates/legion-effects/src/executor.rs",
    "engine/crates/legion-effects/src/lib.rs",
    "engine/crates/legion-effects/src/platform.rs",
    "engine/crates/legion-effects/src/receipt.rs",
    "engine/crates/legion-effects/src/request.rs",
    "engine/crates/legion-effects/src/sandbox.rs",
    "engine/crates/legion-effects/src/unix.rs",
    "engine/crates/legion-effects/src/windows.rs",
    "engine/crates/legion-provider-sdk/Cargo.toml",
    "engine/crates/legion-provider-sdk/src/auth.rs",
    "engine/crates/legion-provider-sdk/src/context.rs",
    "engine/crates/legion-provider-sdk/src/coverage.rs",
    "engine/crates/legion-provider-sdk/src/error.rs",
    "engine/crates/legion-provider-sdk/src/external_project_tool.rs",
    "engine/crates/legion-provider-sdk/src/http_client.rs",
    "engine/crates/legion-provider-sdk/src/inference.rs",
    "engine/crates/legion-provider-sdk/src/lib.rs",
    "engine/crates/legion-provider-sdk/src/provider.rs",
    "engine/crates/legion-provider-sdk/src/registry.rs",
    "engine/crates/legion-provider-sdk/src/result.rs",
    "engine/crates/legion-provider-sdk/src/retry.rs",
    "engine/crates/legion-provider-sdk/src/stream.rs",
    "engine/crates/legion-provider-sdk/src/testkit.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/mod.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/canonical.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/contracts.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/dag.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/mod.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/testkit.rs",
    "engine/crates/legion-rules/Cargo.toml",
    "engine/crates/legion-rules/src/compiler.rs",
    "engine/crates/legion-rules/src/error.rs",
    "engine/crates/legion-rules/src/evidence.rs",
    "engine/crates/legion-rules/src/lexical.rs",
    "engine/crates/legion-rules/src/lib.rs",
    "engine/crates/legion-rules/src/schema.rs",
    "engine/crates/legion-rules/src/structural.rs",
    "engine/crates/legion-rules/src/wf_port/mod.rs",
    "engine/crates/legion-rules/src/wf_port/u06/mod.rs",
    "engine/rust-toolchain.toml",
    "scripts/ci/audit-secrets-history-provider-accuracy.py",
];
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let pairs: BTreeMap<_, _> = map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            Value::Object(pairs.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}
pub(super) fn canonical_digest(value: &Value) -> String {
    digest(&serde_json::to_vec(&sorted(value.clone())).unwrap())
}
fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(ALPHABET[(byte >> 4) as usize] as char);
        out.push(ALPHABET[(byte & 15) as usize] as char);
    }
    out
}
fn artifact(value: &Option<legion_effects::ArtifactRecord>) -> Value {
    value
        .as_ref()
        .map(|v| json!({"path":v.path,"digest":v.digest,"bytes":v.bytes,"immutable":v.immutable}))
        .unwrap_or(Value::Null)
}
pub(super) fn sdk(run: &ToolRun) -> Value {
    let r = &run.actual_receipt;
    let executable = r.executable.as_ref().map(|v| json!({
        "requestedPath":v.requested_path,"canonicalPath":v.canonical_path,"digest":v.digest,
        "digestState":format!("{:?}",v.digest_state),"signature":format!("{:?}",v.signature),
        "version":{"args":v.version.args,"output":v.version.output,"exitCode":v.version.exit_code,"qualified":v.version.qualified,"skippedByPolicy":v.version.skipped_by_policy}}));
    let command = r.command.as_ref().map(|v| json!({"executable":v.executable,"args":v.args,"environmentNames":v.environment_names,
        "redactedArgumentIndexes":v.redacted_argument_indexes,"redactedEnvironmentNames":v.redacted_environment_names}));
    let policy = r.policy.as_ref().map(|v| json!({"id":v.id,"version":v.version,"digest":v.digest,"allowed":v.allowed,"reason":v.reason}));
    json!({"schemaVersion":r.schema_version,"receiptId":r.receipt_id,"requestId":r.request_id,"providerId":r.provider_id,
        "planId":r.plan_id,"policyId":r.policy_id,"policy":policy,"taskId":r.task_id,"state":r.state.as_str(),"complete":r.complete,
        "executable":executable,"command":command,"cwd":r.cwd,"environmentNames":r.environment_names,
        "sandbox":{"required":r.sandbox.required,"receiptId":r.sandbox.receipt_id,"networkEnabled":r.sandbox.network_enabled},
        "processTree":{"started":r.process_tree.started,"terminated":r.process_tree.terminated,"hardKilled":r.process_tree.hard_killed,"reaped":r.process_tree.reaped,"detail":r.process_tree.detail},
        "timing":{"startedAtMs":r.timing.started_at_ms,"completedAtMs":r.timing.completed_at_ms,"durationMs":r.timing.duration_ms},
        "exitCode":r.exit_code,"signal":r.signal,"stdout":artifact(&r.stdout),"stderr":artifact(&r.stderr),
        "parser":{"attempted":r.parser.attempted,"succeeded":r.parser.succeeded,"error":r.parser.error},"gaps":r.gaps})
}
fn raw_git(root: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(out.status.success(), "retained fixture object read failed");
    assert!(out.stdout.len() <= 8 * 1024 * 1024);
    out.stdout
}
fn objects(root: &Path) -> Value {
    let list = raw_git(root, &["rev-list", "--objects", "--all", "HEAD"]);
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&list).unwrap().lines() {
        let oid = line.split_whitespace().next().unwrap();
        let kind_bytes = raw_git(root, &["cat-file", "-t", oid]);
        let kind = std::str::from_utf8(&kind_bytes).unwrap().trim();
        assert!(matches!(kind, "commit" | "tree" | "blob" | "tag"));
        let bytes = raw_git(root, &["cat-file", kind, oid]);
        values.insert(
            oid.to_owned(),
            json!({"kind":kind,"hex":hex(&bytes),"digest":digest(&bytes)}),
        );
    }
    serde_json::to_value(values).unwrap()
}
pub(super) fn changed_run(run: &ToolRun) -> Value {
    json!({"sdk":sdk(run),"projection":run.receipt,"stdoutHex":hex(&run.stdout),"stderrHex":hex(&run.stderr),"tool":run.tool_identity(),"wrapper":Value::Null})
}
pub(super) fn case(
    root: &Path,
    producer: &ArtifactProducer,
    result: &legion_contracts::ProviderResult,
) -> Value {
    let inv = inventory(root);
    let selected = inv
        .entries
        .iter()
        .map(|v| v.path.clone())
        .collect::<Vec<_>>();
    let frozen =
        FrozenHistory::capture(root, producer.snapshot_manifest.as_deref(), &inv, &selected)
            .unwrap();
    let files: BTreeMap<_, _> = selected
        .iter()
        .map(|path| (path.clone(), hex(&fs::read(root.join(path)).unwrap())))
        .collect();
    let runs = producer.retained_secret_runs.lock().unwrap();
    assert_eq!(runs.len(), 2);
    let runs: Vec<_> = runs.iter().map(|run| json!({"sdk":sdk(run),"projection":run.receipt,"stdoutHex":hex(&run.stdout),"stderrHex":hex(&run.stderr),
        "tool":run.tool_identity(),"wrapper":Value::Null})).collect();
    json!({"root":root,"inventory":inv,"providerSpec":spec(&inv),"files":files,"manifest":manifest_value(&frozen.manifest),
        "objects":objects(&frozen.manifest.object_root),"result":result,"runs":runs})
}
pub(super) fn failure<T>(
    controls: &mut BTreeMap<String, Value>,
    name: &str,
    value: Result<T, String>,
) {
    let error = value.err().expect("required native rejection");
    assert!(!error.is_empty());
    assert!(controls
        .insert(name.into(), json!({"observed":"rejected","error":error}))
        .is_none());
}
pub(super) fn predicate(controls: &mut BTreeMap<String, Value>, name: &str, rejected: bool) {
    assert!(rejected, "required native predicate rejection");
    assert!(controls
        .insert(
            name.into(),
            json!({"observed":"rejected","predicate":false})
        )
        .is_none());
}
pub(super) fn incomplete(
    controls: &mut BTreeMap<String, Value>,
    name: &str,
    result: legion_contracts::ProviderResult,
) {
    assert!(!result.complete);
    assert!(controls
        .insert(
            name.into(),
            json!({"observed":"incomplete","result":result})
        )
        .is_none());
}
pub(super) fn emit(
    parent: &Path,
    bin: &Path,
    scanner_digest: &str,
    cases: BTreeMap<String, Value>,
    controls: BTreeMap<String, Value>,
    snapshot: Value,
    signature: Value,
) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let source_files: BTreeMap<_, _> = SOURCE_FILES
        .iter()
        .map(|p| ((*p).to_owned(), digest(&fs::read(root.join(p)).unwrap())))
        .collect();
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let mut provider = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "secrets.current-history")
        .unwrap()
        .clone();
    provider.as_object_mut().unwrap().remove("benchmark");
    let mut row = json!({"schema":"legion-secrets-history-native-qualification/1","family":"secrets-history","provider":"secrets.current-history",
        "stage":"finding","status":"pass","claimScope":"known-answer-fixture-cases","productionQualification":false,"installedCliAdmission":false,
        "admissionScope":"explicit constructed SDK authorizer; sandbox disabled in synthetic fixture only","modelCalls":0,
        "harness":SELECTOR,"repositoryRoot":root,"evidenceRoot":parent,
        "sources":{"files":source_files,"digest":canonical_digest(&serde_json::to_value(&source_files).unwrap()),"providerSpec":provider,"providerSpecDigest":canonical_digest(&provider)},
        "scanner":{"version":"8.30.0","path":bin,"executableDigest":scanner_digest,
            "archiveName":std::env::var("LEGION_GITLEAKS_ARCHIVE_NAME").expect("official archive pin required"),
            "archiveDigest":std::env::var("LEGION_GITLEAKS_ARCHIVE_SHA256").expect("official archive digest required")},
        "cases":cases,"controls":controls,"snapshot":snapshot,"signature":signature});
    row["qualificationDigest"] = json!(canonical_digest(&row));
    fs::write(
        parent.join("secrets.current-history.json"),
        serde_json::to_vec_pretty(&row).unwrap(),
    )
    .unwrap();
    println!(
        "SECRETS_HISTORY_NATIVE_QUALIFICATION {}",
        serde_json::to_string(&row).unwrap()
    );
}
