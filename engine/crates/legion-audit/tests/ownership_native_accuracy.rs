//! Actual owner + SDK controls. Requires provisioned, authenticated, clean committed
//! fixture repos; this harness never fabricates registration, keys, trust or scanner JSON.
#![cfg(unix)]
use legion_audit::{
    native_providers::{
        legacy::{
            governance_ownership,
            ownership_sdk::{validate_envelope, NativeOwner},
        },
        legacy_checks::AuditScratch,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
    ProviderExecutor,
};
use legion_contracts::ProviderSpec;
use legion_effects::{
    platform::unix::UnixProcess, ArtifactWriter, EffectExecutor, ExternalToolRequest,
    PolicyAuthorizer, PolicyDecision,
};
use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio_util::sync::CancellationToken;

const ID: &str = "governance.capability-ownership";
const POLICY: &str = "audit-native-owner-admission-v1";
const FILE: &str = "src/duplicate.swift";
const POSITIVE: &str =
    "let first = AXUIElementCreateSystemWide()\nlet second = AXUIElementCreateSystemWide()\n";
const CLEAN: &str = "let first = 42\nlet second = 43\n";

/// Authorizes only exact fixture root, native binary, args, plan, policy & task.
/// This is explicit constructed SDK admission; it supplies no protected owner trust.
struct FixtureAdmission {
    root: PathBuf,
    owner: NativeOwner,
    plan: String,
    inventory: String,
}
impl PolicyAuthorizer for FixtureAdmission {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let mode = request.task_id.as_deref().unwrap_or("");
        let args = if mode == "ownership-scan" {
            vec![self.root.to_string_lossy().into_owned()]
        } else {
            vec![self.root.to_string_lossy().into_owned(), "--inputs".into()]
        };
        let expected_id = format!(
            "legion-audit/{}",
            legion_audit::native_providers::legacy::common::digest_bytes(
                format!(
                    "{}:{}:{}",
                    self.plan,
                    self.inventory,
                    mode.trim_start_matches("ownership-")
                )
                .as_bytes()
            )
            .trim_start_matches("sha256:")
        );
        // SDK receipt identity is checked by consumer too. Request id must stay in
        // sink-safe namespace; artifact reservation rejects a second use.
        let allowed = request.request_id == expected_id
            && request.provider_id == ID
            && request.plan_id == self.plan
            && request.policy_id == POLICY
            && request.cwd == self.root.to_string_lossy()
            && request.executable == self.owner.executable().to_string_lossy()
            && request.expected_digest.as_ref().map(|s| json!(s))
                == Some(self.owner.identity()["executableDigest"].clone())
            && request.args == args
            && [
                "ownership-inputs-before",
                "ownership-scan",
                "ownership-inputs-after",
            ]
            .contains(&mode)
            && request.origin == legion_effects::ToolOrigin::System
            && request.skip_version_probe
            && !request.shell
            && !request.requires_network_sandbox
            && request.environment.is_empty()
            && request.environment_allowlist.is_empty()
            && request.accepted_exit_codes == [0].into_iter().collect()
            && request.timeout_ms == 120_000
            && request.stdout_limit == 64 * 1024 * 1024
            && request.stderr_limit == 64 * 1024 * 1024;
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: legion_audit::digest(
                &json!({"scope":"constructed ownership SDK fixture","root":self.root,
                "owner":self.owner.identity(),"plan":self.plan}),
            )
            .unwrap(),
            reason: Some(
                if allowed {
                    "exact constructed ownership SDK fixture"
                } else {
                    "outside constructed ownership SDK contract"
                }
                .into(),
            ),
        }
    }
}

struct MutateAfterProbe {
    inner: Arc<dyn ExternalProjectTool>,
    path: PathBuf,
    mutated: AtomicBool,
}
#[async_trait::async_trait]
impl ExternalProjectTool for MutateAfterProbe {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        let probe = request.task_id.as_deref() == Some("ownership-inputs-before");
        let receipt = self.inner.execute(request, cancellation).await;
        if probe && receipt.is_complete() && !self.mutated.swap(true, Ordering::SeqCst) {
            fs::write(&self.path, format!("{POSITIVE}// drift control\n")).unwrap();
        }
        receipt
    }
}

struct Restore {
    path: PathBuf,
    bytes: Vec<u8>,
}
impl Drop for Restore {
    fn drop(&mut self) {
        fs::write(&self.path, &self.bytes).unwrap();
    }
}
struct EnvRestore(Option<std::ffi::OsString>);
impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.0 {
            Some(v) => std::env::set_var(governance_ownership::COMMAND_ENV, v),
            None => std::env::remove_var(governance_ownership::COMMAND_ENV),
        }
    }
}

fn registry_spec() -> ProviderSpec {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == ID)
            .unwrap()
            .clone(),
    )
    .unwrap()
}

async fn run(
    root: &Path,
    source: &Value,
    owner: &NativeOwner,
    output: &Path,
    control: &str,
) -> Value {
    let inventory = FilesystemInventorySource::new(root)
        .unwrap()
        .inventory(ID)
        .unwrap();
    let argv = json!([owner.executable(), root]);
    std::env::set_var(
        governance_ownership::COMMAND_ENV,
        serde_json::to_string(&argv).unwrap(),
    );
    let mut plan =
        AuditPlan::compile_with_root(Some(root), &inventory, &[registry_spec()]).unwrap();
    let provider = plan.providers.iter_mut().find(|p| p.id == ID).unwrap();
    provider
        .configuration
        .insert("ownershipNativeOwner".into(), owner.identity());
    provider
        .configuration
        .insert("ownershipSourceIdentity".into(), source.clone());
    let frozen = plan
        .freeze(Some(b"constructed-ownership-sdk-fixture-key"))
        .unwrap();
    let scratch = Arc::new(AuditScratch::with_scratch_dir(root, output).unwrap());
    let tool: Arc<dyn ExternalProjectTool> = if control == "denial" {
        Arc::new(EffectExecutor::new(
            UnixProcess::new(),
            ArtifactWriter::new(scratch.artifacts_dir()),
            legion_audit::execution_policy::OwnerAdmissionRequired,
        ))
    } else {
        Arc::new(EffectExecutor::new(
            UnixProcess::new(),
            ArtifactWriter::new(scratch.artifacts_dir()),
            FixtureAdmission {
                root: root.to_path_buf(),
                owner: owner.clone(),
                plan: frozen.digest().into(),
                inventory: inventory.digest.clone(),
            },
        ))
    };
    let tool: Arc<dyn ExternalProjectTool> = if control == "drift" {
        Arc::new(MutateAfterProbe {
            inner: tool,
            path: root.join(FILE),
            mutated: AtomicBool::new(false),
        })
    } else {
        tool
    };
    let executor = NativeProviderRegistry::new(root)
        .with_scratch(scratch)
        .with_ownership_owner(owner.clone())
        .with_external_project_tool(tool);
    let result = executor
        .execute_async(
            &frozen,
            frozen.provider(ID).unwrap(),
            &inventory,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    json!({"control":control,"root":root,"inventory":inventory,"plan":frozen.plan(),"planDigest":frozen.digest(),"result":result})
}

#[test]
#[ignore = "requires CI-built native owner + production-authenticated registered committed positive & clean fixtures"]
fn ownership_native_sdk_known_answers() {
    let _restore_env = EnvRestore(std::env::var_os(governance_ownership::COMMAND_ENV));
    let owner = NativeOwner::pin(Path::new(
        &std::env::var_os("LEGION_OWNERSHIP_NATIVE_OWNER").expect("native owner binary required"),
    ))
    .unwrap();
    let manifest_path = PathBuf::from(
        std::env::var_os("LEGION_OWNERSHIP_FIXTURE_IDENTITIES")
            .expect("provisioned fixture identity manifest required"),
    );
    let manifest_bytes = fs::read(&manifest_path).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let output = PathBuf::from(
        std::env::var_os("LEGION_OWNERSHIP_ACCURACY_OUTPUT")
            .expect("retained external output root required"),
    );
    fs::create_dir_all(&output).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = BTreeMap::new();
    for (case, expected) in [("positive", POSITIVE), ("clean", CLEAN)] {
        let source = &manifest[case];
        let root = fs::canonicalize(source["root"].as_str().expect("fixture root")).unwrap();
        assert_eq!(source["root"], json!(root));
        assert_eq!(
            fs::read(root.join(FILE)).unwrap(),
            expected.as_bytes(),
            "fixed planted source required"
        );
        let row = runtime.block_on(run(&root, source, &owner, &output.join(case), case));
        fs::write(
            output.join(format!("{case}-observed.json")),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        assert_eq!(
            row["result"]["complete"], true,
            "actual enrolled owner execution required"
        );
        let details = &row["result"]["details"];
        let report = &details["ownerDocuments"][1]["owner"]["report"];
        let rows = report["violations"].as_array().unwrap();
        if case == "positive" {
            assert_eq!(rows.len(), 2);
            for (index, violation) in rows.iter().enumerate() {
                assert_eq!(violation["fingerprint"], "automation.api.ax-element");
                assert_eq!(violation["capability"], "desktop-automation");
                assert_eq!(violation["package"], "rightkit-automation");
                assert_eq!(violation["file"], FILE);
                assert_eq!(violation["line"], index + 1);
            }
            assert_eq!(row["result"]["findings"].as_array().unwrap().len(), 2);
        } else {
            assert!(rows.is_empty());
            assert!(row["result"]["findings"].as_array().unwrap().is_empty());
        }
        cases.insert(case.to_owned(), row);
    }
    let positive = &cases["positive"];
    let root = PathBuf::from(positive["root"].as_str().unwrap());
    let original = fs::read(root.join(FILE)).unwrap();
    let _restore_source = Restore {
        path: root.join(FILE),
        bytes: original,
    };
    let drift = runtime.block_on(run(
        &root,
        &manifest["positive"],
        &owner,
        &output.join("drift"),
        "drift",
    ));
    assert_eq!(drift["result"]["complete"], false);
    assert!(drift["result"]["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v
            .as_str()
            .unwrap()
            .starts_with("ownership-denominator-drift:")));
    fs::write(root.join(FILE), POSITIVE).unwrap();
    let denied = runtime.block_on(run(
        &root,
        &manifest["positive"],
        &owner,
        &output.join("denial"),
        "denial",
    ));
    assert_eq!(denied["result"]["complete"], false);
    let receipts = denied["result"]["details"]["executionReceipts"]
        .as_array()
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["state"], "unauthorized_effect");
    assert_eq!(receipts[0]["processTree"]["started"], false);
    let genuine = positive["result"]["details"]["ownerDocuments"][1].clone();
    let files: BTreeMap<String, String> =
        serde_json::from_value(positive["result"]["details"]["frozenInputFiles"].clone()).unwrap();
    let mut controls = BTreeMap::new();
    for name in [
        "malformed",
        "outside-denominator",
        "catalog-drift",
        "verdict-drift",
        "input-denominator-drift",
        "source-identity-drift",
    ] {
        let mut mutated = genuine.clone();
        match name {
            "malformed" => {
                mutated["owner"]["report"]["violations"] = json!("malformed");
            }
            "outside-denominator" => {
                mutated["owner"]["report"]["violations"][0]["file"] = json!("outside.swift");
            }
            "catalog-drift" => {
                mutated["owner"]["inputs"]["catalogDigest"] = json!("0".repeat(64));
            }
            "verdict-drift" => {
                mutated["owner"]["verdict"]["admit"] =
                    json!(!genuine["owner"]["verdict"]["admit"].as_bool().unwrap());
            }
            "input-denominator-drift" => {
                mutated["inputInventory"]["files"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "source-identity-drift" => {
                mutated["inputInventory"]["sourceIdentity"]["commit"] = json!("0".repeat(40));
            }
            _ => unreachable!(),
        }
        let error = validate_envelope(&mutated, &files, &owner, &root, true).unwrap_err();
        controls.insert(name, json!({"observed":"rejected","scope":"consumer-boundary mutation of genuine owner envelope","error":error,"mutatedDocument":mutated}));
    }
    controls.insert("drift", drift);
    controls.insert("denial", denied);
    let mut record = json!({"schema":"legion-ownership-native-sdk-controls/1","provider":ID,"productionQualification":false,
        "qualificationEligible":false,"scope":"constructed actual Scanner controls; source-owned boundary checks; pending full qualification validator",
        "fixtureIdentityManifest":{"path":manifest_path,"digest":legion_audit::native_providers::legacy::common::digest_bytes(&manifest_bytes),"document":manifest},
        "nativeOwner":owner.identity(),"cases":cases,"controls":controls});
    record["digest"] = json!(legion_audit::digest(&record).unwrap());
    fs::write(
        output.join("governance.capability-ownership.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
}
