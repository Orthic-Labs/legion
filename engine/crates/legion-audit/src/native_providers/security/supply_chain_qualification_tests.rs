//! Native Syft + consumer refusal controls. Target build provenance stays unproven.
//! No fabricated native stream, signature, trusted receipt or builder identity.
#![cfg(target_os = "macos")]
use super::super::{supply_chain, supply_chain_documents as documents};
use super::*;
use crate::{FilesystemInventorySource, InventorySource};
use legion_effects::{PolicyAuthorizer, PolicyDecision};
use std::sync::Mutex;

const ID: &str = "supply-chain.license-sbom-provenance";
const SOURCE: &str =
    "engine/crates/legion-audit/src/native_providers/security/supply_chain_qualification_tests.rs";
const POLICY: &str = "legion-supply-chain-syft-fixture-only/1";
const SCOPE: &str = "native Syft dual-format SBOM + explicit license policy; full constructed npm-v3 lock including dev/transitive; audited target build provenance unproven";
fn canonical(value: &Value) -> Vec<u8> {
    fn order(value: &Value) -> Value {
        match value {
            Value::Object(rows) => {
                let rows: BTreeMap<_, _> = rows.iter().collect();
                let mut out = serde_json::Map::new();
                for (k, v) in rows {
                    out.insert(k.clone(), order(v));
                }
                Value::Object(out)
            }
            Value::Array(rows) => Value::Array(rows.iter().map(order).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&order(value)).unwrap()
}
fn request_value(request: &ExternalToolRequest) -> Value {
    json!({"schemaVersion":request.schema_version,"requestId":request.request_id,"providerId":request.provider_id,"planId":request.plan_id,"policyId":request.policy_id,"taskId":request.task_id,"executable":request.executable,"args":request.args,"cwd":request.cwd,"origin":"system","shell":request.shell,"expectedDigest":request.expected_digest,"acceptedExitCodes":request.accepted_exit_codes,"versionArgs":request.version_args,"skipVersionProbe":request.skip_version_probe,"versionRequirement":request.version_requirement,"environment":request.environment,"environmentAllowlist":request.environment_allowlist,"requiresNetworkSandbox":request.requires_network_sandbox,"sandbox":request.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),"timeoutMs":request.timeout_ms,"stdoutLimit":request.stdout_limit,"stderrLimit":request.stderr_limit})
}
struct FixturePolicy {
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    requests: Mutex<Vec<ExternalToolRequest>>,
}
impl PolicyAuthorizer for FixturePolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.requests.lock().unwrap().push(request.clone());
        let args = &request.args;
        let prefix = args.len() == 13
            && args[0] == "-f"
            && args[2] == "--"
            && Path::new(&args[3]) == self.tool;
        let profile = args.get(1).and_then(|p| fs::read_to_string(p).ok());
        let escaped = self
            .root
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let expected_profile=format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        let suffix = prefix
            && args[4] == "scan"
            && args[5] == "dir:."
            && args[6] == "--config"
            && args[8] == "--override-default-catalogers"
            && args[9] == "all"
            && args[10] == "-o"
            && matches!(args[11].as_str(), "cyclonedx-json" | "spdx-json")
            && args[12] == "-q";
        let config = suffix
            && fs::read_to_string(&args[7]).ok().as_deref() == Some(documents::SYFT_CONFIGURATION);
        let native = fs::read(&self.tool).is_ok_and(|bytes| digest(&bytes) == self.tool_digest);
        let allowed = request.provider_id == ID
            && request.executable == "/usr/bin/sandbox-exec"
            && request.cwd == self.root.to_string_lossy()
            && request.expected_digest.as_ref()
                == fs::read("/usr/bin/sandbox-exec")
                    .ok()
                    .map(|bytes| digest(&bytes))
                    .as_ref()
            && !request.shell
            && request.requires_network_sandbox
            && request.sandbox.as_ref().is_some_and(|s| {
                s.network
                    && s.id
                        == format!(
                            "sandbox:macos:{}",
                            digest(expected_profile.as_bytes()).trim_start_matches("sha256:")
                        )
            })
            && request.accepted_exit_codes == [0].into_iter().collect()
            && request.timeout_ms == 120_000
            && request.stdout_limit == 8 * 1024 * 1024
            && request.stderr_limit == 8 * 1024 * 1024
            && native
            && config
            && profile.as_deref() == Some(expected_profile.as_str())
            && request.version_args
                == [args.get(..4).unwrap_or(&[]), &["--version".to_owned()]].concat();
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(POLICY.as_bytes()),
            reason: (!allowed).then(|| "exact constructed native request refused".into()),
        }
    }
}
struct ExactPolicy(ExternalToolRequest);
impl PolicyAuthorizer for ExactPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        PolicyDecision {
            allowed: {
                let mut normalized = request.clone();
                normalized.request_id = self.0.request_id.clone();
                normalized == self.0
            },
            policy_id: "legion-supply-chain-refusal-control/1".into(),
            policy_version: 1,
            policy_digest: digest(&canonical(&request_value(&self.0))),
            reason: None,
        }
    }
}
fn license_policy() -> Value {
    json!({"schema":"legion-supply-chain-license-policy/1","allow":["MIT","Apache-2.0","BSD-3-Clause"],"deny":["GPL-3.0-only"],"unknown":"unproven"})
}
fn lock(license: &str) -> String {
    serde_json::to_string_pretty(&json!({"lockfileVersion":3,"requires":true,"packages":{
    "node_modules/direct":{"version":"1.0.0","license":"MIT","dependencies":{"transitive":"2.0.0"}},
    "node_modules/direct/node_modules/transitive":{"version":"2.0.0","license":license},
    "node_modules/dev-only":{"version":"3.0.0","license":"Apache-2.0","dev":true}}}))
    .unwrap()
        + "\n"
}
fn provider(inventory: &InventoryEnvelope) -> AuditProvider {
    let denominator = inventory
        .denominator_entries(&json!({"op":"always"}))
        .unwrap();
    serde_json::from_value(json!({"id":ID,"version":"1.0.0","role":"security","phase":"source","lensIds":[],"dependencies":[],"kind":"typed-external-project-tool","configuration":{"selector":{"op":"always"},"denominatorDigest":denominator.digest,"denominatorCount":denominator.entries.len(),"supplyChainLicensePolicy":license_policy()},"bounds":{},"cleanClaim":"evidence-only","benchmarkStatus":"unproven","benchmarkRequiredForCleanClaim":false,"qualificationDigest":null,"required":false})).unwrap()
}
fn sources(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for row in fs::read_dir(path).unwrap() {
                walk(root, &row.unwrap().path(), out);
            }
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative.starts_with(
                "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/",
            ) && relative.ends_with(".json")
            {
                let name = path.file_stem().unwrap().to_string_lossy();
                if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    return;
                }
            }
            let bytes = fs::read(path).unwrap();
            let hash = if relative == "src/registry/providers.json" {
                let mut registry: Value = serde_json::from_slice(&bytes).unwrap();
                for spec in registry["providers"].as_array_mut().unwrap() {
                    for key in ["status", "qualificationDigest", "qualification"] {
                        spec["benchmark"].as_object_mut().unwrap().remove(key);
                    }
                }
                digest(&canonical(&registry))
            } else {
                digest(&bytes)
            };
            out.insert(relative, hash);
        }
    }
    let mut files = BTreeMap::new();
    for path in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "src/registry/providers.json",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        "scripts/ci/audit-supply-chain-native-accuracy.py",
        "scripts/ci/tests/test_audit_supply_chain_native_accuracy.py",
        "scripts/ci/schemas/audit-supply-chain-native-accuracy.schema.json",
        "scripts/ci/audit-qualification-records.py",
        "scripts/ci/right-git-ci.sh",
        ".github/workflows/ci.yml",
    ] {
        walk(root, &root.join(path), &mut files);
    }
    json!({"files":files,"digest":digest(&canonical(&json!(files))),"registryRawDigest":digest(&fs::read(root.join("src/registry/providers.json")).unwrap())})
}
fn tools(tool: &Path, archive: &Path) -> Value {
    json!({"syft":{"path":tool,"digest":digest(&fs::read(tool).unwrap())},"launcher":{"path":"/usr/bin/sandbox-exec","digest":digest(&fs::read("/usr/bin/sandbox-exec").unwrap())},"archive":{"path":archive,"digest":digest(&fs::read(archive).unwrap())}})
}
fn diagnostics(run: &Path) -> Vec<Value> {
    let directory = run.join("native-diagnostics");
    if !directory.is_dir() {
        return Vec::new();
    }
    let mut paths: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    paths.iter().map(|path|{let bytes=fs::read(path).unwrap();json!({"path":path,"digest":digest(&bytes),"rawBytes":bytes,"record":serde_json::from_slice::<Value>(&bytes).unwrap()})}).collect()
}
fn native_case(
    parent: &Path,
    name: &str,
    license: &str,
    tool: &Path,
) -> (Value, Vec<ExternalToolRequest>) {
    let root = parent.join(name).join("source");
    let run = parent.join(name).join("run");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&run).unwrap();
    fs::write(
        root.join("package-lock.json"),
        if name == "malformed-lock" {
            "{ malformed lock\n".into()
        } else {
            lock(license)
        },
    )
    .unwrap();
    let root = fs::canonicalize(root).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(name)
        .unwrap();
    let provider = provider(&inventory);
    let authorizer = Arc::new(FixturePolicy {
        root: root.clone(),
        tool: tool.to_path_buf(),
        tool_digest: digest(&fs::read(tool).unwrap()),
        requests: Mutex::new(Vec::new()),
    });
    let producer = ArtifactProducer::new(&root)
        .with_run_dir(&run)
        .with_search_path(vec![tool.parent().unwrap().into()])
        .with_policy_authorizer(authorizer.clone());
    let input = match producer.produce(&provider, &inventory) {
        Production::Artifact(input) => input,
        other => panic!("native fixture unavailable: {other:?}"),
    };
    let result = supply_chain::analyze(&input);
    assert_eq!(result["complete"], false);
    assert_eq!(result["status"], "unproven");
    let requests = authorizer.requests.lock().unwrap().clone();
    (
        json!({"control":name,"kind":"native-source-control","root":root,"run":run,"inventory":inventory,"provider":provider,"input":input,"analysis":result,"requests":requests.iter().map(request_value).collect::<Vec<_>>(),"diagnostics":diagnostics(&run)}),
        requests,
    )
}
fn mutation(name: &str, base: &Value, mutate: impl FnOnce(&mut Value)) -> Value {
    let mut input = base["input"].clone();
    mutate(&mut input);
    let result = supply_chain::analyze(&input);
    assert_eq!(result["complete"], false);
    json!({"control":name,"kind":"derived-consumer-refusal","baseline":"nonempty-clean","input":input,"analysis":result})
}
#[test]
#[ignore = "requires managed native pinned Syft; root owns execution"]
fn native_supply_chain_qualification() {
    let parent = PathBuf::from(
        std::env::var_os("LEGION_SUPPLY_CHAIN_RECEIPTS").expect("retained root required"),
    );
    fs::create_dir_all(&parent).unwrap();
    let parent = fs::canonicalize(parent).unwrap();
    let tool = fs::canonicalize(
        std::env::var_os("LEGION_SYFT_BINARY").expect("installed genuine Syft required"),
    )
    .unwrap();
    assert_eq!(tool.file_name().unwrap(), "syft");
    assert!(!tool.starts_with(&parent));
    let archive = fs::canonicalize(
        std::env::var_os("LEGION_SYFT_ARCHIVE").expect("official retained archive required"),
    )
    .unwrap();
    let expected = if cfg!(target_arch = "aarch64") {
        "sha256:1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625"
    } else if cfg!(target_arch = "x86_64") {
        "sha256:e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003"
    } else {
        panic!("unsupported native architecture")
    };
    assert_eq!(digest(&fs::read(&archive).unwrap()), expected);
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source_before = sources(&repository);
    let tools_before = tools(&tool, &archive);
    let (clean, requests) = native_case(&parent, "nonempty-clean", "BSD-3-Clause", &tool);
    assert_eq!(clean["analysis"]["sbomLicenseComplete"], true);
    assert_eq!(clean["analysis"]["reconciliation"]["expected"], 3);
    assert_eq!(clean["analysis"]["reconciliation"]["examined"], 3);
    assert_eq!(clean["analysis"]["findings"], json!([]));
    let (violation, _) = native_case(&parent, "license-violation", "GPL-3.0-only", &tool);
    assert_eq!(
        violation["analysis"]["findings"].as_array().unwrap().len(),
        1
    );
    let (unknown, _) = native_case(&parent, "unknown-license", "AGPL-3.0-only", &tool);
    assert_eq!(unknown["analysis"]["sbomLicenseComplete"], false);
    let (malformed, _) = native_case(&parent, "malformed-lock", "MIT", &tool);
    assert_eq!(malformed["analysis"]["sbomLicenseComplete"], false);
    let mut cases = vec![clean.clone(), violation, unknown, malformed];
    // Missing-package reconciliation consumes unchanged genuine baseline streams.
    // No altered JSON is labelled as Syft output or as a native receipt.
    let cdx = clean["input"]["artifacts"]["supplyChain"]["documents"]["cyclonedx"]["raw"]
        .as_str()
        .unwrap()
        .as_bytes();
    let spdx = clean["input"]["artifacts"]["supplyChain"]["documents"]["spdx"]["raw"]
        .as_str()
        .unwrap()
        .as_bytes();
    let mut expected = documents::parse_lock("package-lock.json", &lock("BSD-3-Clause")).unwrap();
    expected.insert("pkg:npm/missing-package@9.0.0".into());
    let missing = documents::reconcile(&expected, cdx, spdx, &license_policy());
    assert_eq!(missing["complete"], false);
    cases.push(json!({"control":"missing-package","kind":"derived-reconciliation-refusal","baseline":"nonempty-clean","expectedPackages":expected,"reconciliation":missing}));
    cases.push(mutation("malformed-receipt", &clean, |input| {
        input["artifacts"]["supplyChain"]["documents"]["cyclonedx"]["receipt"]["complete"] =
            json!(false)
    }));
    cases.push(mutation("mismatched-binding", &clean, |input| {
        input["plan"]["binding"]["digest"] = json!(digest(b"different source binding"))
    }));
    cases.push(mutation("substituted-subject",&clean,|input|{
        let chain=&mut input["artifacts"]["supplyChain"];chain["subjectArtifact"]=json!({"path":"package-lock.json","digest":digest(b"substituted artifact"),"rawBytes":b"substituted artifact"});
        chain["provenance"]=json!({"binding":clean["input"]["plan"]["binding"],"executionReceipt":clean["input"]["artifacts"]["supplyChain"]["documents"]["cyclonedx"]["receipt"],"raw":String::from_utf8(canonical(&json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"package-lock.json","digest":{"sha256":clean["input"]["artifacts"]["supplyChain"]["sourceBefore"]["files"]["package-lock.json"].as_str().unwrap().trim_start_matches("sha256:")}}],"predicate":{}}))).unwrap()});
    }));
    cases.push(mutation("tampered-provenance",&clean,|input|input["artifacts"]["supplyChain"]["provenance"]=json!({"binding":clean["input"]["plan"]["binding"],"executionReceipt":null,"raw":"{ malformed unsigned control"})));
    // Native SDK refusal controls reuse the original typed request. No target
    // command runs when tool/admission/sandbox evidence is absent.
    let root = PathBuf::from(clean["root"].as_str().unwrap());
    let inventory: InventoryEnvelope = serde_json::from_value(clean["inventory"].clone()).unwrap();
    let provider = provider(&inventory);
    for control in [
        "tool-unavailable",
        "admission-unavailable",
        "sandbox-missing",
    ] {
        let mut request = requests[0].clone();
        request.request_id = format!("supply-chain-refusal:{control}");
        if control == "tool-unavailable" {
            request.executable = parent
                .join("absent-native-syft")
                .to_string_lossy()
                .into_owned();
            request.args = vec![];
            request.version_args = vec!["--version".into()];
            request.expected_digest = Some(digest(b"absent"));
        }
        if control == "sandbox-missing" {
            request.sandbox = None;
        }
        let run_dir = parent.join(control);
        fs::create_dir_all(&run_dir).unwrap();
        let mut producer = ArtifactProducer::new(&root);
        if control != "admission-unavailable" {
            producer = producer.with_policy_authorizer(Arc::new(ExactPolicy(request.clone())));
        }
        let run = Run {
            producer: &producer,
            provider: &provider,
            inventory: &inventory,
            scratch: Scratch::create(Some(&run_dir)).unwrap(),
            denied_receipts: RefCell::new(Vec::new()),
        };
        let receipt = run.execute(request.clone()).unwrap();
        assert!(!receipt.process_tree.started);
        assert!(!receipt.complete);
        assert_eq!(
            receipt.state.as_str(),
            match control {
                "tool-unavailable" => "missing_executable",
                "admission-unavailable" => "unauthorized_effect",
                _ => "sandbox_missing",
            }
        );
        cases.push(json!({"control":control,"kind":"native-sdk-refusal","request":request_value(&request),"receipt":crate::execution_policy::receipt_json(&receipt)}));
    }
    let drift_root = parent.join("source-drift");
    fs::create_dir_all(&drift_root).unwrap();
    fs::write(drift_root.join("package-lock.json"), lock("MIT")).unwrap();
    let frozen = FilesystemInventorySource::new(&drift_root)
        .unwrap()
        .inventory("source-drift")
        .unwrap();
    fs::write(drift_root.join("package-lock.json"), lock("GPL-3.0-only")).unwrap();
    let drift = documents::source_snapshot(&drift_root, &frozen.entries);
    assert_eq!(drift["complete"], false);
    cases.push(json!({"control":"source-drift","kind":"native-source-refusal","root":drift_root,"inventory":frozen,"snapshot":drift}));
    assert_eq!(cases.len(), 13);
    let source_after = sources(&repository);
    let tools_after = tools(&tool, &archive);
    assert_eq!(source_before, source_after);
    assert_eq!(tools_before, tools_after);
    let registry: Value =
        serde_json::from_slice(&fs::read(repository.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let mut spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|spec| spec["id"] == ID)
        .unwrap()
        .clone();
    for key in ["status", "qualificationDigest", "qualification"] {
        spec["benchmark"].as_object_mut().unwrap().remove(key);
    }
    let mut record = json!({"schema":"legion-supply-chain-native-accuracy/1","family":"supply-chain-native","provider":ID,"stage":"candidate","scope":SCOPE,"status":"pass","boundedSbomLicenseKnownAnswerEligible":true,"qualificationEligible":true,"wholeProviderQualification":false,"productionQualification":false,"targetBuildProvenanceVerified":false,"modelCalls":0,"requiredGap":"supply-chain-provenance-invalid","binding":{"providerSpec":spec,"providerSpecDigest":digest(&canonical(&spec)),"sourceBefore":source_before,"sourceAfter":source_after,"harness":SOURCE},"toolchainBefore":tools_before,"toolchainAfter":tools_after,"syftVersion":"1.55.0","cases":cases});
    record["qualificationDigest"] = json!(digest(&canonical(&record)));
    let bytes = canonical(&record);
    let path = parent.join("supply-chain-native.json");
    assert!(!path.exists(), "native evidence must not be overwritten");
    fs::write(&path, &bytes).unwrap();
    println!(
        "SUPPLY_CHAIN_NATIVE_ACCURACY {}",
        String::from_utf8(bytes).unwrap()
    );
    println!(
        "SUPPLY_CHAIN_NATIVE_ACCURACY_HARNESS_SUMMARY {}",
        json!({"family":"supply-chain-native","status":"pass","cases":13,"record":path,"qualificationEligible":true,"boundedSbomLicenseKnownAnswerEligible":true})
    );
}

#[test]
fn frozen_lock_inventory_keeps_dev_nested_and_refuses_unresolved_syntax() {
    let packages = documents::parse_lock("package-lock.json", &lock("MIT")).unwrap();
    assert_eq!(packages.len(), 3);
    assert!(packages.contains("pkg:npm/dev-only@3.0.0"));
    assert!(packages.contains("pkg:npm/transitive@2.0.0"));
    for (path,text) in [("Cargo.lock","[[package]]\nname=\"one\"\nversion=\"1\"\n[[package]]\nname=\"two\"\nversion=\"2\"\n"),("poetry.lock","[[package]]\nname=\"One_Name\"\nversion=\"1\"\n[[package]]\nname=\"two\"\nversion=\"2\"\n"),("pnpm-lock.yaml","packages:\n  one@1.0.0: {}\n  two@2.0.0: {}\n"),("yarn.lock","\"one@^1\":\n  version: \"1.0.0\"\n\"two@^2\":\n  version: \"2.0.0\"\n"),("go.sum","example.org/one v1.0.0 h1:a\nexample.org/two v2.0.0 h1:b\n"),("requirements.txt","one==1.0.0\ntwo==2.0.0\n")] {assert_eq!(documents::parse_lock(path,text).unwrap().len(),2,"{path}");}
    for (path, text) in [
        ("package-lock.json", "{"),
        ("Cargo.lock", "[[package]]\nname='one'"),
        ("uv.lock", "version=1"),
        ("requirements.txt", "-r hidden.txt"),
        ("requirements.txt", "one>=1"),
        ("pnpm-lock.yaml", "packages: []"),
    ] {
        assert!(documents::parse_lock(path, text).is_err(), "{path}");
    }
}
