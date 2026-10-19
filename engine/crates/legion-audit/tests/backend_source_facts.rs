//! Bounded literal backend source facts through original filesystem inventory,
//! frozen plan & native registry. Runtime mounting/auth are never qualified.
use legion_audit::{
    canonical_bytes, digest, execute, AuditPlan, FilesystemInventorySource, InventorySource,
    NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const ID: &str = "framework.backend";
const KEY: &[u8] = b"backend-source-known-answer-frozen-plan";
const HARNESS: &str = "engine/crates/legion-audit/tests/backend_source_facts.rs";
const CORPUS: &str = "scripts/ci/fixtures/audit-backend-source/corpus.json";
const VALIDATOR: &str = "scripts/ci/audit-backend-source-facts.py";
const SCOPE: &str = "exact thirteen named literal backend source-fact controls; runtime, mount composition & auth remain unproven";
const CRATES: [&str; 5] = [
    "legion-audit",
    "legion-effects",
    "legion-provider-sdk",
    "legion-contracts",
    "legion-rules",
];
const FILES: [&str; 12] = [
    "engine/Cargo.toml",
    "engine/Cargo.lock",
    "engine/rust-toolchain.toml",
    HARNESS,
    CORPUS,
    VALIDATOR,
    "scripts/ci/tests/test_audit_backend_source_facts.py",
    "scripts/ci/audit-qualification-records.py",
    "scripts/ci/tests/test_audit_qualification_records.py",
    "qualification/provider-accuracy/schema.json",
    "scripts/ci/right-git-ci.sh",
    ".github/workflows/ci.yml",
];
fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn write(root: &Path, path: &str, body: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, body).unwrap();
}
fn bind_sources(root: &Path) -> BTreeMap<String, String> {
    fn collect(root: &Path, at: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!at.is_symlink());
        if at.is_dir() {
            for child in fs::read_dir(at).unwrap() {
                collect(root, &child.unwrap().path(), out);
            }
        } else {
            assert!(at.is_file());
            let relative = at
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            let generated = relative
                .strip_prefix(
                    "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/",
                )
                .and_then(|name| name.strip_suffix(".json"))
                .is_some_and(|name| {
                    name.len() == 64
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                });
            if !generated {
                out.insert(relative, raw_digest(&fs::read(at).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    for name in CRATES {
        collect(
            root,
            &root.join(format!("engine/crates/{name}/src")),
            &mut out,
        );
        collect(
            root,
            &root.join(format!("engine/crates/{name}/Cargo.toml")),
            &mut out,
        );
    }
    for name in ["src/registry/rules", "src/registry/controls"]
        .into_iter()
        .chain(FILES)
    {
        collect(root, &root.join(name), &mut out);
    }
    out
}
fn observe(retained: &Path, row: &Value, control: &str, shipped: &Value) -> Value {
    let name = row["framework"].as_str().unwrap();
    let case_id = format!("{name}-{control}");
    let root = retained.join("fixtures").join(&case_id);
    assert!(!root.exists(), "fresh native fixture required");
    fs::create_dir_all(&root).unwrap();
    let source = row["source"]["path"].as_str().unwrap();
    let manifest = row["manifest"]["path"].as_str().unwrap();
    let cap;
    let body = match control {
        "positive" | "missing-manifest" | "drift" => row["source"]["body"].as_str().unwrap(),
        "absence" => row["decoy"].as_str().unwrap(),
        "unsupported" => row["unsupported"].as_str().unwrap(),
        "quoted-decoy" => row["quotedDecoy"].as_str().unwrap(),
        "route-cap" => {
            cap = (0..2001)
                .map(|i| format!("app.get('/r{i}', handler);\n"))
                .collect::<String>();
            &cap
        }
        _ => panic!("unknown fixed control"),
    };
    let mut files = BTreeMap::from([(source.to_owned(), body.to_owned())]);
    if control != "missing-manifest" {
        files.insert(
            manifest.into(),
            row["manifest"]["body"].as_str().unwrap().into(),
        );
    }
    for (path, text) in &files {
        write(&root, path, text);
    }
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(shipped.clone()).unwrap();
    let denominator = inventory.denominator_entries(&spec.selector).unwrap();
    assert_eq!(denominator.entries.len(), files.len());
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    assert!(!plan
        .provider(ID)
        .unwrap()
        .configuration
        .contains_key("input"));
    let mut after = files.clone();
    if control == "drift" {
        after.insert(source.into(), "changed after frozen inventory\n".into());
        write(&root, source, &after[source]);
    }
    let report = execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    assert_eq!(report.planned_providers, vec![ID]);
    assert!(report.pending_host.is_empty());
    assert_eq!(report.results.len(), 1);
    assert!(!report.results[0].skipped);
    let result = &report.results[0].result;
    result.validate().unwrap();
    assert!(result.applicable && !result.complete);
    assert!(result.findings.is_empty());
    // These assertions protect capture itself; offline validator independently
    // derives exact full results & all source/plan/inventory fields from corpus.
    if control == "missing-manifest" {
        assert_eq!(
            result.details["availability"]["reason"],
            "no-backend-framework-detected"
        );
    } else {
        assert_eq!(
            result.details["nativeAnalysis"]["certificationClaim"],
            false
        );
        assert_eq!(
            result.details["nativeAnalysis"]["protocolValidation"]["examined"],
            0
        );
    }
    json!({"caseId":case_id,"framework":name,"control":control,"fixtureRoot":root,
        "fixtureFiles":files,"postFreezeFiles":after,"inventory":inventory,"frozenPlan":plan.plan(),
        "planDigest":plan.digest(),"planSignature":plan.signature(),"nativeResult":result,
        "dispatch":{"planDigest":report.plan_digest,"inventoryDigest":report.inventory_digest,
            "plannedProviders":report.planned_providers,"pendingHost":report.pending_host,"skipped":report.results[0].skipped}})
}
#[test]
#[ignore = "dedicated native source-fact qualification; authenticated CI only"]
fn backend_source_native_qualification() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR").expect("dedicated retained root"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = retained.canonicalize().unwrap();
    assert_eq!(retained.file_name().unwrap(), "backend-source");
    let corpus: Value = serde_json::from_slice(&fs::read(root.join(CORPUS)).unwrap()).unwrap();
    let names = [
        "express",
        "fastify",
        "nest",
        "django",
        "fastapi",
        "flask",
        "spring",
        "ktor",
        "aspnet",
        "rails",
        "laravel",
        "go-router",
        "rust-web",
    ];
    assert_eq!(corpus["frameworkDenominator"], json!(names));
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let shipped = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == ID)
        .unwrap();
    let mut spec = shipped.clone();
    spec.as_object_mut().unwrap().remove("benchmark");
    let rows = corpus["frameworks"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    let mut observations = Vec::new();
    for (name, row) in names.iter().zip(rows) {
        assert_eq!(row["framework"], *name);
        assert_eq!(row["routes"].as_array().unwrap().len(), 2);
        for control in ["positive", "absence", "missing-manifest", "drift"] {
            observations.push(observe(&retained, row, control, shipped));
        }
    }
    for name in ["spring", "ktor", "aspnet", "rails", "laravel"] {
        let row = rows.iter().find(|r| r["framework"] == name).unwrap();
        observations.push(observe(&retained, row, "unsupported", shipped));
    }
    for name in ["rails", "laravel"] {
        let row = rows.iter().find(|r| r["framework"] == name).unwrap();
        observations.push(observe(&retained, row, "quoted-decoy", shipped));
    }
    observations.push(observe(&retained, &rows[0], "route-cap", shipped));
    assert_eq!(observations.len(), 60);
    let mut raw = Vec::new();
    for value in &observations {
        raw.extend(canonical_bytes(value).unwrap());
        raw.push(b'\n');
    }
    fs::write(retained.join("native-results.jsonl"), &raw).unwrap();
    let sources = bind_sources(&root);
    let mut record = json!({"schema":"legion-backend-source-facts/1","provider":ID,"providerVersion":spec["providerVersion"],
        "family":"backend-source-facts","stage":"fact-output","scope":SCOPE,
        "executionPath":"native-frozen-plan-self-sourced-backend-source-facts","status":"pass",
        "qualificationEligible":true,"coverageState":"scoped-controls-complete","modelCalls":0,
        "productionQualification":false,"wholeProviderQualified":false,"auditCleanClaim":false,
        "runtimeQualified":false,"authQualified":false,"certificationClaim":false,"runtimeExamined":0,
        "frameworkDenominator":names,"controls":observations.iter().map(|v| v["caseId"].clone()).collect::<Vec<_>>(),
        "binding":{"providerSpec":spec,"providerSpecDigest":digest(&spec).unwrap(),"benchmarkAtExecution":shipped["benchmark"],
            "fixture":HARNESS,"sources":sources,"sourcesDigest":digest(&sources).unwrap()},
        "rawStream":{"path":"native-results.jsonl","sha256":raw_digest(&raw),"bytes":raw.len(),"cases":observations.len()},
        "retainedRoot":retained,"metrics":{"frameworks":13,"cases":60,"matched":60,"mismatched":0,"runtimeExamined":0}});
    record["qualificationDigest"] = json!(digest(&record).unwrap());
    fs::write(
        retained.join("framework_backend.json"),
        canonical_bytes(&record).unwrap(),
    )
    .unwrap();
    println!(
        "BACKEND_SOURCE_FACTS_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
