//! Dedicated bounded generic-source qualification. No compiler/language clean claim.
use legion_audit::native_providers::code::{evidence, long_tail};
use legion_audit::{
    canonical_bytes, digest, execute, AuditPlan, InventoryEntry, InventoryEnvelope,
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

const ID: &str = "code.long-tail";
const KEY: &[u8] = b"code-long-tail-constructed-fixture-key";
const HARNESS: &str = "engine/crates/legion-audit/tests/code_long_tail_accuracy.rs";
const CORPUS: &str = "engine/crates/legion-audit/tests/fixtures/code-long-tail/controls.json";
const VALIDATOR: &str = "scripts/ci/audit-code-long-tail-accuracy.py";
const SCOPE: &str = "constructed frozen native generic-source controls; unsupported-language coverage remains partial";
const SOURCE_ROOTS: [&str; 7] = [
    "engine/crates/legion-audit/src",
    "engine/crates/legion-effects/src",
    "engine/crates/legion-provider-sdk/src",
    "engine/crates/legion-contracts/src",
    "engine/crates/legion-rules/src",
    "src/registry/rules",
    "src/registry/controls",
];
const SOURCE_FILES: [&str; 11] = [
    "engine/Cargo.toml",
    "engine/Cargo.lock",
    "engine/rust-toolchain.toml",
    "engine/crates/legion-audit/Cargo.toml",
    "engine/crates/legion-effects/Cargo.toml",
    "engine/crates/legion-provider-sdk/Cargo.toml",
    "engine/crates/legion-contracts/Cargo.toml",
    "engine/crates/legion-rules/Cargo.toml",
    HARNESS,
    CORPUS,
    VALIDATOR,
];

fn raw_digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn source_bytes(file: &Value) -> Vec<u8> {
    if let Some(raw) = file.get("rawBytes") {
        return raw
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
    }
    if let Some(text) = file.get("text") {
        return text.as_str().unwrap().as_bytes().to_vec();
    }
    let recipe = &file["recipe"];
    match recipe["kind"].as_str().unwrap() {
        "blank-lines" => "\n"
            .repeat(recipe["lines"].as_u64().unwrap() as usize)
            .into_bytes(),
        "digits" => {
            let mut out = String::new();
            for _ in 0..recipe["repeats"].as_u64().unwrap() {
                for n in 0..recipe["lines"].as_u64().unwrap() {
                    let width = recipe["width"].as_u64().unwrap() as usize;
                    if recipe["indent"] == true {
                        out.push_str("  \t");
                    }
                    out.push_str(&format!("{n:0width$}"));
                    if recipe["indent"] == true {
                        out.push_str("  ");
                    }
                    out.push('\n');
                }
            }
            out.into_bytes()
        }
        other => panic!("unknown fixed recipe: {other}"),
    }
}

fn limits(case: &Value) -> evidence::EvidenceLimits {
    let mut limits = evidence::EvidenceLimits::default();
    for (key, value) in case["limits"].as_object().unwrap() {
        let value = value.as_u64().unwrap();
        match key.as_str() {
            "maxFileBytes" => limits.max_file_bytes = value,
            "maxTotalBytes" => limits.max_total_bytes = value,
            "maxFindings" => limits.max_findings = value as usize,
            "maxDuplicateWindows" => limits.max_duplicate_windows = value as usize,
            "maxSkipRecords" => limits.max_skip_records = value as usize,
            _ => panic!("unknown limit"),
        }
    }
    limits
}

fn entry(path: &str, source: bool, bytes: &[u8]) -> InventoryEntry {
    InventoryEntry {
        path: path.into(),
        source_file: source,
        digest: Some(raw_digest(bytes)),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
    }
}

fn extension(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap();
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

fn expected_unsupported(case: &Value) -> Vec<Value> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in case["selected"].as_array().unwrap() {
        let path = path.as_str().unwrap();
        let ext = extension(path);
        grouped
            .entry(if ext.is_empty() {
                "(no extension)".into()
            } else {
                ext
            })
            .or_default()
            .push(path.into());
    }
    grouped.into_iter().map(|(ext, paths)| json!({"kind":"missing-language-provider",
        "language":ext,"extension":ext,"pathCount":paths.len(),"samplePaths":paths.into_iter().take(20).collect::<Vec<_>>()})).collect()
}

fn expected_gaps(case: &Value, unsupported: &[Value]) -> Vec<String> {
    let mut out = unsupported
        .iter()
        .map(|gap| {
            format!(
                "{ID}:missing-language-provider:{}",
                gap["language"].as_str().unwrap()
            )
        })
        .collect::<Vec<_>>();
    let max = limits(case).max_skip_records;
    for (path, reason) in case["expectedSkips"].as_object().unwrap().iter().take(max) {
        out.push(format!(
            "{ID}:file-skipped:{}:{path}",
            reason.as_str().unwrap()
        ));
    }
    out.extend(
        case["extraGaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned()),
    );
    out.sort();
    out.dedup();
    out
}

#[cfg(unix)]
fn mutate(case: &Value, root: &Path) {
    use std::os::unix::fs::symlink;
    match case["mutation"].as_str().unwrap() {
        "none" => {}
        "delete" => {
            for file in case["files"].as_array().unwrap() {
                fs::remove_file(root.join(file["path"].as_str().unwrap())).unwrap();
            }
        }
        "drift" => fs::write(root.join("worker.sh"), "# TODO replacement\n").unwrap(),
        "symlink" => {
            fs::remove_file(root.join("worker.sh")).unwrap();
            fs::write(root.join("target.txt"), "# TODO symlink target\n").unwrap();
            symlink("target.txt", root.join("worker.sh")).unwrap();
        }
        "symlink-parent" => {
            fs::rename(root.join("directory"), root.join("target-directory")).unwrap();
            symlink("target-directory", root.join("directory")).unwrap();
        }
        _ => panic!("unknown mutation"),
    }
}

#[cfg(not(unix))]
fn mutate(_: &Value, _: &Path) {
    panic!("native qualification requires Unix symlink controls");
}

fn observe(case: &Value, retained: &Path, spec: &Value) -> Value {
    let case_id = case["caseId"].as_str().unwrap();
    let root = retained.join("fixtures").join(case_id);
    assert!(!root.exists(), "fresh dedicated fixture directory required");
    fs::create_dir_all(&root).unwrap();
    let mut entries = Vec::new();
    let mut fixtures = BTreeMap::new();
    for file in case["files"].as_array().unwrap() {
        let path = file["path"].as_str().unwrap();
        let bytes = source_bytes(file);
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, &bytes).unwrap();
        entries.push(entry(path, file["sourceFile"].as_bool().unwrap(), &bytes));
        fixtures.insert(
            path.to_owned(),
            json!({"digest":raw_digest(&bytes),"bytes":bytes.len()}),
        );
    }
    // Explicit bound inventory metadata exercises sourceFile true for unknown
    // suffixes; filesystem extraction does not claim to recognize these languages.
    let inventory =
        InventoryEnvelope::new(case_id, "constructed-digest-bound-files-v1", entries).unwrap();
    let plan = AuditPlan::compile_with_root(
        Some(&root),
        &inventory,
        &[serde_json::from_value::<ProviderSpec>(spec.clone()).unwrap()],
    )
    .unwrap()
    .freeze(Some(KEY))
    .unwrap();
    mutate(case, &root);
    let mut native = NativeProviderRegistry::new(&root);
    native.code = native.code.with_limits(limits(case));
    if case["injected"] == true {
        native.code = native.code.with_input(
            ID,
            json!({"files":[{"path":"pretend.sh"}],
            "complete":true,"findings":[],"tools":{},"facts":[{"kind":"claimed-clean"}]}),
        );
    }
    let report = execute(&plan, &inventory, &native).unwrap();
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    let result = serde_json::to_value(&report.results[0].result).unwrap();
    let selected = case["selected"].as_array().unwrap();
    let excluded = case_id == "selection-owned-elsewhere";
    assert_eq!(result["applicable"], !excluded);
    assert_eq!(
        result["complete"], false,
        "generic inspection never proves language coverage"
    );
    let mut wanted_evidence = BTreeMap::new();
    let mut wanted_locations = BTreeMap::new();
    let mut wanted_findings = Vec::new();
    for item in case["expectedFindings"].as_array().unwrap() {
        let rule = item["ruleId"].as_str().unwrap();
        let path = item["path"].as_str().unwrap();
        let line = item["line"].as_u64().unwrap();
        let finding_id = raw_digest(format!("{ID}\0{rule}\0{path}\0{line}").as_bytes());
        wanted_evidence.insert(
            finding_id.clone(),
            json!({"provider":ID,"ruleId":rule,
            "path":path,"line":line,"message":item["message"]}),
        );
        wanted_locations.insert(finding_id.clone(), json!([format!("{path}:{line}")]));
        wanted_findings.push(json!({"id":finding_id,"severity":"low"}));
    }
    assert_eq!(
        result["findings"],
        json!(wanted_findings),
        "{case_id}: exact findings"
    );
    let unsupported = expected_unsupported(case);
    let gaps = expected_gaps(case, &unsupported);
    if excluded {
        assert!(selected.is_empty());
        assert!(result["coverage"].is_null());
        assert_eq!(result["coverage_gaps"], json!([]));
        assert_eq!(
            result["details"]["notApplicableReason"],
            "no-long-tail-files-in-inventory"
        );
    } else {
        assert_eq!(result["status"], "partial");
        assert_eq!(result["coverage_gaps"], json!(gaps));
        assert_eq!(result["coverage"]["expected"], inventory.entries.len());
        let expected_digest = if case["injected"] == true {
            json!(inventory.digest)
        } else {
            plan.providers()[0].configuration["denominatorDigest"].clone()
        };
        assert_eq!(result["coverage"]["denominator_digest"], expected_digest);
        if case["injected"] == true {
            assert!(result["details"].get("nativeProducer").is_none());
            assert!(result["details"].get("findingEvidence").is_none());
        } else {
            assert_eq!(result["details"]["findingEvidence"], json!(wanted_evidence));
            assert_eq!(
                result["details"]["findingLocations"],
                json!(wanted_locations)
            );
            let producer = &result["details"]["nativeProducer"];
            assert_eq!(producer["mode"], "self-sourced");
            assert_eq!(producer["sourceFilesExpected"], selected.len());
            assert_eq!(
                producer["sourceFilesRead"],
                selected.len() - case["expectedSkips"].as_object().unwrap().len()
            );
            assert_eq!(
                producer["rules"],
                json!(["debt-marker", "duplicate-block", "oversized-file"])
            );
            assert_eq!(producer["toolDiscovery"], json!([]));
            assert_eq!(producer["toolReceipts"], json!([]));
            let actual_gaps = &result["details"]["nativeAnalysis"]["coverageGaps"];
            if case_id == "empty-denominator" {
                assert_eq!(
                    actual_gaps,
                    &json!([{"kind":"denominator-gap","language":"generic"}])
                );
            } else {
                assert_eq!(actual_gaps, &json!(unsupported));
            }
        }
    }
    json!({"caseId":case_id,"inventoryOrigin":"constructed-digest-bound-files-v1",
        "fixtureRoot":root,"fixtureSources":fixtures,"inventory":inventory,"frozenPlan":plan.plan(),
        "planDigest":plan.digest(),"planSignature":plan.signature(),"nativeResult":result,"controlMatched":true})
}

fn generated_session_provenance(relative: &Path) -> bool {
    relative.parent()
        == Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
        && relative
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|name| {
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn collect_source_binding(root: &Path, at: &Path, out: &mut BTreeMap<String, String>) {
    assert!(!at.is_symlink());
    if at.is_dir() {
        for child in fs::read_dir(at).unwrap() {
            collect_source_binding(root, &child.unwrap().path(), out);
        }
    } else {
        assert!(at.is_file());
        if generated_session_provenance(at.strip_prefix(root).unwrap()) {
            return;
        }
        let relative = at
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        out.insert(relative, raw_digest(&fs::read(at).unwrap()));
    }
}

fn bind_sources(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for tree in SOURCE_ROOTS {
        collect_source_binding(root, &root.join(tree), &mut out);
    }
    for path in SOURCE_FILES {
        collect_source_binding(root, &root.join(path), &mut out);
    }
    out
}

#[test]
fn source_binding_receipt_exclusion_preserves_other_bytes() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let scratch_base = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(if cfg!(windows) {
                r"D:\scratch"
            } else {
                "/Volumes/D/scratch"
            })
        });
    let scratch = Scratch(scratch_base.join(format!(
        "longtail-bind-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    fs::create_dir(&scratch.0).unwrap();
    let root = &scratch.0;
    let snapshot = || {
        let mut bound = BTreeMap::new();
        collect_source_binding(root, root, &mut bound);
        bound
    };
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, "pub fn retained() {}\n").unwrap();
    let baseline = snapshot();
    assert_eq!(baseline.len(), 1);
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let receipt = root.join(format!("{prefix}{}.json", "a".repeat(64)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, "generated receipt one").unwrap();
    assert_eq!(snapshot(), baseline);
    fs::write(&receipt, "generated receipt two").unwrap();
    assert_eq!(snapshot(), baseline);

    // A matching directory still contributes every descendant.
    let matching_directory = root.join(format!("{prefix}{}.json", "b".repeat(64)));
    fs::create_dir(&matching_directory).unwrap();
    let child = matching_directory.join("retained.rs");
    fs::write(&child, "directory child one").unwrap();
    let directory_binding = snapshot();
    assert_eq!(directory_binding.len(), baseline.len() + 1);
    fs::write(&child, "directory child two").unwrap();
    assert_ne!(snapshot(), directory_binding);
    fs::remove_dir_all(&matching_directory).unwrap();
    assert_eq!(snapshot(), baseline);

    for relative in [
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "c".repeat(64)),
        format!("{prefix}{}.json", "C".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "retained near-match one").unwrap();
        let bound = snapshot();
        assert_eq!(bound.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, "retained near-match two").unwrap();
        assert_ne!(snapshot(), bound, "{relative}");
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    for relative in [
        format!(
            r"engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates/legion-audit/src/.audit/arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates\legion-audit\src\.audit\arcane\receipts\session-provenance\{}.json",
            "a".repeat(64)
        ),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "literal backslash one").unwrap();
        let bound = snapshot();
        assert_eq!(bound.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, "literal backslash two").unwrap();
        assert_ne!(snapshot(), bound, "{relative}");
        fs::remove_file(&path).unwrap();
    }

    fs::write(&source, "pub fn retained_changed() {}\n").unwrap();
    assert_ne!(snapshot(), baseline);
    #[cfg(unix)]
    {
        fs::remove_file(&receipt).unwrap();
        std::os::unix::fs::symlink(&source, &receipt).unwrap();
        assert!(std::panic::catch_unwind(snapshot).is_err());
        fs::remove_file(&receipt).unwrap();
    }
}

#[test]
#[ignore = "dedicated native qualification; run in authenticated CI"]
fn code_long_tail_native_qualification() {
    assert!(cfg!(unix), "Unix native symlink controls required");
    assert!(long_tail::CONFIG.tools.is_empty());
    assert!(long_tail::CONFIG.required_context.is_empty());
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
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let shipped = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == ID)
        .unwrap();
    let mut sanitized = shipped.clone();
    sanitized.as_object_mut().unwrap().remove("benchmark");
    let contract: Value =
        serde_json::from_str(include_str!("fixtures/code-long-tail/controls.json")).unwrap();
    let cases = contract["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| observe(case, &retained, shipped))
        .collect::<Vec<_>>();
    let unsafe_root = retained.join("unsafe-boundary");
    fs::create_dir_all(&unsafe_root).unwrap();
    let mut unsafe_controls = Vec::new();
    for path in contract["unsafePaths"].as_array().unwrap() {
        let path = path.as_str().unwrap();
        let item = entry(path, true, b"# TODO must not read\n");
        let rejected = InventoryEnvelope::new("unsafe", "constructed", vec![item.clone()]).is_err();
        assert!(rejected, "frozen inventory must reject unsafe path");
        let made = evidence::produce(
            ID,
            &long_tail::CONFIG,
            Some(&unsafe_root),
            &[item],
            &evidence::EvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!((made.expected, made.examined), (1, 0));
        assert_eq!(made.skips, vec![format!("unsafe-path:{path}")]);
        assert!(made.findings.is_empty());
        assert_eq!(long_tail::analyze(&made.input)["complete"], false);
        unsafe_controls.push(json!({"path":path,"inventoryRejected":rejected,"route":"native-producer-defense-in-depth",
            "expected":made.expected,"examined":made.examined,"skips":made.skips,
            "sourceAccounting":made.input["sourceAccounting"],"analysis":long_tail::analyze(&made.input)}));
    }
    let sources = bind_sources(&root);
    let mut record = json!({"schema":"legion-code-long-tail-native-accuracy/1","provider":ID,
        "providerVersion":sanitized["providerVersion"],"family":"code-long-tail","stage":"finding",
        "scope":SCOPE,"executionPath":"native-frozen-plan-self-sourced-generic-source",
        "productionQualification":false,"wholeProviderQualified":false,"auditCleanClaim":false,
        "compilerCoverageQualified":false,"languageCoverageQualified":false,"qualificationEligible":true,
        "status":"pass","coverageState":"scoped-controls-complete","modelCalls":0,
        "requiredContract":{"tools":[],"contexts":[],"rules":["debt-marker","duplicate-block","oversized-file"],
            "unsupportedLanguageGapsMandatory":true,"thresholds":contract["thresholds"]},
        "binding":{"providerSpec":sanitized,"providerSpecDigest":digest(&sanitized).unwrap(),"fixture":HARNESS,
            "sources":sources,"sourcesDigest":digest(&sources).unwrap()},
        "cases":cases,"unsafeControls":unsafe_controls,
        "metrics":{"cases":cases.len(),"matched":cases.len(),"mismatched":0,"unsafeControls":unsafe_controls.len()}});
    record["qualificationDigest"] = json!(digest(&record).unwrap());
    fs::write(
        retained.join("code_long-tail.json"),
        canonical_bytes(&record).unwrap(),
    )
    .unwrap();
    println!(
        "CODE_LONG_TAIL_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
