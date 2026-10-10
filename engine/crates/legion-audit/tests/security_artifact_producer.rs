// The security-family producer sources real artifacts when the host injected
// none. Every test runs with no scanners installed: tools are either absent
// (empty search path) or a stub script on a temp search path.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use legion_audit::{
    native_providers::security::{
        adapter::SecurityProviderExecutor,
        producer::{lockfile_inventory, ArtifactProducer, SandboxPolicy},
    },
    AuditProvider, FilesystemInventorySource, InventoryEnvelope, InventorySource, ProviderExecutor,
};
use legion_contracts::ProviderResult;
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-security-producer-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // Canonical so path prefixes match what the producer sees.
    fs::canonicalize(dir).unwrap()
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, text).unwrap();
}

fn provider(id: &str) -> AuditProvider {
    serde_json::from_value(json!({
        "id": id,
        "version": "1.0.0",
        "role": "security",
        "phase": "source",
        "lensIds": [],
        "dependencies": [],
        "kind": "typed-external-project-tool",
        "configuration": {},
        "bounds": {},
        "cleanClaim": "candidates-only",
        "benchmarkStatus": "not-required",
        "benchmarkRequiredForCleanClaim": false,
        "qualificationDigest": null,
        "required": false
    }))
    .unwrap()
}

fn inventory(root: &Path) -> InventoryEnvelope {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("fixture")
        .unwrap()
}

fn run(root: &Path, producer: ArtifactProducer, id: &str) -> ProviderResult {
    SecurityProviderExecutor::default()
        .with_producer(producer)
        .execute(&provider(id), &inventory(root))
        .unwrap()
}

/// No scanner is reachable: an empty search path stands in for a bare host.
fn bare(root: &Path) -> ArtifactProducer {
    ArtifactProducer::new(root).with_search_path(Vec::new())
}

fn analysis(result: &ProviderResult) -> &Value {
    &result.details["analysis"]
}

fn fake_token() -> String {
    // Assembled at runtime so no scanner flags this test source itself.
    format!("{}{}", "ghp_", "R7kQ2mZ9xL4vB8nC1dF6hJ3sT5wY0aE2gU9i")
}

#[test]
fn native_secret_fallback_reports_path_and_line_and_ignores_clean_files() {
    let root = fixture("secrets");
    write(
        &root,
        "src/leak.rs",
        &format!(
            "fn main() {{\n    // config\n    let t = \"{}\";\n}}\n",
            fake_token()
        ),
    );
    write(
        &root,
        "src/clean.rs",
        "fn main() {\n    println!(\"hello\");\n}\n",
    );

    let result = run(&root, bare(&root), "secrets.current-history");

    let findings = analysis(&result)["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["file"], json!("src/leak.rs"));
    assert_eq!(findings[0]["line"], json!(3));
    assert_eq!(findings[0]["ruleId"], json!("github.token"));
    // The secret value never reaches the result.
    assert!(!serde_json::to_string(&result.details)
        .unwrap()
        .contains(&fake_token()));
    assert_eq!(result.details["producer"]["mode"], json!("native-fallback"));
    assert_eq!(
        result.details["producer"]["evidence"],
        json!("native-fallback")
    );
    assert!(analysis(&result)["coverageGaps"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(analysis(&result)["denominator"]["expected"], json!(2));
    assert_eq!(analysis(&result)["denominator"]["examined"], json!(2));
}

#[test]
fn native_secret_fallback_is_quiet_on_a_clean_tree() {
    let root = fixture("secrets-clean");
    write(
        &root,
        "src/clean.rs",
        "const NAME: &str = \"your_token_here\";\n",
    );
    let result = run(&root, bare(&root), "secrets.current-history");
    assert!(analysis(&result)["findings"].as_array().unwrap().is_empty());
    assert_eq!(analysis(&result)["status"], json!("pass"));
}

#[test]
fn lockfile_inventory_lists_planted_dependencies() {
    let root = fixture("lockfiles");
    write(
        &root,
        "Cargo.lock",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.80\"\ndependencies = [\n \"serde\",\n]\n",
    );
    write(
        &root,
        "web/package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"name":"web"},"node_modules/left-pad":{"version":"1.3.0"},"node_modules/@scope/pkg":{"version":"2.0.1"}}}"#,
    );
    write(
        &root,
        "py/requirements.txt",
        "Requests==2.31.0  # http\nflask[async]==3.0.0\n",
    );
    write(
        &root,
        "go.sum",
        "github.com/pkg/errors v0.9.1 h1:abc\ngithub.com/pkg/errors v0.9.1/go.mod h1:def\n",
    );
    write(
        &root,
        "yarn.lock",
        "# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n  resolved \"x\"\n",
    );
    write(
        &root,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n\npackages:\n\n  '@types/node@20.1.0':\n    resolution: {integrity: x}\n\n  chalk@5.3.0:\n    resolution: {integrity: y}\n\nsnapshots:\n\n  chalk@5.3.0: {}\n",
    );
    let paths = inventory(&root)
        .entries
        .iter()
        .map(|e| e.path.clone())
        .collect::<Vec<_>>();
    let packages = lockfile_inventory(&root, &paths);
    for expected in [
        "pkg:cargo/serde@1.0.200",
        "pkg:cargo/anyhow@1.0.80",
        "pkg:npm/left-pad@1.3.0",
        "pkg:npm/%40scope/pkg@2.0.1",
        "pkg:pypi/requests@2.31.0",
        "pkg:pypi/flask@3.0.0",
        "pkg:golang/github.com/pkg/errors@v0.9.1",
        "pkg:npm/lodash@4.17.21",
        "pkg:npm/%40types/node@20.1.0",
        "pkg:npm/chalk@5.3.0",
    ] {
        assert!(
            packages.contains(&expected.to_owned()),
            "missing {expected} in {packages:?}"
        );
    }

    // The provider path labels the evidence and keeps the unproven gaps.
    let result = run(&root, bare(&root), "supply-chain.license-sbom-provenance");
    assert_eq!(result.details["producer"]["mode"], json!("native-fallback"));
    assert_eq!(
        analysis(&result)["denominator"]["expected"],
        json!(packages.len())
    );
    assert_eq!(analysis(&result)["complete"], json!(false));
    let gaps = serde_json::to_string(&analysis(&result)["coverageGaps"]).unwrap();
    assert!(gaps.contains("supply-chain-provenance-invalid"), "{gaps}");
}

// The stub scanner is a `#!/bin/sh` script; Windows cannot execute it as `opengrep`.
#[cfg(unix)]
#[test]
fn stub_scanner_on_path_is_run_and_its_receipt_recorded() {
    let root = fixture("stub-root");
    write(&root, "src/lib.rs", "pub fn f() {}\n");
    write(&root, ".semgrep.yml", "rules: []\n");
    let bin = fixture("stub-bin");
    let canned = json!({
        "results": [{
            "check_id": "rules.demo",
            "path": "src/lib.rs",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 10},
            "extra": {"message": "demo finding", "severity": "ERROR"}
        }],
        "paths": {"scanned": ["src/lib.rs"]},
        "errors": []
    })
    .to_string();
    let script = bin.join("opengrep");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"opengrep 1.2.3\"; exit 0; fi\nprintf '%s\\n' '{canned}'\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let before = fs::read_dir(&root).unwrap().count();

    let producer = ArtifactProducer::new(&root)
        .with_search_path(vec![bin.clone()])
        .with_sandbox(SandboxPolicy::Disabled);
    let result = run(&root, producer, "security.opengrep");

    assert_eq!(
        analysis(&result)["status"],
        json!("candidates"),
        "{:?}",
        analysis(&result)
    );
    assert_eq!(analysis(&result)["candidates"].as_array().unwrap().len(), 1);
    let producer = &result.details["producer"];
    assert_eq!(producer["mode"], json!("tool"));
    assert_eq!(producer["tool"], json!("opengrep"));
    assert!(producer["version"].as_str().unwrap().contains("1.2.3"));
    assert_eq!(producer["offline"], json!(true));
    assert!(producer["argv"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a == "off"));
    assert!(producer["executableDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(producer["stdoutDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(producer["exitCode"], json!(0));
    assert!(result.details.contains_key("executionReceipt"));
    // Scratch lives outside the audited tree.
    assert_eq!(fs::read_dir(&root).unwrap().count(), before);
}

#[test]
fn missing_tools_yield_typed_gaps_per_provider() {
    let root = fixture("missing");
    write(&root, "src/lib.rs", "pub fn f() {}\n");
    write(&root, "Dockerfile", "FROM scratch\n");
    let before = fs::read_dir(&root).unwrap().count();
    for (id, reason) in [
        ("security.opengrep", "tool-missing:opengrep"),
        ("structural.ast-grep", "tool-missing:ast-grep"),
        ("container.iac", "tool-missing:trivy"),
        ("dependency.osv", "tool-missing:osv-scanner"),
        ("imported.sarif", "sarif-not-present:imported.sarif"),
    ] {
        let result = run(&root, bare(&root), id);
        let gap = format!("unavailable:{reason}");
        assert!(
            result.coverage_gaps.contains(&gap),
            "{id}: {:?}",
            result.coverage_gaps
        );
        assert!(!result.complete, "{id}");
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), before);
}

#[test]
fn repository_sarif_file_is_ingested() {
    let root = fixture("sarif");
    write(&root, "src/lib.rs", "pub fn f() {}\n");
    write(
        &root,
        "results.sarif",
        r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo","version":"1.0"}},"results":[{"ruleId":"demo.rule","message":{"text":"x"}}]}]}"#,
    );
    let result = run(&root, bare(&root), "imported.sarif");
    assert_eq!(
        analysis(&result)["complete"],
        json!(true),
        "{:?}",
        analysis(&result)
    );
    assert_eq!(analysis(&result)["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        result.details["producer"]["sarifFiles"],
        json!(["results.sarif"])
    );
}

#[test]
fn injected_artifacts_still_win_over_the_producer() {
    let root = fixture("injected");
    write(&root, "src/lib.rs", "pub fn f() {}\n");
    let mut artifacts = std::collections::BTreeMap::new();
    artifacts.insert("imported.sarif".to_owned(), json!({}));
    let result = SecurityProviderExecutor::new(artifacts)
        .with_producer(bare(&root))
        .execute(&provider("imported.sarif"), &inventory(&root))
        .unwrap();
    assert!(!result.details.contains_key("producer"));
}
