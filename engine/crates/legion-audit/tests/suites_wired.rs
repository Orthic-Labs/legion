//! Production wiring of the data and infrastructure suites, framework family
//! breadth, and the judgment-tier lens routing.

use legion_audit::native_providers::reasoning::lens_plan::lens_plan_packet_value;
use legion_audit::{
    AuditProvider, FilesystemInventorySource, InventoryEntry, InventoryEnvelope, InventorySource,
    NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn registry_providers() -> Vec<Value> {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    registry["providers"].as_array().unwrap().clone()
}

fn provider(id: &str) -> AuditProvider {
    let item = registry_providers()
        .into_iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("{id} is not in the shipped registry"));
    assert_eq!(item["runner"]["kind"], "runtime-script", "{id}");
    let spec: ProviderSpec = serde_json::from_value(item).unwrap();
    AuditProvider {
        id: spec.id.to_string(),
        version: spec.provider_version.clone(),
        role: spec.role.clone(),
        phase: spec.phase.clone(),
        lens_ids: spec.lens_ids.clone(),
        dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([(String::from("selector"), spec.selector.clone())]),
        bounds: BTreeMap::new(),
        clean_claim: spec.clean_claim.clone(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: spec.selectable,
    }
}

fn fixture_root(label: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-suites-wired-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    for (path, body) in files {
        let target = root.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, body).unwrap();
    }
    root
}

fn entry(path: &str, dependencies: &[&str], source_file: bool) -> InventoryEntry {
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: dependencies.iter().map(|name| (*name).to_owned()).collect(),
        package_scripts: Vec::new(),
        source_file,
        digest: None,
    }
}

fn run(id: &str, root: &Path, mut entries: Vec<InventoryEntry>) -> ProviderResult {
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let inventory = InventoryEnvelope::new("suites-wired", "generation", entries).unwrap();
    NativeProviderRegistry::new(root)
        .execute(&provider(id), &inventory)
        .unwrap_or_else(|error| panic!("{id}: {error}"))
}

fn candidate_rules(result: &ProviderResult) -> Vec<String> {
    result.details["candidates"]
        .as_array()
        .expect("candidates stay an array")
        .iter()
        .map(|row| row["ruleId"].as_str().unwrap().to_owned())
        .collect()
}

fn is_partial(result: &ProviderResult) -> bool {
    matches!(result.status, ProviderStatus::Partial) && !result.complete
}

#[test]
fn new_suite_providers_are_registered_selectable_runtime_scripts() {
    for id in [
        "legacy.data.internal-suite",
        "legacy.infrastructure.internal-suite",
    ] {
        let provider = provider(id);
        assert_eq!(provider.role, "candidate-generator", "{id}");
        assert_eq!(provider.phase, "runtime", "{id}");
    }
}

#[test]
fn data_suite_reports_candidates_not_findings() {
    let root = fixture_root(
        "data",
        &[(
            "db/001.sql",
            "ALTER TABLE users ADD COLUMN age INT NOT NULL;\n",
        )],
    );
    let result = run(
        "legacy.data.internal-suite",
        &root,
        vec![
            entry("db/001.sql", &[], false),
            entry("README.md", &[], false),
        ],
    );
    assert!(result.findings.is_empty(), "suite output is candidate-only");
    assert!(result.complete, "{:?}", result.coverage_gaps);
    assert!(matches!(result.status, ProviderStatus::Complete));
    assert!(candidate_rules(&result).contains(&"data.not-null-migration".to_owned()));
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn data_suite_is_never_complete_on_zero_or_unreadable_files() {
    let root = fixture_root("data-zero", &[("README.md", "# docs\n")]);
    let zero = run(
        "legacy.data.internal-suite",
        &root,
        vec![entry("README.md", &[], false)],
    );
    assert!(is_partial(&zero), "{:?}", zero.status);
    assert!(zero
        .coverage_gaps
        .iter()
        .any(|gap| gap == "data-denominator-zero"));

    let missing = run(
        "legacy.data.internal-suite",
        &root,
        vec![entry("db/missing.sql", &[], false)],
    );
    assert!(is_partial(&missing));
    assert!(missing
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("source-unavailable:db/missing.sql")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn data_suite_survives_multibyte_text_at_a_window_boundary() {
    // The sqlite window ends 300 bytes after the match; with 3-byte characters
    // that offset is inside a character.
    let body = format!("sqlite3.open(x{})\n", "\u{20ac}".repeat(200));
    let root = fixture_root("data-utf8", &[("src/db.js", body.as_str())]);
    let result = run(
        "legacy.data.internal-suite",
        &root,
        vec![entry("src/db.js", &[], true)],
    );
    assert!(result.complete, "{:?}", result.coverage_gaps);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn infrastructure_suite_reports_candidates_for_dockerfiles() {
    let root = fixture_root("infra", &[("Dockerfile", "FROM node:latest\nRUN true\n")]);
    let result = run(
        "legacy.infrastructure.internal-suite",
        &root,
        vec![
            entry("Dockerfile", &[], false),
            entry("notes.txt", &[], false),
        ],
    );
    assert!(result.findings.is_empty());
    assert!(result.complete, "{:?}", result.coverage_gaps);
    let rules = candidate_rules(&result);
    assert!(
        rules.contains(&"container.latest-tag".to_owned()),
        "{rules:?}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn infrastructure_suite_is_partial_with_nothing_selected() {
    let root = fixture_root("infra-zero", &[("notes.txt", "hello\n")]);
    let result = run(
        "legacy.infrastructure.internal-suite",
        &root,
        vec![entry("notes.txt", &[], false)],
    );
    assert!(is_partial(&result));
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "infrastructure-denominator-zero"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn framework_families_are_selectable_by_their_real_dependency_names() {
    // (manifest, dependency, source path, source text, expected rule)
    let cases = [
        (
            "package.json",
            "electron",
            "src/main.js",
            "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
            "electron-node-integration",
        ),
        (
            "pyproject.toml",
            "fastapi",
            "app/main.py",
            "allow_origins = [\"*\"]\n",
            "fastapi-open-cors",
        ),
        (
            "package.json",
            "@nestjs/core",
            "src/main.ts",
            "app.enableCors();\n",
            "nest-open-cors",
        ),
        (
            "package.json",
            "@sveltejs/kit",
            "src/routes/a.ts",
            "throw redirect(302, url);\n",
            "sveltekit-unvalidated-redirect",
        ),
        (
            "go.mod",
            "github.com/labstack/echo/v4",
            "main.go",
            "x := template.HTML(body)\n",
            "go-template-html",
        ),
        (
            "Cargo.toml",
            "axum",
            "src/main.rs",
            "Command::new(program);\n",
            "rust-web-command-input",
        ),
    ];
    for (manifest, dependency, path, text, rule) in cases {
        let root = fixture_root("framework", &[(path, text), (manifest, "")]);
        let result = run(
            "legacy.framework.major-suite",
            &root,
            vec![
                entry(manifest, &[dependency], false),
                entry(path, &[], true),
            ],
        );
        let rules = candidate_rules(&result);
        assert!(rules.contains(&rule.to_owned()), "{dependency}: {rules:?}");
        assert!(result.findings.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn framework_family_rules_stay_inside_the_manifest_subtree() {
    let flagged = "new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n";
    let root = fixture_root(
        "framework-scope",
        &[("app/main.js", flagged), ("other/main.js", flagged)],
    );
    let result = run(
        "legacy.framework.major-suite",
        &root,
        vec![
            entry("app/package.json", &["electron"], false),
            entry("app/main.js", &[], true),
            entry("other/main.js", &[], true),
        ],
    );
    let files: Vec<&str> = result.details["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["file"].as_str())
        .collect();
    assert!(files.contains(&"app/main.js"), "{files:?}");
    assert!(!files.contains(&"other/main.js"), "{files:?}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn selected_framework_without_rules_is_a_named_gap_not_a_clean_pass() {
    let root = fixture_root(
        "framework-react",
        &[("src/App.tsx", "export const A = 1;\n")],
    );
    let result = run(
        "legacy.framework.major-suite",
        &root,
        vec![
            entry("package.json", &["react"], false),
            entry("src/App.tsx", &[], true),
        ],
    );
    assert!(is_partial(&result), "{:?}", result.status);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "no-rules-for-family:react"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_files_without_a_detected_family_are_not_a_silent_clean() {
    let root = fixture_root("framework-none", &[("src/a.js", "let a = 1;\n")]);
    let result = run(
        "legacy.framework.major-suite",
        &root,
        vec![entry("src/a.js", &[], true)],
    );
    assert!(is_partial(&result), "{:?}", result.status);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "framework-denominator-zero"));
    fs::remove_dir_all(root).unwrap();
}

/// Runs the framework suite on a real directory: the inventory is walked from
/// disk, so manifest dependencies are parsed by the production inventory code.
fn run_framework_from_disk(root: &Path) -> ProviderResult {
    let inventory = FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("suites-wired")
        .unwrap();
    NativeProviderRegistry::new(root)
        .execute(&provider("legacy.framework.major-suite"), &inventory)
        .unwrap_or_else(|error| panic!("framework suite: {error}"))
}

fn assert_framework_rule_fires(label: &str, files: &[(&str, &str)], rule: &str) {
    let root = fixture_root(label, files);
    let result = run_framework_from_disk(&root);
    let rules = candidate_rules(&result);
    assert!(
        rules.contains(&rule.to_owned()),
        "{label}: {rules:?} gaps {:?}",
        result.coverage_gaps
    );
    assert!(result.findings.is_empty(), "{label}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn spring_family_is_detected_from_maven_and_its_rule_fires() {
    assert_framework_rule_fires(
        "framework-spring",
        &[
            (
                "pom.xml",
                "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>\n",
            ),
            (
                "src/main/java/app/Api.java",
                "http.authorizeHttpRequests(a -> a.requestMatchers(\"/admin/**\").permitAll());\n",
            ),
        ],
        "spring-sensitive-permit-all",
    );
}

#[test]
fn ktor_family_is_detected_from_gradle_kotlin_and_its_rule_fires() {
    assert_framework_rule_fires(
        "framework-ktor",
        &[
            (
                "build.gradle.kts",
                "plugins {\n    id(\"io.ktor.plugin\") version \"2.3.0\"\n}\ndependencies {\n    implementation(\"io.ktor:ktor-server-core:2.3.0\")\n}\n",
            ),
            (
                "src/main/kotlin/Main.kt",
                "fun Application.module() { install(CORS) { anyHost() } }\n",
            ),
        ],
        "ktor-any-host",
    );
}

#[test]
fn rails_family_is_detected_from_gemfile_and_its_rule_fires() {
    assert_framework_rule_fires(
        "framework-rails",
        &[
            (
                "Gemfile",
                "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n",
            ),
            (
                "app/controllers/users_controller.rb",
                "class UsersController < ApplicationController\n  skip_forgery_protection\nend\n",
            ),
        ],
        "rails-forgery-skip",
    );
}

#[test]
fn phoenix_family_is_detected_from_mix_and_its_rule_fires() {
    assert_framework_rule_fires(
        "framework-phoenix",
        &[
            (
                "mix.exs",
                "defp deps do\n  [{:phoenix, \"~> 1.7.0\"}]\nend\n",
            ),
            (
                "lib/app_web/endpoint.ex",
                "socket \"/live\", Phoenix.LiveView.Socket, websocket: [check_origin: false]\n",
            ),
        ],
        "phoenix-check-origin-disabled",
    );
}

#[test]
fn flutter_family_is_detected_from_pubspec_and_its_rule_fires() {
    assert_framework_rule_fires(
        "framework-flutter",
        &[
            (
                "pubspec.yaml",
                "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n",
            ),
            (
                "lib/net.dart",
                "final client = HttpClient()..badCertificateCallback = (cert, host, port) => true;\n",
            ),
        ],
        "flutter-bad-cert-callback",
    );
}

#[test]
fn malformed_new_manifests_detect_no_family_and_never_panic() {
    let root = fixture_root(
        "framework-malformed",
        &[
            (
                "pom.xml",
                "<dependencies><dependency><groupId>org.springframework.boot</groupId>\n",
            ),
            ("build.gradle.kts", "implementation(\"io.ktor:\n"),
            ("Gemfile", "gem '\n"),
            ("mix.exs", "{:\n"),
            ("pubspec.yaml", "dependencies:\n\t:::\n"),
            ("src/Main.java", "x.permitAll();\n"),
            ("lib/net.dart", "badCertificateCallback\n"),
        ],
    );
    let result = run_framework_from_disk(&root);
    let rules = candidate_rules(&result);
    assert!(rules.is_empty(), "{rules:?}");
    assert!(is_partial(&result), "{:?}", result.status);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "framework-denominator-zero"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ai_slop_naming_and_performance_lenses_run_on_the_judgment_tier() {
    for id in [
        "reasoning.ai-slop",
        "reasoning.naming",
        "reasoning.performance",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["modelTier"], "judgment", "{id}");
    }
}
