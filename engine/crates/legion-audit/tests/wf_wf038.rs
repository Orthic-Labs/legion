//! Ported tests for chunk wf038 (`src/providers/native/{javascript,jvm,php,
//! python,ruby}/index.mjs`) against `legion_audit::wf_port::wf038::*`.
//!
//! No dedicated `*.test.mjs` file exercises these five provider modules
//! directly (they are not imported by any test in the JS tree at HEAD), so
//! these assertions are derived directly from each module's own `detect` /
//! `commands` / `normalize` / `coverage` bodies rather than ported from an
//! existing JS test file.

use std::path::PathBuf;

use legion_audit::wf_port::wf038::{
    javascript, jvm, php, python, ruby, CommandsInput, ExecutionResult, Projection,
};

fn projection(parsed_extensions: &[&str], files: &[&str]) -> Projection {
    Projection {
        parsed_extensions: parsed_extensions.iter().map(|s| s.to_string()).collect(),
        files: files.iter().map(|s| s.to_string()).collect(),
    }
}

fn inputs(root: &str, files: &[&str], manifests: &[&str], profile: Option<&str>) -> CommandsInput {
    CommandsInput {
        root: PathBuf::from(root),
        files: files.iter().map(|s| s.to_string()).collect(),
        manifests: manifests.iter().map(|s| s.to_string()).collect(),
        profile: profile.map(|p| p.to_string()),
    }
}

// -- javascript --------------------------------------------------------

#[test]
fn javascript_detect_matches_js_ts_jsx_tsx() {
    assert!(javascript::detect(&projection(&["ts"], &[])));
    assert!(javascript::detect(&projection(&["JSX"], &[])));
    assert!(!javascript::detect(&projection(&["py"], &[])));
}

#[test]
fn javascript_commands_adds_types_only_for_ts_files_and_build_only_with_manifest_and_non_fast() {
    let cmds = javascript::commands(&inputs(
        "/repo",
        &["a.ts", "b.test.ts", "c.js"],
        &["package.json"],
        None,
    ));
    let ids: Vec<&str> = cmds.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["js.types", "js.test", "js.build"]);
    let test_cmd = cmds.iter().find(|c| c.id == "js.test").unwrap();
    assert_eq!(test_cmd.args, vec!["--test".to_string(), "b.test.ts".to_string()]);

    let no_ts = javascript::commands(&inputs("/repo", &["c.js"], &["package.json"], None));
    assert!(!no_ts.iter().any(|c| c.id == "js.types"));

    let fast = javascript::commands(&inputs("/repo", &["a.ts"], &["package.json"], Some("fast")));
    assert!(!fast.iter().any(|c| c.id == "js.build"));

    let no_manifest = javascript::commands(&inputs("/repo", &["a.ts"], &[], None));
    assert!(!no_manifest.iter().any(|c| c.id == "js.build"));
}

#[test]
fn javascript_normalize_and_coverage() {
    let ok = javascript::normalize("js.test", Some(&ExecutionResult { exit_code: Some(0), tool_version: Some("22".into()) }));
    assert_eq!(ok.status, "pass");
    assert!(ok.complete);
    assert!(ok.coverage_gaps.is_empty());

    let err = javascript::normalize("js.test", Some(&ExecutionResult { exit_code: Some(1), tool_version: None }));
    assert_eq!(err.status, "error");
    assert!(!err.complete);
    assert_eq!(err.coverage_gaps.len(), 1);
    assert_eq!(err.coverage_gaps[0].command, "js.test");

    let missing = javascript::normalize("js.test", None);
    assert_eq!(missing.status, "error");

    let cov = javascript::coverage(&projection(&["js", "ts", "py"], &[]));
    assert_eq!(cov.provider, "language.javascript");
    assert_eq!(cov.examined, vec!["js".to_string(), "ts".to_string()]);
    assert!(cov.complete);
}

#[test]
fn javascript_fingerprint_is_stable_sha256() {
    let fp1 = javascript::js_fingerprint("a.ts", 3, "no-eval");
    let fp2 = javascript::js_fingerprint("a.ts", 3, "no-eval");
    let fp3 = javascript::js_fingerprint("a.ts", 4, "no-eval");
    assert!(fp1.starts_with("sha256:"));
    assert_eq!(fp1, fp2);
    assert_ne!(fp1, fp3);
}

// -- jvm -----------------------------------------------------------------

#[test]
fn jvm_detect_matches_source_files_and_build_files() {
    assert!(jvm::detect(&projection(&[], &["src/Main.java"])));
    assert!(jvm::detect(&projection(&[], &["build.gradle.kts"])));
    assert!(!jvm::detect(&projection(&[], &["README.md"])));
}

#[test]
fn jvm_commands_prefers_gradle_over_maven_and_gates_test_on_profile() {
    let gradle = jvm::commands(&inputs("/repo", &[], &["build.gradle"], None));
    assert_eq!(gradle[0].id, "jvm.gradle-wrapper");
    assert_eq!(gradle[0].executable, "./gradlew");
    assert_eq!(gradle[1].id, "jvm.test");
    assert_eq!(gradle[1].executable, "./gradlew");

    let maven = jvm::commands(&inputs("/repo", &[], &["pom.xml"], None));
    assert_eq!(maven[0].id, "jvm.maven-wrapper");
    assert_eq!(maven[0].executable, "./mvnw");
    assert_eq!(maven[1].executable, "./mvnw");

    let fast = jvm::commands(&inputs("/repo", &[], &["pom.xml"], Some("fast")));
    assert!(!fast.iter().any(|c| c.id == "jvm.test"));

    let neither = jvm::commands(&inputs("/repo", &[], &[], None));
    assert!(neither.iter().all(|c| c.id != "jvm.gradle-wrapper" && c.id != "jvm.maven-wrapper"));
}

#[test]
fn jvm_coverage_examines_java_kt_scala_only() {
    let cov = jvm::coverage(&projection(&["java", "kt", "scala", "js"], &[]));
    assert_eq!(cov.examined, vec!["java".to_string(), "kt".to_string(), "scala".to_string()]);
}

// -- php -------------------------------------------------------------------

#[test]
fn php_detect_matches_extension_or_composer_json() {
    assert!(php::detect(&projection(&["php"], &[])));
    assert!(php::detect(&projection(&[], &["composer.json"])));
    assert!(!php::detect(&projection(&["rb"], &["Gemfile"])));
}

#[test]
fn php_commands_gated_on_composer_manifest_and_profile() {
    let none = php::commands(&inputs("/repo", &[], &[], None));
    assert!(none.is_empty());

    let full = php::commands(&inputs("/repo", &[], &["composer.json"], None));
    let ids: Vec<&str> = full.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["php.validate", "php.test", "php.static"]);

    let fast = php::commands(&inputs("/repo", &[], &["composer.json"], Some("fast")));
    let ids: Vec<&str> = fast.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["php.validate"]);
}

// -- python -----------------------------------------------------------------

#[test]
fn python_commands_always_syntax_gated_lint_type_and_test() {
    let base = python::commands(&inputs("/repo", &[], &[], None));
    assert_eq!(base.len(), 3); // syntax, lint, type
    assert_eq!(base[0].id, "py.syntax");
    assert!(base[0].args.contains(&"/repo".to_string()));

    let fast = python::commands(&inputs("/repo", &[], &[], Some("fast")));
    let ids: Vec<&str> = fast.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["py.syntax"]);

    let with_manifest = python::commands(&inputs("/repo", &[], &["pyproject.toml"], Some("fast")));
    let ids: Vec<&str> = with_manifest.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["py.syntax", "py.test"]);
}

#[test]
fn python_detect_and_coverage() {
    assert!(python::detect(&projection(&["PY"], &[])));
    assert!(!python::detect(&projection(&["rb"], &[])));
    let cov = python::coverage(&projection(&["py", "js"], &[]));
    assert_eq!(cov.examined, vec!["py".to_string()]);
}

// -- ruby --------------------------------------------------------------

#[test]
fn ruby_detect_matches_extension_gemfile_or_gemspec() {
    assert!(ruby::detect(&projection(&["rb"], &[])));
    assert!(ruby::detect(&projection(&[], &["Gemfile"])));
    assert!(ruby::detect(&projection(&[], &["foo.gemspec"])));
    assert!(!ruby::detect(&projection(&["py"], &["package.json"])));
}

#[test]
fn ruby_commands_gated_on_gemfile_manifest_and_profile() {
    let none = ruby::commands(&inputs("/repo", &[], &[], None));
    assert!(none.is_empty());

    let full = ruby::commands(&inputs("/repo", &[], &["Gemfile"], None));
    let ids: Vec<&str> = full.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["ruby.test", "ruby.lint", "ruby.security"]);

    let fast = ruby::commands(&inputs("/repo", &[], &["Gemfile"], Some("fast")));
    let ids: Vec<&str> = fast.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["ruby.test"]);
}

#[test]
fn all_five_providers_normalize_errors_when_execution_is_missing() {
    assert_eq!(jvm::normalize("jvm.test", None).status, "error");
    assert_eq!(php::normalize("php.test", None).status, "error");
    assert_eq!(python::normalize("py.test", None).status, "error");
    assert_eq!(ruby::normalize("ruby.test", None).status, "error");
}

#[test]
fn all_five_providers_declare_empty_fixtures() {
    assert!(javascript::fixtures().positive.is_empty());
    assert!(jvm::fixtures().negative.is_empty());
    assert!(php::fixtures().unsupported.is_empty());
    assert!(python::fixtures().positive.is_empty());
    assert!(ruby::fixtures().negative.is_empty());
}
