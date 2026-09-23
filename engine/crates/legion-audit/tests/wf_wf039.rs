//! Tests for chunk wf039: `src/providers/native/rust/index.mjs` and
//! `src/providers/native/swift-objc/index.mjs`, ported into
//! `legion_audit::wf_port::wf039::{rust, swift_objc}`.

use legion_audit::wf_port::wf039::{rust, swift_objc, Execution, PackCommand, Profile};

fn s(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

// ---------------------------------------------------------------------
// rust pack
// ---------------------------------------------------------------------

#[test]
fn rust_detect_matches_lowercased_rs_extension() {
    assert!(rust::detect(&s(&["rs"]), &s(&[])));
    // JS: `ext.toLowerCase() === 'rs'` — mixed case still matches.
    assert!(rust::detect(&s(&["RS"]), &s(&[])));
    assert!(!rust::detect(&s(&["ts"]), &s(&[])));
}

#[test]
fn rust_detect_matches_cargo_toml_file() {
    assert!(rust::detect(&s(&[]), &s(&["Cargo.toml"])));
    // Exact-match only, same as the JS `file === 'Cargo.toml'`.
    assert!(!rust::detect(&s(&[]), &s(&["nested/Cargo.toml"])));
}

#[test]
fn rust_detect_false_without_extension_or_manifest() {
    assert!(!rust::detect(&s(&[]), &s(&[])));
}

#[test]
fn rust_commands_empty_without_manifest() {
    let commands = rust::commands("/root", &s(&[]), &s(&[]), Profile::Other);
    assert!(commands.is_empty());
}

#[test]
fn rust_commands_fast_profile_only_check() {
    let commands = rust::commands("/root", &s(&[]), &s(&["Cargo.toml"]), Profile::Fast);
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].id, "rust.check");
    assert_eq!(commands[0].executable, Some("cargo"));
    assert_eq!(commands[0].args, vec!["check", "--offline"]);
    assert_eq!(commands[0].cwd, "/root");
    assert_eq!(commands[0].kind, "type-check");
}

#[test]
fn rust_commands_non_fast_profile_adds_clippy_and_test() {
    let commands = rust::commands("/root", &s(&[]), &s(&["Cargo.toml"]), Profile::Other);
    let ids: Vec<&str> = commands.iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["rust.check", "rust.clippy", "rust.test"]);
    let clippy = &commands[1];
    assert_eq!(
        clippy.args,
        vec!["clippy", "--offline", "--", "-D", "warnings"]
    );
    assert_eq!(clippy.kind, "lint");
    let test = &commands[2];
    assert_eq!(test.args, vec!["test", "--offline"]);
    assert_eq!(test.kind, "test");
}

#[test]
fn rust_commands_undefined_profile_is_non_fast() {
    // JS: `profile !== 'fast'` — anything but the literal `'fast'` string
    // (including `undefined`) takes the non-fast branch.
    let commands = rust::commands("/root", &s(&[]), &s(&["Cargo.toml"]), Profile::from_str_opt(None));
    assert_eq!(commands.len(), 3);
}

#[test]
fn rust_normalize_pass_on_zero_exit_code() {
    let result = rust::normalize(
        "rust.check",
        Some(&Execution {
            exit_code: Some(0),
            tool_version: Some("1.80.0".into()),
            ..Default::default()
        }),
    );
    assert_eq!(result.provider, "language.rust");
    assert_eq!(result.status, "pass");
    assert!(result.complete);
    assert_eq!(result.command.as_deref(), Some("rust.check"));
    assert_eq!(result.tool_version.as_deref(), Some("1.80.0"));
    assert!(result.coverage_gaps.is_empty());
}

#[test]
fn rust_normalize_error_on_nonzero_exit_code() {
    let result = rust::normalize(
        "rust.clippy",
        Some(&Execution {
            exit_code: Some(1),
            ..Default::default()
        }),
    );
    assert_eq!(result.status, "error");
    assert!(!result.complete);
    assert_eq!(result.coverage_gaps.len(), 1);
    assert_eq!(result.coverage_gaps[0].kind, "command-failed");
    assert_eq!(result.coverage_gaps[0].command.as_deref(), Some("rust.clippy"));
}

#[test]
fn rust_normalize_error_on_missing_execution() {
    // JS: `execution?.exitCode` on `undefined` execution is `undefined`,
    // never `=== 0`.
    let result = rust::normalize("rust.test", None);
    assert_eq!(result.status, "error");
    assert!(!result.complete);
    assert_eq!(result.tool_version, None);
}

#[test]
fn rust_coverage_examines_only_exact_rs_extension() {
    let coverage = rust::coverage(&s(&["rs", "RS", "ts", "rs"]));
    assert_eq!(coverage.provider, "language.rust");
    // Coverage filters with `ext === 'rs'` (not lowercased, unlike detect).
    assert_eq!(coverage.examined, vec!["rs".to_string(), "rs".to_string()]);
    assert!(coverage.complete);
}

#[test]
fn rust_fixtures_are_empty() {
    let fixtures = rust::fixtures();
    assert!(fixtures.positive.is_empty());
    assert!(fixtures.negative.is_empty());
    assert!(fixtures.unsupported.is_empty());
}

#[test]
fn rust_unsafe_boundaries_finds_unsafe_fn_block_and_impl() {
    let files = s(&["a.rs"]);
    let source = "fn main() {}\nunsafe fn raw() {}\nlet x = unsafe { 1 };\nunsafe impl Foo for Bar {}\n";
    let boundaries = rust::unsafe_boundaries(&files, |f| {
        assert_eq!(f, "a.rs");
        Some(source.to_string())
    });
    let kinds: Vec<&str> = boundaries.iter().map(|b| b.kind).collect();
    assert_eq!(kinds, vec!["unsafe-block", "unsafe-block", "unsafe-block"]);
    let lines: Vec<u32> = boundaries.iter().map(|b| b.line).collect();
    assert_eq!(lines, vec![2, 3, 4]);
}

#[test]
fn rust_unsafe_boundaries_finds_extern_c() {
    let files = s(&["ffi.rs"]);
    let source = "extern \"C\" {\n    fn foo();\n}\n";
    let boundaries = rust::unsafe_boundaries(&files, |_| Some(source.to_string()));
    assert_eq!(boundaries.len(), 1);
    assert_eq!(boundaries[0].kind, "ffi-boundary");
    assert_eq!(boundaries[0].line, 1);
}

#[test]
fn rust_unsafe_boundaries_missing_file_reads_as_empty_string() {
    let files = s(&["missing.rs"]);
    let boundaries = rust::unsafe_boundaries(&files, |_| None::<String>);
    assert!(boundaries.is_empty());
}

#[test]
fn rust_unsafe_boundaries_no_matches_is_empty() {
    let files = s(&["clean.rs"]);
    let boundaries = rust::unsafe_boundaries(&files, |_| Some("fn main() {}\n".to_string()));
    assert!(boundaries.is_empty());
}

// ---------------------------------------------------------------------
// swift-objc pack
// ---------------------------------------------------------------------

#[test]
fn swift_detect_matches_source_extensions() {
    assert!(swift_objc::detect(&s(&["App.swift"])));
    assert!(swift_objc::detect(&s(&["Bridge.m"])));
    assert!(swift_objc::detect(&s(&["Bridge.mm"])));
    assert!(!swift_objc::detect(&s(&["App.kt"])));
}

#[test]
fn swift_detect_matches_manifest_markers() {
    assert!(swift_objc::detect(&s(&["Package.swift"])));
    assert!(swift_objc::detect(&s(&["App.xcodeproj/project.pbxproj"])));
    assert!(swift_objc::detect(&s(&["App.xcworkspace/contents.xcworkspacedata"])));
}

#[test]
fn swift_detect_false_otherwise() {
    assert!(!swift_objc::detect(&s(&[])));
    assert!(!swift_objc::detect(&s(&["README.md"])));
}

#[test]
fn swift_commands_non_darwin_platform_is_single_degraded_entry() {
    let commands = swift_objc::commands(
        "/root",
        &s(&[]),
        &s(&["Package.swift"]),
        Profile::Other,
        "linux",
    );
    assert_eq!(commands.len(), 1);
    let entry = &commands[0];
    assert_eq!(entry.id, "swift.degraded");
    assert_eq!(entry.executable, None);
    assert!(entry.args.is_empty());
    assert_eq!(entry.kind, "degraded");
    assert_eq!(entry.reason, Some("Swift toolchain requires macOS"));
}

#[test]
fn swift_commands_darwin_without_manifest_is_empty() {
    let commands = swift_objc::commands("/root", &s(&[]), &s(&[]), Profile::Other, "darwin");
    assert!(commands.is_empty());
}

#[test]
fn swift_commands_darwin_fast_profile_only_build() {
    let commands = swift_objc::commands(
        "/root",
        &s(&[]),
        &s(&["Package.swift"]),
        Profile::Fast,
        "darwin",
    );
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].id, "swift.build");
    assert_eq!(commands[0].executable, Some("swift"));
    assert_eq!(commands[0].args, vec!["build"]);
}

#[test]
fn swift_commands_darwin_non_fast_profile_adds_test_and_lint() {
    let commands = swift_objc::commands(
        "/root",
        &s(&[]),
        &s(&["Package.swift"]),
        Profile::Other,
        "darwin",
    );
    let ids: Vec<&str> = commands.iter().map(|c: &PackCommand| c.id).collect();
    assert_eq!(ids, vec!["swift.build", "swift.test", "swift.lint"]);
    assert_eq!(commands[1].args, vec!["test"]);
    assert_eq!(commands[2].executable, Some("swiftlint"));
    assert_eq!(commands[2].args, vec!["lint"]);
}

#[test]
fn swift_normalize_degraded_execution_is_unproven() {
    let result = swift_objc::normalize(
        "swift.degraded",
        Some(&Execution {
            degraded: true,
            reason: Some("Swift toolchain requires macOS".into()),
            ..Default::default()
        }),
    );
    assert_eq!(result.status, "unproven");
    assert!(!result.complete);
    assert_eq!(result.command, None);
    assert_eq!(result.coverage_gaps.len(), 1);
    assert_eq!(result.coverage_gaps[0].kind, "host-limited");
    assert_eq!(
        result.coverage_gaps[0].reason.as_deref(),
        Some("Swift toolchain requires macOS")
    );
}

#[test]
fn swift_normalize_pass_on_zero_exit_code() {
    let result = swift_objc::normalize(
        "swift.build",
        Some(&Execution {
            exit_code: Some(0),
            tool_version: Some("5.10".into()),
            ..Default::default()
        }),
    );
    assert_eq!(result.status, "pass");
    assert!(result.complete);
    assert_eq!(result.command.as_deref(), Some("swift.build"));
    assert_eq!(result.tool_version.as_deref(), Some("5.10"));
}

#[test]
fn swift_normalize_error_on_nonzero_exit_code() {
    let result = swift_objc::normalize(
        "swift.test",
        Some(&Execution {
            exit_code: Some(2),
            ..Default::default()
        }),
    );
    assert_eq!(result.status, "error");
    assert!(!result.complete);
    assert_eq!(result.coverage_gaps[0].command.as_deref(), Some("swift.test"));
}

#[test]
fn swift_coverage_examines_swift_m_and_mm() {
    let coverage = swift_objc::coverage(&s(&["swift", "m", "mm", "kt", "swift"]));
    assert_eq!(coverage.provider, "language.swift-objc");
    assert_eq!(
        coverage.examined,
        vec!["swift".to_string(), "m".to_string(), "mm".to_string(), "swift".to_string()]
    );
    assert!(coverage.complete);
}

#[test]
fn swift_fixtures_are_empty() {
    let fixtures = swift_objc::fixtures();
    assert!(fixtures.positive.is_empty());
    assert!(fixtures.negative.is_empty());
    assert!(fixtures.unsupported.is_empty());
}
