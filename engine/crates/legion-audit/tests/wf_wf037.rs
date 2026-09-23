//! Integration tests porting the JS test coverage for
//! `src/providers/native/index.mjs`, `src/providers/native/c-family/index.mjs`,
//! `src/providers/native/dart/index.mjs`, `src/providers/native/dotnet/index.mjs`,
//! and `src/providers/native/go/index.mjs` (see
//! `../../../../tests/coverage-registry.test.mjs` in the JS tree for the
//! `NATIVE_PROVIDERS`/`nativeProviderFor` assertions this ports).
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf037;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf037::{
    c_family, dart, dotnet, go, native_provider_for, native_providers, Execution, Profile,
};

fn strv(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

// ---------------------------------------------------------------------
// index.mjs — NATIVE_PROVIDERS / nativeProviderFor
// ---------------------------------------------------------------------

#[test]
fn native_provider_matrix_covers_wave_0_families() {
    for id in [
        "native.javascript",
        "native.python",
        "native.rust",
        "native.go",
        "native.jvm",
        "native.dotnet",
    ] {
        let provider = native_providers().get(id).unwrap_or_else(|| panic!("native provider {id}"));
        assert_eq!(provider.role, "deterministic");
        assert!(provider.commands.lint.is_some(), "{id} has a lint command");
        assert!(provider.commands.test.is_some(), "{id} has a test command");
    }
}

#[test]
fn native_provider_maps_extensions_to_families() {
    assert_eq!(native_provider_for("ts").unwrap().id, "native.javascript");
    assert_eq!(native_provider_for("py").unwrap().id, "native.python");
    assert_eq!(native_provider_for("rs").unwrap().id, "native.rust");
    assert_eq!(native_provider_for("java").unwrap().id, "native.jvm");
    assert_eq!(native_provider_for("cs").unwrap().id, "native.dotnet");
    assert!(native_provider_for("unknown").is_none());
}

#[test]
fn native_provider_maps_every_documented_extension() {
    // Every extension key from the JS `map` object in `nativeProviderFor`.
    for (ext, family) in [
        ("js", "native.javascript"),
        ("ts", "native.javascript"),
        ("mjs", "native.javascript"),
        ("cjs", "native.javascript"),
        ("py", "native.python"),
        ("rs", "native.rust"),
        ("go", "native.go"),
        ("java", "native.jvm"),
        ("kt", "native.jvm"),
        ("scala", "native.jvm"),
        ("cs", "native.dotnet"),
        ("fs", "native.dotnet"),
        ("vb", "native.dotnet"),
    ] {
        assert_eq!(native_provider_for(ext).unwrap().id, family, "extension {ext}");
    }
}

#[test]
fn native_go_and_jvm_and_dotnet_have_no_build_command() {
    // JS omits `build` from these three families' `commands` objects, so
    // the field is `undefined`; this ports that gap as `None`.
    assert!(native_providers()["native.go"].commands.build.is_none());
    assert!(native_providers()["native.jvm"].commands.build.is_none());
    assert!(native_providers()["native.dotnet"].commands.build.is_none());
    assert!(native_providers()["native.javascript"].commands.build.is_some());
    assert!(native_providers()["native.python"].commands.build.is_some());
    assert!(native_providers()["native.rust"].commands.build.is_some());
}

// ---------------------------------------------------------------------
// c-family/index.mjs
// ---------------------------------------------------------------------

#[test]
fn c_family_detects_source_extensions_and_manifests() {
    assert!(c_family::detect(&strv(&["src/main.cpp"])));
    assert!(c_family::detect(&strv(&["include/foo.hpp"])));
    assert!(c_family::detect(&strv(&["CMakeLists.txt"])));
    assert!(c_family::detect(&strv(&["build/compile_commands.json"])));
    assert!(!c_family::detect(&strv(&["src/main.rs", "README.md"])));
}

#[test]
fn c_family_commands_prefers_compile_commands_over_cmake() {
    let cmds = c_family::commands(
        "/repo",
        &[],
        &strv(&["compile_commands.json", "CMakeLists.txt"]),
        Profile::Other,
    );
    // Only the syntax command from the compile-commands branch, plus lint
    // commands (profile is not "fast").
    assert_eq!(cmds[0].id, "c-family.syntax");
    assert_eq!(cmds[0].executable, "clang");
    assert_eq!(
        cmds[0].args,
        vec!["--analyze", "-Xanalyzer", "-analyzer-output=text"]
    );
    assert_eq!(cmds.iter().filter(|c| c.id == "c-family.cmake").count(), 0);
    assert_eq!(cmds[1].id, "c-family.tidy");
    assert_eq!(cmds[2].id, "c-family.cppcheck");
    assert_eq!(cmds.len(), 3);
}

#[test]
fn c_family_commands_falls_back_to_cmake_build() {
    let cmds = c_family::commands("/repo", &[], &strv(&["CMakeLists.txt"]), Profile::Fast);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].id, "c-family.cmake");
    assert_eq!(cmds[0].executable, "cmake");
    assert_eq!(cmds[0].args, vec!["--build", "build"]);
    assert_eq!(cmds[0].kind, "build");
}

#[test]
fn c_family_commands_fast_profile_skips_lint() {
    let cmds = c_family::commands("/repo", &[], &strv(&["compile_commands.json"]), Profile::Fast);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].id, "c-family.syntax");
}

#[test]
fn c_family_commands_no_manifests_still_runs_lint_unless_fast() {
    let cmds = c_family::commands("/repo", &[], &[], Profile::Other);
    assert_eq!(cmds.len(), 2);
    assert_eq!(cmds[0].id, "c-family.tidy");
    assert_eq!(cmds[1].id, "c-family.cppcheck");
    assert!(c_family::commands("/repo", &[], &[], Profile::Fast).is_empty());
}

#[test]
fn c_family_normalize_pass_and_error() {
    let ok = c_family::normalize(
        "c-family.tidy",
        Some(&Execution {
            exit_code: Some(0),
            tool_version: Some("18.0".into()),
        }),
    );
    assert_eq!(ok.provider, "language.c-family");
    assert_eq!(ok.status, "pass");
    assert!(ok.complete);
    assert_eq!(ok.tool_version.as_deref(), Some("18.0"));
    assert!(ok.coverage_gaps.is_empty());

    let err = c_family::normalize(
        "c-family.tidy",
        Some(&Execution {
            exit_code: Some(1),
            tool_version: None,
        }),
    );
    assert_eq!(err.status, "error");
    assert!(!err.complete);
    assert_eq!(err.coverage_gaps.len(), 1);
    assert_eq!(err.coverage_gaps[0].kind, "command-failed");
    assert_eq!(err.coverage_gaps[0].command, "c-family.tidy");

    // Missing execution entirely mirrors `execution?.exitCode` on
    // `undefined`, which is `undefined`, never `=== 0`.
    let missing = c_family::normalize("c-family.tidy", None);
    assert_eq!(missing.status, "error");
    assert!(missing.tool_version.is_none());
}

#[test]
fn c_family_coverage_filters_examinable_extensions() {
    let coverage = c_family::coverage(&strv(&["cpp", "h", "py", "cc", "unknown"]));
    assert_eq!(coverage.provider, "language.c-family");
    assert_eq!(coverage.examined, strv(&["cpp", "h", "cc"]));
    assert!(coverage.complete);
}

#[test]
fn c_family_unsafe_memory_patterns_flags_libc_and_allocation() {
    let files = strv(&["a.c", "b.c", "c.c"]);
    let sources = std::collections::HashMap::from([
        ("a.c".to_string(), "int main() { strcpy(dst, src); return 0; }".to_string()),
        (
            // The port's unchecked-allocation regex is a faithful copy of
            // `src/providers/native/c-family/index.mjs:55`
            // (`\b(?:malloc|realloc)\s*\([^)]*\)\s*\)\s*;`), which requires
            // an extra closing paren before the `;` (e.g. a cast wrapping
            // the call) — a bare `malloc(16);` does not match it in JS
            // either, so this fixture needs that extra paren to exercise
            // the rule.
            "b.c".to_string(),
            "void* p = (malloc(16)); use(p);".to_string(),
        ),
        (
            "c.c".to_string(),
            "void* p = (malloc(16)); free(p);".to_string(),
        ),
    ]);
    let observations = c_family::unsafe_memory_patterns(&files, |file| sources.get(file).cloned());

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].file, "a.c");
    assert_eq!(observations[0].rule_id, "c-family.unsafe-libc");
    assert_eq!(observations[0].severity_hint, "high");
    assert_eq!(observations[1].file, "b.c");
    assert_eq!(observations[1].rule_id, "c-family.unchecked-allocation");
    assert_eq!(observations[1].severity_hint, "medium");
}

#[test]
fn c_family_unsafe_memory_patterns_missing_file_reads_as_empty() {
    let files = strv(&["missing.c"]);
    let observations = c_family::unsafe_memory_patterns(&files, |_| None);
    assert!(observations.is_empty());
}

// ---------------------------------------------------------------------
// dart/index.mjs
// ---------------------------------------------------------------------

#[test]
fn dart_detect_source_and_manifests() {
    assert!(dart::detect(&strv(&["lib/main.dart"])));
    assert!(dart::detect(&strv(&["pubspec.yaml"])));
    assert!(dart::detect(&strv(&["analysis_options.yaml"])));
    assert!(!dart::detect(&strv(&["lib/main.rs"])));
}

#[test]
fn dart_commands_requires_pubspec_and_test_is_gated_by_profile() {
    assert!(dart::commands("/repo", &[], &[], Profile::Other).is_empty());

    let cmds = dart::commands("/repo", &[], &strv(&["pubspec.yaml"]), Profile::Other);
    assert_eq!(cmds.len(), 2);
    assert_eq!(cmds[0].id, "dart.analyze");
    assert_eq!(cmds[0].kind, "static");
    assert_eq!(cmds[1].id, "dart.test");
    assert_eq!(cmds[1].kind, "test");

    let fast = dart::commands("/repo", &[], &strv(&["pubspec.yaml"]), Profile::Fast);
    assert_eq!(fast.len(), 1);
    assert_eq!(fast[0].id, "dart.analyze");
}

#[test]
fn dart_normalize_and_coverage() {
    let result = dart::normalize(
        "dart.test",
        Some(&Execution {
            exit_code: Some(0),
            tool_version: None,
        }),
    );
    assert_eq!(result.provider, "language.dart");
    assert_eq!(result.status, "pass");

    let coverage = dart::coverage(&strv(&["dart", "js", "dart"]));
    assert_eq!(coverage.examined, strv(&["dart", "dart"]));
    assert!(coverage.complete);
}

// ---------------------------------------------------------------------
// dotnet/index.mjs
// ---------------------------------------------------------------------

#[test]
fn dotnet_detect_source_and_manifests() {
    assert!(dotnet::detect(&strv(&["Program.cs"])));
    assert!(dotnet::detect(&strv(&["src/App.fsproj"])));
    assert!(dotnet::detect(&strv(&["solution.sln"])));
    assert!(!dotnet::detect(&strv(&["main.go"])));
}

#[test]
fn dotnet_commands_requires_csproj_or_sln_and_test_gated_by_profile() {
    // A .vbproj/.fsproj manifest is detected but does not itself gate the
    // build command — only csproj/sln do, matching the JS
    // `/\.(csproj|sln)$/` build-manifest regex.
    assert!(dotnet::commands("/repo", &[], &strv(&["App.fsproj"]), Profile::Other).is_empty());

    let cmds = dotnet::commands("/repo", &[], &strv(&["App.csproj"]), Profile::Other);
    assert_eq!(cmds.len(), 2);
    assert_eq!(cmds[0].id, "dotnet.build");
    assert_eq!(cmds[0].args, vec!["build", "--no-restore"]);
    assert_eq!(cmds[1].id, "dotnet.test");

    let fast = dotnet::commands("/repo", &[], &strv(&["solution.sln"]), Profile::Fast);
    assert_eq!(fast.len(), 1);
    assert_eq!(fast[0].id, "dotnet.build");
}

#[test]
fn dotnet_normalize_and_coverage() {
    let result = dotnet::normalize(
        "dotnet.build",
        Some(&Execution {
            exit_code: Some(1),
            tool_version: None,
        }),
    );
    assert_eq!(result.status, "error");
    assert_eq!(result.coverage_gaps[0].command, "dotnet.build");

    let coverage = dotnet::coverage(&strv(&["cs", "fs", "vb", "go"]));
    assert_eq!(coverage.examined, strv(&["cs", "fs", "vb"]));
}

// ---------------------------------------------------------------------
// go/index.mjs
// ---------------------------------------------------------------------

#[test]
fn go_detect_extension_case_insensitive_and_go_mod() {
    assert!(go::detect(&strv(&["Go"]), &[]));
    assert!(go::detect(&strv(&["go"]), &[]));
    assert!(go::detect(&[], &strv(&["go.mod"])));
    assert!(!go::detect(&strv(&["rs"]), &strv(&["Cargo.toml"])));
}

#[test]
fn go_commands_requires_exact_go_mod_and_extras_gated_by_profile() {
    assert!(go::commands("/repo", &[], &[], Profile::Other).is_empty());
    // A manifest path that merely ends with go.mod (not exactly "go.mod")
    // does not match the JS `manifests.some((m) => m === 'go.mod')` check.
    assert!(go::commands("/repo", &[], &strv(&["sub/go.mod"]), Profile::Other).is_empty());

    let cmds = go::commands("/repo", &[], &strv(&["go.mod"]), Profile::Other);
    assert_eq!(cmds.len(), 3);
    assert_eq!(cmds[0].id, "go.vet");
    assert_eq!(cmds[1].id, "go.test");
    assert_eq!(cmds[2].id, "go.vuln");
    assert_eq!(cmds[2].executable, "govulncheck");

    let fast = go::commands("/repo", &[], &strv(&["go.mod"]), Profile::Fast);
    assert_eq!(fast.len(), 1);
    assert_eq!(fast[0].id, "go.vet");
}

#[test]
fn go_normalize_and_coverage() {
    let result = go::normalize(
        "go.vet",
        Some(&Execution {
            exit_code: Some(0),
            tool_version: Some("1.22".into()),
        }),
    );
    assert_eq!(result.provider, "language.go");
    assert_eq!(result.status, "pass");
    assert_eq!(result.tool_version.as_deref(), Some("1.22"));

    let coverage = go::coverage(&strv(&["go", "GO", "rs"]));
    assert_eq!(coverage.examined, strv(&["go"]));
}
