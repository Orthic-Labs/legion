//! LEG-I01 static process-boundary acceptance corpus.
//!
//! These tests scan native production source without executing child processes.

use std::path::{Path, PathBuf};

const FORBIDDEN_RUNTIME_NAMES: &[&str] = &[
    "node", "nodejs", "python", "python3", "npm", "npx", "pip", "pip3",
];

#[test]
fn forbidden_runtime_scan_scope_is_explicit() {
    assert!(!FORBIDDEN_RUNTIME_NAMES.is_empty());
    assert!(FORBIDDEN_RUNTIME_NAMES.contains(&"python3"));
}

#[test]
fn process_launch_surface_is_singleton() {
    let engine = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("engine root");
    let mut violations = Vec::new();
    for root in [engine.join("crates"), engine.join("bins")] {
        scan_rust_sources(&root, &mut |path, source| {
            let normalized = path.to_string_lossy().replace('\\', "/");
            if normalized.contains("/legion-effects/") {
                return;
            }
            for marker in [
                "std::process::Command",
                "tokio::process::Command",
                "Command::new(",
                "libloading",
                "dlopen(",
                "LoadLibrary",
            ] {
                if source.contains(marker) {
                    violations.push(format!("{} contains {marker}", path.display()));
                }
            }
        });
    }
    assert!(
        violations.is_empty(),
        "native process/dynamic-load boundary escaped legion-effects: {violations:?}"
    );
}

#[test]
fn external_effect_boundary_owns_process_launch_and_interpreter_rejection() {
    let launcher = include_str!("../crates/legion-effects/src/unix.rs");
    assert!(launcher.contains("Command::new"));
    let request_validation = include_str!("../crates/legion-effects/src/request.rs");
    for runtime in FORBIDDEN_RUNTIME_NAMES {
        assert!(
            request_validation.contains(&format!("\"{runtime}\"")),
            "effect requests must reject interpreter name {runtime}"
        );
    }
}

#[test]
fn production_source_does_not_reenter_interpreters() {
    let engine = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("engine root");
    let mut violations = Vec::new();
    for root in [engine.join("crates"), engine.join("bins")] {
        scan_rust_sources(&root, &mut |path, source| {
            if let Some(runtime) = forbidden_interpreter_launch(source) {
                violations.push(format!("{} launches {runtime}", path.display()));
            }
        });
    }
    assert!(
        violations.is_empty(),
        "native production source reenters an interpreter: {violations:?}"
    );
}

fn forbidden_interpreter_launch(source: &str) -> Option<&'static str> {
    // Keep this deliberately source-based: native qualification must detect a
    // re-entry route without running a product or trusting developer PATH.
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    for runtime in FORBIDDEN_RUNTIME_NAMES {
        for quote in ['"', '\''] {
            let marker = format!("Command::new({quote}{runtime}{quote}");
            if compact.contains(&marker) {
                return Some(runtime);
            }
        }
    }
    None
}

#[test]
fn interpreter_launch_detector_covers_literal_binary_forms() {
    assert_eq!(
        forbidden_interpreter_launch(r#"std::process::Command::new("python3")"#),
        Some("python3")
    );
    assert_eq!(
        forbidden_interpreter_launch(r#"Command::new( 'node' )"#),
        Some("node")
    );
}

fn scan_rust_sources(root: &Path, visit: &mut impl FnMut(&Path, &str)) {
    let mut pending = vec![PathBuf::from(root)];
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .expect("native source directory must remain readable")
                .map(|entry| entry.expect("native source entry").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && path
                .components()
                .any(|component| component.as_os_str() == "src")
        {
            let source = std::fs::read_to_string(&path).expect("Rust source must be UTF-8");
            visit(&path, &source);
        }
    }
}
