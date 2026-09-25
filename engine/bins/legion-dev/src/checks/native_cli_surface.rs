// Port of `scripts/check-native-cli-surface.mjs`.
// Step 7 — hard gate: JavaScript may build/generate/lint/test-harness only.
// Fails on Node Legion CLI entrypoints, semantic command handlers, and
// product tests that invoke `src/bin/legion.mjs` once cutover phase allows.

use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_RUNTIME_PATHS: [&str; 2] = ["src/bin/legion.mjs", "src/lib/cli/run.mjs"];

// The Node-side CLI binding test was retired with the JS CLI; CLI behaviour
// is now exercised directly against the native binary by
// `engine/bins/legion/tests/*.rs` under `cargo test`. Any future JS-side
// product CLI test must still go through the native executable helper.
const PRODUCT_CLI_TESTS: [&str; 0] = [];

#[derive(Serialize)]
struct Summary {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    kind: &'static str,
    phase: String,
    ok: bool,
    issues: Vec<String>,
    note: &'static str,
}

fn present(path: &Path) -> Option<fs::Metadata> {
    fs::symlink_metadata(path).ok()
}

fn is_node_runtime_file(path: &Path) -> bool {
    let file = path.to_string_lossy().to_lowercase();
    let has_ext = [".cjs", ".js", ".mjs"].iter().any(|ext| file.ends_with(ext));
    has_ext && !file.ends_with(".test.mjs")
}

fn walk(dir: &Path, visitor: &mut dyn FnMut(&Path)) {
    let meta = match present(dir) {
        Some(m) => m,
        None => return,
    };
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "node_modules" || name_str == ".git" || name_str == "dist" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && !path.is_symlink() {
            walk(&path, visitor);
        } else {
            visitor(&path);
        }
    }
}

fn node_runtime_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for rel in ["src/bin", "src/lib/cli"] {
        walk(&root.join(rel), &mut |path| {
            if is_node_runtime_file(path) {
                files.push(path.to_path_buf());
            }
        });
    }
    files.sort();
    files
}

fn rel_forward(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn run(root: &Path, phase_arg: &str) -> bool {
    let summary = compute(root, phase_arg);
    let exit_ok = !(!summary.ok && summary.phase == "enforce");
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    exit_ok
}

fn compute(root: &Path, phase_arg: &str) -> Summary {
    let phase = if phase_arg == "enforce" { "enforce" } else { "record" };
    let mut issues: Vec<String> = Vec::new();
    let mut reported: BTreeSet<String> = BTreeSet::new();

    let mut report_runtime_file = |path: &Path, issues: &mut Vec<String>, reported: &mut BTreeSet<String>| {
        let rel = rel_forward(root, path);
        if reported.contains(&rel) {
            return;
        }
        reported.insert(rel.clone());
        if rel == "src/bin/legion.mjs" || rel == "src/lib/cli/run.mjs" {
            issues.push(format!("forbidden Node Legion entrypoint still present: {rel}"));
        } else if rel.starts_with("src/lib/cli/commands/")
            && !rel["src/lib/cli/commands/".len()..].contains('/')
        {
            issues.push(format!("forbidden Node Legion command handler: {rel}"));
        } else {
            issues.push(format!("forbidden Node Legion runtime file: {rel}"));
        }
    };

    for rel in FORBIDDEN_RUNTIME_PATHS {
        let path = root.join(rel);
        if present(&path).is_some() {
            report_runtime_file(&path, &mut issues, &mut reported);
        }
    }

    let command_directory = present(&root.join("src/lib/cli/commands"));
    if command_directory
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        issues.push("forbidden Node Legion command directory is a symlink".to_string());
    }
    for path in node_runtime_files(root) {
        report_runtime_file(&path, &mut issues, &mut reported);
    }

    walk(&root.join("tests"), &mut |path| {
        let path_str = path.to_string_lossy();
        if !path_str.ends_with(".test.mjs") && !path_str.ends_with(".mjs") {
            return;
        }
        if let Ok(text) = fs::read_to_string(path) {
            if text.contains("src/bin/legion.mjs") || text.contains("from '../bin/legion.mjs'") {
                let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().to_string();
                issues.push(format!("product test still invokes Node CLI: {rel}"));
            }
        }
    });

    for rel in PRODUCT_CLI_TESTS {
        if let Ok(text) = fs::read_to_string(root.join(rel)) {
            if !text.contains("scripts/native-cli/test-helper.mjs") {
                issues.push(format!("product CLI test must use native executable helper: {rel}"));
            }
        }
    }

    if let Ok(pkg_text) = fs::read_to_string(root.join("package.json")) {
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&pkg_text) {
            let bin = pkg.get("bin");
            let has_legion = bin
                .and_then(|b| b.get("legion"))
                .is_some();
            let has_scoped = bin
                .and_then(|b| b.get("@orthic-labs/legion"))
                .is_some();
            if has_legion || has_scoped {
                issues.push("package.json must not register npm bin legion".to_string());
            }
        }
    }

    if let Ok(contract_text) = fs::read_to_string(root.join("release/distribution-contract.json")) {
        if let Ok(contract) = serde_json::from_str::<serde_json::Value>(&contract_text) {
            let access = contract
                .get("nodePackage")
                .and_then(|n| n.get("access"))
                .and_then(serde_json::Value::as_str);
            if access != Some("private-development-tooling") {
                issues.push(
                    "distribution contract must label Node package as private-development-tooling (build/test tooling only)"
                        .to_string(),
                );
            }
        }
    }

    let ok = issues.is_empty();
    let note = if phase == "record" {
        "record phase documents remaining Node runtime surface; pass --phase=enforce after cutover"
    } else {
        "enforce phase fails on any remaining Node Legion runtime semantics"
    };
    Summary {
        schema_version: 1,
        kind: "legion-native-cli-surface-check",
        phase: phase.to_string(),
        ok,
        issues,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "legion-native-surface-{}-{}",
                std::process::id(),
                n
            ));
            for path in ["scripts", "tests", "release"] {
                fs::create_dir_all(root.join(path)).unwrap();
            }
            fs::write(root.join("package.json"), "{}").unwrap();
            fs::write(
                root.join("release/distribution-contract.json"),
                serde_json::json!({ "nodePackage": { "access": "private-development-tooling" } })
                    .to_string(),
            )
            .unwrap();
            for name in ["cli", "doctor", "bind"] {
                fs::write(
                    root.join(format!("tests/{name}.test.mjs")),
                    "import '../scripts/native-cli/test-helper.mjs';\n",
                )
                .unwrap();
            }
            Tree { root }
        }

        fn add(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn enforce_succeeds_when_runtime_entrypoints_and_command_directory_are_absent() {
        let tree = Tree::new();
        let summary = compute(&tree.root, "enforce");
        assert!(summary.ok, "{:?}", summary.issues);
    }

    #[test]
    fn record_reports_real_runtime_gaps_without_granting_enforcement_success() {
        let tree = Tree::new();
        tree.add("src/bin/legion.mjs", "// retained reference implementation\n");
        tree.add("src/lib/cli/commands/state.mjs", "// retained command\n");
        let record = compute(&tree.root, "record");
        assert!(!record.ok);
        assert_eq!(record.issues.len(), 2);
        let enforce = compute(&tree.root, "enforce");
        assert!(!enforce.ok);
        assert_eq!(enforce.issues, record.issues);
        assert!(!run(&tree.root, "enforce"));
        assert!(run(&tree.root, "record"));
    }

    #[test]
    fn native_helper_requirement_matches_current_empty_product_test_list() {
        // PRODUCT_CLI_TESTS is currently empty upstream (the Node-side CLI
        // binding test was retired), so this check is a no-op today; adding
        // an entry to PRODUCT_CLI_TESTS revives the assertion on both sides.
        let tree = Tree::new();
        tree.add("tests/bind.test.mjs", "// no invocation helper\n");
        let summary = compute(&tree.root, "enforce");
        assert!(summary.ok, "{:?}", summary.issues);
    }

    #[test]
    fn development_scripts_are_permitted_but_npm_legion_entrypoints_are_rejected() {
        let tree = Tree::new();
        tree.add("scripts/build.mjs", "// permitted build tooling\n");
        assert!(compute(&tree.root, "enforce").ok);
        fs::write(
            tree.root.join("package.json"),
            serde_json::json!({ "bin": { "legion": "./src/bin/legion.mjs" } }).to_string(),
        )
        .unwrap();
        let summary = compute(&tree.root, "enforce");
        assert!(!summary.ok);
        assert!(summary
            .issues
            .contains(&"package.json must not register npm bin legion".to_string()));
    }

    #[test]
    fn enforce_recursively_rejects_a_nested_node_cli_runtime_module() {
        let tree = Tree::new();
        tree.add(
            "src/lib/cli/commands/governance/deep/retained.mjs",
            "// nested semantic route\n",
        );
        let summary = compute(&tree.root, "enforce");
        assert!(!summary.ok);
        assert!(summary.issues.contains(
            &"forbidden Node Legion runtime file: src/lib/cli/commands/governance/deep/retained.mjs"
                .to_string()
        ));
    }
}
