//! Port of `src/providers/native/javascript/index.mjs` (`language.javascript`).

use sha2::{Digest, Sha256};

use super::{
    coverage_for, cwd, ext_matches, manifests_contains, normalize_for, root_as_arg, CommandSpec,
    CommandsInput, CoverageResult, ExecutionResult, Fixtures, NormalizeResult, Projection,
};

pub const PROVIDER_ID: &str = "language.javascript";
pub const VERSION: &str = "1.0.0";

/// `detect({ projection })`: JS/TS/JSX/TSX parsed extensions present.
pub fn detect(projection: &Projection) -> bool {
    let extensions: std::collections::HashSet<String> = projection
        .parsed_extensions
        .iter()
        .map(|ext| ext.to_ascii_lowercase())
        .collect();
    extensions.contains("js") || extensions.contains("ts") || extensions.contains("jsx") || extensions.contains("tsx")
}

/// `commands({ root, files, manifests, profile })`.
pub fn commands(input: &CommandsInput) -> Vec<CommandSpec> {
    let mut out = Vec::new();
    if input.files.iter().any(|f| ext_matches(f, &["ts", "tsx"])) {
        out.push(CommandSpec {
            id: "js.types",
            executable: "tsc",
            args: vec!["--noEmit".to_string()],
            cwd: cwd(input),
            kind: "type-check",
        });
    }
    let mut test_args = vec!["--test".to_string()];
    test_args.extend(
        input
            .files
            .iter()
            .filter(|f| f.ends_with(".test.js") || f.ends_with(".test.ts"))
            .cloned(),
    );
    out.push(CommandSpec {
        id: "js.test",
        executable: "node",
        args: test_args,
        cwd: cwd(input),
        kind: "test",
    });
    if manifests_contains(&input.manifests, "package.json") && !input.is_fast() {
        out.push(CommandSpec {
            id: "js.build",
            executable: "npm",
            args: vec!["run".to_string(), "build".to_string()],
            cwd: cwd(input),
            kind: "build",
        });
    }
    // `root` is otherwise only used as `cwd`; keep the accessor referenced
    // so a future arg-bearing command can reuse it without relearning the
    // JS shape (`root` was never interpolated into `args` in the source).
    let _ = root_as_arg(&input.root);
    out
}

/// `normalize({ commandId, execution, artifacts })`.
pub fn normalize(command_id: &str, execution: Option<&ExecutionResult>) -> NormalizeResult {
    normalize_for(PROVIDER_ID, command_id, execution)
}

/// `coverage({ projection, plan, results })`.
pub fn coverage(projection: &Projection) -> CoverageResult {
    coverage_for(PROVIDER_ID, projection, &["js", "ts", "jsx", "tsx"])
}

pub fn fixtures() -> Fixtures {
    Fixtures::default()
}

/// `export function jsFingerprint({ file, line, ruleId })`:
/// `sha256:${createHash('sha256').update(\`js-rule\0${ruleId}\0${file}\0${line}\`).digest('hex')}`.
pub fn js_fingerprint(file: &str, line: i64, rule_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"js-rule\0");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(file.as_bytes());
    hasher.update(b"\0");
    hasher.update(line.to_string().as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}
