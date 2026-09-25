//! Subprocess bridge into the external `@rightkit/release` npm package.
//!
//! `@rightkit/release` (and `@rightkit/ax`) are external, npm-published
//! packages — not Legion JS — so per the T4 packet decision they stay in
//! place rather than being ported. `createPortableArchive` and the
//! CycloneDX/in-toto SBOM+provenance helpers it exposes have no published
//! `right-release` CLI subcommand for direct programmatic calls, so this
//! module invokes them the same way the (now-removed) Legion JS scripts did:
//! as a one-shot dynamic `import()` of the package's `.mjs` module, run under
//! `node --input-type=module -e`, with the call's argument object passed as a
//! JSON string on argv and the function's return value captured as JSON on
//! stdout. This is external-package use, not a Legion JS side.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The real Legion checkout, resolved at compile time via `CARGO_MANIFEST_DIR`
/// (`engine/xtask` -> `engine` -> repo root), where `node_modules/@rightkit`
/// actually lives. Node's ESM bare-specifier resolution walks up from the
/// process's cwd, so this — not the caller's `repository_root` business
/// parameter — is what has to be node's cwd: production callers always pass
/// the real repo root as `repository_root` too, but a test fixture root
/// (a fresh temp dir with a fake `release/version.json`, no `node_modules`)
/// must not be forced to also double as the module-resolution root.
fn node_modules_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // engine/xtask
    dir.pop(); // engine
    dir.pop(); // repo root
    dir
}

/// Runs `node --input-type=module -e "<script>" <json-args>` from the real
/// Legion checkout (see `node_modules_root`, not the passed
/// `repository_root`) and parses stdout as JSON. `script` must
/// `process.stdout.write(JSON.stringify(...))` on success and
/// `process.exit(1)` after printing the error to stderr on failure.
fn run_node_module_call(_repository_root: &Path, script: &str, args_json: &Value) -> Result<Value, String> {
    let args_str = serde_json::to_string(args_json).map_err(|e| e.to_string())?;
    let output = Command::new("node")
        .arg("--input-type=module")
        .arg("-e")
        .arg(script)
        .arg(args_str)
        .current_dir(node_modules_root())
        .output()
        .map_err(|e| format!("failed to launch node for @rightkit/release call: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("@rightkit/release call failed: {}", stderr.trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(trimmed).map_err(|e| format!("@rightkit/release call returned non-JSON stdout: {e}"))
}

/// `createPortableArchive({ sourceDir, outputPath })` from
/// `@rightkit/release/direct-bootstrap.mjs`. Returns `{ path, size, sha256 }`.
pub fn create_portable_archive(repository_root: &Path, source_dir: &Path, output_path: &Path) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/direct-bootstrap.mjs').then((m) => {
  const args = JSON.parse(process.argv[1]);
  const result = m.createPortableArchive({ sourceDir: args.sourceDir, outputPath: args.outputPath });
  process.stdout.write(JSON.stringify(result));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    let args = serde_json::json!({
        "sourceDir": source_dir.to_string_lossy(),
        "outputPath": output_path.to_string_lossy(),
    });
    run_node_module_call(repository_root, script, &args)
}

/// `materializeCycloneDxSbom({ outputPath, product, version, target,
/// sourceCommit, files, createdAt })` from `@rightkit/release/supply-chain-evidence.mjs`.
/// Writes the SBOM to `outputPath`; return value (if any) is passed through as JSON.
pub fn materialize_cyclonedx_sbom(repository_root: &Path, args: &Value) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/supply-chain-evidence.mjs').then((m) => {
  const result = m.materializeCycloneDxSbom(JSON.parse(process.argv[1]));
  process.stdout.write(JSON.stringify(result ?? null));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    run_node_module_call(repository_root, script, args)
}

/// `materializeInTotoSlsaProvenance({...})` from
/// `@rightkit/release/supply-chain-evidence.mjs`.
pub fn materialize_in_toto_slsa_provenance(repository_root: &Path, args: &Value) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/supply-chain-evidence.mjs').then((m) => {
  const result = m.materializeInTotoSlsaProvenance(JSON.parse(process.argv[1]));
  process.stdout.write(JSON.stringify(result ?? null));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    run_node_module_call(repository_root, script, args)
}

/// `validateCycloneDxSbom(path, { expectedFile })` from
/// `@rightkit/release/supply-chain-evidence.mjs`. Returns the parsed/validated
/// SBOM document.
pub fn validate_cyclonedx_sbom(repository_root: &Path, path: &Path, expected_file: &Value) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/supply-chain-evidence.mjs').then((m) => {
  const args = JSON.parse(process.argv[1]);
  const result = m.validateCycloneDxSbom(args.path, { expectedFile: args.expectedFile });
  process.stdout.write(JSON.stringify(result ?? null));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    let args = serde_json::json!({
        "path": path.to_string_lossy(),
        "expectedFile": expected_file,
    });
    run_node_module_call(repository_root, script, &args)
}

/// `validateInTotoSlsaProvenance(path, { expectedSubject })` from
/// `@rightkit/release/supply-chain-evidence.mjs`. Returns the parsed/validated
/// provenance document.
pub fn validate_in_toto_slsa_provenance(repository_root: &Path, path: &Path, expected_subject: &Value) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/supply-chain-evidence.mjs').then((m) => {
  const args = JSON.parse(process.argv[1]);
  const result = m.validateInTotoSlsaProvenance(args.path, { expectedSubject: args.expectedSubject });
  process.stdout.write(JSON.stringify(result ?? null));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    let args = serde_json::json!({
        "path": path.to_string_lossy(),
        "expectedSubject": expected_subject,
    });
    run_node_module_call(repository_root, script, &args)
}

/// Generic single-call bridge to any exported async-or-sync function of an
/// `@rightkit/release/<module>.mjs` module: `fn(args)`, JSON in, JSON out.
/// Used by `package_windows_release::finalize` for the handful of
/// `direct-bootstrap.mjs`/`github-release.mjs`/`native-release-finalization.mjs`
/// calls that have no dedicated typed wrapper above.
pub fn call_module_function(repository_root: &Path, module: &str, function: &str, args: &Value) -> Result<Value, String> {
    let script = format!(
        r#"
import('{module}').then(async (m) => {{
  const result = await m.{function}(JSON.parse(process.argv[1]));
  process.stdout.write(JSON.stringify(result ?? null));
}}).catch((e) => {{ console.error(e.stack || e.message); process.exit(1); }});
"#
    );
    run_node_module_call(repository_root, &script, args)
}

/// `readNativeFinalizationOutput(path)` + `validateNativeFinalizationOutput(receipt, options)`
/// from `@rightkit/release/native-release-finalization.mjs`, composed in one
/// subprocess call since callers always need both.
pub fn read_and_validate_native_finalization_output(repository_root: &Path, path: &Path, validate_options: &Value) -> Result<Value, String> {
    let script = r#"
import('@rightkit/release/native-release-finalization.mjs').then((m) => {
  const args = JSON.parse(process.argv[1]);
  const receipt = m.readNativeFinalizationOutput(args.path);
  m.validateNativeFinalizationOutput(receipt, args.validateOptions);
  process.stdout.write(JSON.stringify(receipt));
}).catch((e) => { console.error(e.stack || e.message); process.exit(1); });
"#;
    let args = serde_json::json!({ "path": path.to_string_lossy(), "validateOptions": validate_options });
    run_node_module_call(repository_root, script, &args)
}
