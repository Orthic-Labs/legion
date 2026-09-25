//! Subprocess shims to `@rightkit/release` (an external npm package that
//! stays JS by decision — see `mod.rs`) and to legion's own
//! not-yet-ported `scripts/ci/prepare-unsigned-candidate.mjs`.
//!
//! Each shim runs `node -e "import('<module>').then(...)"`, passing JSON
//! arguments on stdin and reading a single JSON result line from stdout.
//! This keeps the actual call sites in Rust (argument construction, result
//! interpretation, error propagation) while the handful of functions this
//! port cannot own natively — Azure manifest signing, GitHub Releases API
//! calls, and the not-yet-ported unsigned-candidate check — still execute
//! through their existing, tested JS.

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

/// Calls `export async function <function_name>(args)` from `module_path`
/// (resolved relative to the repository root, e.g.
/// `"@rightkit/release/direct-bootstrap.mjs"` or
/// `"./scripts/ci/prepare-unsigned-candidate.mjs"`), passing `args` as its
/// single object argument and returning its JSON-serializable result.
pub fn call_node_function(repository_root: &Path, module_path: &str, function_name: &str, args: &Value) -> Result<Value, String> {
    let script = format!(
        "import('{module_path}').then(async (m) => {{ \
           const result = await m.{function_name}(JSON.parse(process.argv[1])); \
           process.stdout.write(JSON.stringify(result ?? null)); \
         }}).catch((error) => {{ process.stderr.write(String(error && error.stack || error)); process.exit(1); }});"
    );
    let output = Command::new("node")
        .arg("--input-type=module")
        .arg("-e")
        .arg(&script)
        .arg(serde_json::to_string(args).map_err(|e| e.to_string())?)
        .current_dir(repository_root)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to launch node for {module_path}#{function_name}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{module_path}#{function_name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&stdout).map_err(|e| format!("{module_path}#{function_name} returned non-JSON output: {e}"))
}
