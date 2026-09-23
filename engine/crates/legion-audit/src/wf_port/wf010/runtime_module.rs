//! Port of `src/lib/providers/executor/runtime-module.mjs`'s sealing guard
//! clauses: a sealed module path plus a pinned digest are required, the
//! resolved module path must stay inside `package_root`, and the module's
//! bytes must hash to the pinned digest before it would be loaded.
//!
//! GAP: `runRuntimeModule` goes on to `import()` the now-verified module and
//! invoke its exported `render`/`analyze` function. There is no Rust
//! analogue of dynamically importing and invoking an arbitrary JS ES module;
//! a native renderer/analyzer is a compiled Rust function, so that final
//! dispatch step has no port here (see the equivalent gap note on
//! [`super::provider_executor`]). Everything provable ahead of that dynamic
//! `import()` — the sealing guard clauses — is ported faithfully below.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerKind {
    Renderer,
    Analyzer,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RuntimeModuleError {
    #[error("runtime runner requires sealed module path and digest")]
    MissingSealedRunner,
    #[error("runtime module escapes package root")]
    EscapesPackageRoot,
    #[error("runtime module digest mismatch: {script}")]
    DigestMismatch { script: String },
    #[error("runtime module provider mismatch: {provider_id}")]
    ProviderMismatch { provider_id: String },
}

/// Faithful port of the guard clauses in `runRuntimeModule` up to (but not
/// including) the dynamic `import()` call. Returns the verified, resolved
/// module path on success.
///
/// `script` is `provider.runner.script ?? provider.runner.module`;
/// `module_digest` is `provider.runner.moduleDigest`; `module_bytes` are the
/// bytes read from the resolved path (the JS reads them with `readFile`
/// before comparing digests — callers read the file themselves and pass the
/// bytes in, since this port has no filesystem I/O of its own to keep it
/// synchronous and host-agnostic).
pub fn verify_sealed_runtime_module(
    script: Option<&str>,
    module_digest: Option<&str>,
    package_root: &Path,
    module_bytes: &[u8],
) -> Result<PathBuf, RuntimeModuleError> {
    let (Some(script), Some(module_digest)) = (script, module_digest) else {
        return Err(RuntimeModuleError::MissingSealedRunner);
    };
    let module_path = package_root.join(script);
    let resolved = normalize_path(&module_path);
    let normalized_root = normalize_path(package_root);
    if !resolved.starts_with(&normalized_root) {
        return Err(RuntimeModuleError::EscapesPackageRoot);
    }
    let actual = sha256_digest(module_bytes);
    if actual != module_digest {
        return Err(RuntimeModuleError::DigestMismatch { script: script.to_string() });
    }
    Ok(resolved)
}

/// Faithful port of the module/provider-id cross-check:
/// `if (module.default?.id && module.default.id !== provider.id) throw ...`.
pub fn verify_module_provider_id(module_declared_id: Option<&str>, provider_id: &str) -> Result<(), RuntimeModuleError> {
    if let Some(declared) = module_declared_id {
        if declared != provider_id {
            return Err(RuntimeModuleError::ProviderMismatch { provider_id: provider_id.to_string() });
        }
    }
    Ok(())
}

/// Lexical `..`/`.` normalization (no filesystem access, so it also works
/// for paths that do not exist yet), matching `node:path`'s `resolve`
/// enough to detect escape via `..` segments the way JS `relative(...)
/// .startsWith('..')` does.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}
