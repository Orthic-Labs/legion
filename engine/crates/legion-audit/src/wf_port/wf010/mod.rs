//! Port of `src/lib/providers/{executor/runtime-module.mjs,
//! executor/tool-identity.mjs, external-process.mjs,
//! provider-executor.mjs, registry.mjs}`.
//!
//! These five files form the generic provider-execution layer: qualifying
//! an external tool's identity ([`tool_identity`]), spawning it under a
//! sealed allowlist/digest/output-cap policy ([`external_process`]),
//! dispatching a sealed plan's providers by runner kind
//! ([`provider_executor`]), verifying a sealed runtime module before it
//! would be dynamically loaded ([`runtime_module`]), and resolving a
//! provider registry's aliases ([`registry`]).
//!
//! No existing native Rust coverage was found for any of these five files
//! (`git grep` for their exported function names across `engine/` was
//! empty); `legion-provider-sdk::registry` is a related but differently-
//! shaped native registry — see the gap note on [`registry`].
//!
//! Two files (`runtime-module.mjs`, and the `runtime-script`/
//! `security-pack` branch of `provider-executor.mjs`) center on Node's
//! dynamic `import()` of an arbitrary JS module at a sealed path. Rust has
//! no equivalent of loading and invoking an arbitrary compiled module at
//! runtime by path; those files' sealing/verification guard clauses (digest
//! pinning, path containment, provider-id cross-check) are ported faithfully,
//! and the dynamic-dispatch step itself is called out as an explicit gap in
//! each module's doc comment rather than silently dropped.

pub mod external_process;
pub mod provider_executor;
pub mod registry;
pub mod runtime_module;
pub mod tool_identity;
