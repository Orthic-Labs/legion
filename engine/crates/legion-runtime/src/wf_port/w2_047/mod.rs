//! Faithful port of `src/lib/host/arcane/{hook-adapter-core,host-event-ledger,
//! host-event,host-runtime-output,legacy-bridge}.mjs` (chunk w2_047).
//!
//! ## Scope actually ported here
//!
//! - `host_event`: `EVENT_TYPE`, `LEGACY_HOST_EVENT_TYPE`,
//!   `LIFECYCLE_TELEMETRY_EVENT_TYPES`, `HOST_EVENT_SCHEMA`,
//!   `HOST_EVENT_BOUND_FIELDS`, `validateHostEvent`, `normalizeHostEvent`,
//!   and `classifyObservation` from `host-event.mjs` — ported in full,
//!   including the closed `HOST_EVENT_SCHEMA` validation, which now runs
//!   through the same generic JSON-Schema-subset engine
//!   `legion_policy::wf_port::wf068::validate_schema` already ports from
//!   `qualification/schema-validator.mjs` (this crate depends on
//!   `legion-policy`), rather than an ad-hoc subset of field checks.
//! - `hook_adapter_pure`: `isDestructiveCommand`, `classifyVcsPush`, and
//!   `vcsRewriteApprovalKey` from `hook-adapter-core.mjs` — the three
//!   self-contained regex/string decision functions. These are ported in
//!   full, byte-for-byte against the JS regexes.
//! - `observation_outbox`: `ObservationOutbox` from `host-event-ledger.mjs`
//!   — the durable delivery queue. Fully self-contained (file-based JSON
//!   state, no signing), ported in full.
//! - `host_runtime_output`: `renderHostRuntimeOutput` /
//!   `serializeHostRuntimeOutput` from `host-runtime-output.mjs`, ported in
//!   full including both JS dependencies: `decision-envelope.mjs`'s
//!   `createDecisionEnvelope`/`publicReason` (`w2_046::decision_envelope`,
//!   wired into `wf_port` in this crate) and the
//!   `arcane-host-runtime-output-v1` schema assertion
//!   (`legion_policy::wf_port::wf068::RuntimeSchemaSet`, embedding the same
//!   schema JSON the JS `RuntimeSchemaSet` loads). `render_host_runtime_output`
//!   / `serialize_host_runtime_output` keep the low-level, dependency-free
//!   shape logic behind an injected envelope closure (useful for testing the
//!   shape mapping in isolation); `render_host_runtime_output_checked` /
//!   `serialize_host_runtime_output_checked` are the fully-wired entry
//!   points and are the faithful equivalent of calling the JS functions
//!   directly.
//!
//! ## Not ported in this chunk (documented gap, not silently dropped)
//!
//! - `hook-adapter-core.mjs`'s `handleHookEvent`/`runHookMain`/
//!   `evaluateHostStop` full pipelines: they orchestrate `HostIngestor`
//!   (`verification/arcane/ingest.mjs`, already ported at
//!   `legion-policy::wf_port::wf072::ingest`), `KeyRing`/`signRecord`
//!   (`guard/compat/audit/receipt-auth.mjs`), `evaluateCodexEscalation`
//!   (already ported at `legion-runtime::wf_port::w2_046::codex_escalation`,
//!   also not yet wired), `SessionBindingStore`, `PreEffectCorrelationStore`,
//!   and `evaluateCompletion` (`verification/arcane/completion-gate.mjs`,
//!   not ported anywhere yet). None of those five collaborators are owned
//!   by this chunk (`wf_port/w2_047/**`), and wiring them from here would
//!   mean reaching into other in-flight or not-yet-started chunks' territory
//!   without those files being stable. The three pure decision functions the
//!   pipeline calls (`isDestructiveCommand`, `classifyVcsPush`,
//!   `vcsRewriteApprovalKey`) are ported in full in `hook_adapter_pure`, so
//!   an integrator wiring the full pipeline later has faithful building
//!   blocks to call.
//! - `host-event-ledger.mjs`'s `HostEventLedger` class (the signed, hash-
//!   chained append log) is not ported: it depends on `signRecord`/
//!   `verifyRecord` (`guard/compat/audit/receipt-auth.mjs`) and
//!   `digestValue` (`contracts/arcane/canonical.mjs`), neither of which is
//!   owned by this chunk, and `wf067`'s own header already flags
//!   `HostEventLedger` as unowned territory it takes as an injected
//!   `LedgerStore` trait rather than reimplementing. This chunk follows the
//!   same discipline: `ObservationOutbox` (no signing dependency) is ported
//!   in full; `HostEventLedger` is left for whichever chunk owns
//!   `guard/compat/audit/receipt-auth.mjs` and `contracts/arcane/canonical.mjs`
//!   Rust ports, so its signing is byte-faithful rather than a second,
//!   possibly-diverging HMAC scheme.
//! - `legacy-bridge.mjs` (Forge compatibility bridge: `bridgeStoreSnapshot`,
//!   `migrationDryRun`, `parityReport`, `dispositionFor`) is not ported.
//!   Every one of its entry points reads
//!   `arcane-compatibility/forge/{schema-map,operation-map}.json` and (for
//!   `migrationDryRun`) bundled fixture files via `import.meta.url`-relative
//!   paths, and calls `kernelStatus()` (`core/kernel-binding.mjs`, unowned)
//!   and `assertValid`/`canonicalJson`/`digestValue`
//!   (`contracts/arcane/{validate,canonical}.mjs`, unowned). It concerns
//!   Forge (the legacy predecessor product), not Membrane/Blueprint, so it
//!   is not dropped for the Membrane/Blueprint retirement — it is simply
//!   out of this chunk's budget once the schema/JSON-file and
//!   `kernel-binding` dependencies are subtracted. Flagged for a follow-up
//!   chunk once `contracts/arcane/{validate,canonical}.mjs` and
//!   `core/kernel-binding.mjs` have Rust ports to build on.

pub mod host_event;
pub mod hook_adapter_pure;
pub mod host_runtime_output;
pub mod observation_outbox;
