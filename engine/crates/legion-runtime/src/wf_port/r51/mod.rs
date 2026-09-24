//! Packet r51 — completes the port of `src/lib/host/arcane/{hook-adapter-core,
//! host-event-ledger}.mjs`, closing the gaps `wf_port::w2_047`'s own header
//! documented as not-yet-ported ("Not ported — explicit gaps" items 1 and 2
//! there).
//!
//! - [`pipeline`]: the orchestration half of `hook-adapter-core.mjs` that
//!   `w2_047::hook_adapter_pure` deliberately left out —
//!   `handleHookEvent`/`evaluateHostStop`/`runHookMain`/`hostStopHookOutput`/
//!   `signHostEvent`/`resolveSourceRevision`/`deriveTouchedPaths`. Ported in
//!   full: every branch, refusal code, message, and ordering from the JS
//!   source is reproduced. The five collaborators the JS source itself takes
//!   as constructor/`deps` arguments (`HostIngestor`, `KeyRing`,
//!   `SessionBindingStore`, `PreEffectCorrelationStore`, the completion gate)
//!   are represented as injected Rust traits, mirroring the JS file's own
//!   dependency-injection boundary rather than reimplementing those other
//!   files' logic here.
//! - [`host_event_ledger`]: `HostEventLedger` from `host-event-ledger.mjs`
//!   (`ObservationOutbox` in the same source file was already ported in full
//!   at `w2_047::observation_outbox`). Ported in full: the append lock
//!   (`mkdir`-based mutual exclusion with owner-pid liveness and stale-lock
//!   reclaim), the hash-chained, sequence-numbered append log, and
//!   `verify`/`inspect`. Signing/verification of each record is an injected
//!   `LedgerSigner` trait (mirrors the JS constructor's own `keyRing`
//!   parameter); the chain digest itself uses
//!   `legion_contracts::canonical::canonical_digest`, which already
//!   reproduces `contracts/arcane/canonical.mjs`'s `digestValue` exactly
//!   (sorted-key canonical JSON, `sha256:<hex>` form).

pub mod host_event_ledger;
pub mod pipeline;
