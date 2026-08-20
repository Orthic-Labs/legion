// Arcane — the deterministic enforcement/evidence plane (Legion lane E).
//
// Arcane is not a model or prompt. It is
// deterministic code — hooks, brokers, validators, and a receipt store — that
// sits on the host boundary and executes on every turn. Nothing in this
// package calls a model, and nothing in it takes an npm dependency.
//
// Three interception points (§24a):
//   PRE-PROMPT GATE     authority identity per turn -> lib/authority.mjs
//   PRE-EFFECT GATE     capability/path/effect-class/latitude -> lib/preeffect-gate.mjs
//   POST-EFFECT RECEIPT host-observed effect -> lib/ingest.mjs + lib/receipt-store.mjs
//
// Deliverable map:
//   S01 legacy mapping + runtime bridge   lib/legacy-bridge.mjs + captured compatibility maps
//   S02 policy + authority boundary       lib/policy.mjs, lib/authority.mjs, policy/
//   S03 authenticated receipts            lib/keys.mjs, lib/receipt-auth.mjs,
//                                         lib/replay.mjs, lib/receipt-store.mjs
//   S04 host-event ingestion              lib/host-event.mjs, lib/ingest.mjs
//   S05 evidence envelope + invalidation  lib/evidence-envelope.mjs,
//                                         lib/invalidation.mjs, lib/evidence-migration.mjs
//   D6  pre-effect gate                   lib/preeffect-gate.mjs

// Foundation
export * from './lib/errors.mjs';
export * from './lib/canonical.mjs';
export * from './lib/validate.mjs';

// `mintId` exists in BOTH lib/ids.mjs and lib/kernel-binding.mjs with
// different return types (a bare string vs `{id, provisional}`). A blanket
// `export *` from both would make the name ambiguous, and ESM resolves that by
// dropping it SILENTLY — importers get `undefined` and a confusing failure far
// from the cause. Disambiguate by hand so both stay reachable and the
// difference is visible at the call site.
export {
  ulid,
  isId,
  assertId,
  mintId as mintLocalId,
  ID_PATTERN,
  HANDLE_PREFIX,
} from './lib/ids.mjs';
export {
  bindKernel,
  unbindKernel,
  kernelBound,
  kernelStatus,
  mintId as mintKernelId,
  appendEvent,
  readObject,
  putObject,
  ARCANE_NAMESPACE,
} from './lib/kernel-binding.mjs';

// S01 — predecessor compatibility
export * from './lib/legacy-bridge.mjs';

// S02 — policy and authority
export * from './lib/policy.mjs';
export * from './lib/authority.mjs';

// S03 — authenticated receipts, replay defense, capability + receipt stores
export * from './lib/keys.mjs';
export * from './lib/receipt-auth.mjs';
export * from './lib/replay.mjs';
export * from './lib/receipt-store.mjs';

// S04 — host-event ingestion
export * from './lib/host-event.mjs';
export * from './lib/ingest.mjs';
export * from './lib/runtime-schema.mjs';
export * from './lib/state-paths.mjs';
export * from './lib/capability-store.mjs';
export * from './lib/contract-seal-store.mjs';
export * from './lib/budget-governance-store.mjs';
export * from './lib/task-budget-seal-store.mjs';
export * from './lib/architecture-router.mjs';
export * from './lib/architecture-state.mjs';
export * from './lib/architecture-fingerprints.mjs';
export * from './lib/scoped-acceptance.mjs';
export * from './lib/continuity.mjs';
export * from './lib/architecture-event-store.mjs';
export * from './lib/s09-runtime-executor.mjs';
export * from './lib/authority-binding-store.mjs';
export * from './lib/session-binding.mjs';
export * from './lib/host-event-ledger.mjs';
export * from './lib/authority-invocation-proof.mjs';
export * from './lib/pending-terminal-operation-store.mjs';
export * from './lib/advisory-profile.mjs';
export * from './lib/advisory-certification.mjs';
export * from './lib/advisory-judgment.mjs';
export * from './lib/preeffect-correlation.mjs';
export * from './host/host-runtime-output.mjs';
export * from './host/host-runtime.mjs';

// S05 — evidence envelope, invalidation cascade, migration
export * from './lib/evidence-envelope.mjs';
export * from './lib/invalidation.mjs';
export * from './lib/evidence-migration.mjs';

// D6 — the pre-effect gate
export * from './lib/preeffect-gate.mjs';
