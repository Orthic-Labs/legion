// Kernel binding — the seam between Arcane and Lane D's deterministic substrate.
//
// SEQUENCING NOTE (typed, not silent): DISPATCH-11 line 29 instructs this lane
// to build S01's mapping statically and stub the store binding with a typed
// note if the Kernel lane has not yet reported its primitives. At the time this
// module was written, `src/packages/kernel/` does not exist — `src/packages/` contains
// only `contracts/`. So:
//
//   - Arcane NEVER maintains a private ID allocator (S01 action 2 forbids it).
//     `mintId` here delegates to a bound Kernel allocator when one is
//     installed, and otherwise mints a *provisional* id and records that fact
//     on the binding, so nothing downstream can mistake a provisional id for a
//     Kernel-issued one.
//   - Every canonical-state write goes through this seam. With no Kernel bound,
//     writes fail closed with ARC_KERNEL_PRIMITIVE_UNAVAILABLE rather than
//     falling back to a second store root (detailed plan §5.1: "do not create
//     an unrelated predecessor/predecessor state root as the new authority").
//   - Arcane's own append-only receipt store (lib/receipt-store.mjs) is NOT a
//     second authority: it is the Arcane namespace's local journal, and it is
//     designed to be re-parented onto the Kernel event store by swapping this
//     binding. That is recorded as a typed blocker, not a design claim.
//
// Lane D's DISPATCH-10 final report is expected to name which store/lifecycle
// primitives are ready; `bindKernel()` is the one function that changes when it
// lands. No other Arcane module imports `src/packages/kernel` directly.

import { ArcaneError } from './errors.mjs';
import { mintId as mintProvisionalId } from './ids.mjs';

/**
 * @typedef {object} KernelPrimitives
 * @property {(family: string) => string} [mintId] Kernel identity allocator.
 * @property {(namespace: string, record: object) => Promise<void>|void} [appendEvent]
 * @property {(namespace: string, key: string) => Promise<object|null>|object|null} [readObject]
 * @property {(namespace: string, key: string, record: object) => Promise<void>|void} [putObject]
 */

/** @type {KernelPrimitives|null} */
let bound = null;

/** Install the Kernel primitives. Called once at host startup when Lane D lands. */
export function bindKernel(primitives) {
  if (!primitives || typeof primitives !== 'object') {
    throw new ArcaneError('ARC_KERNEL_PRIMITIVE_UNAVAILABLE', 'bindKernel requires a primitives object', {});
  }
  bound = primitives;
  return bound;
}

/** Remove the binding (tests only). */
export function unbindKernel() {
  bound = null;
}

export function kernelBound() {
  return bound !== null;
}

/**
 * Current binding status, for enforcement-health reporting. Arcane reports its
 * own degradation honestly & per capability rather than
 * claiming a strength it does not have.
 */
export function kernelStatus() {
  return Object.freeze({
    bound: bound !== null,
    identity: Boolean(bound?.mintId),
    events: Boolean(bound?.appendEvent),
    objects: Boolean(bound?.readObject && bound?.putObject),
    note: bound
      ? 'kernel primitives bound'
      : 'packages/kernel not available at build time (Lane D pending) — ids are provisional and canonical writes fail closed',
  });
}

/**
 * Mint an id. Uses the Kernel allocator when bound; otherwise mints a
 * provisional id of the same grammar and flags it.
 * @returns {{id: string, provisional: boolean}}
 */
export function mintId(family) {
  if (bound?.mintId) return { id: bound.mintId(family), provisional: false };
  return { id: mintProvisionalId(family), provisional: true };
}

/** Append to the Kernel event store, or fail closed. */
export async function appendEvent(namespace, record) {
  if (!bound?.appendEvent) {
    throw new ArcaneError(
      'ARC_KERNEL_PRIMITIVE_UNAVAILABLE',
      'canonical event write requires a bound Kernel event store',
      { namespace, primitive: 'appendEvent' },
    );
  }
  return bound.appendEvent(namespace, record);
}

/** Read a Kernel-stored object, or fail closed. */
export async function readObject(namespace, key) {
  if (!bound?.readObject) {
    throw new ArcaneError(
      'ARC_KERNEL_PRIMITIVE_UNAVAILABLE',
      'canonical object read requires a bound Kernel object store',
      { namespace, primitive: 'readObject' },
    );
  }
  return bound.readObject(namespace, key);
}

/** Write a Kernel-stored object, or fail closed. */
export async function putObject(namespace, key, record) {
  if (!bound?.putObject) {
    throw new ArcaneError(
      'ARC_KERNEL_PRIMITIVE_UNAVAILABLE',
      'canonical object write requires a bound Kernel object store',
      { namespace, primitive: 'putObject' },
    );
  }
  return bound.putObject(namespace, key, record);
}

/** The Legion store namespace Arcane owns (detailed plan §5.1). */
export const ARCANE_NAMESPACE = 'arcane';
