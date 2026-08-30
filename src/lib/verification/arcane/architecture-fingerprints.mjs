// Stage 3 fingerprints stay canonical, content-addressed, & free of replay
// envelope metadata. State owns its exact projection definition; this module
// exposes durable event/history identities for the trajectory boundary.

import { digestValue } from '../../contracts/arcane/canonical.mjs';
import { fingerprintArchitectureState } from './architecture-state.mjs';

export const ARCHITECTURE_ACCEPTED_EVENT_KIND = 'architecture-accepted-event.v1';

/**
 * State's self-reference plus replay-tail reference must never feed its own
 * digest. Delegating this to state keeps live acceptance & replay identical.
 */
export function architectureStateFingerprint(state) {
  return fingerprintArchitectureState(state);
}

/** Digest of an immutable accepted event, including its authentication. */
export function architectureEventFingerprint(event) {
  return digestValue(event);
}

/** Stable CAS/tail identity for an empty or non-empty trajectory. */
export function architectureTrajectoryFingerprint(events = []) {
  return digestValue(events);
}

export function architectureDecisionFingerprint(decision) {
  return digestValue(decision);
}

export function architectureEvidenceFingerprint(evidence) {
  return digestValue(evidence);
}

export function architectureFindingFingerprint(finding) {
  return digestValue(finding);
}

export function architectureRetryFingerprint(retry) {
  return digestValue(retry);
}
