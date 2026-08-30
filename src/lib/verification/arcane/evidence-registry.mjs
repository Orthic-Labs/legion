// Acceptance evidence is compiled from caller-owned receipts/artifacts;
// ReceiptStore remains its sole durable evidence plane.
import { decision } from '../../contracts/arcane/errors.mjs';

const LIFECYCLES = new Set(['CURRENT', 'REFRESH_REQUIRED', 'DEPRECATED', 'WAIVED']);
function fail(code, message, detail = {}) { return decision({ allowed: false, code, message, detail }); }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

export function evidenceFreshness(artifact, { integratedState, latestMaterialChange, now = new Date() } = {}) {
  if (!artifact || artifact.authenticated !== true) return { status: 'STALE', reason: 'unauthenticated-artifact' };
  if (!same(artifact.integratedState, integratedState)) return { status: 'STATE_MISMATCH', reason: 'integrated-state' };
  const observedAt = Date.parse(artifact.observedAt);
  const changedAt = latestMaterialChange ? Date.parse(latestMaterialChange) : -Infinity;
  if (!Number.isFinite(observedAt) || observedAt < changedAt) return { status: 'STALE', reason: 'material-change' };
  if (!Number.isFinite(Date.parse(artifact.validUntil)) || Date.parse(artifact.validUntil) < now.valueOf()) return { status: 'EXPIRED', reason: 'validity-horizon' };
  return { status: 'FRESH', reason: null };
}

/** Eliminate mechanically-evaluable hard-gate failures before any scoring. */
export function compareEvidenceCandidates({ candidates = [], hardGates = [], score = (candidate) => candidate.score ?? 0 } = {}) {
  const eliminated = [], eligible = [];
  for (const candidate of candidates) {
    const failures = [];
    for (const gate of hardGates) {
      let result;
      if (typeof gate?.evaluate === 'function') result = gate.evaluate(candidate);
      else if (gate?.field && Object.hasOwn(candidate ?? {}, gate.field)) {
        const value = candidate[gate.field];
        result = gate.equals !== undefined ? value === gate.equals : Array.isArray(gate.oneOf) ? gate.oneOf.includes(value) : gate.includes !== undefined ? Array.isArray(value) && value.includes(gate.includes) : undefined;
      }
      if (result !== true) failures.push({ gateId: gate?.id ?? null, reason: result === false ? 'hard-gate-failed' : 'hard-gate-not-mechanically-evaluable' });
    }
    if (failures.length) eliminated.push(Object.freeze({ candidate, status: 'ELIMINATED', phase: 'HARD_GATE', failures }));
    else eligible.push(candidate);
  }
  const ranked = eligible.map((candidate) => Object.freeze({ candidate, score: score(candidate) })).sort((a, b) => b.score - a.score);
  return Object.freeze({ phase: 'WEIGHTED_COMPARISON', eligible: Object.freeze(eligible), eliminated: Object.freeze(eliminated), ranked: Object.freeze(ranked) });
}

export class AcceptanceEvidenceRegistry {
  #entries = new Map(); #waivers = new Map();
  register(entry) {
    const required = ['acceptanceId', 'claimType', 'producer', 'durableStore', 'verifier', 'completionConsumer', 'integratedStateBinding', 'validityPolicy'];
    const missing = required.filter((key) => !entry?.[key]);
    if (missing.length) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is incomplete', { missing });
    if (entry.producer === entry.verifier || entry.producer === entry.completionConsumer) return fail('ARC_SELF_CERTIFICATION', 'producer cannot verify or consume its own closure evidence', { acceptanceId: entry.acceptanceId });
    if (entry.lifecycle && !LIFECYCLES.has(entry.lifecycle)) return fail('ARC_SCHEMA_INVALID', 'unknown evidence lifecycle', { lifecycle: entry.lifecycle });
    const normalized = Object.freeze({ lifecycle: 'CURRENT', ...entry });
    const prior = this.#entries.get(entry.acceptanceId);
    if (prior && !same(prior, normalized)) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is immutable for this acceptance id', { acceptanceId: entry.acceptanceId });
    this.#entries.set(entry.acceptanceId, normalized);
    return decision({ allowed: true, message: 'acceptance evidence entry registered', detail: { acceptanceId: entry.acceptanceId } });
  }
  get(acceptanceId) { return this.#entries.get(acceptanceId) ?? null; }
  entries() { return [...this.#entries.values()]; }
  registerWaiver(waiver) {
    const required = ['waiverId', 'acceptanceId', 'reason', 'carrierState', 'issuedAt', 'validUntil'];
    const missing = required.filter((key) => !waiver?.[key]);
    if (missing.length) return fail('ARC_SCHEMA_INVALID', 'evidence waiver is incomplete', { missing });
    const normalized = Object.freeze({ ...waiver, lifecycle: 'WAIVED', visible: true });
    const prior = this.#waivers.get(waiver.waiverId);
    if (prior && !same(prior, normalized)) return fail('ARC_UNSOUND_SEAL', 'evidence waiver is immutable for this waiver id', { waiverId: waiver.waiverId });
    this.#waivers.set(waiver.waiverId, normalized);
    return decision({ allowed: true, message: 'evidence waiver registered', detail: { waiverId: waiver.waiverId, lifecycle: 'WAIVED', visible: true } });
  }
  getWaiver(waiverId, context = {}) {
    const waiver = this.#waivers.get(waiverId);
    if (!waiver) return null;
    const now = context.now ?? new Date();
    const carrierState = context.carrierState ?? context.integratedState;
    const refresh = !Number.isFinite(Date.parse(waiver.validUntil)) || Date.parse(waiver.validUntil) < now.valueOf() || (carrierState !== undefined && !same(waiver.carrierState, carrierState));
    return Object.freeze({ ...waiver, lifecycle: refresh ? 'REFRESH_REQUIRED' : 'WAIVED', visible: true });
  }
  evaluateWaiver(waiverId, context = {}) {
    const waiver = this.getWaiver(waiverId, context);
    if (!waiver) return fail('ARC_EVIDENCE_INSUFFICIENT', 'evidence waiver is missing', { waiverId });
    if (waiver.lifecycle === 'REFRESH_REQUIRED') return fail('ARC_EVIDENCE_STALE', 'evidence waiver requires refresh', { waiverId, lifecycle: 'REFRESH_REQUIRED', visible: true });
    return decision({ allowed: true, message: 'current visible evidence waiver verified', detail: { waiverId, lifecycle: 'WAIVED', visible: true } });
  }
  verify(acceptanceId, artifact, context = {}) {
    const entry = this.get(acceptanceId);
    if (!entry) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is missing', { acceptanceId });
    if (artifact?.acceptanceId !== acceptanceId || artifact?.producer !== entry.producer || artifact?.verifier !== entry.verifier || artifact?.completionConsumer !== entry.completionConsumer) return fail('ARC_BINDING_MISMATCH', 'evidence artifact does not match registered producer/verifier/consumer', { acceptanceId });
    const freshness = evidenceFreshness(artifact, context);
    if (freshness.status !== 'FRESH') return fail('ARC_EVIDENCE_STALE', 'acceptance evidence is not fresh for exact integrated state', { acceptanceId, completion: 'CANDIDATE', ...freshness });
    return decision({ allowed: true, message: 'fresh exact-state acceptance evidence verified', detail: { acceptanceId, freshness: 'FRESH' } });
  }
}
