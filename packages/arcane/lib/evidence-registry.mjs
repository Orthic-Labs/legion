// S05 acceptance-evidence registry. This is deliberately a compiler over
// caller-owned receipts/artifacts: ReceiptStore remains the sole durable plane.
import { decision } from './errors.mjs';

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

export class AcceptanceEvidenceRegistry {
  #entries = new Map();
  register(entry) {
    const required = ['acceptanceId', 'claimType', 'producer', 'durableStore', 'verifier', 'completionConsumer', 'integratedStateBinding', 'validityPolicy'];
    const missing = required.filter((key) => !entry?.[key]);
    if (missing.length) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is incomplete', { missing });
    if (entry.producer === entry.verifier || entry.producer === entry.completionConsumer) return fail('ARC_SELF_CERTIFICATION', 'producer cannot verify or consume its own closure evidence', { acceptanceId: entry.acceptanceId });
    if (entry.lifecycle && !LIFECYCLES.has(entry.lifecycle)) return fail('ARC_SCHEMA_INVALID', 'unknown evidence lifecycle', { lifecycle: entry.lifecycle });
    const prior = this.#entries.get(entry.acceptanceId);
    if (prior && !same(prior, entry)) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is immutable for this acceptance id', { acceptanceId: entry.acceptanceId });
    this.#entries.set(entry.acceptanceId, Object.freeze({ lifecycle: 'CURRENT', ...entry }));
    return decision({ allowed: true, message: 'acceptance evidence entry registered', detail: { acceptanceId: entry.acceptanceId } });
  }
  get(acceptanceId) { return this.#entries.get(acceptanceId) ?? null; }
  entries() { return [...this.#entries.values()]; }
  verify(acceptanceId, artifact, context = {}) {
    const entry = this.get(acceptanceId);
    if (!entry) return fail('ARC_UNSOUND_SEAL', 'acceptance evidence entry is missing', { acceptanceId });
    if (artifact?.acceptanceId !== acceptanceId || artifact?.producer !== entry.producer || artifact?.verifier !== entry.verifier || artifact?.completionConsumer !== entry.completionConsumer) return fail('ARC_BINDING_MISMATCH', 'evidence artifact does not match registered producer/verifier/consumer', { acceptanceId });
    const freshness = evidenceFreshness(artifact, context);
    if (freshness.status !== 'FRESH') return fail('ARC_EVIDENCE_STALE', 'acceptance evidence is not fresh for exact integrated state', { acceptanceId, ...freshness });
    return decision({ allowed: true, message: 'fresh exact-state acceptance evidence verified', detail: { acceptanceId, freshness: 'FRESH' } });
  }
}
