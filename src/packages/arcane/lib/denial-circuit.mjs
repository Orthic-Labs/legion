// EC-603 T-4 — one authenticated retry circuit for conversational denials.
// It is intentionally not an authorization mechanism: opening it releases only
// conversation termination; the original denial remains false in every path.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalJson, digestValue } from './canonical.mjs';
import { ArcaneError, decision } from './errors.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

const DOMAIN = 'arcane-denial-circuit:v1';
const MAX_IDENTICAL_DENIALS = 2;

export const DENIAL_CIRCUIT_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'sessionId', 'runId', 'taskId', 'controlClass',
  'code', 'missingEvidenceDigest', 'targetDigest', 'fingerprint', 'count', 'issuedAt',
]);

function required(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new ArcaneError('ARC_SCHEMA_INVALID', `denial circuit requires ${field}`, { field });
  return value;
}

function recordPath(root, scope) {
  return join(root, `${createHash('sha256').update(canonicalJson(scope), 'utf8').digest('hex')}.json`);
}

function circuitFingerprint({ sessionId, runId, taskId, controlClass, code, missingEvidenceDigest, targetDigest }) {
  return digestValue({ sessionId, runId, taskId, controlClass, code, missingEvidenceDigest, targetDigest });
}

export function denialControlClass({ eventType = null, code = null, controlClass = null } = {}) {
  if (typeof controlClass === 'string') return controlClass;
  if (eventType === 'PreToolUse' || eventType === 'PostToolUse' || eventType === 'PostToolUseFailure') return 'effect';
  if (typeof code === 'string' && (/^ARC_AUTH_|^ARC_BINDING_|^ARC_REPLAY_|^ARC_CAPABILITY_|^ARC_HOST_EVENT_|^ARC_STORE_CORRUPT$/.test(code))) return 'security';
  if (code === 'ARC_ESCALATION_UNEVIDENCED') return 'escalation';
  if (code === 'ARC_STOP_SHAPE') return 'stop';
  return 'evidence';
}

export class DenialCircuit {
  #root; #keyRing; #keyId; #clock;

  constructor({ root, keyRing, keyId, clock = () => new Date().toISOString() }) {
    if (!root || !keyRing || !keyId) throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', 'authenticated denial circuit requires root and active key', {});
    this.#root = root; this.#keyRing = keyRing; this.#keyId = keyId; this.#clock = clock;
  }

  record({ sessionId, runId, taskId, controlClass, code, missingEvidence = [], target = null }) {
    const scope = { sessionId: required(sessionId, 'sessionId'), runId: required(runId, 'runId'), taskId: required(taskId, 'taskId') };
    const normalizedClass = required(controlClass, 'controlClass');
    const normalizedCode = required(code, 'code');
    const missingEvidenceDigest = digestValue(Array.isArray(missingEvidence) ? [...missingEvidence].sort() : []);
    const targetDigest = digestValue(target ?? null);
    const fingerprint = circuitFingerprint({ ...scope, controlClass: normalizedClass, code: normalizedCode, missingEvidenceDigest, targetDigest });
    const path = recordPath(this.#root, scope);
    let prior = null;
    try {
      if (existsSync(path)) {
        prior = JSON.parse(readFileSync(path, 'utf8'));
        const verified = verifyRecord(prior, prior.authentication, { keyRing: this.#keyRing, boundFields: DENIAL_CIRCUIT_BOUND_FIELDS, expectedBinding: scope, macDomain: DOMAIN });
        if (!verified.allowed) throw new ArcaneError(verified.code, 'denial circuit receipt authentication failed', verified.detail);
      }
      const count = prior?.fingerprint === fingerprint ? Math.min(prior.count + 1, MAX_IDENTICAL_DENIALS) : 1;
      const receipt = { schemaVersion: 1, kind: 'arcane-denial-circuit-receipt', ...scope, controlClass: normalizedClass, code: normalizedCode, missingEvidenceDigest, targetDigest, fingerprint, count, issuedAt: this.#clock() };
      receipt.authentication = signRecord(receipt, { keyRing: this.#keyRing, keyId: this.#keyId, boundFields: DENIAL_CIRCUIT_BOUND_FIELDS, macDomain: DOMAIN });
      mkdirSync(this.#root, { recursive: true });
      const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
      writeFileSync(temp, `${JSON.stringify(receipt)}\n`, 'utf8');
      renameSync(temp, path);
      return Object.freeze({ receipt, opened: count >= MAX_IDENTICAL_DENIALS && !['effect', 'security'].includes(normalizedClass) });
    } catch (error) {
      if (error instanceof ArcaneError) throw error;
      throw new ArcaneError('ARC_STORE_CORRUPT', 'authenticated denial circuit state is unavailable', {});
    }
  }
}

/** Preserve denial while exposing an authenticated retry signature. */
export function applyDenialCircuit(result, circuit, context) {
  if (result?.allowed || !circuit) return result;
  const detail = result.detail ?? {};
  const controlClass = denialControlClass({ eventType: context.eventType, code: result.code, controlClass: context.controlClass });
  const recorded = circuit.record({ sessionId: context.sessionId, runId: context.runId, taskId: context.taskId, controlClass, code: result.code, missingEvidence: detail.missingClasses ?? detail.missingEvidence ?? [], target: context.target ?? null });
  return decision({ allowed: false, code: result.code, message: result.message, enforcementHealth: result.enforcementHealth, detail: { ...detail, retrySignature: recorded.receipt.fingerprint, termination: recorded.opened ? 'terminate' : detail.termination } });
}
