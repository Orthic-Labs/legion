import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { canonicalJson, constantTimeEqual, digestValue } from '../../../contracts/arcane/canonical.mjs';
import { ArcaneError, decision } from '../../../contracts/arcane/errors.mjs';
import { classifyLatestUserIntent, latestExternalUserTurn } from '../../../cognitive/arcane/user-intent.mjs';

const TTL_SECONDS = 900;
const BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'keyId', 'sessionDigest', 'runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest', 'effectClass', 'targetDigest', 'userTurnDigest', 'issuedAt', 'expiresAt']);
const macFor = (record, key) => createHmac('sha256', key).update(canonicalJson(Object.fromEntries(BOUND_FIELDS.map((field) => [field, record[field]]))), 'utf8').digest('hex');
const approvalDigestFor = (record) => digestValue({ domain: 'arcane.user-approval.digest.v1', values: [record.keyId, record.sessionDigest, record.runId, record.taskId, record.contractId, record.contractVersion, record.contractDigest, record.effectClass, record.targetDigest, record.userTurnDigest, record.issuedAt, record.expiresAt, record.mac] });
const approvalDenial = (code, message) => decision({ allowed: false, code, message, detail: {} });

/** Host-held, transcript-derived approval authority. No model payload can mint one. */
export class UserApprovalAuthority {
  #keyRing; #clock; #used = new Set(); #approvalRequired;
  constructor({ keyRing, policy, clock = () => Date.now() } = {}) {
    this.#keyRing = keyRing ?? null;
    this.#clock = clock;
    this.#approvalRequired = new Set(policy?.approvalRequiredEffectClasses?.() ?? []);
  }

  #requiresApproval(effectClass) { return this.#approvalRequired.has(effectClass); }

  #latestApprovedTurn(transcriptPath) {
    if (typeof transcriptPath !== 'string' || transcriptPath.length === 0) return null;
    let transcript;
    try { transcript = readFileSync(transcriptPath, 'utf8'); } catch { return null; }
    const intent = classifyLatestUserIntent(transcript);
    const turn = latestExternalUserTurn(transcript);
    return turn && ['EXECUTE', 'CONTINUE'].includes(intent.intent) ? turn : null;
  }

  deriveRecord({ transcriptPath, sessionId, runId, taskId, contractId, contractVersion, contractDigest, effectClass, target }) {
    if (!this.#requiresApproval(effectClass)) return null;
    if (![sessionId, runId, taskId, contractId, contractDigest, target].every((value) => typeof value === 'string' && value.length > 0) || !Number.isInteger(contractVersion) || contractVersion < 1) return null;
    const turn = this.#latestApprovedTurn(transcriptPath);
    if (!turn) return null;
    try {
      const now = this.#clock(); const issuedAt = new Date(now).toISOString(); const expiresAt = new Date(now + TTL_SECONDS * 1000).toISOString();
      const keyId = this.#keyRing?.activeKeyId(); const key = this.#keyRing?.get(keyId).key;
      if (!keyId || !key) return null;
      const record = {
        schemaVersion: 1, kind: 'arcane-user-approval', keyId,
        sessionDigest: digestValue({ domain: 'arcane.user-approval.session.v1', values: [sessionId] }),
        runId, taskId, contractId, contractVersion, contractDigest, effectClass,
        targetDigest: digestValue({ domain: 'arcane.user-approval.target.v1', values: [target] }),
        userTurnDigest: digestValue({ domain: 'arcane.user-approval.turn.v1', values: [turn] }), issuedAt, expiresAt,
      };
      return { ...record, mac: macFor(record, key) };
    } catch { return null; }
  }

  consume(record, expected) {
    if (!record || typeof record !== 'object') return approvalDenial('ARC_APPROVAL_REQUIRED', 'required user approval is missing');
    const fields = ['transcriptPath', 'sessionId', 'runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest', 'effectClass', 'target'];
    if (!fields.every((field) => Object.hasOwn(expected, field))) return approvalDenial('ARC_APPROVAL_REQUIRED', 'required user approval binding is incomplete');
    if (![expected.sessionId, expected.runId, expected.taskId, expected.contractId, expected.contractDigest, expected.target].every((value) => typeof value === 'string' && value.length > 0) || !Number.isInteger(expected.contractVersion) || expected.contractVersion < 1 || !this.#requiresApproval(expected.effectClass)) return approvalDenial('ARC_APPROVAL_REQUIRED', 'required user approval binding is invalid');
    const turn = this.#latestApprovedTurn(expected.transcriptPath);
    if (!turn) return approvalDenial('ARC_APPROVAL_REQUIRED', 'latest external user turn does not approve this effect');
    const now = this.#clock(); const issued = Date.parse(record.issuedAt); const expires = Date.parse(record.expiresAt);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires - issued > TTL_SECONDS * 1000 || expires <= issued || now < issued || now >= expires) return approvalDenial('ARC_APPROVAL_REQUIRED', 'required user approval is expired or unreadable');
    const bound = {
      sessionDigest: digestValue({ domain: 'arcane.user-approval.session.v1', values: [expected.sessionId] }),
      runId: expected.runId, taskId: expected.taskId, contractId: expected.contractId, contractVersion: expected.contractVersion, contractDigest: expected.contractDigest,
      effectClass: expected.effectClass, targetDigest: digestValue({ domain: 'arcane.user-approval.target.v1', values: [expected.target] }),
      userTurnDigest: digestValue({ domain: 'arcane.user-approval.turn.v1', values: [turn] }),
    };
    if (Object.entries(bound).some(([field, value]) => record[field] !== value)) return approvalDenial('ARC_BINDING_MISMATCH', 'user approval binding differs');
    let key;
    try { key = this.#keyRing?.get(record.keyId).key; } catch (error) { return approvalDenial(error.code ?? 'ARC_AUTH_KEY_UNAVAILABLE', 'approval key unavailable'); }
    if (!key || typeof record.mac !== 'string' || !constantTimeEqual(macFor(record, key), record.mac)) return approvalDenial('ARC_AUTH_FORGED', 'user approval authentication failed');
    const replayKey = `${record.keyId}:${record.mac}`;
    if (this.#used.has(replayKey)) return approvalDenial('ARC_REPLAY_NONCE_SEEN', 'user approval was already consumed');
    this.#used.add(replayKey);
    return decision({ allowed: true, detail: { approvalDigest: approvalDigestFor(record), evidence: record } });
  }

  derive(effectRequest, ctx) {
    if (!this.#requiresApproval(effectRequest.effectClass)) return decision({ allowed: true, detail: { approvalDigest: null, evidence: null } });
    const record = this.deriveRecord({ transcriptPath: ctx?.transcriptPath, sessionId: ctx?.sessionId, runId: effectRequest.runId, taskId: effectRequest.taskId, contractId: effectRequest.contractId, contractVersion: ctx?.expectedContractVersion, contractDigest: ctx?.contractDigest, effectClass: effectRequest.effectClass, target: effectRequest.target });
    return this.consume(record, { transcriptPath: ctx?.transcriptPath, sessionId: ctx?.sessionId, runId: effectRequest.runId, taskId: effectRequest.taskId, contractId: effectRequest.contractId, contractVersion: ctx?.expectedContractVersion, contractDigest: ctx?.contractDigest, effectClass: effectRequest.effectClass, target: effectRequest.target });
  }
}

export { BOUND_FIELDS as USER_APPROVAL_BOUND_FIELDS, TTL_SECONDS as USER_APPROVAL_TTL_SECONDS, approvalDigestFor };
