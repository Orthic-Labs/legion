import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalJson, digestValue } from './canonical.mjs';
import { ArcaneError } from './errors.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

export const CONTRACT_TRANSITION_RECEIPT_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'transactionId', 'action', 'state', 'sessionId', 'runId',
  'predecessorBinding', 'successorBinding', 'predecessorDigest', 'successorDigest',
  'deliveryDigest', 'createdAt', 'nonce', 'previousReceiptDigest',
]);
const DOMAIN = 'arcane.contract-transition.v1';
const fail = (code, message, detail = {}) => { throw new ArcaneError(code, message, detail); };
const equal = (left, right) => canonicalJson(left) === canonicalJson(right);

/**
 * Authenticated write-ahead lifecycle journal.  PREPARED receipt lands before
 * binding CAS; COMMITTED lands after it. Repair uses those exact bytes only,
 * so an interrupted transition can neither discard delivery/work state nor
 * apply a substituted successor.
 */
export class ContractLifecycle {
  #root; #bindings; #seals; #keyRing; #keyId; #clock; #failpoint;
  constructor({ root, bindingStore, sealStore, keyRing, keyId = null, clock = () => new Date().toISOString(), failpoint = null }) {
    if (!root || !bindingStore || !sealStore || !keyRing) fail('ARC_STORE_CORRUPT', 'contract lifecycle requires durable stores and host keyring');
    this.#root = root; this.#bindings = bindingStore; this.#seals = sealStore; this.#keyRing = keyRing;
    this.#keyId = keyId ?? keyRing.activeKeyId(); this.#clock = clock; this.#failpoint = failpoint;
  }
  #path(sessionId) { return join(this.#root, `${digestValue({ domain: DOMAIN, sessionId }).slice(7)}.jsonl`); }
  #records(sessionId) {
    const path = this.#path(sessionId); if (!existsSync(path)) return [];
    const text = readFileSync(path, 'utf8'); if (text && !text.endsWith('\n')) fail('ARC_STORE_CORRUPT', 'contract transition journal has partial record');
    let previous = null;
    return text.split('\n').filter(Boolean).map((line) => {
      let record; try { record = JSON.parse(line); } catch { fail('ARC_STORE_CORRUPT', 'contract transition journal is unreadable'); }
      const verified = verifyRecord(record, record.authentication, { keyRing: this.#keyRing, boundFields: CONTRACT_TRANSITION_RECEIPT_BOUND_FIELDS, expectedBinding: { sessionId }, macDomain: DOMAIN });
      if (!verified.allowed) fail(verified.code, 'contract transition receipt authentication failed', verified.detail);
      if (record.previousReceiptDigest !== previous) fail('ARC_STORE_CORRUPT', 'contract transition journal chain is discontinuous');
      previous = digestValue(record); return record;
    });
  }
  #append(unsigned) {
    const record = { ...unsigned, authentication: signRecord(unsigned, { keyRing: this.#keyRing, keyId: this.#keyId, boundFields: CONTRACT_TRANSITION_RECEIPT_BOUND_FIELDS, macDomain: DOMAIN }) };
    mkdirSync(this.#root, { recursive: true }); appendFileSync(this.#path(record.sessionId), `${canonicalJson(record)}\n`, { encoding: 'utf8', mode: 0o600, flush: true });
    return record;
  }
  #receipt({ action, state, transactionId, sessionId, predecessorBinding, successorBinding, previousReceiptDigest }) {
    return {
      schemaVersion: 1, kind: 'arcane-contract-transition-receipt', transactionId, action, state, sessionId,
      runId: predecessorBinding.runId, predecessorBinding, successorBinding,
      predecessorDigest: digestValue(predecessorBinding), successorDigest: digestValue(successorBinding),
      deliveryDigest: digestValue(predecessorBinding.delivery ?? null), createdAt: this.#clock(), nonce: transactionId,
      previousReceiptDigest,
    };
  }
  #validateBinding(binding, sessionId) {
    if (!binding?.runId || !binding.contractId || !Number.isInteger(binding.contractVersion) || !binding.contractDigest) fail('ARC_BINDING_MISMATCH', 'active sealed binding is required', { sessionId });
    if (binding.lifecycle?.state === 'suspended') return;
    if (binding.lifecycle != null && binding.lifecycle.state !== 'active') fail('ARC_BINDING_MISMATCH', 'binding lifecycle state is invalid');
  }
  #recover(sessionId, records) {
    const pending = [...records].reverse().find((record) => record.state === 'PREPARED' && !records.some((other) => other.state === 'COMMITTED' && other.transactionId === record.transactionId));
    if (!pending) return null;
    const current = this.#bindings.getBinding(sessionId);
    if (!equal(current, pending.predecessorBinding) && !equal(current, pending.successorBinding)) fail('ARC_BINDING_MISMATCH', 'prepared transition no longer matches active binding');
    if (equal(current, pending.predecessorBinding)) {
      const swapped = this.#bindings.compareAndSwap(sessionId, { expected: pending.predecessorBinding, next: pending.successorBinding });
      if (!swapped.ok) fail(swapped.code, 'contract transition compare-and-swap failed');
    }
    if (this.#failpoint === 'after-cas') throw new Error('injected lifecycle crash after CAS');
    const committed = this.#append(this.#receipt({ ...pending, state: 'COMMITTED', previousReceiptDigest: digestValue(records.at(-1)) }));
    return committed;
  }
  transition({ action, sessionId, transactionId, target = null }) {
    if (!['suspend', 'supersede'].includes(action)) fail('ARC_SCHEMA_INVALID', 'unsupported lifecycle action');
    if (typeof sessionId !== 'string' || !sessionId || typeof transactionId !== 'string' || transactionId.length < 16) fail('ARC_SCHEMA_INVALID', 'sessionId and transactionId are required');
    const records = this.#records(sessionId);
    const seen = records.filter((record) => record.transactionId === transactionId);
    if (seen.length) {
      if (seen.some((record) => record.state === 'COMMITTED')) fail('ARC_REPLAY_NONCE_SEEN', 'transition id was already committed');
      if (seen[0].action !== action) fail('ARC_REPLAY_NONCE_SEEN', 'transition id cannot authorize a different action');
      return this.#recover(sessionId, records);
    }
    if (records.some((record) => record.state === 'PREPARED' && !records.some((other) => other.state === 'COMMITTED' && other.transactionId === record.transactionId))) fail('ARC_REPLAY_NONCE_SEEN', 'repair pending transition before starting another');
    const predecessorBinding = this.#bindings.getBinding(sessionId); this.#validateBinding(predecessorBinding, sessionId);
    let successorBinding;
    if (action === 'suspend') successorBinding = { ...predecessorBinding, lifecycle: { state: 'suspended', transactionId } };
    else {
      if (!target?.contractId || !Number.isInteger(target.version)) fail('ARC_SCHEMA_INVALID', 'supersede requires sealed target contract and version');
      const seal = this.#seals.get(target.contractId, target.version); if (!seal) fail('ARC_NO_CONTRACT', 'supersede target is not sealed');
      successorBinding = { ...predecessorBinding, contractId: seal.contractId, contractVersion: seal.version, contractDigest: seal.contractDigest, taskId: target.taskId ?? predecessorBinding.taskId, lifecycle: { state: 'active', transactionId } };
    }
    const prepared = this.#append(this.#receipt({ action, state: 'PREPARED', transactionId, sessionId, predecessorBinding, successorBinding, previousReceiptDigest: records.length ? digestValue(records.at(-1)) : null }));
    if (this.#failpoint === 'after-prepare') throw new Error('injected lifecycle crash after prepare');
    const swapped = this.#bindings.compareAndSwap(sessionId, { expected: predecessorBinding, next: successorBinding });
    if (!swapped.ok) fail(swapped.code, 'contract transition compare-and-swap failed');
    if (this.#failpoint === 'after-cas') throw new Error('injected lifecycle crash after CAS');
    return this.#append(this.#receipt({ ...prepared, state: 'COMMITTED', previousReceiptDigest: digestValue(prepared) }));
  }
  repair({ sessionId }) {
    if (typeof sessionId !== 'string' || !sessionId) fail('ARC_SCHEMA_INVALID', 'sessionId is required');
    const recovered = this.#recover(sessionId, this.#records(sessionId));
    if (!recovered) fail('ARC_BINDING_MISMATCH', 'no prepared transition requires repair');
    return recovered;
  }
}
