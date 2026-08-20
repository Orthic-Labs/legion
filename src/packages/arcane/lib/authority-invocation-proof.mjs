import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { digestValue } from './canonical.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';
import { decision } from './errors.mjs';
import { HOST_EVENT_LEDGER_FIELDS } from './host-event-ledger.mjs';

export const AUTHORITY_PROOF_FIELDS = Object.freeze(['schemaVersion','kind','invocationId','eventDigest','eventSequence','purpose','role','sessionId','runId','taskId','contractId','contractVersion','contractDigest','sourceRevision','turnCorrelationDigest','stopOrdinal','domain','issuedAt','expiresAt','nonce']);
const PURPOSES = new Set(['completion-claim','budget-amendment']);
const ROLES = new Set(['legion','alchemist','sage','oracle']);
const ROLE_PURPOSES = Object.freeze({ oracle: new Set(['completion-claim']) });
const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const deny = (code, message) => decision({ allowed: false, code, message, detail: {} });
const macDomainFor = (role, purpose) => `arcane-authority-proof:v1:${role}:${purpose}`;
const keyIdFor = (rootKeyId, role, purpose) => `${rootKeyId}:authority-proof:${role}:${purpose}`;

export class AuthorityInvocationProofIssuer {
  constructor({ root, keyRing, keyId, ledgerStore, clock = () => new Date().toISOString() }) {
    this.root = root;
    this.keyRing = keyRing;
    this.keyId = keyId;
    this.ledgerStore = ledgerStore;
    this.clock = clock;
  }

  #path(id) { return join(this.root, 'proofs', id.slice(7) + '.json'); }
  #transition(id, state) { return join(this.root, 'transitions', id.slice(7) + '-' + state + '.json'); }
  #credentials(role, purpose) {
    const macDomain = macDomainFor(role, purpose);
    const keyId = keyIdFor(this.keyId, role, purpose);
    if (!this.keyRing.has(keyId)) {
      const rootKey = this.keyRing.get(this.keyId);
      const material = createHmac('sha256', rootKey.key).update(`arcane-key-derivation:v1\0${macDomain}`, 'utf8').digest();
      this.keyRing.add(keyId, material, { custody: `derived:${this.keyId}:${macDomain}` });
    }
    return { keyId, macDomain };
  }

  issue({ ledger, binding, purpose, role }) {
    if (!this.ledgerStore || !ledger || !binding || !PURPOSES.has(purpose) || !ROLES.has(role) || (ROLE_PURPOSES[role] && !ROLE_PURPOSES[role].has(purpose))
      || !this.ledgerStore.verify().allowed
      || digestValue(this.ledgerStore.records().at(-1)) !== digestValue(ledger)
      || !verifyRecord(ledger, ledger.authentication, { keyRing: this.keyRing, boundFields: HOST_EVENT_LEDGER_FIELDS }).allowed
      || ledger.observedAuthority !== role) throw new TypeError('invalid current invocation proof input');

    const { keyId, macDomain } = this.#credentials(role, purpose);
    const eventDigest = digestValue(ledger);
    const bindingKey = { sessionId: ledger.sessionId, runId: binding.runId, taskId: binding.taskId, contractId: binding.contractId, contractVersion: binding.contractVersion, contractDigest: binding.contractDigest };
    const invocationId = digestValue({ eventDigest, purpose, role, binding: bindingKey });
    const file = this.#path(invocationId);
    try {
      const existing = read(file);
      if (existing.authentication?.keyId !== keyId || existing.authentication?.macDomain !== macDomain) throw new TypeError('authority proof key domain mismatch');
      return { state: 'ISSUED', proof: existing };
    } catch (error) {
      if (error instanceof SyntaxError || error?.code === 'ENOENT') {
        // Create a fresh proof below.
      } else {
        throw error;
      }
    }

    mkdirSync(join(this.root, 'proofs'), { recursive: true });
    mkdirSync(join(this.root, 'transitions'), { recursive: true });
    const issuedAt = this.clock();
    const domain = 'arcane-authority-proof:' + role + ':' + purpose;
    const unsigned = {
      schemaVersion: 1, kind: 'arcane-authority-invocation-proof', invocationId, eventDigest, eventSequence: ledger.eventSequence,
      purpose, role, sessionId: ledger.sessionId, runId: binding.runId, taskId: binding.taskId, contractId: binding.contractId,
      contractVersion: binding.contractVersion, contractDigest: binding.contractDigest, sourceRevision: ledger.sourceRevision,
      turnCorrelationDigest: ledger.turnCorrelationDigest, stopOrdinal: ledger.stopOrdinal, domain, issuedAt,
      expiresAt: new Date(Date.parse(issuedAt) + 300000).toISOString(), nonce: randomBytes(16).toString('hex'),
    };
    const proof = { ...unsigned, authentication: signRecord(unsigned, { keyRing: this.keyRing, keyId, boundFields: AUTHORITY_PROOF_FIELDS, macDomain }) };
    try {
      writeFileSync(file, JSON.stringify(proof), { flag: 'wx' });
      writeFileSync(this.#transition(invocationId, 'issued'), JSON.stringify({ state: 'ISSUED', proofDigest: digestValue(proof), at: issuedAt }), { flag: 'wx' });
      return { state: 'ISSUED', proof };
    } catch (error) {
      if (error.code === 'EEXIST') return { state: 'ISSUED', proof: read(file) };
      throw error;
    }
  }

  findByDigest(proofDigest) {
    try { return readdirSync(join(this.root, 'proofs')).map((name) => read(join(this.root, 'proofs', name))).find((proof) => digestValue(proof) === proofDigest) || null; }
    catch { return null; }
  }

  verify(proof, { expected = {} } = {}) {
    if (!proof || proof.role !== 'oracle' || proof.purpose !== 'completion-claim') return deny('ARC_AUTH_FORGED', 'Oracle completion authority proof is invalid');
    const macDomain = macDomainFor(proof.role, proof.purpose);
    const suffix = `:authority-proof:${proof.role}:${proof.purpose}`;
    const rootKeyId = typeof proof.authentication?.keyId === 'string' && proof.authentication.keyId.endsWith(suffix)
      ? proof.authentication.keyId.slice(0, -suffix.length) : null;
    if (!rootKeyId) return deny('ARC_AUTH_FORGED', 'authority proof key identifier is invalid');
    try { this.#credentials(proof.role, proof.purpose); } catch { /* issuer root may differ after reload; derive below */ }
    try {
      if (!this.keyRing.has(proof.authentication.keyId)) {
        const rootKey = this.keyRing.get(rootKeyId);
        const material = createHmac('sha256', rootKey.key).update(`arcane-key-derivation:v1\0${macDomain}`, 'utf8').digest();
        this.keyRing.add(proof.authentication.keyId, material, { custody: `derived:${rootKeyId}:${macDomain}` });
      }
    } catch { return deny('ARC_AUTH_KEY_UNAVAILABLE', 'authority proof root key is unavailable'); }
    if (!verifyRecord(proof, proof.authentication, { keyRing: this.keyRing, boundFields: AUTHORITY_PROOF_FIELDS, macDomain }).allowed) return deny('ARC_AUTH_FORGED', 'authority proof authentication is invalid');
    if (proof.authentication.keyId !== keyIdFor(rootKeyId, proof.role, proof.purpose) || Date.parse(proof.expiresAt) < Date.parse(this.clock())) return deny('ARC_AUTH_FORGED', 'authority proof is expired or misbound');
    if (!Object.entries(expected).every(([key, value]) => proof[key] === value)) return deny('ARC_BINDING_MISMATCH', 'authority proof does not bind this completion execution');
    let issued;
    try { issued = read(this.#path(proof.invocationId)); } catch { return deny('ARC_STORE_CORRUPT', 'authority proof missing'); }
    if (digestValue(issued) !== digestValue(proof) || !this.ledgerStore?.verify?.().allowed) return deny('ARC_AUTH_FORGED', 'authority proof persistence or host ledger is invalid');
    const event = this.ledgerStore.records().find((record) => digestValue(record) === proof.eventDigest);
    if (!event || event.observedAuthority !== 'oracle' || event.sessionId !== proof.sessionId || event.runId !== proof.runId || event.taskId !== proof.taskId || event.contractId !== proof.contractId || event.contractVersion !== proof.contractVersion || event.contractDigest !== proof.contractDigest || event.sourceRevision !== proof.sourceRevision) return deny('ARC_BINDING_MISMATCH', 'authority proof host binding is unavailable');
    return decision({ allowed: true, detail: { proof } });
  }

  consume(proof, { artifactDigest } = {}) {
    const macDomain = PURPOSES.has(proof?.purpose) && ROLES.has(proof?.role) ? macDomainFor(proof.role, proof.purpose) : null;
    const verified = verifyRecord(proof, proof?.authentication, { keyRing: this.keyRing, boundFields: AUTHORITY_PROOF_FIELDS, macDomain });
    if (!verified.allowed) return verified;
    if (proof.authentication.keyId !== keyIdFor(this.keyId, proof.role, proof.purpose)) return deny('ARC_AUTH_FORGED', 'authority proof key identifier does not match role and purpose');
    if (Date.parse(proof.expiresAt) < Date.parse(this.clock())) return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'authority proof expired');
    let issued;
    try { issued = read(this.#path(proof.invocationId)); } catch { return deny('ARC_STORE_CORRUPT', 'authority proof missing'); }
    if (digestValue(issued) !== digestValue(proof)) return deny('ARC_AUTH_FORGED', 'authority proof does not match issued record');
    const file = this.#transition(proof.invocationId, 'consumed');
    const transition = { state: 'CONSUMED', proofDigest: digestValue(proof), artifactDigest: artifactDigest ?? null, at: this.clock() };
    try {
      writeFileSync(file, JSON.stringify(transition), { flag: 'wx' });
      return decision({ allowed: true, detail: { transition } });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const prior = read(file);
      return prior.artifactDigest === transition.artifactDigest
        ? decision({ allowed: true, detail: { transition: prior, idempotent: true } })
        : deny('ARC_REPLAY_NONCE_SEEN', 'authority proof already consumed');
    }
  }
}
