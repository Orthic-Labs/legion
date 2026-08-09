import { existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { ArcaneError, decision } from './errors.mjs';
import { canonicalJson, digestValue } from './canonical.mjs';

const key = (id) => digestValue({ domain: 'arcane.capability.key.v1', values: [id] }).slice(7);
const fail = (code, id, detail = {}) => decision({ allowed: false, code, message: `${code}: ${id}`, detail: { capabilityId: id, ...detail } });
const stamp = (clock) => new Date(clock()).toISOString();
const write = (file, value) => { const fd = openSync(file, 'wx', 0o600); try { writeSync(fd, `${canonicalJson(value)}\n`); fsyncSync(fd); } finally { closeSync(fd); } };
const read = (file, id) => { try { if (!lstatSync(file).isFile()) throw Error('non-file'); return JSON.parse(readFileSync(file, 'utf8')); } catch (error) { throw new ArcaneError('ARC_STORE_CORRUPT', 'capability record is corrupt', { capabilityId: id, error: String(error.message) }); } };

export class CapabilityStore {
  #root; #grants; #transitions; #clock; #memory = new Map();
  constructor({ root, clock = Date.now } = {}) { this.#root = root || null; this.#clock = clock; if (root) { this.#grants = join(root, 'grants'); this.#transitions = join(root, 'transitions'); mkdirSync(this.#grants, { recursive: true }); mkdirSync(this.#transitions, { recursive: true }); } }
  #paths(id) { const name = `${key(id)}.json`; return [join(this.#grants, name), join(this.#transitions, name)]; }
  #legacyIssue(input) { const record = { ...input, issuedAt: input.issuedAt || stamp(this.#clock), usedCount: 0, status: 'active', revokedReason: null }; this.#memory.set(input.capabilityId, record); return input.capabilityId; }
  issue(input) {
    if (!this.#root) return this.#legacyIssue(input);
    const issuedAt = input.issuedAt || stamp(this.#clock); const expiresAt = input.expiresAt;
    const ttl = (Date.parse(expiresAt) - Date.parse(issuedAt)) / 1000;
    if (!Number.isInteger(ttl) || ttl !== 900 || input.maxUses !== undefined && input.maxUses !== 1 || input.delegable !== undefined && input.delegable !== false) throw new ArcaneError('ARC_STORE_CORRUPT', 'invalid B1 capability ttl or use policy', { capabilityId: input.capabilityId });
    const grant = { schemaVersion: 1, kind: 'arcane-capability-grant', capabilityId: input.capabilityId, runId: input.runId, taskId: input.taskId, workspace: input.workspace, contractId: input.contractId, contractVersion: input.contractVersion, contractDigest: input.contractDigest, sourceRevision: input.sourceRevision, authority: input.authority ?? 'alchemist', turnId: input.turnId, operation: input.operation, effectClass: input.effectClass, targets: input.targets, policyId: input.policyId, policyVersion: input.policyVersion, policyDigest: input.policyDigest, issuedAt, expiresAt, ttlSeconds: 900, maxUses: 1, delegable: false, status: 'active', usedCount: 0 };
    const [file] = this.#paths(grant.capabilityId);
    try { write(file, grant); } catch (error) { if (error.code !== 'EEXIST') throw error; if (canonicalJson(read(file, grant.capabilityId)) !== canonicalJson(grant)) throw new ArcaneError('ARC_BINDING_MISMATCH', 'capability grant binding differs', { capabilityId: grant.capabilityId }); }
    return grant.capabilityId;
  }
  get(capabilityId) {
    if (!this.#root) return this.#memory.get(capabilityId) || null;
    const [grantFile, transitionFile] = this.#paths(capabilityId); if (!existsSync(grantFile)) return null;
    const grant = read(grantFile, capabilityId); if (grant.capabilityId !== capabilityId || grant.kind !== 'arcane-capability-grant' || grant.schemaVersion !== 1) throw new ArcaneError('ARC_STORE_CORRUPT', 'invalid capability grant', { capabilityId });
    let transition = null; if (existsSync(transitionFile)) { transition = read(transitionFile, capabilityId); if (transition.capabilityId !== capabilityId || transition.kind !== 'arcane-capability-transition' || transition.schemaVersion !== 1 || !['consumed', 'revoked'].includes(transition.state)) throw new ArcaneError('ARC_STORE_CORRUPT', 'invalid capability transition', { capabilityId }); }
    return { ...grant, status: transition?.state === 'revoked' ? 'revoked' : grant.status, usedCount: transition?.state === 'consumed' ? 1 : grant.usedCount, transition };
  }
  check(capabilityId, ctx = {}) {
    const record = this.get(capabilityId); if (!record) return fail('ARC_CAPABILITY_UNKNOWN', capabilityId);
    if (record.status === 'revoked') return fail('ARC_CAPABILITY_REVOKED', capabilityId);
    if (!this.#root) {
      const now = ctx.now || stamp(this.#clock); if (record.expiresAt && now >= record.expiresAt) return fail('ARC_CAPABILITY_EXPIRED', capabilityId);
      if (record.maxUses !== null && record.maxUses !== undefined && record.usedCount >= record.maxUses) return fail('ARC_CAPABILITY_EXHAUSTED', capabilityId);
      for (const field of ['runId', 'taskId', 'workspace', 'operation', 'effectClass']) if (ctx[field] !== undefined && record[field] !== undefined && ctx[field] !== record[field]) return fail('ARC_BINDING_MISMATCH', capabilityId, { field, expected: record[field], actual: ctx[field] });
      if (ctx.target !== undefined && Array.isArray(record.targets) && !record.targets.includes(ctx.target)) return fail('ARC_BINDING_MISMATCH', capabilityId, { field: 'target', expected: record.targets, actual: ctx.target });
      return decision({ allowed: true, detail: { capabilityId } });
    }
    const now = ctx.now || stamp(this.#clock); if (now >= record.expiresAt) return fail('ARC_CAPABILITY_EXPIRED', capabilityId);
    if (record.usedCount >= record.maxUses) return fail('ARC_CAPABILITY_EXHAUSTED', capabilityId);
    for (const field of ['runId', 'taskId', 'workspace', 'contractId', 'contractVersion', 'contractDigest', 'sourceRevision', 'authority', 'turnId', 'operation', 'effectClass']) if (ctx[field] !== undefined && ctx[field] !== record[field]) return fail('ARC_BINDING_MISMATCH', capabilityId, { field, expected: record[field], actual: ctx[field] });
    if (ctx.target !== undefined && !record.targets.includes(ctx.target)) return fail('ARC_BINDING_MISMATCH', capabilityId, { field: 'target', expected: record.targets, actual: ctx.target });
    return decision({ allowed: true, detail: { capabilityId } });
  }
  consume(capabilityId, ctx = {}) {
    if (!this.#root) { const d = this.check(capabilityId, ctx); if (!d.allowed) throw new ArcaneError(d.code, d.message, d.detail); const r = this.#memory.get(capabilityId); r.usedCount += 1; return { capabilityId, usedCount: r.usedCount, maxUses: r.maxUses }; }
    if (!/^req_[0-9A-HJKMNP-TV-Z]{26}$/.test(ctx.requestId || '')) throw new ArcaneError('ARC_STORE_CORRUPT', 'invalid consume request id', { capabilityId });
    const d = this.check(capabilityId, ctx); if (!d.allowed) throw new ArcaneError(d.code, d.message, d.detail);
    const [, file] = this.#paths(capabilityId); const transition = { schemaVersion: 1, kind: 'arcane-capability-transition', capabilityId, state: 'consumed', at: ctx.consumedAt || stamp(this.#clock), requestId: ctx.requestId };
    try { write(file, transition); } catch (error) { if (error.code !== 'EEXIST') throw error; const current = this.get(capabilityId); const code = current.status === 'revoked' ? 'ARC_CAPABILITY_REVOKED' : 'ARC_CAPABILITY_EXHAUSTED'; throw new ArcaneError(code, `${code}: ${capabilityId}`, { capabilityId }); }
    return { capabilityId, usedCount: 1, maxUses: 1, requestId: transition.requestId, consumedAt: transition.at };
  }
  revoke(capabilityId, reason = 'revoked') {
    if (!this.#root) { const r = this.#memory.get(capabilityId); if (!r) throw new ArcaneError('ARC_CAPABILITY_UNKNOWN', 'unknown capability', { capabilityId }); r.status = 'revoked'; r.revokedReason = reason; return r; }
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 500) throw new ArcaneError('ARC_STORE_CORRUPT', 'invalid revoke reason', { capabilityId });
    const d = this.check(capabilityId, {}); if (!d.allowed && d.code !== 'ARC_CAPABILITY_REVOKED') { if (d.code === 'ARC_CAPABILITY_EXHAUSTED') throw new ArcaneError(d.code, d.message, d.detail); if (d.code === 'ARC_CAPABILITY_UNKNOWN') throw new ArcaneError(d.code, d.message, d.detail); }
    const [, file] = this.#paths(capabilityId); const transition = { schemaVersion: 1, kind: 'arcane-capability-transition', capabilityId, state: 'revoked', at: stamp(this.#clock), reason };
    try { write(file, transition); } catch (error) { if (error.code !== 'EEXIST') throw error; const current = this.get(capabilityId); if (current.status === 'revoked') return current.transition; throw new ArcaneError('ARC_CAPABILITY_EXHAUSTED', 'capability consumed', { capabilityId }); }
    return transition;
  }
}
