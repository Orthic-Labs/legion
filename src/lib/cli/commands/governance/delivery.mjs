import { assessControlRetirement } from './delivery/control-lifecycle.mjs';
import { recoverControlState } from './delivery/control-recovery.mjs';
import { assessMigrationCutover } from './delivery/migration-cutover.mjs';
import { admitCapacity, admitTaskPhase, assessRealization, classifyHandoff } from './delivery/dispatch-scheduler.mjs';
import { EXIT } from '../../../errors.mjs';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function frozen(value) { return Object.freeze(value); }
function denied(code, detail = {}) { return frozen({ allowed: false, code, ...detail }); }
const PROVIDER_CAPABILITIES = new WeakMap();
const PACKET_CAPABILITIES = new WeakMap();
const PACKET_STORES = new WeakMap();
const PROVIDER_NAMES = new Set(['controlRetirementEvidence', 'migrationCutoverEvidence', 'phaseProofEvidence', 'controlRecoveryAuthority']);
function diagnostic(operation, result) {
  return frozen({ allowed: false, consumable: false, code: 'ARC_DIAGNOSTIC_ONLY', operation, diagnostic: result });
}
function consumable(result) {
  const admitted = result?.allowed === true || result?.ready === true || result?.outcome === 'ACTIVATION_ADMITTED';
  return frozen({ ...result, consumable: admitted });
}

function providerResult(capability, name, input) {
  const provider = PROVIDER_CAPABILITIES.get(capability)?.[name];
  if (typeof provider !== 'function') return null;
  const result = provider(frozen(input));
  return record(result) ? result : null;
}

function packetState(value) {
  if (!record(value) || !Number.isSafeInteger(value.revision) || value.revision < 0 || !Array.isArray(value.packetDigests)) return null;
  const packetDigests = value.packetDigests;
  if (packetDigests.some((digest) => typeof digest !== 'string' || !digest) || new Set(packetDigests).size !== packetDigests.length) return null;
  return frozen({ revision: value.revision, packetDigests: frozen([...packetDigests]) });
}

/** Create an opaque, host-only provider capability. Plain provider objects fail closed. */
export function createTrustedDeliveryEvidenceCapability(providers = {}) {
  if (!record(providers) || Object.keys(providers).some((name) => !PROVIDER_NAMES.has(name) || typeof providers[name] !== 'function')) throw new TypeError('trusted delivery providers must be known functions');
  const capability = frozen({});
  PROVIDER_CAPABILITIES.set(capability, frozen({ ...providers }));
  return capability;
}

function readStore(entry) {
  if (!existsSync(entry.statePath)) return frozen({ revision: 0, packetDigests: frozen([]) });
  let parsed;
  try { parsed = JSON.parse(readFileSync(entry.statePath, 'utf8')); } catch { parsed = null; }
  const state = packetState(parsed);
  if (!state) throw Object.assign(new Error('durable packet state is invalid'), { code: 'ARC_PACKET_STORE_CORRUPT' });
  return state;
}

function acquire(entry) {
  try { return openSync(entry.lockPath, 'wx', 0o600); }
  catch { throw Object.assign(new Error('durable packet store is locked'), { code: 'ARC_PACKET_STORE_LOCKED' }); }
}

function persistStore(entry, state) {
  const temporary = `${entry.statePath}.${process.pid}.${randomUUID()}.tmp`;
  let temporaryFd;
  let directoryFd;
  try {
    temporaryFd = openSync(temporary, 'wx', 0o600);
    writeFileSync(temporaryFd, JSON.stringify({ schemaVersion: 1, ...state }), 'utf8');
    fsyncSync(temporaryFd);
    closeSync(temporaryFd);
    temporaryFd = undefined;
    renameSync(temporary, entry.statePath);
    directoryFd = openSync(dirname(entry.statePath), 'r');
    fsyncSync(directoryFd);
  } finally {
    if (temporaryFd !== undefined) closeSync(temporaryFd);
    if (directoryFd !== undefined) closeSync(directoryFd);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

/** Concrete host-owned store. Root selects persistence location, never callbacks. */
export class DurablePacketAdmissionStore {
  constructor({ root } = {}) {
    if (typeof root !== 'string' || !root) throw new TypeError('durable packet store requires root');
    const resolved = resolve(root);
    mkdirSync(resolved, { recursive: true, mode: 0o700 });
    const entry = frozen({ root: resolved, statePath: resolve(resolved, 'packet-admissions.json'), lockPath: resolve(resolved, 'packet-admissions.lock') });
    PACKET_STORES.set(this, entry);
    Object.freeze(this);
  }
}

/** Capability identity binds a dispatcher to a genuine on-disk store instance. */
export function createDurablePacketAdmissionCapability(store) {
  const entry = PACKET_STORES.get(store);
  if (!entry) throw new TypeError('packet store must be a genuine DurablePacketAdmissionStore');
  // Reject malformed persisted state at startup, before any admission claim.
  readStore(entry);
  const capability = frozen({});
  PACKET_CAPABILITIES.set(capability, { entry });
  return capability;
}

function admitDurablePacket(capability, input) {
  const entry = PACKET_CAPABILITIES.get(capability);
  if (!entry) return null;
  const packetDigest = input.packetDigest;
  if (typeof packetDigest !== 'string' || !packetDigest) return denied('ARC_PACKET_DIGEST_REQUIRED', { packetDigest: packetDigest ?? null });
  let lock;
  try {
    lock = acquire(entry.entry);
    const state = readStore(entry.entry);
    if (state.packetDigests.includes(packetDigest)) return denied('ARC_PACKET_DIGEST_REPLAY', { packetDigest });
    const next = frozen({ revision: state.revision + 1, packetDigests: frozen([...state.packetDigests, packetDigest]) });
    persistStore(entry.entry, next);
    return frozen({ outcome: 'PACKET_ADMITTED', packetDigest, revision: next.revision, consumable: true });
  } catch (error) {
    return denied(error?.code ?? 'ARC_PACKET_ADMISSION_PERSIST_FAILED', { consumable: false, packetDigest });
  } finally {
    if (lock !== undefined) { closeSync(lock); try { unlinkSync(entry.entry.lockPath); } catch {} }
  }
}

function operationResult(operation, input, { providerCapability, packetCapability }) {
  if (!record(input)) return denied('ARC_SCHEMA_INVALID', { operation, message: 'operation input must be an object' });
  switch (operation) {
    case 'control-retirement': {
      const trusted = providerResult(providerCapability, 'controlRetirementEvidence', input);
      return trusted ? consumable(assessControlRetirement(trusted)) : diagnostic(operation, assessControlRetirement(input));
    }
    case 'migration-cutover': {
      const trusted = providerResult(providerCapability, 'migrationCutoverEvidence', input);
      return trusted ? consumable(assessMigrationCutover(trusted)) : diagnostic(operation, assessMigrationCutover(input));
    }
    case 'dispatch-capacity':
      return admitCapacity(input);
    case 'dispatch-phase': {
      const trusted = providerResult(providerCapability, 'phaseProofEvidence', input);
      return trusted ? consumable(admitTaskPhase(trusted)) : diagnostic(operation, admitTaskPhase(input));
    }
    case 'dispatch-handoff':
      return classifyHandoff(input);
    case 'dispatch-realization':
      return assessRealization(input);
    case 'dispatch-packet': {
      const admitted = admitDurablePacket(packetCapability, input);
      if (admitted === null) {
        return diagnostic(operation, denied('ARC_DURABLE_PACKET_REGISTRY_REQUIRED', { packetDigest: input.packetDigest ?? null }));
      }
      return admitted;
    }
    case 'control-recovery': {
      const trusted = providerResult(providerCapability, 'controlRecoveryAuthority', input);
      if (trusted) return consumable(recoverControlState(trusted));
      // Call only with deny-safe callbacks. JSON cannot authorize, repair, or
      // verify a recovery, yet this produces actionable diagnostic state.
      if (typeof input.controlId !== 'string' || !input.controlId || !record(input.authorization)) return diagnostic(operation, denied('ARC_SCHEMA_INVALID', { controlId: input.controlId ?? null }));
      const safe = recoverControlState({ ...input, authenticate: () => false, repair: () => { throw new Error('unreachable'); }, verify: () => false });
      return diagnostic(operation, safe);
    }
    default:
      return denied('ARC_OPERATION_UNKNOWN', { operation });
  }
}

/**
 * Host-owned trusted providers are mandatory for consumable control decisions.
 * Packet capability must originate from a durable, atomically locked store.
 */
export function createDeliveryGovernanceDispatcher({ providerCapability = null, packetCapability = null } = {}) {
  if (providerCapability !== null && !PROVIDER_CAPABILITIES.has(providerCapability)) throw new TypeError('providerCapability must be created by createTrustedDeliveryEvidenceCapability');
  if (packetCapability !== null && !PACKET_CAPABILITIES.has(packetCapability)) throw new TypeError('packetCapability must be created by createDurablePacketAdmissionCapability');
  return Object.freeze({
    dispatch(request) {
      if (!record(request) || typeof request.operation !== 'string' || !request.operation) return denied('ARC_SCHEMA_INVALID', { message: 'operation is required' });
      try { return operationResult(request.operation, request.input, { providerCapability, packetCapability }); }
      catch (error) { return denied(error?.code ?? 'ARC_OPERATION_FAILED', { operation: request.operation }); }
    },
  });
}

export function dispatchDeliveryGovernance(request, dispatcher = createDeliveryGovernanceDispatcher()) {
  return dispatcher.dispatch(request);
}

// Thin handler for callers that already decoded one structured JSON request.
export function runDeliveryGovernance(request, { stdout, dispatcher = createDeliveryGovernanceDispatcher() } = {}) {
  const result = dispatcher.dispatch(request);
  stdout?.write(`${JSON.stringify(result)}\n`);
  const pass = result.consumable === true;
  return frozen({ exitCode: pass ? EXIT.PASS : EXIT.INCOMPLETE, result });
}
