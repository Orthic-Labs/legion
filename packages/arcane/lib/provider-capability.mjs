import { decision } from './errors.mjs';

const REQUIRED = ['providerId', 'machineReadable', 'gateable', 'downloadable', 'trustedRetrieval', 'trajectoryBindable', 'sensitivity', 'retention', 'deletionOwner'];
const ADAPTER_REQUIRED = ['adapterId', 'machineReadable', 'gateable', 'downloadable', 'trustedRetrieval', 'trajectoryBindable'];

function missingFields(value, fields) {
  return fields.filter((key) => value?.[key] === undefined || value?.[key] === null || value?.[key] === '');
}

function adapterState(adapter) {
  if (!adapter || typeof adapter !== 'object') return null;
  const missing = missingFields(adapter, ADAPTER_REQUIRED);
  if (missing.length || !ADAPTER_REQUIRED.slice(1).every((key) => adapter[key] === true)) return null;
  return Object.freeze({ adapterId: adapter.adapterId, machineReadable: true, gateable: true, downloadable: true, trustedRetrieval: true, trajectoryBindable: true });
}

function adapterRead(adapter, providerId) {
  if (typeof adapter?.readProviderCapability === 'function') return adapter.readProviderCapability(providerId);
  if (typeof adapter?.get === 'function') return adapter.get(providerId);
  if (typeof adapter?.read === 'function') return adapter.read(providerId);
  return undefined;
}

function adapterWrite(adapter, providerId, record) {
  if (typeof adapter?.writeProviderCapability === 'function') return adapter.writeProviderCapability(providerId, record);
  if (typeof adapter?.set === 'function') return adapter.set(providerId, record);
  if (typeof adapter?.write === 'function') return adapter.write(providerId, record);
  return undefined;
}

function hasAdapterWrite(adapter) {
  return ['writeProviderCapability', 'set', 'write'].some((name) => typeof adapter?.[name] === 'function');
}

/**
 * Durable provider capability state.  Catalog metadata is not evidence: the
 * adapter must persist an observed capability record before gateability exists.
 * The adapter is deliberately small so host-owned durable stores can provide it
 * without Arcane inventing another persistence plane.
 */
export class ProviderCapabilityRegistry {
  #adapter;
  constructor({ adapter } = {}) { this.#adapter = adapter; }

  record({ providerId, adapter, observedAt, validUntil = null, sensitivity = 'normal', retention = null, deletionOwner = null } = {}) {
    if (!providerId || !adapter || !observedAt) return decision({ allowed: false, code: 'ARC_SCHEMA_INVALID', message: 'provider capability observation is incomplete', detail: { providerId: providerId ?? null } });
    const state = adapterState(adapter);
    if (!state) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'provider adapter cannot establish machine-gate capability', detail: { providerId, admission: 'INFORMATIONAL_ONLY' } });
    if (sensitivity === 'sensitive' && (!retention || !deletionOwner)) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'sensitive provider capability lacks retention or deletion ownership', detail: { providerId, missing: [!retention && 'retention', !deletionOwner && 'deletionOwner'].filter(Boolean), admission: 'DENIED' } });
    const record = Object.freeze({ providerId, adapter: state, observedAt, validUntil, sensitivity, retention, deletionOwner });
    if (!hasAdapterWrite(this.#adapter)) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'provider capability has no durable adapter-backed state', detail: { providerId, admission: 'INFORMATIONAL_ONLY' } });
    adapterWrite(this.#adapter, providerId, record);
    return decision({ allowed: true, message: 'adapter-backed provider capability recorded', detail: { providerId, record } });
  }

  get(providerId) { return adapterRead(this.#adapter, providerId) ?? null; }

  verify(providerId, { now = new Date() } = {}) {
    const record = this.get(providerId);
    if (!record) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'provider capability is not durably recorded', detail: { providerId, admission: 'INFORMATIONAL_ONLY' } });
    const capability = { ...record, ...record.adapter, providerId };
    if (record.validUntil && Date.parse(record.validUntil) < now.valueOf()) return decision({ allowed: false, code: 'ARC_EVIDENCE_STALE', message: 'provider capability observation requires refresh', detail: { providerId, lifecycle: 'REFRESH_REQUIRED' } });
    return verifyExternalProviderCapability(capability, { providerId });
  }
}

export function verifyExternalProviderCapability(capability, { providerId = capability?.providerId } = {}) {
  const missing = missingFields(capability, REQUIRED);
  if (missing.length || capability?.providerId !== providerId) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'external provider capability is incomplete or substituted', detail: { providerId, missing } });
  if (!REQUIRED.slice(1, 6).every((key) => capability[key] === true)) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'external provider cannot produce closure-grade evidence', detail: { providerId } });
  if (capability.sensitivity === 'sensitive' && (!capability.retention || !capability.deletionOwner)) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'sensitive provider evidence lacks retention or deletion ownership', detail: { providerId, missing: [!capability.retention && 'retention', !capability.deletionOwner && 'deletionOwner'].filter(Boolean) } });
  return decision({ allowed: true, message: 'external provider capability supports closure-grade evidence', detail: { providerId } });
}
