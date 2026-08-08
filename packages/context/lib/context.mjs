import { createHash } from 'node:crypto';

const TRUST_CLASSES = new Set(['repository-fact', 'derived', 'external']);
const CAPABILITY_STATES = new Set(['available', 'degraded', 'absent']);
const CONSUMERS = new Set(['sage', 'seer', 'arcane']);
const AUTHORITIES = new Set(['legion', 'sage', 'alchemist', 'seer', 'arcane', 'covenant', 'kernel']);
const RECEIPT_CONSUMERS = new Set(['sage-acceptance', 'arcane-proof', 'seer-control']);
const DEPENDENCY_KINDS = new Set(['decision', 'source-revision', 'config-digest', 'tool-digest', 'policy-digest', 'evidence']);
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const OPAQUE_ID_PATTERN = /^(?:ev|run)_[0-9A-HJKMNP-TV-Z]{26}$/;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  if (typeof value === 'string') return value;
  return value;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${label} is required`);
}

function validateSource(source, index) {
  if (!isObject(source)) throw new TypeError(`sources[${index}] must be an object`);
  requireString(source.id, `sources[${index}].id`);
  requireString(source.origin, `sources[${index}].origin`);
  if (!DIGEST_PATTERN.test(source.digest ?? '')) throw new TypeError(`sources[${index}].digest is invalid`);
  if (source.generation !== null) requireString(source.generation, `sources[${index}].generation`);
  if (source.revision !== null) requireString(source.revision, `sources[${index}].revision`);
  requireString(source.observedAt, `sources[${index}].observedAt`);
  if (Number.isNaN(Date.parse(source.observedAt))) throw new TypeError(`sources[${index}].observedAt is invalid`);
  if (!TRUST_CLASSES.has(source.trustClass)) throw new TypeError(`sources[${index}].trustClass is invalid`);
}

export function validateContextPacket(packet) {
  if (!isObject(packet)) throw new TypeError('packet must be an object');
  if (packet.schemaVersion !== 'legion.context-packet.v1') throw new TypeError('schemaVersion is invalid');
  requireString(packet.runId, 'runId');
  if (!CONSUMERS.has(packet.consumer)) throw new TypeError('consumer is invalid');
  requireString(packet.purpose, 'purpose');
  if (!isObject(packet.repositoryBinding)) throw new TypeError('repositoryBinding is required');
  requireString(packet.repositoryBinding.repository, 'repositoryBinding.repository');
  requireString(packet.repositoryBinding.revision, 'repositoryBinding.revision');
  if (!Array.isArray(packet.sources) || packet.sources.length === 0) throw new TypeError('sources must be non-empty');
  packet.sources.forEach(validateSource);
  if (typeof packet.stale !== 'boolean') throw new TypeError('stale must be boolean');
  if (!DIGEST_PATTERN.test(packet.packetDigest ?? '')) throw new TypeError('packetDigest is invalid');
  const { packetDigest, ...unsigned } = packet;
  if (digest(unsigned) !== packetDigest) throw new TypeError('packetDigest mismatch');
  return true;
}

export function assembleContextPacket({ runId, consumer, purpose, repositoryBinding, sources }) {
  const unsigned = {
    schemaVersion: 'legion.context-packet.v1',
    runId,
    consumer,
    purpose,
    repositoryBinding,
    sources,
    stale: false,
  };
  const packet = { ...unsigned, packetDigest: digest(unsigned) };
  validateContextPacket(packet);
  return packet;
}

function sameBinding(left, right) {
  return digest(left ?? null) === digest(right ?? null);
}

export function bindCortexProjection(projection, expectedBinding) {
  if (projection === null || projection === undefined) {
    return {
      capability: 'cortex', status: 'absent', reason: 'projection-absent', stale: false,
      generation: null, projection: null,
    };
  }
  if (projection.schemaVersion !== 1) {
    return {
      capability: 'cortex', status: 'degraded', reason: 'unsupported-projection-schema', stale: false,
      generation: null, projection: null,
    };
  }
  if (!sameBinding(projection.binding, expectedBinding)) {
    return {
      capability: 'cortex', status: 'degraded', reason: 'repository-binding-mismatch', stale: true,
      generation: projection.generation || (projection.manifestDigest ?? null), projection: null,
    };
  }
  const generation = projection.generation || (projection.manifestDigest ?? null);
  if (!generation) {
    return {
      capability: 'cortex', status: 'degraded', reason: 'generation-identity-missing', stale: false,
      generation: null, projection: null,
    };
  }
  return { capability: 'cortex', status: 'available', reason: null, stale: false, generation, projection };
}

export function assessPacketFreshness(packet, currentState) {
  validateContextPacket(packet);
  if (!isObject(currentState)) throw new TypeError('currentState is required');
  requireString(currentState.revision, 'currentState.revision');
  const generations = currentState.generations ?? {};
  const mismatches = [];
  for (const source of packet.sources) {
    if (source.revision !== null && source.revision !== currentState.revision) {
      mismatches.push({ sourceId: source.id, field: 'revision', expected: source.revision, actual: currentState.revision });
    }
    const currentGeneration = generations[source.origin];
    if (source.generation !== null && currentGeneration !== undefined && source.generation !== currentGeneration) {
      mismatches.push({ sourceId: source.id, field: 'generation', expected: source.generation, actual: currentGeneration });
    }
  }
  const stale = mismatches.length > 0;
  const unsigned = { ...packet, stale };
  delete unsigned.packetDigest;
  return { stale, mismatches, packet: { ...unsigned, packetDigest: digest(unsigned) } };
}

const RECEIPT_CONSUMER = {
  sage: 'sage-acceptance',
  arcane: 'arcane-proof',
  seer: 'seer-control',
};

export function validateContextReceipt(receipt) {
  if (!isObject(receipt)) throw new TypeError('receipt must be an object');
  const required = [
    'schemaVersion', 'kind', 'evidenceId', 'runId', 'taskId', 'contractId', 'producerAuthority',
    'capability', 'observation', 'evidenceClass', 'authentication', 'replayDefense', 'sourceRevision',
    'dependsOn', 'stale', 'consumers', 'observedAt',
  ];
  const extras = Object.keys(receipt).filter((key) => !required.includes(key));
  if (extras.length > 0) throw new TypeError(`receipt has unsupported properties: ${extras.join(', ')}`);
  for (const key of required) if (!(key in receipt)) throw new TypeError(`receipt.${key} is required`);
  if (receipt.schemaVersion !== 1 || receipt.kind !== 'legion-evidence-capability-receipt') {
    throw new TypeError('receipt schema identity is invalid');
  }
  if (!OPAQUE_ID_PATTERN.test(receipt.evidenceId) || !receipt.evidenceId.startsWith('ev_')) {
    throw new TypeError('receipt.evidenceId is invalid');
  }
  if (!OPAQUE_ID_PATTERN.test(receipt.runId) || !receipt.runId.startsWith('run_')) {
    throw new TypeError('receipt.runId is invalid');
  }
  if (!AUTHORITIES.has(receipt.producerAuthority)) throw new TypeError('receipt.producerAuthority is invalid');
  if (receipt.capability !== 'context-assembly') throw new TypeError('receipt.capability is invalid');
  if (!isObject(receipt.observation)) throw new TypeError('receipt.observation is invalid');
  if (receipt.evidenceClass !== 'deterministic') throw new TypeError('receipt.evidenceClass is invalid');
  if (!isObject(receipt.authentication) || receipt.authentication.verificationMethod !== 'unauthenticated'
      || receipt.authentication.perMessage !== false) throw new TypeError('receipt.authentication is invalid');
  if (!isObject(receipt.replayDefense)) throw new TypeError('receipt.replayDefense is invalid');
  requireString(receipt.sourceRevision, 'receipt.sourceRevision');
  if (!Array.isArray(receipt.dependsOn) || receipt.dependsOn.some((item) => !isObject(item)
      || !DEPENDENCY_KINDS.has(item.kind) || typeof item.ref !== 'string' || item.ref.length === 0)) {
    throw new TypeError('receipt.dependsOn is invalid');
  }
  if (typeof receipt.stale !== 'boolean') throw new TypeError('receipt.stale is invalid');
  if (!Array.isArray(receipt.consumers) || receipt.consumers.some((value) => !RECEIPT_CONSUMERS.has(value))) {
    throw new TypeError('receipt.consumers is invalid');
  }
  if (Number.isNaN(Date.parse(receipt.observedAt))) throw new TypeError('receipt.observedAt is invalid');
  return true;
}

export function createContextReceipt({ packet, evidenceId, producerAuthority, currentState, observedAt }) {
  const freshness = assessPacketFreshness(packet, currentState);
  requireString(evidenceId, 'evidenceId');
  requireString(producerAuthority, 'producerAuthority');
  requireString(observedAt, 'observedAt');
  const receipt = {
    schemaVersion: 1,
    kind: 'legion-evidence-capability-receipt',
    evidenceId,
    runId: packet.runId,
    taskId: null,
    contractId: null,
    producerAuthority,
    capability: 'context-assembly',
    observation: {
      packetDigest: packet.packetDigest,
      consumer: packet.consumer,
      purpose: packet.purpose,
      selectedSources: packet.sources.map(({ id, origin, digest: sourceDigest, generation, revision, trustClass }) => ({
        id, origin, digest: sourceDigest, generation, revision, trustClass,
      })),
      transformations: [],
      omissions: [],
      truncation: null,
      freshnessMismatches: freshness.mismatches,
    },
    evidenceClass: 'deterministic',
    authentication: {
      issuerIdentity: producerAuthority,
      verificationMethod: 'unauthenticated',
      perMessage: false,
      verifiedAt: null,
    },
    replayDefense: { nonce: null, sequence: null, freshnessWindowSeconds: null, freshAt: null },
    sourceRevision: packet.repositoryBinding.revision,
    dependsOn: packet.sources.flatMap((source) => [
      ...(source.revision === null ? [] : [{ kind: 'source-revision', ref: `${source.id}:${source.revision}` }]),
      ...(source.generation === null ? [] : [{ kind: 'config-digest', ref: `${source.origin}:${source.generation}` }]),
    ]),
    stale: freshness.stale,
    consumers: RECEIPT_CONSUMER[packet.consumer] ? [RECEIPT_CONSUMER[packet.consumer]] : [],
    observedAt,
  };
  validateContextReceipt(receipt);
  return { receipt, receiptDigest: digest(receipt), packet: freshness.packet };
}

function capability(name, wireName, input) {
  if (!isObject(input)) throw new TypeError(`${name} capability status is required`);
  if (!CAPABILITY_STATES.has(input.status)) throw new TypeError(`${name} capability status is invalid`);
  const reason = input.reason ?? null;
  if (input.status !== 'available') requireString(reason, `${name} capability reason`);
  return { capability: wireName, status: input.status, reason };
}

export function createCapabilityReport(input) {
  if (!isObject(input)) throw new TypeError('capability input is required');
  return {
    cortex: capability('cortex', 'cortex', input.cortex),
    memory: capability('memory', 'memory', input.memory),
    externalEvidence: capability('external evidence', 'external-evidence', input.externalEvidence),
  };
}

export function createUnavailableContextAdapter(capabilityName, reason) {
  requireString(capabilityName, 'capabilityName');
  requireString(reason, 'reason');
  return Object.freeze({
    capability: Object.freeze({ capability: capabilityName, status: 'absent', reason }),
    async read() {
      return { status: 'absent', reason, items: [] };
    },
  });
}