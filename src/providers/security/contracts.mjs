// Shared security evidence, verdict, path, chain, and fact contracts.
// The canonical source for security enums used by runtime code and generated
// JSON schemas. Per the authority order, the current code controls existing
// compatibility surfaces: the verdict enum retains `HARDENING_GAP` (the value
// the current schema and adjudicator emit) rather than the appendix's
// `HARDENING`, which PR28 may migrate.

import { createHash } from 'node:crypto';
import {
  EVIDENCE_CLASS,
  JUDGMENT_VERDICT,
  PROVIDER_ROLE,
  PROVIDER_STATUS,
} from '../../lib/contracts/enums.mjs';

// Core provider/evidence/judgment vocabularies are owned by lib/contracts and
// re-exported here so security code has one import site and no local copy can
// drift from the core.
export { EVIDENCE_CLASS, JUDGMENT_VERDICT, PROVIDER_ROLE, PROVIDER_STATUS };

export const EVIDENCE_STRENGTH = Object.freeze([
  'possible',
  'strong-inference',
  'verified',
]);

export const EVIDENCE_RANK = Object.freeze({
  possible: 0,
  'strong-inference': 1,
  verified: 2,
});

export const SECURITY_VERDICTS = Object.freeze([
  'TRUE_POSITIVE',
  'LIKELY_TRUE_POSITIVE',
  'LIKELY_FALSE_POSITIVE',
  'FALSE_POSITIVE',
  'OUT_OF_SCOPE',
  'HARDENING_GAP',
  'MISUSE_HAZARD',
]);

export const PATH_STATUS = Object.freeze([
  'PROPOSED',
  'PARTIALLY_SUPPORTED',
  'PROVEN',
  'REFUTED',
  'BLOCKED',
  'UNPROVEN',
]);

export const PATH_PRIORITY = Object.freeze([
  'DIRECT_CROWN_JEWEL',
  'PRIVILEGE_ESCALATION',
  'CROSS_TENANT',
  'CREDENTIAL_PIVOT',
  'LATERAL_PIVOT',
  'CONTROL_BYPASS',
  'PERSISTENT_COMPROMISE',
  'DATA_EXFILTRATION',
  'INTEGRITY_DESTRUCTION',
  'AVAILABILITY_FAILURE',
  'PARTIAL_PATH',
]);

export const CHAIN_ROLES = Object.freeze([
  'starter',
  'enabler',
  'pivot',
  'privilege-escalation',
  'control-bypass',
  'impact',
]);

export const FACT_KINDS = Object.freeze([
  'attacker-position',
  'knowledge',
  'capability',
  'credential-possession',
  'principal-access',
  'network-reachability',
  'data-access',
  'object-access',
  'code-execution',
  'workflow-state',
  'control-bypass',
  'persistence',
  'availability-impact',
  'integrity-impact',
  'confidentiality-impact',
]);

// The primitive verdict vocabulary is the security verdict vocabulary; the
// alias exists so adjudication code can name what it is judging.
export const PRIMITIVE_VERDICTS = SECURITY_VERDICTS;

export const ENTITY_KINDS = Object.freeze([
  'actor',
  'principal',
  'identity',
  'entrypoint',
  'asset',
  'crown-jewel',
  'trust-boundary',
  'control',
  'source',
  'sink',
  'service',
  'process',
  'repository-artifact',
  'data-store',
  'tool-capability',
  'permission-scope',
  'deployment-context',
  'workflow-state',
]);

export const RELATION_KINDS = Object.freeze([
  'assumes-role',
  'authenticates-as',
  'authorizes',
  'calls',
  'contains',
  'crosses',
  'delegates-to',
  'derives-from',
  'executes',
  'exposes',
  'flows-to',
  'grants',
  'loads',
  'protects',
  'publishes-to',
  'reaches',
  'reads',
  'retrieves-from',
  'runs-as',
  'stores',
  'trusts',
  'validates',
  'writes',
]);

export const CONTROL_STATES = Object.freeze([
  'enforced',
  'present-unenforced',
  'misconfigured',
  'absent',
  'unknown',
  'not-applicable',
]);

// Supported schema versions per security artifact kind. Anything else — a
// future version included — is rejected rather than best-effort parsed.
export const SECURITY_SCHEMA_VERSIONS = Object.freeze({
  'security-binding': Object.freeze([1]),
  'security-model': Object.freeze([1]),
  'security-candidate': Object.freeze([2]),
  'security-verdict': Object.freeze([1]),
  'attack-path-hypothesis': Object.freeze([1]),
  'security-chain-verdict': Object.freeze([1]),
  'security-variant-receipt': Object.freeze([2]),
  'security-evidence-synthesis': Object.freeze([1]),
  'hazard-model': Object.freeze([1]),
  'ai-quality-evaluation-receipt': Object.freeze([1]),
  'remediation-sandbox-receipt': Object.freeze([1]),
  'remediation-effect-graph': Object.freeze([1]),
  'remediation-verification': Object.freeze([1]),
  'remediation-apply-receipt': Object.freeze([1]),
  'remediation-accepted-risk': Object.freeze([1]),
  'untrusted-evidence': Object.freeze([1]),
});

export function assertEnum(label, values, value) {
  if (!values.includes(value)) throw new TypeError(`unknown ${label}: ${String(value)}`);
  return value;
}

export function assertEntityKind(value) {
  return assertEnum('security entity kind', ENTITY_KINDS, value);
}

export function assertRelationKind(value) {
  return assertEnum('security relation kind', RELATION_KINDS, value);
}

export function assertControlState(value) {
  return assertEnum('security control state', CONTROL_STATES, value);
}

export function assertFactKind(value) {
  return assertEnum('security fact kind', FACT_KINDS, value);
}

export function assertSecuritySchemaVersion(kind, version) {
  const supported = SECURITY_SCHEMA_VERSIONS[kind];
  if (!supported) throw new TypeError(`unknown security artifact kind: ${String(kind)}`);
  if (!supported.includes(version)) {
    throw new TypeError(`${kind} unsupported schema version: ${String(version)}`);
  }
  return version;
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function stableId(namespace, value) {
  const body = JSON.stringify(canonicalize(value));
  return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
}

export function digest(value) {
  return stableId('digest', value);
}

export function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

export function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

export function requireArray(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return value;
}

export function assertBinding(binding) {
  requireObject(binding, 'binding');
  for (const key of [
    'planDigest', 'repositoryRevision', 'blueprintGenerationId',
    'blueprintManifestDigest', 'registryDigest',
  ]) requireString(binding[key], `binding.${key}`);
  if (binding.dirtyPatchDigest !== null) {
    requireString(binding.dirtyPatchDigest, 'binding.dirtyPatchDigest');
  }
  return binding;
}

export function bindingFromPlan(plan) {
  if (!plan?.seal?.digest) throw new Error('plan has no seal digest');
  return assertBinding({
    planDigest: plan.seal.digest,
    repositoryRevision: plan.binding.repositoryRevision,
    dirtyPatchDigest: plan.binding.dirtyPatchDigest,
    blueprintGenerationId: plan.binding.blueprint.generationId,
    blueprintManifestDigest: plan.binding.blueprint.manifestDigest,
    registryDigest: plan.binding.registryDigest,
  });
}

export function sameBinding(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

export function assertArtifactBinding(artifact, expectedBinding, label) {
  assertBinding(artifact?.binding);
  if (!sameBinding(artifact.binding, expectedBinding)) {
    throw new Error(`${label} binding does not match the frozen audit plan`);
  }
}

// Every security artifact — model, candidate, verdict, hypothesis, receipt —
// carries the canonical binding and the denominator digest it was measured
// against. An artifact missing either cannot support a clean claim.
export function assertSecurityArtifact(artifact, kind) {
  requireObject(artifact, `${kind} artifact`);
  assertSecuritySchemaVersion(kind, artifact.schemaVersion);
  assertBinding(artifact.binding);
  requireString(artifact.denominatorDigest, `${kind}.denominatorDigest`);
  return artifact;
}

// The canonical artifact-store record (SNIP-04) with the security invariant
// that the denominator digest is mandatory, not optional.
export function securityArtifactRecord({
  path,
  digest: contentDigest,
  bytes,
  producer,
  producerVersion,
  mediaType = 'application/json',
  binding,
  denominatorDigest,
}) {
  requireString(path, 'artifact.path');
  requireString(contentDigest, 'artifact.digest');
  if (!Number.isInteger(bytes) || bytes < 0) throw new TypeError('artifact.bytes must be a non-negative integer');
  requireString(producer, 'artifact.producer');
  requireString(producerVersion, 'artifact.producerVersion');
  requireString(denominatorDigest, 'artifact.denominatorDigest');
  return {
    schemaVersion: 1,
    kind: 'legion-artifact-record',
    path,
    digest: contentDigest,
    bytes,
    producer,
    producerVersion,
    mediaType,
    binding: assertBinding(binding),
    denominatorDigest,
  };
}
