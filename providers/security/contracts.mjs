// Shared security evidence, verdict, path, chain, and fact contracts.
// The canonical source for security enums used by runtime code and generated
// JSON schemas. Per the authority order, the current code controls existing
// compatibility surfaces: the verdict enum retains `HARDENING_GAP` (the value
// the current schema and adjudicator emit) rather than the appendix's
// `HARDENING`, which PR28 may migrate.

import { createHash } from 'node:crypto';

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
    'planDigest', 'repositoryRevision', 'cortexGenerationId',
    'cortexManifestDigest', 'registryDigest',
  ]) requireString(binding[key], `binding.${key}`);
  if (binding.dirtyPatchDigest !== null) {
    requireString(binding.dirtyPatchDigest, 'binding.dirtyPatchDigest');
  }
  return binding;
}
