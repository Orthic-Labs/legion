import { createHash } from 'node:crypto';
import { IntegrityError } from '../errors.mjs';

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  if (typeof value === 'string') return value.replaceAll('\\', '/');
  return value;
}

export function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

export function sameBinding(left, right) {
  return digest(left ?? null) === digest(right ?? null);
}

export function assertArtifactBinding(artifact, expectedBinding, label = 'artifact') {
  if (!artifact || !sameBinding(artifact.binding, expectedBinding)) {
    throw new IntegrityError(`${label} binding does not match sealed plan`);
  }
  return artifact;
}
