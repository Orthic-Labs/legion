import { createHash } from 'node:crypto';

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
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
    const error = new Error(`${label} binding does not match sealed plan`);
    error.code = 'INTEGRITY';
    throw error;
  }
  return artifact;
}
