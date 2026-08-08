import { createHash } from 'node:crypto';

const IDENTITY_KEYS = ['route', 'state', 'viewport', 'platform', 'browserPolicy', 'baselineId'];
export function baselineIdentity(value = {}) {
  const identity = Object.fromEntries(IDENTITY_KEYS.map((key) => [key, value[key] ?? null]));
  return `sha256:${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

export function baselineCompatibility(baseline = {}, actual = {}) {
  const mismatches = IDENTITY_KEYS.filter((key) => baseline[key] !== actual[key]);
  return { compatible: mismatches.length === 0, mismatches };
}
