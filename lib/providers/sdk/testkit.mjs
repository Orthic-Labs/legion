// Public provider test kit: stable ID helper, path-denominator helper, result
// normalizer, and schema validator. Third-party providers build against this
// surface without touching the core planner/executor.

import { createHash } from 'node:crypto';
import { validateProviderResult, normalizeProviderResult } from '../../../scripts/normalize-provider-result.mjs';
import { canonicalJson } from '../../../registry/provider-registry.mjs';

export function stableId(namespace, value) {
  const body = JSON.stringify(canonicalJson(value));
  return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
}

export function pathDenominator(paths, { exclude = [] } = {}) {
  const normalized = [...new Set(paths)]
    .filter((path) => !exclude.some((pattern) => path.includes(pattern)))
    .sort();
  return {
    pathCount: normalized.length,
    paths: normalized,
    pathDigest: stableId('path-denominator', normalized),
  };
}

export { validateProviderResult, normalizeProviderResult };

export function validateProviderRecord(record) {
  return Boolean(record?.id && record?.providerVersion && record?.role && record?.phase);
}
