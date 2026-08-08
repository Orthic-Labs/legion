import { denominator, exactBinding, finalize, sortById } from '../shared.mjs';

export function inspectWebBackend({ binding = {}, endpoints = [] } = {}) {
  if (!Array.isArray(endpoints) || endpoints.some((item) => !item || typeof item !== 'object')) return finalize('nemesis-web-backend-inventory', { status: 'error', terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['backend-collection-invalid'] });
  const receipts = sortById(endpoints).map((item) => { const gaps = []; for (const key of ['id', 'method', 'path']) if (!item[key]) gaps.push(`missing-${key}`); return { id: item.id, method: item.method, path: item.path, status: gaps.length ? 'unproven' : 'pass', terminal: true, coverageGaps: gaps }; });
  const counts = denominator(endpoints.map((item) => item.id), receipts);
  const gaps = [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...receipts.flatMap((item) => item.coverageGaps.map((gap) => `${item.id}:${gap}`))];
  if (endpoints.length === 0) gaps.push('backend-denominator-empty');
  const ids = endpoints.map((item) => item.id);
  for (const id of new Set(ids)) if (ids.filter((value) => value === id).length > 1) gaps.push(`backend-id-duplicate:${id}`);
  if (ids.some((id) => typeof id !== 'string' || id.length === 0)) gaps.push('backend-id-missing');
  return finalize('nemesis-web-backend-inventory', { status: gaps.length ? 'unproven' : 'pass', terminal: true, claimLevel: 'source', binding, denominator: counts, receipts, coverageGaps: gaps.sort() });
}
