import { contentId, textDigest } from './identity.mjs';
export function createContentInventory({ items = [], binding = {} } = {}) {
  const normalized = items.map((item) => ({ schemaVersion: 1, kind: 'legion-content-item', ...item, id: item.id ?? contentId(item), textDigest: textDigest(item.text ?? ''), source: item.source ?? {}, surface: item.surface ?? {}, evidenceRefs: item.evidenceRefs ?? [], binding }));
  return { schemaVersion: 1, kind: 'legion-content-inventory', items: normalized, binding, complete: normalized.every((item) => item.text && item.source.file), coverageGaps: normalized.filter((item) => !item.source.file).map((item) => `source-missing:${item.id}`) };
}
