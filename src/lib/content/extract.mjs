import { createContentInventory } from './inventory.mjs';

const TEXT = />\s*([^<>{}\n][^<>{}]*?)\s*</g;
const QUOTED = /(?:title|label|placeholder|aria-label|accessibilityLabel|message)\s*[:=]\s*["'`]([^"'`]+)["'`]/g;

export function extractVisibleContent({ artifacts = [], binding = {} } = {}) {
  const items = [];
  for (const artifact of artifacts) {
    for (const match of artifact.text?.matchAll(TEXT) ?? []) items.push(item(match[1], artifact));
    for (const match of artifact.text?.matchAll(QUOTED) ?? []) items.push(item(match[1], artifact));
  }
  return createContentInventory({ items, binding });
}

function item(text, artifact) {
  return { text: text.trim(), source: { file: artifact.path, kind: artifact.kind ?? 'unknown' },
    surface: { route: artifact.route ?? null, type: artifact.surfaceType ?? 'unknown' }, evidenceRefs: artifact.evidenceRefs ?? [] };
}
