import { createHash } from 'node:crypto';
import { normalizeGeometry } from '../../lib/design/geometry.mjs';
import { decodePng } from '../visual-core.mjs';

function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function redact(value, sensitiveValues) {
  let output = String(value ?? '');
  for (const secret of sensitiveValues.filter(Boolean)) output = output.replaceAll(String(secret), '[REDACTED]');
  return output;
}

export function captureVisualEvidence(input = {}) {
  if (!input.surfaceId || !input.screenshotBytes || !input.browser || !input.viewport || !input.binding) throw new Error('surface, screenshot, browser, viewport, and binding are required');
  const decoded = decodePng(input.screenshotBytes);
  const raw = { dom: redact(input.dom ?? null, input.sensitiveValues ?? []), styles: input.styles ?? {}, geometry: input.geometry ?? [], stacking: input.stacking ?? [], scrollExtents: input.scrollExtents ?? null };
  const normalized = { dom: raw.dom, styles: raw.styles, geometry: normalizeGeometry(raw.geometry), stacking: raw.stacking, scrollExtents: raw.scrollExtents };
  return { schemaVersion: 1, kind: 'legion-visual-evidence', surfaceId: input.surfaceId,
    screenshot: { path: input.screenshotPath ?? null, digest: digest(input.screenshotBytes), bytes: input.screenshotBytes.length, width: decoded.width, height: decoded.height }, browser: input.browser,
    route: input.route ?? null, viewport: input.viewport, state: input.state ?? 'default', locale: input.locale ?? null, direction: input.direction ?? null,
    tokenDigest: input.tokenDigest ?? null, baselineDigest: input.baselineDigest ?? null, accessibilityRef: input.accessibilityRef ?? null,
    contentItemIds: input.contentItemIds ?? [], raw, normalized, binding: input.binding };
}
