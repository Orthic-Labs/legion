import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { auditVisualArtifacts, buildCoverageMatrix, comparePng, decodePng, encodePng } from '../providers/visual-core.mjs';

function solid(width, height, color) {
  return encodePng({ width, height, rgba: Buffer.from(Array.from({ length: width * height }, () => color).flat()) });
}

test('PNG codec round-trips RGBA without dependencies', () => {
  const png = solid(2, 1, [10, 20, 30, 255]);
  const decoded = decodePng(png);
  assert.equal(decoded.width, 2);
  assert.equal(decoded.height, 1);
  assert.deepEqual([...decoded.rgba], [10, 20, 30, 255, 10, 20, 30, 255]);
});

test('pixel comparison honors thresholds and masks', () => {
  const expected = solid(2, 1, [0, 0, 0, 255]);
  const actual = encodePng({ width: 2, height: 1, rgba: Buffer.from([255, 0, 0, 255, 0, 0, 0, 255]) });
  const changed = comparePng(expected, actual);
  assert.equal(changed.changedPixels, 1);
  assert.equal(changed.changedRatio, 0.5);
  const masked = comparePng(expected, actual, { masks: [{ x: 0, y: 0, width: 1, height: 1 }] });
  assert.equal(masked.status, 'match');
});

test('coverage matrix reports every missing case', () => {
  const matrix = buildCoverageMatrix({
    expected: { routes: ['/','/settings'], states: ['default'], viewports: ['desktop'], themes: ['light'], locales: ['en'], platforms: ['web'] },
    captures: [{ id: 'home', route: '/', state: 'default', viewport: 'desktop', theme: 'light', locale: 'en', platform: 'web' }],
  });
  assert.equal(matrix.expectedCount, 2);
  assert.equal(matrix.missingCount, 1);
  assert.equal(matrix.complete, false);
});

test('visual artifact audit fails on regression and preserves evidence', () => {
  const root = mkdtempSync(join(tmpdir(), 'audit-visual-'));
  try {
    mkdirSync(join(root, 'shots'));
    writeFileSync(join(root, 'shots/base.png'), solid(1, 1, [0, 0, 0, 255]));
    writeFileSync(join(root, 'shots/actual.png'), solid(1, 1, [255, 255, 255, 255]));
    const result = auditVisualArtifacts({ root, spec: {
      expected: { cases: [{ route: '/', state: 'default', viewport: 'desktop', theme: 'light', locale: 'en', platform: 'web' }] },
      captures: [{ id: 'home', route: '/', state: 'default', viewport: 'desktop', theme: 'light', locale: 'en', platform: 'web', path: 'shots/actual.png', baseline: 'shots/base.png' }],
    } });
    assert.equal(result.status, 'fail');
    assert.equal(result.findings[0].ruleId, 'visual.regression');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('capture without baseline requires review rather than passing clean', () => {
  const root = mkdtempSync(join(tmpdir(), 'audit-visual-review-'));
  try {
    writeFileSync(join(root, 'actual.png'), solid(1, 1, [0, 0, 0, 255]));
    const result = auditVisualArtifacts({ root, spec: {
      expected: { cases: [{ route: '/', state: 'default', viewport: 'desktop', theme: 'light', locale: 'en', platform: 'web' }] },
      captures: [{ id: 'home', route: '/', state: 'default', viewport: 'desktop', theme: 'light', locale: 'en', platform: 'web', path: 'actual.png' }],
    } });
    assert.equal(result.status, 'unproven');
    assert.equal(result.reviewRequired, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
