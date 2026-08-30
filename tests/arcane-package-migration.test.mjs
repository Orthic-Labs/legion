import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const resultPath = resolve(root, 'docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json');
const result = JSON.parse(readFileSync(resultPath, 'utf8'));

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

test('P0.5 migration maps every triaged Arcane file without target collisions', () => {
  assert.deepEqual(result.inventory, { expected: 235, observed: 235, migrated: 232, retiredUnconsumed: 3 });
  assert.equal(result.entries.length, 235);
  assert.equal(new Set(result.entries.map(({ oldPath }) => oldPath)).size, 235);
  const targets = result.entries.filter(({ newPath }) => newPath).map(({ newPath }) => newPath);
  assert.equal(new Set(targets).size, 232);
});

test('P0.5 migration preserves every migrated target byte hash in current result map', () => {
  for (const entry of result.entries.filter(({ newPath }) => newPath)) {
    const target = resolve(root, entry.newPath);
    assert.equal(existsSync(target), true, entry.newPath);
    assert.equal(entry.sha256AfterMove, sha256(target), entry.newPath);
    assert.ok(entry.owners.length > 0, entry.oldPath);
    assert.ok(Array.isArray(entry.oldConsumers), entry.oldPath);
    assert.ok(Array.isArray(entry.newConsumers), entry.newPath);
  }
});

test('P0.5 retires only three zero-consumer Band-1 files & removes old package root', () => {
  const retired = result.entries.filter(({ newPath }) => !newPath);
  assert.deepEqual(retired.map(({ oldPath }) => oldPath).sort(), [
    'src/packages/arcane/INTERFACES.md',
    'src/packages/arcane/index.mjs',
    'src/packages/arcane/policy/README.md',
  ]);
  assert.ok(retired.every(({ oldConsumers, resultDisposition }) => oldConsumers.length === 0 && resultDisposition === 'retired-unconsumed'));
  assert.equal(existsSync(resolve(root, 'src/packages/arcane')), false);
});

test('P0.5 Node production targets are included by canonical src/lib publication root', () => {
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  assert.ok(pkg.files.includes('src/lib/'));
  const productionModules = result.entries
    .map(({ newPath }) => newPath)
    .filter((path) => path?.endsWith('.mjs') && !path.startsWith('tests/'));
  assert.ok(productionModules.length >= 100);
  assert.ok(productionModules.every((path) => path.startsWith('src/lib/')));
});

test('P0.5 migrated production module graph resolves from canonical owners', async () => {
  const productionModules = result.entries
    .map(({ newPath }) => newPath)
    .filter((path) => path?.endsWith('.mjs') && !path.startsWith('tests/'));
  for (const path of productionModules) await import(pathToFileURL(resolve(root, path)).href);
});
