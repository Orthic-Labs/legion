import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const MANIFESTS = join(ROOT, 'skills', 'manifests');
const manifests = readdirSync(MANIFESTS)
  .filter((name) => name.endsWith('.json') && !name.endsWith('.import-receipt.json'))
  .map((name) => JSON.parse(readFileSync(join(MANIFESTS, name), 'utf8')));
const walk = (root, current = root, out = []) => {
  for (const name of readdirSync(current).sort()) {
    if (name === '.DS_Store' || name === '__pycache__' || name.endsWith('.pyc')) continue;
    const path = join(current, name);
    if (statSync(path).isDirectory()) walk(root, path, out);
    else out.push(relative(root, path).replaceAll('\\', '/'));
  }
  return out;
};
const digest = (path) => `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;

test('all 25 public skills freeze complete parity dimensions', () => {
  assert.equal(manifests.length, 25);
  for (const manifest of manifests) {
    for (const key of ['triggers','outputs','scripts','templates','schemas','receipts','evals','consumers','legacyArtifacts']) {
      assert.ok(Array.isArray(manifest.parity?.[key]), `${manifest.id}.${key}`);
    }
    assert.ok(manifest.parity.triggers.length >= 2, `${manifest.id}.triggers`);
    assert.ok(manifest.parity.consumers.length >= 1, `${manifest.id}.consumers`);
  }
});

test('every retired artifact survives byte-for-byte under canonical entrypoint', () => {
  const retired = manifests.filter(({ parity }) => parity?.legacyRef);
  assert.equal(retired.length, 9);
  assert.equal(retired.reduce((sum, manifest) => sum + manifest.parity.legacyArtifacts.length, 0), 87);
  for (const manifest of retired) {
    const legacyName = manifest.parity.legacyArtifacts[0]?.sourcePath.split('/')[2];
    const root = join(ROOT, 'skills', manifest.id, 'legacy-source', legacyName);
    const records = new Map(manifest.parity.legacyArtifacts.map((item) => [item.migratedPath.split('/').slice(2).join('/'), item]));
    assert.deepEqual([...records.keys()].sort(), walk(root));
    for (const [relativePath, record] of records) {
      const path = join(root, relativePath);
      assert.equal(existsSync(path), true, record.sourcePath);
      assert.equal(digest(path), record.digest, record.sourcePath);
    }
  }
});
