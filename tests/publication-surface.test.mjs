import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkPublicationSurface, validatePublicationSurface } from '../scripts/check-publication-surface.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('package & manifest publish one ordered surface', () => {
  assert.equal(checkPublicationSurface(root).status, 'pass');
});

test('publication surface rejects an ordered split even when entries match as a set', () => {
  const fixture = mkdtempSync(join(tmpdir(), 'legion-publication-surface-'));
  try {
    writeFileSync(join(fixture, 'one.mjs'), 'export {};\n');
    writeFileSync(join(fixture, 'two.mjs'), 'export {};\n');
    const errors = validatePublicationSurface({
      packageFiles: ['one.mjs', 'two.mjs'],
      manifestFiles: ['two.mjs', 'one.mjs'],
    }, fixture);
    assert.deepEqual(errors, ['package.json#files & MANIFEST.package.json#allowlistedTopLevel must be exactly equal in order & content']);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
