import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkPublicationChannel, publicationSurfaceDigest } from '../scripts/check-publication-policy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('publication grant digest binds current package surface', () => {
  const policy = JSON.parse(readFileSync(join(root, 'release/publication-policy.json'), 'utf8'));
  assert.equal(policy.channels.npm.policyDigest, publicationSurfaceDigest(root));
  assert.equal(checkPublicationChannel('npm', root).status, 'pass');
});

test('publication guard rejects surface drift without digest update', () => {
  const fixture = mkdtempSync(join(tmpdir(), 'legion-publication-policy-'));
  try {
    for (const path of ['package.json', 'MANIFEST.package.json', 'release/publication-policy.json']) {
      mkdirSync(dirname(join(fixture, path)), { recursive: true });
      cpSync(join(root, path), join(fixture, path));
    }
    const pkgPath = join(fixture, 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    pkg.files.push('unexpected/');
    writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
    const result = checkPublicationChannel('npm', fixture);
    assert.equal(result.status, 'blocked');
    assert.match(result.message, /policy digest drift/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
