import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkPublicationChannel, publicationSurfaceDigest } from '../scripts/check-publication-policy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('private Node package has no public npm grant', () => {
  const policy = JSON.parse(readFileSync(join(root, 'release/publication-policy.json'), 'utf8'));
  assert.equal(policy.channels.npm.allowed, false);
  assert.equal(checkPublicationChannel('npm', root).status, 'blocked');
  assert.match(publicationSurfaceDigest(root), /^sha256:/);
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
    const policyPath = join(fixture, 'release/publication-policy.json');
    const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
    policy.channels['test-public'] = {
      allowed: true,
      approvedBy: 'test',
      approvedAt: '2026-08-27',
      policyDigest: publicationSurfaceDigest(root),
    };
    writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
    const result = checkPublicationChannel('test-public', fixture);
    assert.equal(result.status, 'blocked');
    assert.match(result.message, /(?:policy digest drift|publication surface mismatch)/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
