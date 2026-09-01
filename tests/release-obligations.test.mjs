import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkReleaseObligations } from '../scripts/check-release-obligations.mjs';

test('the shipped release obligations manifest is consistent', () => {
  assert.deepEqual(checkReleaseObligations(), { ok: true, issues: [] });
});

// The manifest exists to stop unbacked coverage claims, so prove it rejects one.
test('an obligation naming a nonexistent producer is rejected', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-obligations-'));
  mkdirSync(join(root, 'release'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: {} }));
  writeFileSync(join(root, 'release/obligations.json'), JSON.stringify({
    schemaVersion: 1, kind: 'legion-release-obligations', product: 'legion',
    gates: [
      { id: '0A', name: 'static', grant: null, obligations: [{ id: 'a', requirement: 'r', evidence: 'release:does-not-exist' }] },
      { id: '1', name: 'candidate', grant: 'BUILD_AUTHORIZED', obligations: [{ id: 'b', requirement: 'r', evidence: 'candidate stage-summary' }] },
      { id: '3', name: 'sign', grant: 'SIGNING_AUTHORIZED', obligations: [{ id: 'c', requirement: 'r', evidence: 'candidate stage-summary' }] },
      { id: '6', name: 'auth', grant: 'RELEASE_AUTHORIZED', obligations: [{ id: 'd', requirement: 'r', evidence: 'candidate stage-summary' }] },
    ],
  }));
  const report = checkReleaseObligations(root);
  assert.equal(report.ok, false);
  assert.ok(report.issues.some((issue) => issue.includes('does not exist')), report.issues.join('; '));
});

test('an unimplemented obligation must name its gap', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-obligations-gap-'));
  mkdirSync(join(root, 'release'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: {} }));
  writeFileSync(join(root, 'release/obligations.json'), JSON.stringify({
    schemaVersion: 1, kind: 'legion-release-obligations', product: 'legion',
    gates: [
      { id: '0A', name: 'static', grant: null, obligations: [{ id: 'a', requirement: 'r', evidence: null, implemented: false }] },
      { id: '1', name: 'candidate', grant: 'BUILD_AUTHORIZED', obligations: [{ id: 'b', requirement: 'r', evidence: 'candidate stage-summary' }] },
      { id: '3', name: 'sign', grant: 'SIGNING_AUTHORIZED', obligations: [{ id: 'c', requirement: 'r', evidence: 'candidate stage-summary' }] },
      { id: '6', name: 'auth', grant: 'RELEASE_AUTHORIZED', obligations: [{ id: 'd', requirement: 'r', evidence: 'candidate stage-summary' }] },
    ],
  }));
  const report = checkReleaseObligations(root);
  assert.equal(report.ok, false);
  assert.ok(report.issues.some((issue) => issue.includes('names no gap')), report.issues.join('; '));
});
