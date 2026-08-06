import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256File, verifyReleaseManifest } from '../scripts/verify-release.mjs';

function readFile(path) {
  return readFileSync(fileURLToPath(path), 'utf8');
}

test('verifyReleaseManifest accepts a complete manifest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-rel-'));
  try {
    writeFileSync(join(dir, 'nemesis'), 'binary');
    writeFileSync(join(dir, 'SHA256SUMS'), 'sums');
    writeFileSync(join(dir, 'nemesis.sbom.json'), '{}');
    writeFileSync(join(dir, 'THIRD_PARTY_NOTICES.md'), 'notices');
    const digest = sha256File(join(dir, 'nemesis'));
    const manifest = {
      schemaVersion: 1, kind: 'nemesis-release-manifest',
      artifacts: [{ path: 'nemesis', digest }],
      checksums: ['SHA256SUMS'], sboms: ['nemesis.sbom.json'],
      notices: ['THIRD_PARTY_NOTICES.md'], attestations: ['attestation.jsonl'],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    assert.equal(result.valid, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyReleaseManifest rejects digest mismatch', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-rel-'));
  try {
    writeFileSync(join(dir, 'nemesis'), 'changed');
    const manifest = {
      schemaVersion: 1, kind: 'nemesis-release-manifest',
      artifacts: [{ path: 'nemesis', digest: 'sha256:wrong' }],
      checksums: ['SHA256SUMS'], sboms: ['s.json'], notices: ['n.md'], attestations: ['a.jsonl'],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((issue) => issue.issue === 'digest-mismatch'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyReleaseManifest rejects missing required artifacts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-rel-'));
  try {
    const manifest = {
      schemaVersion: 1, kind: 'nemesis-release-manifest',
      artifacts: [], checksums: [], sboms: [], notices: [], attestations: [],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((issue) => issue.issue === 'missing'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('release workflow requires qualification before signing', () => {
  const workflow = readWorkflow();
  const qualificationIndex = workflow.indexOf('qualify-release.mjs');
  const signingIndex = workflow.indexOf('sign-and-attest');
  assert.ok(qualificationIndex >= 0);
  assert.ok(signingIndex > qualificationIndex, 'qualification must precede signing');
  // Never expose credentials to PR code.
  assert.ok(!workflow.includes('pull_request'));
});

test('release workflow uses artifact attestation permissions', () => {
  const workflow = readWorkflow();
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /attestations: write/);
  assert.match(workflow, /attest-build-provenance@v2/);
});

test('macOS and Windows signing outlines are documented', () => {
  const mac = readFile(new URL('../packaging/macos/sign.md', import.meta.url), 'utf8');
  assert.match(mac, /codesign --force --options runtime --timestamp/);
  assert.match(mac, /notarytool submit/);
  assert.match(mac, /spctl --assess/);
  const win = readFile(new URL('../packaging/windows/sign.md', import.meta.url), 'utf8');
  assert.match(win, /signtool\.exe sign/);
  assert.match(win, /\/tr "http:\/\/timestamp\.acs\.microsoft\.com"/);
  assert.match(win, /signtool\.exe verify/);
});

function readWorkflow() {
  return readFile(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
}
