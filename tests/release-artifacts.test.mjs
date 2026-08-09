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

test('verifyReleaseManifest rejects an unsigned manifest (no false clean)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-rel-'));
  try {
    writeFileSync(join(dir, 'nemesis'), 'binary');
    writeFileSync(join(dir, 'SHA256SUMS'), 'sums');
    writeFileSync(join(dir, 'nemesis.sbom.json'), '{}');
    writeFileSync(join(dir, 'THIRD_PARTY_NOTICES.md'), 'notices');
    writeFileSync(join(dir, 'attestation.jsonl'), '{"predicateType":"test"}\n');
    const digest = sha256File(join(dir, 'nemesis'));
    const manifest = {
      schemaVersion: 1, kind: 'nemesis-release-manifest',
      version: '0.0.0-test', sourceRevision: '0123456789abcdef',
      artifacts: [{ path: 'nemesis', digest }],
      checksums: ['SHA256SUMS'], sboms: ['nemesis.sbom.json'],
      notices: ['THIRD_PARTY_NOTICES.md'], attestations: ['attestation.jsonl'],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    // An unsigned, un-notarized manifest is NOT a valid release — asserting
    // valid:true here encoded a false clean. The verifier correctly demands
    // signatures, notarization, qualification artifacts, and per-entry digests.
    assert.equal(result.valid, false);
    const kinds = result.issues.map((issue) => issue.issue).sort();
    assert.ok(kinds.includes('missing'), 'unsigned manifest must report missing signature/notarization');
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

test('release workflow fails closed until pinned signing workflow exists', () => {
  const workflow = readWorkflow();
  assert.match(workflow, /workflow_dispatch/);
  assert.match(workflow, /BLOCKED: immutable action pins/);
  assert.match(workflow, /exit 1/);
  assert.ok(!workflow.includes('pull_request'));
});

test('blocked release workflow grants no signing or attestation permissions', () => {
  const workflow = readWorkflow();
  assert.doesNotMatch(workflow, /id-token: write/);
  assert.doesNotMatch(workflow, /attestations: write/);
  assert.doesNotMatch(workflow, /uses:/);
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
