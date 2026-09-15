import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assertNativeOracle,
  compareObservations,
  installedExecutablePath,
  loadManifest,
  runBounded,
  sha256,
  summarizeResults,
  validateExecutableProvenance,
  validateInstalledSkillLinks,
} from '../scripts/native-cli/gate.mjs';

const manifestPath = fileURLToPath(new URL('../tests/native-cli-characterization/fixtures.json', import.meta.url));

function temporaryDirectory(prefix = 'legion-native-gate-test-') { return mkdtempSync(join(tmpdir(), prefix)); }

test('the frozen manifest is content addressed and has unique rows', () => {
  const manifest = loadManifest(manifestPath);
  assert.equal(manifest.rowCount, manifest.rowIds.length);
  assert.match(manifest.manifestSha256, /^[a-f0-9]{64}$/);
  assert.equal(new Set(manifest.rowIds).size, manifest.rowCount);
  assert.ok(manifest.rows.every((row) => /^[a-f0-9]{64}$/.test(row.fixtureSha256)));
});

test('parity compares stdout, stderr, exit code, and filesystem mutation', () => {
  const baseline = {
    exitCode: 2,
    stdout: 'same stdout',
    stderr: 'important diagnostic',
    error: null, signal: null, timedOut: false, outputLimitExceeded: false, mismatch: [],
    filesystem: { before: {}, after: { cwd: [{ path: 'state.json', type: 'file', sha256: 'a' }] } },
  };
  const actual = {
    exitCode: 2,
    stdout: 'same stdout',
    stderr: 'different diagnostic',
    error: null, signal: null, timedOut: false, outputLimitExceeded: false, mismatch: [],
    filesystem: { before: {}, after: { cwd: [{ path: 'state.json', type: 'file', sha256: 'b' }] } },
  };
  assert.deepEqual(compareObservations(baseline, actual, { fixture: {} }), [
    'stderr differs from baseline',
    'filesystem mutation differs from baseline',
  ]);
});

test('temp-root normalization covers filesystem symlink targets', () => {
  const observation = (target) => ({
    exitCode: 0, stdout: '', stderr: '', error: null, signal: null,
    timedOut: false, outputLimitExceeded: false, mismatch: [],
    filesystem: { before: {}, after: { cwd: [{ path: '.agents/skills/audit', type: 'symlink', target }] } },
  });
  assert.deepEqual(compareObservations(
    observation('D:\\repo\\skills\\audit'),
    observation('C:\\installed\\plugin\\skills\\audit'),
    { fixture: { normalization: { tempRoots: true } }, tempRoots: ['D:\\repo', 'C:\\installed\\plugin'] },
  ), []);
});

test('installed skill links must target installed plugin & reject checkout roots', () => {
  const evidence = (target) => ({ after: { cwd: [{ path: '.agents/skills/audit', type: 'symlink', target }] } });
  assert.deepEqual(validateInstalledSkillLinks(evidence('C:\\installed\\plugin\\skills\\audit'), 'C:\\installed\\plugin\\skills', 'D:\\repo'), []);
  assert.deepEqual(validateInstalledSkillLinks(evidence('D:\\repo\\skills\\audit'), 'C:\\installed\\plugin\\skills', 'D:\\repo'), [
    '.agents/skills/audit does not target installed plugin skills',
    '.agents/skills/audit targets development checkout',
  ]);
});

test('capture-only and native-only rows require an explicit native oracle', () => {
  assert.throws(() => assertNativeOracle({ id: 'capture-only', captureOnly: true }, { exitCode: 0, stdout: '', stderr: '' }), /no (?:explicit|valid) native behavior oracle(?: object)?/);
  assert.deepEqual(assertNativeOracle({ id: 'native-help', nativeOracle: { exitCode: 0, stdoutIncludes: ['Usage'] } }, { exitCode: 0, stdout: 'Usage: legion', stderr: '', error: null, signal: null, timedOut: false, outputLimitExceeded: false, mismatch: [], filesystem: { before: {}, after: {} } }), []);
  assert.deepEqual(assertNativeOracle({ id: 'native-help', nativeOracle: { exitCode: 0, stderrIncludes: ['diagnostic'] } }, { exitCode: 0, stdout: '', stderr: 'other', error: null, signal: null, timedOut: false, outputLimitExceeded: false, mismatch: [], filesystem: { before: {}, after: {} } }), ['stderr native oracle assertion failed']);
});

test('bounded execution turns timeout and output overflow into failures', () => {
  const overflow = runBounded(process.execPath, ['-e', "process.stdout.write('x'.repeat(100))"], { maxOutputBytes: 16, timeoutMs: 5_000 });
  assert.equal(overflow.outputLimitExceeded, true);
  assert.match(overflow.error, /output limit exceeded/);
  const timeout = runBounded(process.execPath, ['-e', 'setTimeout(() => {}, 250)'], { maxOutputBytes: 1024, timeoutMs: 20 });
  assert.equal(timeout.timedOut, true);
  assert.match(timeout.error, /timeout exceeded/);
});

test('summary cannot qualify skipped, blocked, unmatched, or mismatched rows', () => {
  const summary = summarizeResults([
    { id: 'matched', status: 'matched' },
    { id: 'blocked', status: 'blocked' },
    { id: 'unmatched', status: 'unmatched' },
    { id: 'skipped', status: 'skipped' },
  ], { manifestSha256: 'manifest', sourceRevision: 'source' });
  assert.equal(summary.total, 4);
  assert.equal(summary.matched, 1);
  assert.equal(summary.blocked, 1);
  assert.equal(summary.unmatched, 1);
  assert.equal(summary.skipped, 1);
  assert.equal(summary.qualifying, false);
});

test('provenance binds source tree, manifest, executable bytes, and receipt', () => {
  const directory = temporaryDirectory();
  try {
    const executable = process.execPath;
    const manifestSha256 = 'b'.repeat(64);
    const source = { sourceRevision: 'a'.repeat(40), sourceTreeSha256: 'c'.repeat(64) };
    const evidencePath = join(directory, 'evidence.json');
    writeFileSync(evidencePath, `${JSON.stringify({
      schemaVersion: 1,
      kind: 'legion-native-cli-build-evidence',
      status: 'verified',
      sourceRevision: source.sourceRevision,
      sourceTreeSha256: source.sourceTreeSha256,
      manifestSha256,
      executableSha256: sha256(requireBytes(executable)),
      executable: { path: executable, sha256: sha256(requireBytes(executable)) },
    })}\n`);
    const identity = validateExecutableProvenance({ executable, evidencePath, manifestSha256, source, mode: 'current-tree' });
    assert.equal(identity.manifestSha256, manifestSha256);
    assert.equal(identity.executableSha256, sha256(requireBytes(executable)));
    assert.match(identity.receiptSha256, /^[a-f0-9]{64}$/);
    assert.throws(() => validateExecutableProvenance({
      executable,
      evidencePath,
      manifestSha256: 'd'.repeat(64),
      source,
      mode: 'current-tree',
    }), /manifest SHA-256/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('installed executable resolution is restricted to stable current', () => {
  const directory = temporaryDirectory();
  try {
    const localAppData = join(directory, 'local-app-data');
    const executable = join(localAppData, 'Orthic Labs', 'Legion', 'current', 'bin', 'legion.exe');
    mkdirSync(join(executable, '..'), { recursive: true });
    writeFileSync(executable, 'synthetic executable');
    const result = installedExecutablePath({ LOCALAPPDATA: localAppData });
    assert.equal(result.executable, executable);
    assert.throws(() => installedExecutablePath({ LOCALAPPDATA: join(directory, 'arbitrary') }), /stable installed executable is missing/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

function requireBytes(path) {
  return readFileSync(path);
}
