import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  assertNativeOracle,
  compareObservations,
  inventoryClosure,
  snapshotSandbox,
  summarizeResults,
} from '../scripts/native-cli/gate.mjs';

function tempDirectory(prefix = 'legion-native-boundary-') { return mkdtempSync(join(tmpdir(), prefix)); }
function sandboxFor(root) {
  const home = join(root, 'home');
  const localAppData = join(root, 'local-app-data');
  const stateRoot = join(root, 'state');
  for (const path of [home, localAppData, stateRoot]) mkdirSync(path, { recursive: true });
  return { cwd: root, home, localAppData, stateRoot };
}
function clean(root) { rmSync(root, { recursive: true, force: true }); }

const cleanObservation = (overrides = {}) => ({
  exitCode: 0,
  stdout: 'ok',
  stderr: '',
  error: null,
  signal: null,
  timedOut: false,
  outputLimitExceeded: false,
  mismatch: [],
  filesystem: { before: { cwd: [] }, after: { cwd: [] } },
  ...overrides,
});

test('native oracle rejects empty, array, unknown, and non-meaningful assertions', () => {
  for (const nativeOracle of [{}, [], { note: 'not an assertion' }, { exitCode: '0' }, { stdoutIncludes: [] }, { exitCode: 0, unknown: true }]) {
    assert.throws(
      () => assertNativeOracle({ id: 'oracle-boundary', nativeOracle }, cleanObservation()),
      /oracle|assertion|exitCode|unknown/i,
      JSON.stringify(nativeOracle),
    );
  }
  assert.deepEqual(assertNativeOracle({ id: 'oracle-ok', nativeOracle: { exitCode: 0 } }, cleanObservation()), []);
});

test('native oracle rejects failed, signaled, timed out, and output-limited observations', () => {
  for (const observation of [
    cleanObservation({ error: 'spawn failed' }),
    cleanObservation({ signal: 'SIGTERM' }),
    cleanObservation({ timedOut: true }),
    cleanObservation({ outputLimitExceeded: true }),
  ]) {
    assert.throws(
      () => assertNativeOracle({ id: 'failed-observation', nativeOracle: { exitCode: 0 } }, observation),
      /observation|spawn|signal|timeout|output/i,
    );
  }
});

test('filesystem snapshots fail closed when the file bound is exceeded', () => {
  const root = tempDirectory();
  try {
    for (let index = 0; index < 2001; index += 1) writeFileSync(join(root, `file-${index}.txt`), 'x');
    assert.throws(() => snapshotSandbox(sandboxFor(root)), /file|bound|limit/i);
  } finally { clean(root); }
});

test('filesystem snapshots fail closed when a sandbox root vanishes', () => {
  const root = tempDirectory();
  try {
    const sandbox = sandboxFor(root);
    rmSync(root, { recursive: true, force: true });
    assert.throws(() => snapshotSandbox(sandbox), /vanished|missing/i);
  } finally { clean(root); }
});

test('filesystem snapshots fail closed when the depth bound is exceeded', () => {
  const root = tempDirectory();
  try {
    let current = root;
    for (let depth = 0; depth < 18; depth += 1) {
      current = join(current, `level-${depth}`);
      mkdirSync(current);
    }
    writeFileSync(join(current, 'deep.txt'), 'x');
    assert.throws(() => snapshotSandbox(sandboxFor(root)), /depth|bound|limit/i);
  } finally { clean(root); }
});

test('filesystem snapshots record links without following them', () => {
  const root = tempDirectory();
  try {
    const target = join(root, 'target');
    const link = join(root, 'link');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'secret');
    try { symlinkSync(target, link, 'junction'); } catch { symlinkSync(target, link, 'dir'); }
    const snapshot = snapshotSandbox(sandboxFor(root));
    const cwdEntries = snapshot.value.cwd;
    assert.equal(cwdEntries.find((entry) => entry.path === 'link')?.type, 'symlink');
    assert.equal(cwdEntries.some((entry) => entry.path === 'link/secret.txt'), false);
  } finally { clean(root); }
});

test('comparison rejects failed or incomplete observations and compares initial state', () => {
  const baseline = cleanObservation();
  const actual = cleanObservation({ filesystem: { before: { cwd: [{ path: 'changed', type: 'file' }] }, after: { cwd: [] } } });
  assert.deepEqual(compareObservations(baseline, actual), ['filesystem mutation differs from baseline']);
  for (const failed of [
    { error: 'baseline failed' },
    { mismatch: ['old mismatch'] },
    { signal: 'SIGTERM' },
    { timedOut: true },
    { outputLimitExceeded: true },
  ]) {
    assert.ok(compareObservations(cleanObservation(failed), cleanObservation()).some((message) => /baseline|observation|signal|timeout|output/i.test(message)), JSON.stringify(failed));
    assert.ok(compareObservations(cleanObservation(), cleanObservation(failed)).some((message) => /native|observation|signal|timeout|output/i.test(message)), JSON.stringify(failed));
  }
  assert.ok(compareObservations({ ...baseline, filesystem: { after: { cwd: [] } } }, baseline).some((message) => /filesystem/i.test(message)));
});

test('temporary-root normalization covers plain and JSON-escaped Windows paths', () => {
  const root = String.raw`C:\Temp\legion-native`;
  const baseline = cleanObservation({ stdout: `${root}\n${JSON.stringify({ path: root })}` });
  const actualRoot = String.raw`D:\Cache\legion-native`;
  const actual = cleanObservation({ stdout: `${actualRoot}\n${JSON.stringify({ path: actualRoot })}` });
  assert.deepEqual(compareObservations(baseline, actual, {
    fixture: { normalization: { tempRoots: true } },
    tempRoots: [root, actualRoot],
  }), []);
});

test('stack-frame normalization preserves error text while removing runtime frames', () => {
  const baseline = cleanObservation({ stderr: "Error: missing input\n    at nodeSource (file.mjs:1:1)\n" });
  const actual = cleanObservation({ stderr: "Error: missing input\n" });
  assert.deepEqual(compareObservations(baseline, actual, {
    fixture: { normalization: { stackFrames: true } },
  }), []);
  assert.notDeepEqual(compareObservations(baseline, cleanObservation({ stderr: "Error: different\n" }), {
    fixture: { normalization: { stackFrames: true } },
  }), []);
});

test('summary rejects duplicate IDs, incomplete manifest coverage, and tainted matched rows', () => {
  const identity = { rowIds: ['a', 'b'], rowCount: 2, manifestSha256: 'manifest' };
  const duplicate = summarizeResults([
    { id: 'a', status: 'matched', mismatch: [], error: null },
    { id: 'a', status: 'matched', mismatch: [], error: null },
  ], identity);
  assert.equal(duplicate.qualifying, false);
  assert.ok(duplicate.duplicateIds.includes('a'));
  assert.ok(duplicate.missingIds.includes('b'));

  const tainted = summarizeResults([
    { id: 'a', status: 'matched', mismatch: ['unexpected'], error: null },
    { id: 'b', status: 'matched', mismatch: [], error: 'spawn failed' },
  ], identity);
  assert.equal(tainted.qualifying, false);
  assert.equal(tainted.mismatched, 2);
});

test('inventory closure fails on every unresolved Rust classification', () => {
  const clean = {
    rustStubs: 0,
    rustPartial: 0,
    rustDivergent: 0,
    rustUnknown: 0,
    uncharacterizedNodeCommands: 0,
  };
  assert.equal(inventoryClosure(clean).ok, true);
  for (const key of Object.keys(clean)) {
    const result = inventoryClosure({ ...clean, [key]: 1 });
    assert.equal(result.ok, false, key);
    assert.equal(result.blockers[key], 1, key);
  }
});
