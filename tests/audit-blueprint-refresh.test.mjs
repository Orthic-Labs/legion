import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import {
  BLUEPRINT_ERROR_CODES,
  DEFAULT_OUT_DIR,
  collectRepositoryBinding,
  describeUntrackedEntry,
  enforceAuditOutputBoundary,
  readBlueprintPacket,
} from '../src/adapters/blueprint-packet.mjs';

const GENERATION_ID = 'xxh128:audit-run-1';

function packetPayload() {
  return {
    schema: 'membrane.blueprint-packet.v1',
    status: 'ready',
    state: 'ready',
    generationId: GENERATION_ID,
    manifestDigest: `sha256:${'b'.repeat(64)}`,
    sourceObservation: { head: 'a'.repeat(40), dirty: true },
    files: ['src/a.ts'],
  };
}

function fakeBlueprint(mode, logPath = '') {
  const dir = mkdtempSync(join(tmpdir(), 'legion-audit-blueprint-'));
  const bin = join(dir, 'blueprint');
  const script = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const command = args.slice(0, 2).join(' ');
const mode = ${JSON.stringify(mode)};
${logPath ? `fs.appendFileSync(${JSON.stringify(logPath)}, command + '\\n');` : ''}
const packet = ${JSON.stringify(packetPayload())};
const outIndex = args.indexOf('--out');
if (outIndex >= 0 && /^([A-Za-z]:[\\\\/]|[\\\\/])/.test(args[outIndex + 1] ?? '')) {
  process.stderr.write(JSON.stringify({ error: { code: 'absolute_out_not_supported' } }));
  process.exit(8);
}
if (command === 'graph build') {
  if (mode === 'build-failed') {
    process.stderr.write(JSON.stringify({ error: { code: 'graph_build_failed' } }));
    process.exit(1);
  }
  process.exit(0);
}
if (command === 'graph status') {
  if (mode === 'stale') {
    process.stderr.write(JSON.stringify({ error: { code: 'graph_stale' } }));
    process.exit(4);
  }
  console.log(JSON.stringify({ state: 'fresh', manifest: { generationId: packet.generationId } }));
  process.exit(0);
}
if (command === 'graph audit-projection') {
  if (mode === 'projection-exact-code') {
    console.log(JSON.stringify({ schema: 'membrane.blueprint-packet.v1', status: 'unavailable', reason: 'blueprint-projection-denied' }));
    process.exit(9);
  }
  if (mode === 'generation-mismatch') {
    console.log(JSON.stringify({ ...packet, generationId: 'xxh128:gen-other' }));
    process.exit(0);
  }
  console.log(JSON.stringify(packet));
  process.exit(0);
}
console.log(JSON.stringify(packet));
process.exit(0);
`;
  writeFileSync(bin, script);
  chmodSync(bin, 0o755);
  return { dir, bin };
}

test('builds a run-scoped graph, pins its generation, then projects that exact graph', () => {
  const logPath = join(mkdtempSync(join(tmpdir(), 'legion-audit-log-')), 'invocations.log');
  const fixture = fakeBlueprint('ready', logPath);
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.status, 'ready');
    assert.equal(packet.state, 'ready');
    assert.equal(packet.generationId, GENERATION_ID);
    assert.equal(readFileSync(logPath, 'utf8'), 'graph build\ngraph status\ngraph audit-projection\n');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
    rmSync(dirname(logPath), { recursive: true, force: true });
  }
});

test('preserves the exact stale code instead of collapsing it into transport failure', () => {
  const fixture = fakeBlueprint('stale');
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.status, 'unavailable');
    assert.equal(packet.reason, 'graph_stale');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('preserves typed graph build failure', () => {
  const fixture = fakeBlueprint('build-failed');
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.status, 'unavailable');
    assert.equal(packet.reason, 'graph_build_failed');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('missing Blueprint binary degrades as transport-unavailable', () => {
  const packet = readBlueprintPacket(process.cwd(), { blueprintBin: '/missing/blueprint' });
  assert.equal(packet.status, 'unavailable');
  assert.equal(packet.reason, BLUEPRINT_ERROR_CODES.transportUnavailable);
});

test('preserves Blueprint CLI exact code on projection failure', () => {
  const fixture = fakeBlueprint('projection-exact-code');
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.status, 'unavailable');
    assert.equal(packet.reason, 'blueprint-projection-denied');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('binds projection to the pinned generation & rejects mismatched graphs', () => {
  const fixture = fakeBlueprint('generation-mismatch');
  try {
    const packet = readBlueprintPacket(process.cwd(), { blueprintBin: fixture.bin });
    assert.equal(packet.status, 'unavailable');
    assert.equal(packet.reason, BLUEPRINT_ERROR_CODES.generationMismatch);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('output defaults under .audit & Audit-owned boundaries are enforced before invoking Blueprint', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-audit-root-'));
  const logPath = join(mkdtempSync(join(tmpdir(), 'legion-audit-log-')), 'invocations.log');
  const fixture = fakeBlueprint('ready', logPath);
  try {
    assert.equal(DEFAULT_OUT_DIR, join('.audit', 'blueprint'));
    assert.deepEqual(enforceAuditOutputBoundary(root), { ok: true, outDir: join(root, '.audit', 'blueprint') });
    const outside = enforceAuditOutputBoundary(root, '../outside');
    assert.equal(outside.ok, false);
    assert.equal(outside.code, BLUEPRINT_ERROR_CODES.outputOutsideAuditBoundary);
    assert.equal(enforceAuditOutputBoundary(root, root).ok, false);
    const packet = readBlueprintPacket(root, { blueprintBin: fixture.bin, outDir: '..' });
    assert.equal(packet.status, 'unavailable');
    assert.equal(packet.reason, BLUEPRINT_ERROR_CODES.outputOutsideAuditBoundary);
    assert.equal(existsSync(logPath) ? readFileSync(logPath, 'utf8') : '', '');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
    rmSync(dirname(logPath), { recursive: true, force: true });
  }
});

test('hashes untracked entries safely: files by content, symlinks by target, directories explicit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-untracked-'));
  try {
    const file = join(dir, 'file.txt');
    writeFileSync(file, 'audit evidence\n');
    assert.deepEqual(describeUntrackedEntry(file), {
      kind: 'file',
      contentDigest: `sha256:${createHash('sha256').update('audit evidence\n').digest('hex')}`,
    });
    const link = join(dir, 'link');
    symlinkSync(file, link);
    assert.deepEqual(describeUntrackedEntry(link), { kind: 'symlink', target: file });
    const nested = join(dir, 'nested');
    mkdirSync(nested);
    assert.deepEqual(describeUntrackedEntry(nested), { kind: 'directory' });
    assert.deepEqual(describeUntrackedEntry(join(dir, 'missing')), { kind: 'unreadable' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collectRepositoryBinding digests untracked changes deterministically without reading directories as bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-git-binding-'));
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '--allow-empty', '-q', '-m', 'init'], { cwd: dir });
    writeFileSync(join(dir, 'untracked.txt'), 'v1');
    const first = collectRepositoryBinding(dir);
    assert.ok(first.repositoryRevision);
    assert.equal(first.dirty, true);
    assert.equal(first.dirtyPatchDigest, collectRepositoryBinding(dir).dirtyPatchDigest);
    writeFileSync(join(dir, 'untracked.txt'), 'v2');
    assert.notEqual(collectRepositoryBinding(dir).dirtyPatchDigest, first.dirtyPatchDigest);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
