import assert from 'node:assert/strict';
import test from 'node:test';
import rustPack, { unsafeBoundaries } from '../../../providers/native/rust/index.mjs';
import tauriPack from '../../../providers/frameworks/tauri/index.mjs';

const projection = (files = [], exts = []) => ({ files, parsedExtensions: exts, auditFacts: {} });

test('rust pack detects rust projects', () => {
  assert.equal(rustPack.detect({ projection: projection(['Cargo.toml']) }), true);
  assert.equal(rustPack.detect({ projection: projection([], ['rs']) }), true);
  assert.equal(rustPack.detect({ projection: projection(['a.py']) }), false);
});

test('rust pack emits offline cargo commands', () => {
  const commands = rustPack.commands({ root: '/repo', files: ['src/main.rs'], manifests: ['Cargo.toml'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'rust.check'));
  assert.ok(commands.some((c) => c.id === 'rust.clippy'));
  assert.ok(commands.some((c) => c.id === 'rust.test'));
  for (const command of commands) {
    assert.ok(command.args.includes('--offline'), `${command.id} must run offline`);
  }
});

test('rust pack normalizes execution', () => {
  const result = rustPack.normalize({ commandId: 'rust.check', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(result.status, 'pass');
});

test('unsafe boundaries and FFI are modeled', () => {
  const files = ['src/lib.rs'];
  const readFile = () => 'unsafe { raw() }\nextern "C" { fn c_func(); }';
  const boundaries = unsafeBoundaries(files, readFile);
  assert.ok(boundaries.some((b) => b.kind === 'unsafe-block'));
  assert.ok(boundaries.some((b) => b.kind === 'ffi-boundary'));
});

test('tauri pack detects tauri config', () => {
  assert.equal(tauriPack.detect({ projection: projection(['src-tauri/tauri.conf.json']) }), true);
});

test('tauri pack flags insecure updater transport', () => {
  const observations = tauriPack.analyze({ files: ['tauri.conf.json'], readFile: () => '{"updater": {"active": true, "dangerousInsecureTransportProtocol": true}}' });
  assert.ok(observations.some((o) => o.ruleId === 'tauri.updater.insecure-transport'));
});

test('tauri pack flags updater without signature verification', () => {
  const observations = tauriPack.analyze({ files: ['tauri.conf.json'], readFile: () => '{"updater": {"active": true, "endpoints": ["https://x/updates"]}}' });
  assert.ok(observations.some((o) => o.ruleId === 'tauri.updater.no-signature'));
});

test('tauri pack flags broad shell and fs scopes', () => {
  const files = ['tauri.conf.json', 'capabilities/default.json'];
  const readFile = (f) => f.includes('capabilities') ? '{"fs": {"scope": ["**"]}}' : '{"app": {"windows": []}}';
  const observations = tauriPack.analyze({ files, readFile });
  assert.ok(observations.some((o) => o.ruleId === 'tauri.fs.broad-scope'));
});

test('tauri pack is clean for signed updater config', () => {
  const observations = tauriPack.analyze({
    files: ['tauri.conf.json'],
    readFile: () => '{"updater": {"active": true, "pubkey": "abc123", "endpoints": ["https://x"]}}',
  });
  assert.ok(!observations.some((o) => o.ruleId === 'tauri.updater.no-signature'));
});
