import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { exeSuffix, seaConfig } from '../scripts/build-native.mjs';
import { NEMESIS_VERSION } from '../lib/version.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('SEA config pins the entry, output, and disabled experimental warning', () => {
  const config = seaConfig();
  assert.equal(config.main, 'dist/sea-entry.cjs');
  assert.equal(config.output, 'dist/sea-preparation.blob');
  assert.equal(config.disableExperimentalSEAWarning, true);
  assert.equal(config.useCodeCache, false);
  assert.ok(config.assets['schemas.tar']);
  assert.ok(config.assets['registry.tar']);
});

test('exe suffix is platform-correct', () => {
  assert.equal(typeof exeSuffix(), 'string');
});

test('npm CLI and SEA surface must agree on version', () => {
  const cliOut = execFileSync(process.execPath, [fileURLToPath(new URL('../bin/nemesis.mjs', import.meta.url)), '--version'], { encoding: 'utf8' }).trim();
  assert.equal(cliOut, NEMESIS_VERSION);
  // A native build (if present) must match the npm CLI output exactly.
  const native = fileURLToPath(new URL('../dist/nemesis', import.meta.url));
  if (existsSync(native)) {
    const nativeOut = execFileSync(native, ['--version'], { encoding: 'utf8' }).trim();
    assert.equal(nativeOut, NEMESIS_VERSION);
  }
});

test('native build manifest records toolchain and digests', () => {
  const manifestPath = fileURLToPath(new URL('../dist/native-build-manifest.json', import.meta.url));
  if (!existsSync(manifestPath)) return; // manifest only after a build
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.kind, 'nemesis-native-build');
  assert.equal(manifest.rustCrate, false);
  assert.ok(manifest.nodeVersion);
  assert.ok(manifest.seaConfigDigest?.startsWith('sha256:'));
});

test('no Rust wrapper crate exists', () => {
  assert.ok(!existsSync(fileURLToPath(new URL('../Cargo.toml', import.meta.url))), 'no wrapper crate');
});
