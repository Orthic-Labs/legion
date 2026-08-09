import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LEGION_VERSION } from '../lib/version.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('package manifest version agrees with the CLI and schema versions', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.version, LEGION_VERSION);
  assert.equal(pkg.name, '@orthic-labs/legion');
  assert.equal(pkg.bin.legion, './bin/legion.mjs');
  assert.equal(pkg.engines.node, '>=22.13');
  // Core API and schema versions agree.
  const config = JSON.parse(readFileSync(new URL('../schemas/legion-config-v1.schema.json', import.meta.url), 'utf8'));
  assert.equal(config.properties.schemaVersion.const, 1);
});

test('package files allowlist excludes internal state', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const files = pkg.files;
  assert.ok(files.includes('bin/'));
  assert.ok(files.includes('lib/'));
  assert.ok(files.includes('registry/'));
  assert.ok(files.includes('schemas/'));
  // No internal dispatch/plan docs, no runtime audit dirs.
  assert.ok(!files.some((f) => /dispatch|_audit|UPGRADE/i.test(f)));
});

test('package smoke manifest is present and forbids internal content', () => {
  const manifest = JSON.parse(readFileSync(new URL('../MANIFEST.package.json', import.meta.url), 'utf8'));
  assert.equal(manifest.name, '@orthic-labs/legion');
  assert.ok(manifest.forbiddenContents.some((f) => /dispatch/i.test(f)));
  assert.ok(manifest.forbiddenContents.some((f) => /operator/i.test(f)));
});

test('bin entry is executable and versioned', () => {
  const bin = fileURLToPath(new URL('../bin/legion.mjs', import.meta.url));
  const out = execFileSync(process.execPath, [bin, '--version'], { cwd: root, encoding: 'utf8' });
  assert.equal(out.trim(), LEGION_VERSION);
});
