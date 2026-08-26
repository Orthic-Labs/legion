import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { LEGION_VERSION } from '../src/lib/version.mjs';

test('development workspace version agrees with native release and schema versions', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.version, LEGION_VERSION);
  assert.equal(pkg.name, '@orthic-labs/legion');
  assert.equal(pkg.private, true);
  assert.equal(pkg.bin, undefined);
  assert.equal(pkg.engines.node, '>=22.13');
  // Core API and schema versions agree.
  const config = JSON.parse(readFileSync(new URL('../src/schemas/legion-config-v1.schema.json', import.meta.url), 'utf8'));
  assert.equal(config.properties.schemaVersion.const, 1);
});

test('package files allowlist excludes internal state', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const files = pkg.files;
  assert.ok(files.includes('src/bin/'));
  assert.ok(files.includes('src/lib/'));
  assert.ok(files.includes('src/registry/'));
  assert.ok(files.includes('src/schemas/'));
  // No internal dispatch/plan docs, no runtime audit dirs.
  assert.ok(!files.some((f) => /dispatch|_audit|UPGRADE/i.test(f)));
});

test('package smoke manifest is present and forbids internal content', () => {
  const manifest = JSON.parse(readFileSync(new URL('../MANIFEST.package.json', import.meta.url), 'utf8'));
  assert.equal(manifest.name, '@orthic-labs/legion');
  assert.ok(manifest.forbiddenContents.some((f) => /dispatch/i.test(f)));
  assert.ok(manifest.forbiddenContents.some((f) => /operator/i.test(f)));
});
