import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadProviderRegistry, selectProviders } from '../src/registry/provider-registry.mjs';

const root = resolve(import.meta.dirname, '..');
const files = [
  'execution-contract.md',
  'provider-architecture.md',
  'engine-interface.md',
  'lens-routing.md',
  'manual.md',
];

test('Audit skill ships every consumed manual as a byte-identical package resource', () => {
  const skill = readFileSync(resolve(root, 'skills/audit/SKILL.md'), 'utf8');
  assert.doesNotMatch(skill, /\.\.\/\.\.\/references\//);
  assert.doesNotMatch(skill, /\.\.\/\.\.\/tools\/audit\//);
  // The native binary is the packaged runner: no `tools/` directory ships in
  // an installed plugin root, so the Node path resolved only in a checkout.
  assert.match(skill, /`legion audit <root> --out <run-dir>`/);
  assert.doesNotMatch(skill, /node <package-root>\/tools\/audit\/audit-run\.mjs/);
  assert.match(skill, /CHILD_AGENTS_MAX: 16/);
  assert.match(skill, /native-provider-composition-partial/);
  assert.match(skill, /fullAudit: false/);
  assert.match(skill, /one parallel wave/);
  assert.doesNotMatch(skill, /CHILD_AGENTS_MAX: 0/);
  for (const file of files) {
    assert.equal(
      readFileSync(resolve(root, 'skills/audit/references', file), 'utf8'),
      readFileSync(resolve(root, 'references', file), 'utf8'),
      file,
    );
    assert.match(skill, new RegExp(`references/${file.replace('.', '\\.')}`));
  }
});

test('Audit executable registry freezes every core reasoning lens', () => {
  const registry = loadProviderRegistry();
  const projection = {
    state: 'ready',
    files: ['src/index.js', 'package.json'],
    parsedExtensions: ['js'],
    auditFacts: { packageManifests: [] },
  };
  const selected = selectProviders(registry, projection).selected;
  const lenses = new Set(selected.filter(({ phase }) => phase === 'reasoning').map(({ id }) => id.replace(/^reasoning\./, '')));
  for (const lens of ['doc-drift', 'architecture', 'correctness', 'ai-slop', 'naming', 'dead-file', 'schema', 'security', 'minimize', 'performance', 'resilience', 'release-readiness']) {
    assert.equal(lenses.has(lens), true, lens);
  }
});

test('Audit runner fans independent reasoning contracts through concurrent reviewer calls', () => {
  const runner = readFileSync(resolve(root, 'tools/audit/audit-run.mjs'), 'utf8');
  assert.match(runner, /Promise\.all\([\s\S]+reasoning-contract/);
  assert.match(runner, /reasoning-reviewer-unavailable/);
});
