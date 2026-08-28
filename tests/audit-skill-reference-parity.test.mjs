import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

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
  assert.match(skill, /legion audit <root> --out <out-dir>/);
  for (const file of files) {
    assert.equal(
      readFileSync(resolve(root, 'skills/audit/references', file), 'utf8'),
      readFileSync(resolve(root, 'references', file), 'utf8'),
      file,
    );
    assert.match(skill, new RegExp(`references/${file.replace('.', '\\.')}`));
  }
});
