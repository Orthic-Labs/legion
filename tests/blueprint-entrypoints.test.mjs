import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

test('Blueprint is public current-state & docs entrypoint consumed by Architect & Audit', () => {
  const blueprint = readFileSync(resolve(root, 'skills/blueprint/SKILL.md'), 'utf8');
  const architect = readFileSync(resolve(root, 'skills/architect/SKILL.md'), 'utf8');
  const audit = readFileSync(resolve(root, 'skills/audit/SKILL.md'), 'utf8');
  assert.match(blueprint, /discoverability: public/);
  assert.match(blueprint, /hostRequirements:\s+\- blueprint-graph/);
  assert.match(blueprint, /blueprint reconcile --json/);
  assert.match(blueprint, /graph architecture/);
  assert.match(blueprint, /graph flows/);
  assert.match(architect, /routes `\/blueprint` first/);
  assert.match(audit, /public Blueprint\/Membrane/);
});
