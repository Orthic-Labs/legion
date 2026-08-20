import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');

for (const [skill, count, methodPointer] of [
  ['architect', 14, 'doctrine/architecture'],
  ['debugger', 9, 'references/manual.md'],
]) test(`${skill} public capability owns its method & retains recovered eval coverage`, () => {
  const base = resolve(root, 'skills', skill);
  const skillText = readFileSync(resolve(base, 'SKILL.md'), 'utf8');
  const manifest = JSON.parse(readFileSync(resolve(base, 'evals/evals.json'), 'utf8'));
  const cases = Object.values(manifest).filter(Array.isArray).flat();

  assert.equal(manifest.skill, skill);
  assert.equal(cases.length, count);
  // The capability owns its method and does not route through Sage for routine work.
  assert.doesNotMatch(skillText, /agents\/sage\.md/);
  assert.doesNotMatch(skillText, /Sage (?:Architect|Diagnose)/i);
  assert.match(skillText, new RegExp(methodPointer.replace('.', '\\.')));
  assert.ok(existsSync(resolve(base, 'references/manual.md')));
});
