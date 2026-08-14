import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');

for (const [skill, route, count, doctrine] of [
  ['architect', 'sage:architect', 14, 'sage-architect.md'],
  ['debugger', 'sage:diagnose', 9, 'sage-diagnose.md'],
]) test(`${skill} public entrypoint preserves Sage route & recovered eval coverage`, () => {
  const base = resolve(root, 'skills', skill);
  const skillText = readFileSync(resolve(base, 'SKILL.md'), 'utf8');
  const manifest = JSON.parse(readFileSync(resolve(base, 'evals/evals.json'), 'utf8'));
  const cases = Object.values(manifest).filter(Array.isArray).flat();

  assert.equal(manifest.skill, skill);
  assert.equal(manifest.route, route);
  assert.equal(cases.length, count);
  assert.match(skillText, /agents\/sage\.md/);
  assert.match(skillText, new RegExp(doctrine.replace('.', '\\.')));
  assert.ok(existsSync(resolve(base, 'references/manual.md')));
});
