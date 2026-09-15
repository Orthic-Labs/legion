import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(resolve(root, path), 'utf8');

test('research and blueprint exclude ordinary local reading', () => {
  const research = read('skills/research/SKILL.md');
  const blueprint = read('skills/blueprint/SKILL.md');
  assert.match(research, /external information/);
  assert.match(research, /local transcript inspection/);
  assert.match(research, /simple supplied-source reading/);
  assert.match(blueprint, /ordinary bounded file inspection/);
  assert.match(blueprint, /only to claims requiring graph completeness/);
});

test('debugger can repair directly and graph grounding is conditional', () => {
  const skill = read('skills/debugger/SKILL.md');
  const dependencies = JSON.parse(read('skills/debugger/dependencies.json'));
  assert.match(skill, /apply an explicitly authorized routine repair in the same task/);
  assert.match(skill, /Use Blueprint\s+only when unresolved repository relationships/);
  assert.deepEqual(dependencies.resources, []);
});

test('architect, QA, wake, and dispatch avoid universal ceremony', () => {
  assert.match(read('skills/architect/SKILL.md'), /does not imply a contract/);
  assert.match(read('skills/qa/SKILL.md'), /Focused native checks need no browser ceremony/);
  const wake = read('skills/wake/SKILL.md');
  assert.match(wake, /Use an existing completion\/event wait/);
  assert.match(wake, /Scope narrowing cancels only work outside remaining authorization/);
  assert.match(wake, /Never claim timing, execution, or deadline enforcement/);
  const dispatch = read('skills/dispatch/SKILL.md');
  assert.match(dispatch, /For ordinary delegation, stop there/);
  assert.match(dispatch, /only for\s+explicit\/locked governed work/);
});
