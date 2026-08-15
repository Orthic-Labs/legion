import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('./fixtures/stage10/handoff-fixtures.json', import.meta.url)));
const read = (path) => readFile(new URL(path, root), 'utf8');
const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const phrasePattern = (value) => new RegExp(escape(value).replaceAll(' ', '\\s+'), 'i');

const advanceAcceptance = (frozenIds, id) => {
  if (!frozenIds.includes(id)) throw new Error(`unfrozen acceptance ID: ${id}`);
  return { acceptance_id: id, status: 'advanced' };
};
const readyAntichain = (tasks, completed) => tasks
  .filter((task) => !completed.has(task.id) && task.consumes.every((input) => completed.has(input)))
  .map((task) => task.id)
  .sort();
const closeFinding = ({ mapped, fresh, exactState }) => mapped && fresh && exactState ? 'CLOSED' : 'OPEN';

test('S10-01 Sage freezes acceptance, ownership, cutover, & consumption-only execution dependencies', async () => {
  const sage = await read('doctrine/sage.md');
  for (const phrase of fixture.required_phrases['doctrine/sage.md']) assert.match(sage, phrasePattern(phrase));
  assert.deepEqual(readyAntichain(fixture.task_dag, new Set()), ['author-a', 'author-b']);
  assert.deepEqual(readyAntichain(fixture.task_dag, new Set(['author-a'])), ['author-b', 'test-a']);
  assert.deepEqual(readyAntichain(fixture.task_dag, new Set(['author-a', 'author-b'])), ['test-a', 'test-b']);
});

test('S10-02 Alchemist advances only frozen IDs, emits handoff evidence, & never mints COMPLETE', async () => {
  const alchemist = await read('doctrine/alchemist.md');
  for (const phrase of fixture.required_phrases['doctrine/alchemist.md']) assert.match(alchemist, phrasePattern(phrase));
  assert.deepEqual(advanceAcceptance(fixture.acceptance_ids, 'AC-auth'), { acceptance_id: 'AC-auth', status: 'advanced' });
  assert.throws(() => advanceAcceptance(fixture.acceptance_ids, 'AC-extra'), /unfrozen acceptance ID/);
  assert.equal(fixture.terminal_outcomes.includes('COMPLETE'), false);
  assert.deepEqual([...fixture.terminal_outcomes].sort(), ['BLOCKED', 'CANDIDATE']);
});

test('S10-03 Oracle packet, dismissal-first scope, preserved findings, & fresh closure reject authority drift', async () => {
  for (const path of ['doctrine/oracle.md', 'roster/oracle.md']) {
    const oracle = await read(path);
    for (const phrase of fixture.required_phrases[path]) assert.match(oracle, phrasePattern(phrase));
  }
  assert.equal(closeFinding({ mapped: true, fresh: true, exactState: true }), 'CLOSED');
  assert.equal(closeFinding({ mapped: true, fresh: false, exactState: true }), 'OPEN');
  assert.equal(closeFinding({ mapped: false, fresh: true, exactState: true }), 'OPEN');
});

test('S10-04 Covenant remains one-shot advisory & Legion references, rather than duplicates, constitution', async () => {
  for (const path of ['doctrine/covenant-seat.md', 'doctrine/legion.md']) {
    const body = await read(path);
    for (const phrase of fixture.required_phrases[path]) assert.match(body, phrasePattern(phrase));
    for (const phrase of fixture.forbidden_phrases[path] ?? []) assert.doesNotMatch(body, phrasePattern(phrase));
  }
});

test('S10-05 every role bundle carries same bounded handoff contract', async () => {
  for (const path of Object.keys(fixture.required_phrases).filter((path) => path.startsWith('doctrine/bundles/'))) {
    const body = await read(path);
    for (const phrase of fixture.required_phrases[path]) assert.match(body, phrasePattern(phrase));
  }
});
