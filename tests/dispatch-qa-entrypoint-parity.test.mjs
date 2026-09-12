import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
for (const skill of ['dispatch', 'qa']) test(`${skill} public capability routes to shared engine`, () => {
  const base = resolve(root, 'skills', skill);
  assert.ok(existsSync(resolve(base, 'SKILL.md')));
  const evals = JSON.parse(readFileSync(resolve(base, 'evals/evals.json')));
  const groups = Object.entries(evals).filter(([, value]) => Array.isArray(value));
  const cases = groups.flatMap(([, value]) => value);
  const ids = cases.map(({ id }) => id);
  assert.equal(new Set(ids).size, ids.length, `${skill} eval IDs must be unique`);
  assert.ok(cases.every(({ expected_behavior }) => typeof expected_behavior === 'string' && expected_behavior.trim()), `${skill} evals need meaningful expected behavior`);
  if (skill === 'dispatch') {
    for (const family of ['should_trigger', 'should_not_trigger', 'output_quality', 'safety', 'pressure', 'compatibility']) assert.ok(groups.some(([name]) => name === family), `dispatch needs ${family} eval family`);
    for (const id of ['dispatch-acceptance-readback', 'dispatch-relay-never-authority', 'dispatch-worker-result-contract']) assert.ok(ids.includes(id), `dispatch needs ${id}`);
  } else {
    assert.equal(cases.length, 12);
  }
});

test('dispatch & qa scripts are adapters, not duplicated engines', () => {
  assert.match(readFileSync(resolve(root, 'skills/dispatch/scripts/validate-dispatch.py'), 'utf8'), /dispatch-validator/);
  for (const script of ['qa.mjs', 'qa-shot.mjs', 'qa-functional.mjs']) assert.match(readFileSync(resolve(root, 'skills/qa/scripts', script), 'utf8'), /lib\/qa-engine/);
});

test('dispatch example packet has a receipt-bound route bundle', () => {
  const examples = resolve(root, 'skills/dispatch/examples');
  const packet = JSON.parse(readFileSync(resolve(examples, 'sage-adjudication-dispatch.json')));
  const receipt = JSON.parse(readFileSync(resolve(examples, 'sage-adjudication-dispatch.receipt.json')));
  assert.equal(packet.packetType, 'sage');
  assert.equal(packet.routeBundle.path, 'skills/dispatch/examples/sage-adjudication.json');
  assert.equal(receipt.schema_version, 4);
  const expected = [packet.sourceArtifact, packet.promptArtifact, packet.routeBundle.path].sort();
  assert.deepEqual(receipt.referenced_artifacts.map(({ path }) => path).sort(), expected);
  for (const artifact of receipt.referenced_artifacts) {
    const bytes = readFileSync(resolve(root, artifact.path));
    assert.equal(artifact.sha256, `sha256:${createHash('sha256').update(bytes).digest('hex')}`);
  }
});
