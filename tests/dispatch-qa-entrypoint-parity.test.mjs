import assert from 'node:assert/strict';
import test from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
for (const skill of ['dispatch', 'qa']) test(`${skill} public entrypoint routes to shared engine`, () => {
  const base = resolve(root, 'skills', skill);
  assert.ok(existsSync(resolve(base, 'SKILL.md')));
  const evals = JSON.parse(readFileSync(resolve(base, 'evals/evals.json')));
  const count = Object.values(evals).filter(Array.isArray).flat().length;
  assert.equal(count, skill === 'dispatch' ? 36 : 10);
});

test('dispatch & qa scripts are adapters, not duplicated engines', () => {
  assert.match(readFileSync(resolve(root, 'skills/dispatch/scripts/validate-dispatch.py'), 'utf8'), /dispatch-validator/);
  for (const script of ['qa.mjs', 'qa-shot.mjs', 'qa-functional.mjs']) assert.match(readFileSync(resolve(root, 'skills/qa/scripts', script), 'utf8'), /lib\/qa-engine/);
});

test('dispatch example packet has a receipt-bound route bundle', () => {
  const examples = resolve(root, 'skills/dispatch/examples');
  const packet = JSON.parse(readFileSync(resolve(examples, 'sage-architect-dispatch.json')));
  const receipt = JSON.parse(readFileSync(resolve(examples, 'sage-architect-dispatch.receipt.json')));
  assert.equal(packet.packetType, 'sage');
  assert.equal(packet.routeBundle.path, 'skills/dispatch/examples/sage-architect-route.json');
  assert.equal(receipt.schema_version, 3);
  assert.equal(receipt.referenced_artifacts.length, 1);
});
