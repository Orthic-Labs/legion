import assert from 'node:assert/strict';
import test from 'node:test';
import { topologicalProviders, validateProviderDag, validateRoleOutput } from '../lib/providers/sdk/dag.mjs';

const P = (id, deps = [], produces = [], consumes = [], role = 'deterministic') => ({
  id, providerVersion: '1.0.0', role, phase: 'runtime',
  dependsOn: deps, produces, consumes,
  activation: { kind: 'always' }, runner: { kind: 'runtime-script' },
  benchmark: { status: 'unproven', requiredForCleanClaim: true },
});

test('topological order respects dependencies', () => {
  const ordered = topologicalProviders([
    P('c', ['a', 'b']), P('a', []), P('b', ['a']),
  ]);
  assert.deepEqual(ordered.map((p) => p.id), ['a', 'b', 'c']);
});

test('unknown dependency is rejected', () => {
  assert.throws(() => topologicalProviders([P('a', ['ghost'])]), /depends on unknown/);
});

test('self-dependency is rejected', () => {
  assert.throws(() => topologicalProviders([P('a', ['a'])]), /depends on itself/);
});

test('dependency cycle is rejected', () => {
  assert.throws(() => topologicalProviders([P('a', ['b']), P('b', ['a'])]), /cycle/);
});

test('unproduced consumed artifact is rejected', () => {
  assert.throws(() => validateProviderDag([P('a', [], [], ['security-surface-model'])]), /consumes unproduced/);
});

test('duplicate singleton producer is rejected', () => {
  assert.throws(() => validateProviderDag([
    P('a', [], ['security-candidates']),
    P('b', [], ['security-candidates']),
  ]), /produced by both/);
});

test('role/output authority violations are rejected', () => {
  // A model-builder may not produce security-candidates.
  assert.throws(() => validateRoleOutput(P('a', [], ['security-candidates'], [], 'model-builder')), /may not produce/);
  // An adjudicator may not produce findings.
  assert.throws(() => validateRoleOutput(P('a', [], ['findings'], [], 'adjudicator')), /may not produce/);
  // A candidate-generator may not produce attack-path-hypotheses.
  assert.throws(() => validateRoleOutput(P('a', [], ['attack-path-hypotheses'], [], 'candidate-generator')), /may not produce/);
  // Evidence-synthesizer may produce findings.
  assert.doesNotThrow(() => validateRoleOutput(P('a', [], ['findings'], [], 'evidence-synthesizer')));
});

test('unknown role is rejected', () => {
  assert.throws(() => validateRoleOutput({ id: 'x', role: 'not-a-role', produces: [] }), /unknown role/);
});

test('valid DAG validates cleanly', () => {
  assert.equal(validateProviderDag([
    P('surface', [], ['security-surface-model'], [], 'model-builder'),
    P('packs', ['surface'], ['security-candidates'], ['security-surface-model'], 'candidate-generator'),
  ]), true);
});
