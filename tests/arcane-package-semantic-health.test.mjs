import assert from 'node:assert/strict';
import test from 'node:test';
import { runSemanticHealth, SEMANTIC_PROBE_TIMEOUT_MS } from '../src/lib/verification/arcane/semantic-health.mjs';

test('EC-603 semantic health runs fresh behavior probes', () => {
  const report = runSemanticHealth();
  assert.equal(report.healthy, true, JSON.stringify(report));
  assert.deepEqual(report.probes.map(({ id }) => id), [
    'generated-input-rejection', 'ambient-availability-bypass', 'locked-unavailable-denial', 'uncertified-stop-exit',
    'two-denial-release', 'recovery-preservation', 'adapter-parity',
    'budget_store_integrity', 'budget_binding_exactness', 'budget_monotonicity', 'budget_stop_enforcement',
    'budget_role_cap_enforcement', 'budget_amendment_authority',
  ]);
});

test('EC-603 semantic health reports injected behavior failure as unhealthy', () => {
  const report = runSemanticHealth({ env: { ARCANE_SEMANTIC_HEALTH_INJECT_FAILURE: 'ambient-availability-bypass' } });
  assert.equal(report.healthy, false);
  assert.equal(report.probes.find(({ id }) => id === 'ambient-availability-bypass').ok, false);
});

test('EC-603 semantic health bounds each child probe and reports lifecycle', () => {
  const calls = [];
  const lifecycle = [];
  const report = runSemanticHealth({
    spawn: (_command, _args, options) => {
      calls.push(options);
      return { stdout: '', stderr: '', error: new Error('timed out') };
    },
    onProbe: (event) => lifecycle.push(event),
  });
  assert.equal(report.healthy, false);
  assert.ok(calls.every(({ timeout }) => timeout === SEMANTIC_PROBE_TIMEOUT_MS));
  assert.equal(lifecycle.length, report.probes.length * 2);
  assert.equal(lifecycle[0].phase, 'started');
  assert.equal(lifecycle[1].phase, 'finished');
});
