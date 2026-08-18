import { test } from 'node:test';
import assert from 'node:assert/strict';
import { executeEvidenceClosureRuntimeCase } from '../lib/s11-bindings/evidence-closure.mjs';

const row = (id, family = 'evidence') => ({ id, family });

test('S11 evidence closure bindings use production verifiers & return exact state identities', () => {
  for (const id of ['AE-EVIDENCE-ARTIFACTS-001', 'AE-EVIDENCE-ARTIFACTS-002', 'AE-EVIDENCE-FRESHNESS-001', 'AE-GATE-VALIDITY-001', 'AE-GATE-VALIDITY-002', 'AE-SEAL-REACHABILITY-001']) {
    const result = executeEvidenceClosureRuntimeCase(row(id));
    assert.equal(result.status, 'PASS', `${id}: ${result.reason ?? ''}`);
    assert.match(result.integratedStateIdentity, /^sha256:[0-9a-f]{64}$/);
  }
});

test('S11 evidence closure reports only exact absent production capabilities as pending', () => {
  const result = executeEvidenceClosureRuntimeCase(row('AE-FINDING-LIFECYCLE-002', 'finding-lifecycle'));
  assert.equal(result.status, 'PENDING');
  assert.match(result.missingCapability, /independent finding-closure verifier/);
});
