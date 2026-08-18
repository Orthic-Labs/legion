import assert from 'node:assert/strict';
import test from 'node:test';
import {
  adrCanonClarifyBindings,
  adrCanonClarifyRuntimeIds,
  executeAdrCanonClarifyCase,
  validateAdrCanonClarifyObservation,
  evaluateAdrAdmission,
  evaluateCanonOwnerDrift,
  evaluateGeneratedSourceDrift,
  evaluateClarificationConvergence,
  evaluateFogMetadata,
} from '../lib/s11-bindings/eval-adr-canon-clarify.mjs';

test('all six evaluators return independently validated structured observations', () => {
  assert.deepEqual(adrCanonClarifyRuntimeIds(), Object.keys(adrCanonClarifyBindings));
  for (const id of adrCanonClarifyRuntimeIds()) assert.equal(validateAdrCanonClarifyObservation(id, executeAdrCanonClarifyCase(id)), true);
});

test('ADR admission and canon drift enforce typed semantics', () => {
  assert.equal(evaluateAdrAdmission({ reversible: true, boundaryAccepted: true, architectureWorth: false }).artifact, 'LOCAL_DECISION_LOG');
  assert.equal(evaluateCanonOwnerDrift({ owners: ['a', 'b'] }).status, 'FAIL');
  assert.equal(evaluateGeneratedSourceDrift({ source: { x: 1 }, generated: { x: 2 } }).remediation, 'REGENERATE_FROM_SOURCE');
});

test('clarification convergence preserves FOG as metadata', () => {
  assert.equal(evaluateClarificationConvergence({ impact: { acceptance: false, ranking: false, authority: false, safety: false, increment: false }, dispositionsRecorded: true }).status, 'STOP');
  assert.equal(evaluateFogMetadata({ question: '', sharpeningObservation: '' }).scheduledWork, false);
});
