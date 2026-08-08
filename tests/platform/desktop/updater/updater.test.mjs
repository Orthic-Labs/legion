import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateUpdaterEvidence, UPDATE_CASES } from '../../../../providers/runtime/desktop/updater/index.mjs';

const receipt = (status, digest) => ({ status, artifactDigest: digest });

test('B4-023 stops execution after manifest/payload verification failure', () => {
  const result = evaluateUpdaterEvidence({
    artifact: { digest: `sha256:${'a'.repeat(64)}`, publisher: 'Orthic Labs' },
    verification: { application: receipt('pass', `sha256:${'a'.repeat(64)}`), metadata: receipt('fail', `sha256:${'a'.repeat(64)}`), payload: receipt('fail', `sha256:${'a'.repeat(64)}`), timestamp: receipt('pass', `sha256:${'a'.repeat(64)}`) }, attempts: [{ id: 'forged-manifest', verificationPassed: false, executed: false, terminal: true }],
  });
  assert.equal(result.status, 'fail');
  assert.equal(result.stopShip, true);
  assert.equal(result.attempts[0].executed, false);
});

test('B4-023 requires QA/update/distribution promotion equivalence', () => {
  const digest = `sha256:${'b'.repeat(64)}`;
  const verification = Object.fromEntries(['application', 'metadata', 'payload', 'timestamp'].map((id) => [id, receipt('pass', digest)]));
  const attempts = UPDATE_CASES.map((id) => ({ id, verificationPassed: true, executed: id === 'staged-rollout', terminal: true }));
  const result = evaluateUpdaterEvidence({ artifact: { digest, publisher: 'Orthic Labs' }, verification, attempts, promotion: { qaDigest: digest, updateDigest: digest, distributedDigest: digest, privilegedService: { revalidated: true }, channel: 'stable', rollout: 'staged', qaGate: 'mandatory', mandatory: true, logs: ['verification complete'] } });
  assert.equal(result.status, 'pass');
  assert.equal(result.promotionEquivalent, true);
});

test('B4-023 cannot pass without promotion, negative cases, privileged revalidation & redacted logs', () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  const result = evaluateUpdaterEvidence({ artifact: { digest, publisher: 'x' }, verification: Object.fromEntries(['application', 'metadata', 'payload', 'timestamp'].map((id) => [id, receipt('pass', digest)])) });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('promotion-evidence-missing'));
  assert.ok(result.coverageGaps.includes('mandatory-qa-promotion-missing'));
});
