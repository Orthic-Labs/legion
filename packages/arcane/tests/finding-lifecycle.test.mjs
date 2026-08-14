import assert from 'node:assert/strict';
import test from 'node:test';
import {
  FindingLifecycleStore, applyScopedRecheck, filterFindingsByThreshold,
  fingerprintFinding, verifyFindingClosure,
} from '../lib/finding-lifecycle.mjs';

const finding = Object.freeze({ ruleId: 'RULE-1', subjectId: 'src/a.mjs', artifactFingerprint: 'sha256:artifact-a', severity: 'high' });

test('finding lifecycle upserts by stable fingerprint, not prose or line anchor', () => {
  const store = new FindingLifecycleStore();
  const first = store.upsert({ finding: { ...finding, message: 'old', line: 4 }, reviewRoundId: 'round-1' });
  const second = store.upsert({ finding: { ...finding, message: 'new', line: 90 }, reviewRoundId: 'round-2' });
  assert.equal(first.disposition, 'NEW_RECORD');
  assert.equal(second.disposition, 'EXISTING_RECORD');
  assert.equal(second.record.review_round_id, 'round-1');
  assert.equal(store.records().length, 1);
  assert.equal(fingerprintFinding(finding), fingerprintFinding({ ...finding, message: 'anything', line: 999 }));
});

test('finding lifecycle rejects fix-author closure & compares observed artifact evidence', () => {
  const self = verifyFindingClosure({ finding, closure: { fixAuthorId: 'alchemist', reviewerId: 'alchemist', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e-self', reviewerId: 'alchemist', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed' } });
  assert.equal(self.allowed, false);
  assert.equal(self.code, 'ARC_SELF_CERTIFICATION');
  const independent = verifyFindingClosure({ finding, closure: { fixAuthorId: 'alchemist', reviewerId: 'oracle', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e-1', reviewerId: 'oracle', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed', narrative: 'ignored' } });
  assert.equal(independent.allowed, true);
  assert.equal(independent.detail.event.event_type, 'FINDING_UPSERTED');
});

test('threshold retains informational findings & scoped recheck closes only targets', () => {
  const filtered = filterFindingsByThreshold({ findings: [{ ...finding, severity: 'high' }, { ...finding, subjectId: 'src/nit.mjs', severity: 'low' }], threshold: 3 });
  assert.equal(filtered.blocking.length, 1);
  assert.equal(filtered.informational.length, 1);
  const open = { id: 'f-1', stable_fingerprint: fingerprintFinding(finding), status: 'OPEN' };
  const close = verifyFindingClosure({ finding, closure: { fixAuthorId: 'fixer', reviewerId: 'oracle', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e-2', reviewerId: 'oracle', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed' } });
  const result = applyScopedRecheck({ records: [open], targetFindingFingerprints: [open.stable_fingerprint], closures: [{ findingFingerprint: open.stable_fingerprint, ...close }], discoveredFindings: [{ ...finding, subjectId: 'src/nit.mjs', severity: 'low' }] });
  assert.equal(result.closed.length, 1);
  assert.equal(result.deferred[0].disposition, 'DEFERRED_INFORMATIONAL');
});
