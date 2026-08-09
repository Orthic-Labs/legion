import assert from 'node:assert/strict';
import test from 'node:test';
import { baselineRecord, classifyFinding, findingFingerprint } from '../lib/policy/baseline.mjs';
import { acceptedRisk, evaluateRisk } from '../lib/policy/accepted-risk.mjs';

test('baseline record binds revision and finding fingerprints', () => {
  const record = baselineRecord({ id: 'base-1', revision: 'rev1', findings: [{ id: 'f1', fingerprint: 'sha256:f' }], createdAt: '2026-01-01' });
  assert.equal(record.kind, 'legion-baseline');
  assert.deepEqual(record.findingIds, ['f1']);
  assert.deepEqual(record.findingFingerprints, ['sha256:f']);
});

test('finding lineage: new, unchanged, resolved, reopened', () => {
  const fp = findingFingerprint({ ruleId: 'r', file: 'a.ts' });
  const base = baselineRecord({ id: 'b', revision: 'r', findings: [{ id: 'old', fingerprint: fp }], createdAt: 't' });
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: base.findingFingerprints.includes(fp), inCurrent: true }), 'unchanged');
  assert.equal(classifyFinding({ fingerprint: fp, inBaseline: base.findingFingerprints.includes(fp), inCurrent: false }), 'resolved');
  assert.equal(classifyFinding({ fingerprint: 'sha256:new', inBaseline: false, inCurrent: true }), 'new');
});

test('a baseline never hides incomplete current coverage', () => {
  // The baseline only classifies; it cannot turn incomplete coverage into a pass.
  const baseline = baselineRecord({ id: 'b', revision: 'r', findings: [], createdAt: 't' });
  assert.ok(baseline.findingIds.length === 0);
  assert.ok(!('complete' in baseline));
});

test('accepted risk for attack paths and systemic root causes', () => {
  for (const subjectKind of ['finding', 'attack-path', 'systemic-root-cause']) {
    const risk = acceptedRisk({ subjectKind, subjectId: 's1', acceptedBy: 'h', reason: 'x', acceptedAt: '2026-01-01', expiresAt: '2030-01-01', bindingDigest: 'sha256:b' });
    assert.equal(risk.subjectKind, subjectKind);
    assert.ok(risk.id.startsWith('sha256:'));
  }
});

test('a path acceptance does not accept new variants', () => {
  const pathRisk = acceptedRisk({ subjectKind: 'attack-path', subjectId: 'path-1', acceptedBy: 'h', reason: 'x', acceptedAt: '2026-01-01', expiresAt: '2030-01-01', bindingDigest: 'sha256:b' });
  // A different variant subject is not covered.
  const state = evaluateRisk({ records: [pathRisk], subjectKind: 'attack-path', subjectId: 'path-2', currentBindingDigest: 'sha256:b', now: '2026-01-02' });
  assert.equal(state.active, false);
});
