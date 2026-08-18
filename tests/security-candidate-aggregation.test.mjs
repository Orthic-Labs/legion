import assert from 'node:assert/strict';
import test from 'node:test';
import { aggregateSecurityCandidates } from '../tools/audit/audit-run.mjs';

// The frozen plan record is the only authority for candidate providers.
const CANDIDATE_PLAN = {
  providers: [
    { id: 'security.internal-suite', producesSecurityCandidates: true },
    { id: 'data.internal-suite', producesSecurityCandidates: true },
    { id: 'infrastructure.internal-suite', producesSecurityCandidates: true },
    { id: 'framework.major-suite', producesSecurityCandidates: true },
    { id: 'visual.core', producesSecurityCandidates: false },
  ],
};

test('candidate provider candidates enter the adjudication report', () => {
  const report = aggregateSecurityCandidates(
    CANDIDATE_PLAN,
    {
      provider: 'security.internal-suite', complete: true,
      candidates: [{ id: 'internal-1', provider: 'security.internal-suite', ruleId: 'security.command', claim: 'command sink', evidence: [{ file: 'src/a.ts', line: 1 }] }],
      coverage: {}, coverageGaps: [],
    },
    [
      {
        provider: 'data.internal-suite',
        ownerProvider: 'data.internal-suite',
        candidates: [{ id: 'data-1', ruleId: 'data.sql-interpolation', severityHint: 'high', claim: 'SQL interpolation', file: 'src/db.ts', line: 12 }],
        findings: [],
      },
      {
        provider: 'infrastructure.internal-suite',
        ownerProvider: 'infrastructure.internal-suite',
        candidates: [{ ruleId: 'infra.container.privileged', severityHint: 'high', claim: 'Privileged container', file: 'deploy/pod.yml', line: 8 }],
        findings: [],
      },
    ],
  );
  assert.equal(report.candidates.length, 3);
  assert.deepEqual(report.coverage.candidateProviders, ['data.internal-suite', 'infrastructure.internal-suite', 'security.internal-suite']);
  assert.ok(report.candidates.every((candidate) => candidate.adjudicationRequired !== false));
});

test('framework family candidates enter under their owner provider authority', () => {
  const report = aggregateSecurityCandidates(
    CANDIDATE_PLAN,
    { provider: 'security.internal-suite', complete: true, candidates: [], coverage: {}, coverageGaps: [] },
    [{
      provider: 'framework.framework.next',
      ownerProvider: 'framework.major-suite',
      candidates: [{
        ruleId: 'framework.next.missing-csrf',
        severityHint: 'high',
        claim: 'Server action exposes state change without visible CSRF control.',
        file: 'app/action.ts',
        line: 5,
      }],
      findings: [],
    }],
  );
  assert.equal(report.candidates.length, 1);
  assert.equal(report.candidates[0].provider, 'framework.framework.next');
  assert.equal(report.candidates[0].ruleId, 'framework.next.missing-csrf');
  assert.deepEqual(report.coverage.candidateProviders, ['framework.framework.next']);
});

test('non-candidate provider findings and candidates are not promoted', () => {
  const report = aggregateSecurityCandidates(
    CANDIDATE_PLAN,
    { complete: true, candidates: [], coverage: {}, coverageGaps: [] },
    [
      { provider: 'visual.core', findings: [{ id: 'visual-1', ruleId: 'visual.diff', message: 'pixel diff' }] },
      { provider: 'visual.core', ownerProvider: 'visual.core', candidates: [{ id: 'visual-c', ruleId: 'visual.diff', claim: 'pixel diff' }], findings: [] },
    ],
  );
  assert.deepEqual(report.candidates, []);
});

test('candidate provider emitting findings throws a contract violation', () => {
  assert.throws(() => aggregateSecurityCandidates(
    CANDIDATE_PLAN,
    { complete: true, candidates: [], coverage: {}, coverageGaps: [] },
    [{
      provider: 'data.internal-suite',
      ownerProvider: 'data.internal-suite',
      findings: [{ id: 'data-1', ruleId: 'data.sql-interpolation', message: 'SQL interpolation' }],
    }],
  ), /candidate provider .* emitted findings/);
});

test('unplanned candidate source is rejected', () => {
  // A result claiming to be a candidate provider that the plan never authorized
  // must not enter the report.
  const report = aggregateSecurityCandidates(
    CANDIDATE_PLAN,
    { complete: true, candidates: [], coverage: {}, coverageGaps: [] },
    [{
      provider: 'rogue.provider',
      ownerProvider: 'rogue.provider',
      candidates: [{ id: 'rogue-1', ruleId: 'rogue.rule', claim: 'not authorized' }],
      findings: [],
    }],
  );
  assert.deepEqual(report.candidates, []);
});
