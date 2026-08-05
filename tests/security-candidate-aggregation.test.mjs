import assert from 'node:assert/strict';
import test from 'node:test';
import { aggregateSecurityCandidates } from '../audit-run.mjs';

test('candidate-generating provider findings enter adjudication report', () => {
  const report = aggregateSecurityCandidates(
    {
      provider: 'security.internal-suite', complete: true,
      candidates: [{ id: 'internal-1', provider: 'security.internal-suite', ruleId: 'security.command', claim: 'command sink', evidence: [{ file: 'src/a.ts', line: 1 }] }],
      coverage: {}, coverageGaps: [],
    },
    [
      {
        provider: 'data.internal-suite',
        findings: [{ id: 'data-1', ruleId: 'data.sql-interpolation', level: 'error', message: 'SQL interpolation', file: 'src/db.ts', line: 12 }],
      },
      {
        provider: 'infrastructure.internal-suite',
        findings: [{ ruleId: 'infra.container.privileged', level: 'error', message: 'Privileged container', file: 'deploy/pod.yml', line: 8 }],
      },
    ],
  );
  assert.equal(report.candidates.length, 3);
  assert.deepEqual(report.coverage.candidateProviders, ['data.internal-suite', 'infrastructure.internal-suite', 'security.internal-suite']);
  assert.ok(report.candidates.every((candidate) => candidate.adjudicationRequired !== false));
});

test('framework family findings enter adjudication report under their concrete provider id', () => {
  const report = aggregateSecurityCandidates(
    { provider: 'security.internal-suite', complete: true, candidates: [], coverage: {}, coverageGaps: [] },
    [{
      provider: 'framework.framework.next',
      family: 'framework.next',
      findings: [{
        ruleId: 'framework.next.missing-csrf',
        level: 'error',
        message: 'Server action exposes state change without visible CSRF control.',
        file: 'app/action.ts',
        line: 5,
      }],
    }],
  );
  assert.equal(report.candidates.length, 1);
  assert.equal(report.candidates[0].provider, 'framework.framework.next');
  assert.equal(report.candidates[0].ruleId, 'framework.next.missing-csrf');
  assert.deepEqual(report.coverage.candidateProviders, ['framework.framework.next']);
});

test('non-candidate provider findings are not promoted', () => {
  const report = aggregateSecurityCandidates({ complete: true, candidates: [], coverage: {}, coverageGaps: [] }, [
    { provider: 'visual.core', findings: [{ id: 'visual-1', ruleId: 'visual.diff', message: 'pixel diff' }] },
  ]);
  assert.deepEqual(report.candidates, []);
});
