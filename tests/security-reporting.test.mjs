import assert from 'node:assert/strict';
import test from 'node:test';
import { reportToSarif } from '../scripts/report-to-sarif.mjs';

test('SARIF primitive result references candidate and variant receipt', () => {
  const sarif = reportToSarif({
    findings: [{
      id: 'f1', candidateId: 'c1', ruleId: 'credentials.format', severity: 'high', title: 'Credential',
      file: 'a.ts', line: 3, variantReceiptId: 'sha256:receipt', relatedAttackPathIds: ['path-1'],
    }],
  });
  const result = sarif.runs[0].results[0];
  assert.equal(result.properties.candidateId, 'c1');
  assert.equal(result.properties.variantReceiptId, 'sha256:receipt');
  assert.deepEqual(result.properties.relatedAttackPathIds, ['path-1']);
});

test('SARIF emits an ordered code flow for a proven path', () => {
  const sarif = reportToSarif({
    security: {
      attackPaths: {
        proven: [{
          id: 'path-1', severity: 'critical', priority: 'PRIVILEGE_ESCALATION',
          start: { factIds: ['f1'] }, objective: { id: 'objective.privilege-escalation' },
          stepAssessments: [
            { candidateId: 'c1', file: 'a.ts', line: 3 },
            { candidateId: 'c2', file: 'b.ts', line: 9 },
          ],
          constituentFindingIds: ['f1'], proof: { digest: 'sha256:p' },
        }],
      },
    },
  });
  const pathResult = sarif.runs[0].results.find((result) => result.ruleId.startsWith('security.attack-path'));
  assert.ok(pathResult, 'path result present');
  assert.equal(pathResult.partialFingerprints['nemesisPath/v1'], 'path-1');
  assert.equal(pathResult.codeFlows[0].threadFlows[0].locations.length, 2);
  assert.equal(pathResult.codeFlows[0].threadFlows[0].locations[0].order, 0);
});

test('partial paths are never emitted as failing SARIF results', () => {
  const sarif = reportToSarif({
    security: {
      attackPaths: {
        proven: [],
        partiallySupported: [{ id: 'p2', severity: null }],
      },
    },
  });
  assert.ok(!sarif.runs[0].results.some((result) => result.ruleId.startsWith('security.attack-path')));
});

test('path identity is stable across line shifts', () => {
  const make = (line) => reportToSarif({
    security: {
      attackPaths: {
        proven: [{
          id: 'path-1', severity: 'high', priority: 'PRIVILEGE_ESCALATION',
          objective: { id: 'objective.privilege-escalation' },
          stepAssessments: [{ candidateId: 'c1', file: 'a.ts', line }],
          constituentFindingIds: [],
        }],
      },
    },
  });
  const a = make(3).runs[0].results.find((r) => r.ruleId.startsWith('security.attack-path'));
  const b = make(40).runs[0].results.find((r) => r.ruleId.startsWith('security.attack-path'));
  assert.equal(a.partialFingerprints['nemesisPath/v1'], b.partialFingerprints['nemesisPath/v1']);
});

test('no double-counted vulnerability total: paths and primitives counted separately', () => {
  const sarif = reportToSarif({
    findings: [{ id: 'f1', ruleId: 'r', severity: 'high', title: 'x' }],
    security: {
      attackPaths: {
        proven: [{
          id: 'path-1', severity: 'critical', priority: 'DIRECT_CROWN_JEWEL',
          objective: { id: 'objective.crown-jewel-access' },
          stepAssessments: [], constituentFindingIds: ['f1'],
        }],
      },
    },
  });
  const primitive = sarif.runs[0].results.filter((r) => r.ruleId === 'r');
  const paths = sarif.runs[0].results.filter((r) => r.ruleId.startsWith('security.attack-path'));
  assert.equal(primitive.length, 1);
  assert.equal(paths.length, 1);
  // Distinct rule IDs and fingerprints — never merged into one vulnerability.
  assert.notEqual(primitive[0].ruleId, paths[0].ruleId);
  assert.notEqual(primitive[0].partialFingerprints['nemesisFinding/v1'], paths[0].partialFingerprints['nemesisPath/v1']);
});
