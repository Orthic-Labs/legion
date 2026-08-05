import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runDataSuite } from '../providers/data-suite.mjs';
import { runFrameworkSuite } from '../providers/framework-suite.mjs';
import { runInfrastructureSuite } from '../providers/infrastructure-suite.mjs';
import { reportToSarif } from '../scripts/report-to-sarif.mjs';

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-authority-'));
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), content);
  }
  return root;
}

function planWith(families) {
  return { coverageFamilies: Object.entries(families).map(([id, paths]) => ({ id, denominator: { paths } })) };
}

test('data suite emits candidates with findings: [] and status candidates', () => {
  const root = fixture({ 'src/db.ts': `db.query('SELECT * FROM users WHERE id = ' + request.params.id)` });
  try {
    const result = runDataSuite({ root, files: ['src/db.ts'] });
    assert.equal(result.status, 'candidates');
    assert.equal(result.role, 'candidate-generator');
    assert.equal(result.ownerProvider, 'data.internal-suite');
    assert.ok(result.candidates.some((item) => item.ruleId === 'data.sql-interpolation'));
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('infrastructure suite emits candidates with findings: []', () => {
  const root = fixture({ 'deploy/pod.yml': 'spec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n' });
  try {
    const result = runInfrastructureSuite({ root, files: ['deploy/pod.yml'] });
    assert.equal(result.status, 'candidates');
    assert.equal(result.role, 'candidate-generator');
    assert.ok(result.candidates.some((item) => item.ruleId === 'k8s-privileged'));
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('framework family results are owned by the plan provider', () => {
  const root = fixture({ 'app/action.ts': `export async function action(req) { return redirect(req.url); }` });
  try {
    const result = runFrameworkSuite({ root, plan: planWith({ 'framework.next': ['app/action.ts'] }) })[0];
    assert.equal(result.ownerProvider, 'framework.major-suite');
    assert.equal(result.role, 'candidate-generator');
    assert.deepEqual(result.findings, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('SARIF uses the canonical Orthic Labs Nemesis identity', () => {
  const sarif = reportToSarif({ findings: [{ id: 'f1', ruleId: 'security.command', severity: 'high', title: 'Command injection', file: 'src/a.ts', line: 3 }] });
  const driver = sarif.runs[0].tool.driver;
  assert.equal(driver.name, 'Nemesis');
  assert.equal(driver.fullName, 'Orthic Labs Nemesis');
  assert.equal(driver.organization, 'Orthic Labs');
  assert.equal(driver.informationUri, 'https://github.com/Orthic-Labs/nemesis');
  assert.equal(sarif.version, '2.1.0');
  assert.ok(!JSON.stringify(sarif).includes('operator'));
});

test('SARIF results carry stable nemesisFinding partial fingerprints', () => {
  const sarif = reportToSarif({ findings: [{ id: 'f1', ruleId: 'security.command', severity: 'high', title: 'Command injection', file: 'src/a.ts', line: 3 }] });
  const result = sarif.runs[0].results[0];
  assert.equal(result.partialFingerprints['nemesisFinding/v1'], 'f1');
  // Line-number shifts must not change the semantic finding fingerprint.
  const moved = reportToSarif({ findings: [{ id: 'f1', ruleId: 'security.command', severity: 'high', title: 'Command injection', file: 'src/a.ts', line: 40 }] });
  assert.equal(moved.runs[0].results[0].partialFingerprints['nemesisFinding/v1'], 'f1');
});

test('SARIF includes root-cause fingerprint when present', () => {
  const sarif = reportToSarif({ findings: [{ id: 'f1', ruleId: 'security.command', severity: 'high', title: 'Command injection', file: 'src/a.ts', line: 3, rootCauseDigest: 'sha256:abc' }] });
  assert.equal(sarif.runs[0].results[0].partialFingerprints['nemesisRootCause/v1'], 'sha256:abc');
});
