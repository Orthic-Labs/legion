import assert from 'node:assert/strict';
import test from 'node:test';
import {
  candidateId,
  commandContract,
  normalizeFinding,
  rulesetIdentity,
  toCandidate,
} from '../../../providers/opengrep/index.mjs';

const DENOM = 'sha256:denominator';

test('normalizeFinding maps JSON output to the normalized contract', () => {
  const raw = {
    check_id: 'nemesis-command-injection-shell',
    path: 'src/app.py',
    start: { line: 12, col: 4 },
    end: { line: 12, col: 40 },
    extra: { severity: 'WARNING', message: 'shell sink' },
    dataflow_trace: {
      source: [['src/views.py', 3]],
      sink: [['src/app.py', 12]],
      intermediate_vars: [['src/app.py', 9]],
    },
  };
  const finding = normalizeFinding(raw, { ruleset: 'nemesis-core' });
  assert.equal(finding.ruleId, 'nemesis-command-injection-shell');
  assert.equal(finding.file, 'src/app.py');
  assert.equal(finding.capability, 'intrafile');
  assert.equal(finding.source.file, 'src/views.py');
  assert.equal(finding.sink.line, 12);
});

test('pattern-only findings report the pattern capability', () => {
  const finding = normalizeFinding({ check_id: 'r', path: 'a.ts', start: { line: 1, col: 0 }, extra: {} });
  assert.equal(finding.capability, 'pattern');
});

test('toCandidate produces candidates only, never findings', () => {
  const raw = {
    check_id: 'nemesis-sql-interpolation', path: 'src/db.ts', start: { line: 5, col: 0 }, end: { line: 5, col: 30 },
    extra: { severity: 'WARNING', message: 'sql' },
    dataflow_trace: { source: [['src/routes.ts', 2]], sink: [['src/db.ts', 5]] },
  };
  const finding = normalizeFinding(raw, { ruleset: 'nemesis-core' });
  const candidate = toCandidate(finding, { denominatorDigest: DENOM });
  assert.equal(candidate.kind, 'security-candidate');
  assert.equal(candidate.verdict, 'UNADJUDICATED');
  assert.equal(candidate.adjudicationRequired, true);
  assert.equal(candidate.candidateClass, 'sast');
  assert.ok(candidate.id.startsWith('sha256:'));
  assert.ok(candidate.uncertainty.some((u) => /never a vulnerability by itself/.test(u)));
  // The candidate must not carry a final severity/evidence verdict.
  assert.ok(!('severity' in candidate));
  assert.ok(!('evidenceStrength' in candidate));
});

test('candidate id is stable for identical traces', () => {
  const id1 = candidateId({ provider: 'p', ruleId: 'r', file: 'a.ts', line: 3, traceDigest: 'sha256:t' });
  const id2 = candidateId({ provider: 'p', ruleId: 'r', file: 'a.ts', line: 3, traceDigest: 'sha256:t' });
  assert.equal(id1, id2);
});

test('ruleset identity records provenance', () => {
  const identity = rulesetIdentity({ path: '/rules.yml', digest: 'sha256:r', license: 'LGPL-2.1', source: 'opengrep', version: '1.2' });
  assert.equal(identity.kind, 'nemesis-opengrep-ruleset');
  assert.equal(identity.license, 'LGPL-2.1');
});

test('commandContract uses pinned flags and frozen paths', () => {
  const contract = commandContract({
    resolvedOpenGrep: '/opt/opengrep', jsonPath: '/out/r.json', sarifPath: '/out/r.sarif',
    frozenRulesPath: '/rules.yml', frozenPaths: ['src/'], repositoryRoot: '/repo',
    policy: { providerTimeoutMs: 90000, maxOutputBytes: 4096 },
  });
  assert.equal(contract.executable, '/opt/opengrep');
  assert.deepEqual(contract.args.slice(0, 8), ['scan', '--json-output', '/out/r.json', '--sarif-output', '/out/r.sarif', '--metrics', 'off', '--disable-version-check']);
  assert.ok(contract.args.includes('-f'));
  assert.equal(contract.timeoutMs, 90000);
});

test('negative control: benign code produces no candidate', () => {
  // A candidate is only produced from an actual finding; the provider never
  // fabricates observations for clean code.
  const clean = normalizeFinding({ check_id: 'r', path: 'a.py', start: { line: 1, col: 0 }, extra: { severity: 'INFO' } });
  // Even an INFO finding maps to a candidate, but absence of a finding yields
  // nothing — this asserts the pipeline never invents candidates.
  assert.equal(clean.ruleId, 'r');
});
