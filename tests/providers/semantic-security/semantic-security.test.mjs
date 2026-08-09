import assert from 'node:assert/strict';
import test from 'node:test';
import { joinReachability, reachabilityGap, REACHABILITY_STATES } from '../../../lib/analysis/reachability.mjs';
import { assertRepositoryBinding, importedSarifReceipt, sarifSourceDigest } from '../../../providers/codeql/index.mjs';
import { semgrepCapability, semgrepCommand } from '../../../providers/semgrep/index.mjs';

test('missing graph evidence is unknown, never safe', () => {
  const joined = joinReachability({ vulnerability: { id: 'CVE-1' }, callEvidence: [], graphScope: 'none' });
  assert.equal(joined.reachability, 'unknown');
  assert.ok(!['reachable', 'not-reached-in-observed-graph'].includes(joined.reachability));
});

test('reached call evidence yields reachable', () => {
  const joined = joinReachability({
    vulnerability: { id: 'CVE-1' },
    callEvidence: [{ id: 'e1', reached: true }],
    graphScope: 'scip',
  });
  assert.equal(joined.reachability, 'reachable');
  assert.deepEqual(joined.evidenceRefs, ['e1']);
});

test('possible reachability stays categorical', () => {
  const joined = joinReachability({
    vulnerability: { id: 'CVE-1' },
    callEvidence: [{ id: 'e1', reached: 'possibly' }],
    graphScope: 'compiler',
  });
  assert.equal(joined.reachability, 'possibly-reachable');
});

test('examined-and-not-reached is distinct from unknown', () => {
  const joined = joinReachability({
    vulnerability: { id: 'CVE-1' },
    callEvidence: [{ id: 'e1', reached: false }, { id: 'e2', reached: false }],
    graphScope: 'codeql',
  });
  assert.equal(joined.reachability, 'not-reached-in-observed-graph');
});

test('reachability states are frozen', () => {
  assert.deepEqual(REACHABILITY_STATES, ['reachable', 'possibly-reachable', 'not-reached-in-observed-graph', 'unknown']);
});

test('reachability gap records scope and reason', () => {
  const gap = reachabilityGap({ packageName: 'lodash', graphScope: null, reason: 'no call graph' });
  assert.equal(gap.kind, 'reachability-unproven');
  assert.equal(gap.packageName, 'lodash');
});

test('imported SARIF receipt carries the source artifact and binding', () => {
  const receipt = importedSarifReceipt({
    provider: 'codeql', providerVersion: '2.17.0',
    sourceArtifact: { path: 'input/codeql.sarif', digest: 'sha256:abc' },
    repositoryBinding: { repositoryRevision: 'rev1' },
    tool: { name: 'CodeQL' }, capabilities: { languages: ['javascript'] },
  });
  assert.equal(receipt.kind, 'legion-imported-sarif');
  assert.equal(receipt.complete, true);
});

test('SARIF whose repository binding mismatches the plan is rejected', () => {
  const receipt = importedSarifReceipt({
    provider: 'codeql', providerVersion: '2.17.0',
    sourceArtifact: { path: 'x.sarif', digest: 'sha256:abc' },
    repositoryBinding: { repositoryRevision: 'old-rev' },
    tool: {}, capabilities: {},
  });
  assert.throws(() => assertRepositoryBinding(receipt, { binding: { repositoryRevision: 'new-rev' } }), /does not match plan revision/);
  assert.doesNotThrow(() => assertRepositoryBinding(receipt, { binding: { repositoryRevision: 'old-rev' } }));
});

test('SARIF without a repository binding is rejected', () => {
  const receipt = importedSarifReceipt({
    provider: 'codeql', providerVersion: '2.17.0',
    sourceArtifact: { path: 'x.sarif', digest: 'sha256:abc' },
    repositoryBinding: {}, tool: {}, capabilities: {},
  });
  assert.throws(() => assertRepositoryBinding(receipt, { binding: { repositoryRevision: 'r' } }), /no repository binding/);
});

test('sarif source digest is stable', () => {
  assert.equal(sarifSourceDigest('src/a.ts'), sarifSourceDigest('src/a.ts'));
  assert.ok(sarifSourceDigest('src/a.ts').startsWith('sha256:'));
});

test('semgrep capability distinguishes ce from platform', () => {
  const ce = semgrepCapability({ mode: 'ce', accountRequired: false, networkRequired: false });
  assert.equal(ce.mode, 'ce');
  assert.equal(ce.accountRequired, false);
  const platform = semgrepCapability({ mode: 'platform', accountRequired: true, networkRequired: true });
  assert.equal(platform.accountRequired, true);
});

test('semgrep command is local and offline-capable', () => {
  const contract = semgrepCommand({ resolvedSemgrep: '/opt/semgrep', rulesPath: '/rules.yml', repositoryRoot: '/repo', policy: {}, outputPath: '/out.json' });
  assert.equal(contract.args[0], 'scan');
  assert.ok(!JSON.stringify(contract).includes('--upload'));
  assert.ok(!JSON.stringify(contract).includes('login'));
});
