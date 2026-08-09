import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateFixLoop, fixProposal, FIX_STOPS } from '../../lib/remediation/fix-contract.mjs';
import { mechanicalAstGrepProposal, mechanicalConfigProposal, mechanicalDependencyProposal } from '../../lib/remediation/mechanical.mjs';
import { agentPatchPacket, agentPatchProposal } from '../../lib/remediation/agent-patch.mjs';

const FINDING = { id: 'f1', ruleId: 'r', rootCauseDigest: 'sha256:root' };

test('fix proposal binds finding, root cause, patch, and validation commands', () => {
  const proposal = fixProposal({
    findingId: 'f1', rootCauseDigest: 'sha256:root', producer: { kind: 'mechanical' },
    targetPaths: ['a.ts'], preconditions: ['p'], patch: { path: 'patches/fix.patch', digest: 'sha256:d' },
    expectedBehavior: ['b'], risks: ['r'], validationCommands: ['v'], tier: 'MECHANICAL',
  });
  assert.equal(proposal.kind, 'legion-fix-proposal');
  assert.equal(proposal.findingId, 'f1');
  assert.equal(proposal.tier, 'MECHANICAL');
  assert.ok(proposal.id.startsWith('sha256:'));
});

test('mechanical ast-grep proposal is idempotent by id', () => {
  const a = mechanicalAstGrepProposal({ finding: FINDING, edits: [{ file: 'a.ts' }] });
  const b = mechanicalAstGrepProposal({ finding: FINDING, edits: [{ file: 'a.ts' }] });
  assert.equal(a.id, b.id);
  assert.equal(a.tier, 'MECHANICAL');
});

test('mechanical config and dependency producers exist with validation commands', () => {
  const config = mechanicalConfigProposal({ finding: FINDING, configPath: 'config.json', change: {} });
  assert.equal(config.targetPaths[0], 'config.json');
  assert.ok(config.validationCommands.includes('config-schema-check'));
  const dep = mechanicalDependencyProposal({ finding: FINDING, manifestPath: 'package.json', dependencyChange: {} });
  assert.equal(dep.targetPaths[0], 'package.json');
});

test('fix loop stops on max-batches at exactly 4', () => {
  assert.deepEqual(evaluateFixLoop({ batchIndex: 4, maxBatches: 4, progress: true }), { stop: true, reason: 'max-batches' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 3, maxBatches: 4, progress: true }), { stop: false, reason: null });
});

test('fix loop stops on every stop condition', () => {
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, progress: false }), { stop: true, reason: 'no-progress' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, regression: true }), { stop: true, reason: 'regression' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, drift: true }), { stop: true, reason: 'plan-drift' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, newHighCritical: true }), { stop: true, reason: 'new-high-critical' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, manualRequired: true }), { stop: true, reason: 'manual-finding-required' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, missingVariantProof: true }), { stop: true, reason: 'missing-variant-or-proof' });
  assert.deepEqual(evaluateFixLoop({ batchIndex: 0, scopeExpansion: true }), { stop: true, reason: 'scope-expansion' });
});

test('stop reasons are frozen and complete', () => {
  assert.deepEqual(FIX_STOPS, ['max-batches', 'no-progress', 'regression', 'plan-drift', 'new-high-critical', 'manual-finding-required', 'missing-variant-or-proof', 'scope-expansion']);
});

test('agent patch packet is bounded and worktree-isolated', () => {
  const packet = agentPatchPacket({ finding: FINDING, worktreePath: '/w', scope: ['a.ts'], maxBatches: 4 });
  assert.equal(packet.bounded, true);
  assert.equal(packet.worktreePath, '/w');
  assert.match(packet.verification, /neutral verification/);
});

test('agent patch proposal is AGENT_GUIDED and never self-verified', () => {
  const packet = agentPatchPacket({ finding: FINDING, worktreePath: '/w', scope: [] });
  const proposal = agentPatchProposal({ finding: FINDING, packet, patch: { targetPaths: ['a.ts'], path: 'patches/agent.patch', digest: 'sha256:d' } });
  assert.equal(proposal.tier, 'AGENT_GUIDED');
  assert.ok(proposal.preconditions.includes('packet is bounded'));
  assert.ok(proposal.preconditions.includes('worktree is isolated'));
});

test('manual findings are never auto-applied', () => {
  // No mechanical/agent producer emits a MANUAL-tier proposal; MANUAL fixes
  // exist only as human steps.
  const mechanical = mechanicalAstGrepProposal({ finding: FINDING, edits: [] });
  const agent = agentPatchProposal({ finding: FINDING, packet: agentPatchPacket({ finding: FINDING, worktreePath: '/w', scope: [] }), patch: {} });
  assert.notEqual(mechanical.tier, 'MANUAL');
  assert.notEqual(agent.tier, 'MANUAL');
});
