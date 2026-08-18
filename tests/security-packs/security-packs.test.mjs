import assert from 'node:assert/strict';
import test from 'node:test';
import { runSecurityPack } from '../../src/providers/security/candidate-engine.mjs';
import authorizationPack from '../../src/providers/security/packs/authorization-tenant.mjs';
import aiPromptPack from '../../src/providers/security/packs/ai-prompt-injection.mjs';
import aiOutputPack from '../../src/providers/security/packs/ai-output-handling.mjs';
import aiAgencyPack from '../../src/providers/security/packs/ai-excessive-agency.mjs';
import { entity } from '../../src/providers/security/model-extractors/common.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  cortexGenerationId: 'gen1', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(providerId) {
  return {
    seal: { digest: 'sha256:plan' },
    binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
    providers: [{ id: providerId, benchmark: { requiredForCleanClaim: true, status: 'unproven' }, denominator: { pathDigest: 'sha256:denom', pathCount: 1, paths: ['app.ts'] } }],
  };
}

function modelFor(file) {
  const artifact = entity('repository-artifact', file, { path: file }, ['ev1']);
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities: [artifact], relations: [], initialFacts: [], evidence: [{ id: 'ev1', kind: 'source-location', file }], coverage: {}, coverageGaps: [],
  };
}

function run(pack, sourceText) {
  const file = 'app.ts';
  const plan = planFor(pack.id);
  const projection = { files: [file], sourceText: { [file]: sourceText }, auditFacts: {} };
  const providerPlan = plan.providers[0];
  return runSecurityPack({ pack, root: '/repo', plan, projection, model: modelFor(file), providerPlan });
}

test('authorization pack flags tenant-object writes without owner checks', () => {
  const result = run(authorizationPack, 'await updateProject(req.params.id, body)');
  assert.equal(result.status, 'candidates');
  assert.ok(result.candidates.some((c) => c.ruleId === 'authorization.object-write.missing-owner-check'));
  assert.deepEqual(result.findings, []);
});

test('authorization pack stays clean when an owner check is present', () => {
  const result = run(authorizationPack, 'await updateProject(req.params.id, body, { tenant: currentTenant })');
  assert.ok(!result.candidates.some((c) => c.ruleId === 'authorization.object-write.missing-owner-check'));
});

test('authorization pack flags privileged functions without role checks', () => {
  const result = run(authorizationPack, 'await deleteUser(req.params.id)');
  assert.ok(result.candidates.some((c) => c.ruleId === 'authorization.privileged-function.missing-role-check'));
});

test('authorization pack flags role-gated privileged functions only when gate missing', () => {
  const result = run(authorizationPack, 'await deleteUser(req.params.id, { requireRole: "admin" })');
  assert.ok(!result.candidates.some((c) => c.ruleId === 'authorization.privileged-function.missing-role-check'));
});

test('ai prompt-injection pack flags untrusted content in prompts', () => {
  const result = run(aiPromptPack, 'const prompt = `Review this PR: ${pr.body}`;');
  assert.ok(result.candidates.some((c) => c.ruleId === 'ai.prompt-injection.indirect-untrusted-content'));
  assert.ok(result.candidates.some((c) => c.uncertainty.some((u) => /not tool compromise/.test(u))));
});

test('ai output-handling pack flags model output to shell', () => {
  const result = run(aiOutputPack, 'exec(modelOutput)');
  assert.ok(result.candidates.some((c) => c.ruleId === 'ai.output-handling.model-output-to-shell'));
});

test('ai output-handling pack flags model output to HTML', () => {
  const result = run(aiOutputPack, 'element.innerHTML = completion');
  assert.ok(result.candidates.some((c) => c.ruleId === 'ai.output-handling.model-output-to-html'));
});

test('ai excessive-agency pack flags destructive tools without approval', () => {
  const result = run(aiAgencyPack, 'const publishTool = { name: "publish", run: async () => {} };');
  assert.ok(result.candidates.some((c) => c.ruleId === 'ai.agency.destructive-tool-without-approval'));
});

test('ai excessive-agency pack accepts approval-gated tools', () => {
  const result = run(aiAgencyPack, 'const publishTool = { name: "publish", requireApproval: true, run: async () => {} };');
  assert.ok(!result.candidates.some((c) => c.ruleId === 'ai.agency.destructive-tool-without-approval'));
});

test('all packs emit candidates with empty findings and adjudication required', () => {
  for (const pack of [authorizationPack, aiPromptPack, aiOutputPack, aiAgencyPack]) {
    const result = run(pack, 'const x = update(req.params.id, body); exec(output); publish()');
    assert.deepEqual(result.findings, [], `${pack.id} must not emit findings`);
    for (const candidate of result.candidates) {
      assert.equal(candidate.verdict, 'UNADJUDICATED');
      assert.equal(candidate.adjudicationRequired, true);
    }
  }
});
