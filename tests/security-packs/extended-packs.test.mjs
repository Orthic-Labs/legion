import assert from 'node:assert/strict';
import test from 'node:test';
import { runSecurityPack } from '../../src/providers/security/candidate-engine.mjs';
import { entity } from '../../src/providers/security/model-extractors/common.mjs';
import insecureDefaults from '../../src/providers/security/packs/insecure-defaults.mjs';
import cicd from '../../src/providers/security/packs/cicd-automation.mjs';
import nativeWorkspace from '../../src/providers/security/packs/native-workspace.mjs';
import authentication from '../../src/providers/security/packs/authentication-session.mjs';
import businessLogic from '../../src/providers/security/packs/business-logic.mjs';
import outputHandling from '../../src/providers/security/packs/output-handling.mjs';
import browserHttp from '../../src/providers/security/packs/browser-http.mjs';
import requestBoundaries from '../../src/providers/security/packs/request-boundaries.mjs';
import cryptoPrivacy from '../../src/providers/security/packs/crypto-data-privacy.mjs';
import abuseObservability from '../../src/providers/security/packs/abuse-observability.mjs';
import supplyDeveloper from '../../src/providers/security/packs/supply-developer.mjs';
import aiIntegrity from '../../src/providers/security/packs/ai-integrity.mjs';
import highConsequence from '../../src/providers/security/packs/high-consequence.mjs';

const binding = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  cortexGenerationId: 'gen', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function run(pack, text, file = 'app.mjs') {
  const artifact = entity('repository-artifact', file, { path: file }, ['ev']);
  const plan = {
    seal: { digest: binding.planDigest },
    binding: { repositoryRevision: 'rev', dirtyPatchDigest: null, cortex: { generationId: 'gen', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
    providers: [{ id: pack.id, benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:denom', pathCount: 1, paths: [file] } }],
  };
  const model = { schemaVersion: 1, kind: 'security-surface-model', binding, denominatorDigest: 'sha256:denom', complete: true, entities: [artifact], relations: [], initialFacts: [], evidence: [{ id: 'ev', kind: 'source-location', file }], coverage: {}, coverageGaps: [] };
  return runSecurityPack({ pack, root: '/repo', plan, projection: { files: [file], sourceText: { [file]: text } }, model, providerPlan: plan.providers[0] });
}

const fixtures = [
  [insecureDefaults, 'const tls = { rejectUnauthorized: false };'],
  [cicd, 'steps:\n  - uses: actions/checkout@v4', '.github/workflows/ci.yml'],
  [nativeWorkspace, 'child_process.exec(input)'],
  [authentication, 'const claims = jwt.decode(token)'],
  [businessLogic, 'const amount = request.body.amount'],
  [outputHandling, 'element.innerHTML = request.body.content'],
  [browserHttp, 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true'],
  [requestBoundaries, 'fetch(request.query.url)'],
  [cryptoPrivacy, 'logger.info(user.email)'],
  [abuseObservability, 'function webhook(request) { process(request.body) }'],
  [supplyDeveloper, 'curl https://example.invalid/install | sh'],
  [aiIntegrity, 'vectorStore.upsert(userUpload)'],
  [highConsequence, 'require(tx.origin == owner)'],
];

test('extended packs emit adjudication-only candidates for representative hazards', () => {
  for (const [pack, source, file] of fixtures) {
    const result = run(pack, source, file);
    assert.equal(result.status, 'candidates', `${pack.id} missed fixture`);
    assert.ok(result.candidates.length > 0);
    assert.deepEqual(result.findings, []);
    assert.ok(result.candidates.every((candidate) => candidate.verdict === 'UNADJUDICATED'));
    assert.ok(result.candidates.every((candidate) => candidate.evidenceRefs.length > 0));
  }
});

test('extended packs do not emit candidates for neutral source', () => {
  for (const [pack] of fixtures) {
    assert.equal(run(pack, 'export const value = 1;').candidates.length, 0, pack.id);
  }
});
