// Security fixtures bench: runs the implemented core lens packs over synthetic
// positive/negative fixtures and verifies candidate counts.
import { runSecurityPack } from '../../../providers/security/candidate-engine.mjs';
import authorizationPack from '../../../providers/security/packs/authorization-tenant.mjs';
import aiAgencyPack from '../../../providers/security/packs/ai-excessive-agency.mjs';

const BINDING = { planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null, cortexGenerationId: 'gen1', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry' };
const plan = { seal: { digest: 'sha256:plan' }, binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' }, providers: [{ id: 'x', benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:d', pathCount: 2, paths: ['app.ts', 'clean.ts'] } }] };
const file = 'app.ts';
const model = { schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:d', complete: true, entities: [], relations: [], initialFacts: [], evidence: [], coverage: {}, coverageGaps: [] };
function run(pack, sourceText) {
  const projection = { files: [file], sourceText: { [file]: sourceText }, auditFacts: {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}
const positive = run(authorizationPack, 'await updateProject(req.params.id, body)');
const negative = run(authorizationPack, 'await updateProject(req.params.id, body, { tenant: currentTenant })');
const agency = run(aiAgencyPack, 'const publishTool = { name: "publish", run: async () => {} };');
console.log(`fixtures bench: positive=${positive.candidates.length}, negative=${negative.candidates.length}, agency=${agency.candidates.length}`);
if (positive.candidates.length < 1) process.exit(1);
if (negative.candidates.length !== 0) process.exit(1);
if (agency.candidates.length < 1) process.exit(1);
console.log('GATE: PASS');
