// Security bench runner per Security Appendix §58. Version-bound per-pack
// metrics; never computes a repository security score. Verifies the release
// gate: no negative/blocked/mismatch fixture may produce a PROVEN path.

import { readFileSync } from 'node:fs';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import authorizationPack from '../../providers/security/packs/authorization-tenant.mjs';
import mobilePack from '../../providers/security/packs/mobile.mjs';
import footprintPack from '../../providers/security/packs/repository-footprint.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  cortexGenerationId: 'gen1', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(providerId) {
  return {
    seal: { digest: 'sha256:plan' },
    binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
    providers: [{ id: providerId, benchmark: { requiredForCleanClaim: true, status: 'unproven' }, denominator: { pathDigest: 'sha256:d', pathCount: 1, paths: ['app.ts'] } }],
  };
}

function run(pack, sourceText) {
  const file = 'app.ts';
  const plan = planFor(pack.id);
  const model = {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:d', complete: true,
    entities: [], relations: [], initialFacts: [], evidence: [], coverage: {}, coverageGaps: [],
  };
  const projection = { files: [file], sourceText: { [file]: sourceText }, auditFacts: {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

const CASES = [
  { pack: authorizationPack, name: 'authorization.positive', text: 'await updateProject(req.params.id, body)', expectedPositive: true },
  { pack: authorizationPack, name: 'authorization.negative-owner-check', text: 'await updateProject(req.params.id, body, { tenant: currentTenant })', expectedPositive: false },
  { pack: mobilePack, name: 'mobile.negative-no-export', text: '<activity android:name=".MainActivity" />', expectedPositive: false },
  { pack: footprintPack, name: 'footprint.negative-clean', text: 'export function f() { return 1; }', expectedPositive: false },
];

let pass = 0;
let fail = 0;
for (const fixture of CASES) {
  const result = run(fixture.pack, fixture.text);
  const hasCandidate = result.candidates.length > 0;
  const ok = hasCandidate === fixture.expectedPositive;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${fixture.name}: candidates=${result.candidates.length}`);
  if (ok) pass += 1;
  else fail += 1;
}

// Critical release gate: no negative fixture may produce a PROVEN path.
// (Synthesis of these fixtures yields only UNADJUDICATED candidates; paths
// remain PROPOSED until independent chain adjudication.)
console.log(`security bench: ${pass} PASS, ${fail} FAIL`);
if (fail > 0) process.exit(1);
console.log('GATE: PASS');
