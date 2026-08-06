// Security chains bench: runs the bounded attack-path synthesizer over a
// synthetic two-step chain and verifies hypothesis generation.
import { synthesizeAttackPaths } from '../../../providers/security/attack-path-synthesis.mjs';
import { fact } from '../../../providers/security/model-extractors/common.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  cortexGenerationId: 'gen1', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};
const plan = {
  seal: { digest: 'sha256:plan' },
  binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
  providers: [],
};
const OBJECTIVES = [
  { id: 'objective.privilege-escalation', priority: 'PRIVILEGE_ESCALATION', description: 'priv', matches: { factKind: 'principal-access', scopePatterns: ['admin', 'owner'] } },
];

const start = fact('principal-access', { subject: 'actor:external', action: 'authenticate', scope: 'low' }, ['ev1']);
const model = {
  schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
  entities: [], relations: [], initialFacts: [start], evidence: [], coverage: {}, coverageGaps: [],
};
const candidate = (id, pre, eff) => ({
  schemaVersion: 2, kind: 'security-candidate', id, provider: 'security.test', providerVersion: '1', ruleId: 'r', candidateClass: 'test',
  claim: 'test', severityHint: 'high', sources: [], sinks: [], assets: [], trustBoundaryCrossings: [],
  preconditions: pre, effects: eff, chainRoles: [], requiredControls: [], observedControls: [], evidenceRefs: ['ev1'],
  binding: BINDING, denominatorDigest: 'sha256:denom', verdict: 'UNADJUDICATED', adjudicationRequired: true,
});
const step1 = candidate('step1',
  [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'low' }],
  [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'admin' }]);
const step2 = candidate('step2',
  [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'admin' }],
  [{ kind: 'principal-access', subject: 'actor:external', action: 'act-as', scope: 'release' }]);

const result = synthesizeAttackPaths({
  plan, model,
  candidatesArtifact: { schemaVersion: 1, kind: 'security-candidates', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, candidates: [step1, step2] },
  bridges: [], objectives: OBJECTIVES,
});
console.log(`chains bench: ${result.hypotheses.length} hypotheses, complete=${result.complete}`);
if (result.hypotheses.length < 1) process.exit(1);
console.log('GATE: PASS');
