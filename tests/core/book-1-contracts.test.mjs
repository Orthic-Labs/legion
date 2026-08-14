import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const json = async (path) => JSON.parse(await readFile(new URL(`../../${path}`, import.meta.url), 'utf8'));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

test('B1-001 package manifest exposes one public binary and later-book public paths', async () => {
  const pkg = await json('package.json');
  const manifest = await json('MANIFEST.package.json');
  assert.deepEqual(pkg.bin, { legion: './bin/legion.mjs' });
  assert.ok(pkg.files.includes('integrations/') && pkg.files.includes('skills/'));
  assert.ok(manifest.forbiddenContentMarkers.includes('C:\\Users\\'));
});

test('B1-002 canonical enums reject unknown values and future schema versions', async () => {
  const { PROVIDER_STATUS, assertEnum, assertSchemaVersion } = await import('../../lib/contracts/enums.mjs');
  assert.ok(PROVIDER_STATUS.includes('unproven'));
  assert.throws(() => assertEnum('provider status', PROVIDER_STATUS, 'future'));
  assert.throws(() => assertSchemaVersion('provider', 2, [1]));
});

test('B1-003 command catalogue generates complete strict CLI help', async () => {
  const { COMMANDS, parseRootArguments, renderHelp } = await import('../../lib/cli/help.mjs');
  assert.deepEqual(COMMANDS.map(({ name }) => name), ['init','doctor','bind','inspect','targets','components','stacks','controls','skills','languages','providers','rules','schedule','plan','audit','verify','explain','report','fix','hooks','mcp','run','budget','contract','assurance','completion','host','authority','state','minimize']);
  assert.throws(() => parseRootArguments(['audit', '--mystery']), /unknown option/);
  assert.match(renderHelp(), /controls/);
});

test('B1-004 fixed host returns typed unavailable capability receipts', async () => {
  const { fixedHost } = await import('../../lib/host/fixed-host.mjs');
  const { requireCapability } = await import('../../lib/host/capabilities.mjs');
  const host=fixedHost();
  assert.ok(host.allowedExecutables instanceof Set);
  assert.deepEqual(requireCapability(host, 'signing'), { available: false, status: 'blocked', capability: 'signing', receipt: null });
});

test('B1-005 artifact paths reject alternate separators and digests bind bytes', async () => {
  const { safeArtifactPath } = await import('../../lib/artifacts/paths.mjs');
  const { digestBytes } = await import('../../lib/artifacts/digests.mjs');
  assert.throws(() => safeArtifactPath('C:/run', '..\\escape.json'), /escape/);
  assert.equal(digestBytes(Buffer.from('legion')), sha256('legion'));
});

test('B1-006 run manifest rejects orphan and missing declared files', async () => {
  const { validateRunManifest } = await import('../../lib/core/run-manifest.mjs');
  const base={binding:{sourceRevision:'r'},sourceRevision:'r',terminalAbsences:[]};
  assert.deepEqual(validateRunManifest({...base,artifacts: [{ path: 'facts/a.json', digest: sha256('a') }] }, [{ path: 'facts/a.json', digest: sha256('a') }],base.binding), []);
  assert.deepEqual(validateRunManifest({...base,artifacts: [] }, [{ path: 'facts/a.json', digest: sha256('a') }],base.binding), ['orphan:facts/a.json']);
  assert.ok(validateRunManifest({...base,binding:{sourceRevision:'forged'},artifacts:[]},[],base.binding).includes('binding:mismatch'));
});

test('B1-007 trusted merge rejects repository attempts to grant host policy', async () => {
  const { mergeTrustedConfig } = await import('../../lib/config/merge.mjs');
  assert.throws(() => mergeTrustedConfig({ defaults: {}, repository: { signing: true } }), /host-owned/);
  assert.equal(mergeTrustedConfig({ defaults: { profile: 'fast' }, repository: {} }).digest, mergeTrustedConfig({ repository: {}, defaults: { profile: 'fast' } }).digest);
});

test('B1-008 sealed profiles expose resource, cache, cancellation, schedule, and reasoning policy', async () => {
  const { sealedProfile } = await import('../../lib/config/profiles.mjs');
  const profile = sealedProfile('release');
  assert.deepEqual(Object.keys(profile.resources).sort(), ['browser','nativeSurface','projectExecution','providerConcurrency','reviewer','signing']);
  assert.ok(profile.schedule && profile.cache && profile.cancellation && profile.reasoning);
});

test('B1-009 family and lens registries reject dependency cycles', async () => {
  const { validateFamilies } = await import('../../lib/contracts/families.mjs');
  const { validateLenses } = await import('../../lib/contracts/lenses.mjs');
  assert.throws(() => validateFamilies([{ id: 'a', dependencies: ['b'] }, { id: 'b', dependencies: ['a'] }]), /cycle/);
  assert.throws(() => validateLenses([{ id: 'x', family: 'code', dependencies: ['x'], denominatorKind: 'path', evidence: [], cleanClaim: 'evidence', decisionMode: 'deterministic', reasoning: 'none', benchmark: 'unproven' }]), /cycle/);
});

test('B1-010 provider v2 rejects candidate generators that emit findings', async () => {
  const { validateProviderV2, validateProviderOutputAuthority } = await import('../../lib/providers/sdk/contracts.mjs');
  const provider = { schemaVersion: 2, id: 'security.x', providerVersion:'1.0.0', family: 'security', lensIds: ['security.sast'], role: 'candidate-generator', phase: 'source', dependsOn: [], consumes: [], produces: ['candidates'], selector: {}, denominatorKind: 'paths', runner: { kind: 'external-process' }, hostCapabilities: [], execution:{scheduleClass:'parallel-safe',resourceClaims:{cpu:1,memoryMb:64,io:1},concurrencyKey:null,maxParallelism:null,orderSensitive:false,interruptible:true,cachePolicy:'content-addressed',failurePolicy:'block-dependents'}, reasoning:{requirement:'none',trigger:'candidate',subjectKind:'finding',freshContext:true,producerSeparation:true}, benchmark:{status:'unproven',requiredForCleanClaim:true,qualificationDigest:null}, cleanClaim: 'never', controlIds: [], scopes: [],selectable:false };
  assert.deepEqual(validateProviderV2(provider), provider);
  assert.throws(() => validateProviderOutputAuthority(provider, { findings: [{}] }), /candidate-generator/);
});

test('B1-011 schedule compiler uses lexical waves and rejects impossible resources', async () => {
  const { compileSchedule } = await import('../../lib/providers/sdk/schedule.mjs');
  const result = compileSchedule([{ id: 'b', dependencies: [], resources: { cpu: 1 }, scheduleClass: 'parallel' }, { id: 'a', dependencies: [], resources: { cpu: 1 }, scheduleClass: 'parallel' }], { cpu: 2 });
  assert.deepEqual(result.waves, [['a', 'b']]);
  assert.throws(() => compileSchedule([{ id: 'x', dependencies: [], resources: { cpu: 3 }, scheduleClass: 'parallel' }], { cpu: 2 }), /resource/);
});

test('B1-012 reasoning runner prepares a packet without invoking a reviewer', async () => {
  const { executeRunner } = await import('../../lib/providers/executor/index.mjs');
  let invoked = false;
  const receipt = await executeRunner({ id: 'judge', runner: { kind: 'reasoning-contract' } }, { reviewer: { invoke() { invoked = true; } } }, { evidence: ['facts.json'] });
  assert.equal(invoked, false);
  assert.equal(receipt.state, 'packet-prepared');
});

test('B1-013 precomputed Cortex projection rejects stale repository binding', async () => {
  const { loadPrecomputedProjection } = await import('../../lib/adapters/cortex/precomputed.mjs');
  assert.throws(() => loadPrecomputedProjection({ schemaVersion: 1, binding: { revision: 'old' } }, { revision: 'new' }), /binding/);
});

test('B1-014 binding comparison is stable across path separators', async () => {
  const { sameBinding } = await import('../../lib/core/binding.mjs');
  assert.equal(sameBinding({ root: 'C:\\repo', revision: 'x' }, { root: 'C:/repo', revision: 'x' }), true);
});

test('B1-015 planning stage registry is fixed and missing required stages are typed', async () => {
  const { PLANNING_STAGE_IDS, runPlanningStages } = await import('../../lib/core/plan-stages/registry.mjs');
  assert.deepEqual(PLANNING_STAGE_IDS.slice(0, 3), ['repository-binding', 'cortex-projection', 'product-portfolio']);
  const result = await runPlanningStages([], { claimLevel: 'source' });
  assert.equal(result.status, 'unproven');
  assert.ok(result.gaps.some(({ stage }) => stage === 'control-baseline'));
});

test('B1-016 scheduler preserves independent work when one dependency blocks', async () => {
  const { scheduleProviders } = await import('../../lib/core/scheduler.mjs');
  const result = scheduleProviders([{ id: 'a', dependencies: [], resources: { cpu: 2 } }, { id: 'b', dependencies: ['missing'], resources: { cpu: 1 } }, { id: 'c', dependencies: [], resources: { cpu: 1 } }], { mode: 'auto', resources: { cpu: 2 } });
  assert.deepEqual(result.admitted, ['a']);
  assert.deepEqual(result.blocked, [{ id: 'b', reason: 'unknown-dependency:missing' }]);
  assert.deepEqual(result.ready, ['c']);
});

test('B1-017 zero findings with a required gap is incomplete', async () => {
  const { reconcileClaim } = await import('../../lib/core/completeness.mjs');
  assert.deepEqual(reconcileClaim({ findings: [], requiredEvidence: ['runtime'], evidence: [] }), { complete: false, status: 'incomplete', gaps: ['runtime'] });
});

test('B1-018 reviewer policy rejects context reuse and self-adjudication', async () => {
  const { reviewerPolicy } = await import('../../lib/core/reviewer-policy.mjs');
  assert.throws(() => reviewerPolicy({ producer: 'model-a', reviewer: 'model-a', contextId: 'c1', usedContexts: [] }), /self-adjudication/);
  assert.throws(() => reviewerPolicy({ producer: 'model-a', reviewer: 'model-b', contextId: 'c1', usedContexts: ['c1'] }), /context reuse/);
});

test('B1-019 report model preserves topology, controls, and per-claim decisions without a score', async () => {
  const { buildReportModel } = await import('../../lib/report/model.mjs');
  const report = buildReportModel({ targets: [{ id: 'web' }], controls: [{ id: 'scope' }], claims: { source: 'pass' } });
  assert.deepEqual(report.claims, { source: 'pass' });
  assert.equal('score' in report, false);
});

test('B1-020 semantic verification excludes time, paths, and presentation ordering', async () => {
  const { semanticProjection } = await import('../../lib/verification/projection.mjs');
  const a = semanticProjection({ generatedAt: 'now', outputDir: 'a', providers: [{ id: 'b' }, { id: 'a' }] });
  const b = semanticProjection({ generatedAt: 'later', outputDir: 'b', providers: [{ id: 'a' }, { id: 'b' }] });
  assert.deepEqual(a, b);
});

test('B1-021 schedule command is a pure canonical renderer', async () => {
  const { renderSchedule } = await import('../../lib/cli/commands/schedule.mjs');
  const plan = { waves: [['b', 'a']] };
  assert.equal(renderSchedule(plan, 'json'), '{"waves":[["a","b"]]}\n');
  assert.deepEqual(plan, { waves: [['b', 'a']] });
});

test('B1-022 skill bundle contract rejects absolute internal URIs and separates profiles', async () => {
  const { validateSkillBundle } = await import('../../lib/skills/contracts.mjs');
  const base={schemaVersion:1,id:'x',version:'1',entry:'SKILL.md',provenance:'test',licenseState:'unresolved',rightsReceipt:null,files:[]};
  assert.throws(() => validateSkillBundle({ ...base, rootUri: 'C:/skills', profiles: {} }), /legion-skill/);
  assert.throws(() => validateSkillBundle({ ...base, rootUri: 'legion-skill://x/', profiles: { audit: {} } }), /authoring/);
});

test('B1-023 skill URI resolver and verifier are package-relative and digest-bound', async () => {
  const { parseSkillUri } = await import('../../lib/skills/uri.mjs');
  const { verifySkillBytes } = await import('../../lib/skills/verify.mjs');
  assert.deepEqual(parseSkillUri('legion-skill://designer/SKILL.md'), { bundle: 'designer', path: 'SKILL.md' });
  assert.throws(() => parseSkillUri('file:///tmp/x'), /unsupported/);
  assert.equal(verifySkillBytes('text', sha256('text')).ok, true);
});

test('B1-024 skill transformation is deterministic, neutral, and strips audit mutation authority', async () => {
  const { transformSkillText } = await import('../../lib/skills/transform.mjs');
  const rules = [{ from: 'the operator', to: 'the approving human' }];
  const value = transformSkillText('allowed-tools: Write\nAsk the operator\n[ref](./guide.md)', { bundle: 'designer', profile: 'audit', rules });
  assert.equal(value.includes('allowed-tools'), false);
  assert.match(value, /the approving human/);
  assert.match(value, /legion-skill:\/\/designer\/guide.md/);
});

test('B1-025 Designer bundle preserves audit authority boundaries', async () => {
  const manifest = await json('skills/manifests/designer.json');
  assert.equal(manifest.profiles.audit.mutation, false);
  assert.deepEqual(manifest.protectedActions, ['rewrite-approved-words', 'distort-protected-subjects', 'enter-protected-regions']);
});

test('B1-026 Writing bundle makes proof and no-fabrication explicit', async () => {
  const manifest = await json('skills/manifests/writing.json');
  assert.equal(manifest.profiles.audit.publish, false);
  assert.equal(manifest.noFabrication, true);
  assert.equal(manifest.approvedWordsRequireRevision, true);
});

test('B1-027 qualifier supports Books 1 through 6 and package smoke exercises library plus plan', async () => {
  const { discoverBookTests } = await import('../../scripts/qualify-book.mjs');
  const { packageSmokeContract } = await import('../../scripts/package-smoke.mjs');
  for (const book of [1, 2, 3, 4, 5, 6]) assert.ok((await discoverBookTests(book)).length > 0);
  assert.deepEqual(packageSmokeContract(), ['binary', 'library-import', 'cortex-projection', 'plan', 'schedule', 'serial-execution', 'auto-execution', 'audit', 'verify', 'tasklist', 'dispatch', 'coder', 'qa', 'handoff', 'transcripts', 'decisions']);
});

test('B1-028 qualification digest ignores duration and noisy test bytes', async () => {
  const { qualificationDigest } = await import('../../scripts/qualify-book.mjs');
  const a = qualificationDigest({ status: 'pass', tests: [{ name: 'x', status: 'pass', duration_ms: 1 }], stdout: 'duration_ms 1' });
  const b = qualificationDigest({ status: 'pass', tests: [{ name: 'x', status: 'pass', duration_ms: 99 }], stdout: 'duration_ms 99' });
  assert.equal(a, b);
});
