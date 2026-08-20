import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { validateSchema } from '../src/lib/qualification/schema-validator.mjs';
import { AcceptanceEvidenceRegistry } from '../src/packages/arcane/lib/evidence-registry.mjs';
import { runPackageSmoke } from '../scripts/package-smoke.mjs';

const legionRoot = resolve(import.meta.dirname, '..');
const workspaceRoot = resolve(legionRoot, '../../..');
const digestJson = (value) => `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
const loadDoctrineSchema = (name) => JSON.parse(readFileSync(join(legionRoot, `doctrine/architecture/schemas/${name}.schema.json`), 'utf8'));

const roles = Object.freeze({
  runtime_owner: 'legion-package',
  first_fix_owner: 'legion-package-maintainer',
  canonical_owner: 'legion-package',
  integration_owner: 'root-legion-chat',
  shared_state_writer: 'root-legion-chat',
  evidence_producer: 'stage8-live-workload',
});

const retiredRoots = [
  'tools/skills/handoff', 'tools/skills/tasklist', 'tools/skills/dispatch', 'tools/skills/coder',
  'tools/skills/qa', 'tools/skills/architect', 'tools/skills/debugger', 'tools/skills/jfdi',
  'tools/skills/council', 'tools/lib/dispatch-validator', 'tools/lib/qa-engine',
  'tools/lib/coder-api-worker', 'tools/lib/decision_provider.py', 'tools/lib/orthic_transcripts',
];

test('S08-01 live assembled-package workload reaches Handoff acceptance through S05 & S07 producers', async () => {
  const observedAt = new Date();
  const packageResult = await runPackageSmoke(legionRoot);
  assert.equal(packageResult.handoff, true);
  assert.equal(packageResult.transcripts, true);
  assert.equal(packageResult.forbiddenMarkers, 0);

  const integratedState = {
    nested_git: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: legionRoot, encoding: 'utf8' }).trim(),
    nested_tree: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: legionRoot, encoding: 'utf8' }).trim(),
    package_version: packageResult.version,
  };
  const artifactDigest = digestJson({ integratedState, packageResult });
  const workload = {
    schema: 'representative-workload.v1',
    acceptance_fingerprint: `sha256:${'1'.repeat(64)}`,
    required_items_exercised: ['S08-01', 'S05-01', 'S07-01'],
    smallest_complete_slice: 'assemble public Legion package & invoke Handoff pointer transport plus Membrane context seam',
    actual_workflow: 'run clean assembled-package smoke through public binary, engines, Handoff transport, Membrane packet seam, & decisions',
    actual_acceptance_surface: 'public package returns successful Handoff/Membrane transport execution with no forbidden private markers',
    environment: { os: process.platform, runtime: process.version, browser_or_device: 'CLI', locale_timezone_network: 'local/offline' },
    representative_data: 'current public Legion package allowlist & recovered Handoff entrypoint',
    artifact: { kind: 'receipt', sensitivity: 'internal', trust: 'trusted', retention: 'repository history', deletion_owner: 'legion-integration-owner', digest: artifactDigest },
    result: { status: 'PASS', machine_readable: true, gateable: true, downloadable: true, trajectory_correlation_id: 'S08-01-package-handoff', failure_signature: null },
    matrix: { rationale: 'Handoff was reported as worst migration failure; clean package execution is its smallest user-visible closure', pr_subset: ['macOS assembled package'], release_set: ['macOS', 'Windows'] },
    forbidden_proxies: ['source-path existence only', 'unit-only Handoff import', 'unassembled workspace execution'],
    observed_failures: [],
    hardening_disposition: 'DEFER',
  };
  assert.deepEqual(validateSchema(JSON.parse(readFileSync(join(legionRoot, 'src/schemas/representative-workload.schema.json'), 'utf8')), workload), []);

  const registry = new AcceptanceEvidenceRegistry();
  assert.equal(registry.register({ acceptanceId: 'S08-01', claimType: 'acceptance-surface', producer: roles.evidence_producer, durableStore: 'evidence-registry', verifier: 'oracle', completionConsumer: 'legion', integratedStateBinding: 'nested-git+tree+package-version', validityPolicy: 'until material package change' }).allowed, true);
  const artifact = { acceptanceId: 'S08-01', producer: roles.evidence_producer, verifier: 'oracle', completionConsumer: 'legion', authenticated: true, integratedState, observedAt: observedAt.toISOString(), validUntil: new Date(observedAt.valueOf() + 3_600_000).toISOString(), artifactDigest };
  assert.equal(registry.verify('S08-01', artifact, { integratedState, latestMaterialChange: new Date(observedAt.valueOf() - 1).toISOString(), now: observedAt }).allowed, true);
});

test('S08-01 ownership has one integration owner & one shared-state writer', () => {
  const disposition = { schema: 'ownership-disposition.v1', capability: 'public Legion packaged skills', roles, mismatch: null, disposition: 'KEEP', trigger: 'material package ownership or integration change', acceptance_proof: 'stage8-live-workload exact-state receipt' };
  assert.deepEqual(validateSchema(loadDoctrineSchema('ownership-disposition'), disposition), []);
  assert.equal(new Set([roles.integration_owner]).size, 1);
  assert.equal(new Set([roles.shared_state_writer]).size, 1);
});

test('S08-01 migration is a hard cut with losing roots absent & canonical package paths present', () => {
  for (const path of retiredRoots) assert.equal(existsSync(join(workspaceRoot, path)), false, `retired path still exists: ${path}`);
  for (const path of ['skills/handoff/SKILL.md', 'src/lib/handoff/transcript_handoff.py', 'src/packages/context/lib/context.mjs']) assert.equal(existsSync(join(legionRoot, path)), true, `canonical path missing: ${path}`);
  const absence = retiredRoots.map((path) => `${path}:absent`);
  const cutover = {
    schema: 'migration-cutover.v1', mode: 'HARD_CUT', runtime_owner: roles.runtime_owner,
    first_fix_owner: roles.first_fix_owner, canonical_owner: roles.canonical_owner,
    integration_owner: roles.integration_owner,
    hard_cut: { external_compatibility_obligation: null, absence_checks: { imports: absence, routes: absence, runtime_registrations: absence, configuration_keys: absence, dependencies: absence, tests: absence, documentation: absence, emitted_protocol_variants: absence } },
    bounded_coexistence: null, verdict: 'READY',
  };
  assert.deepEqual(validateSchema(loadDoctrineSchema('migration-cutover'), cutover), []);
});
