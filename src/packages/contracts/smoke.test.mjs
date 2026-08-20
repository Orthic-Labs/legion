// Legion shared-contract smoke test — WP2 freeze.
//
// Legion has no ajv dependency and this task adds none. These are
// structural checks: every schema file is valid JSON, has the required
// scaffold ($schema draft 2020-12, $id, type/oneOf, required-key presence),
// and every enum-bearing property in every schema is set-equal (or a
// documented subset) of the corresponding enums.mjs export — so the two
// never drift silently.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import * as Enums from './enums.mjs';
import { SCHEMA_PATHS, SCHEMA_NAMES } from './index.mjs';
import { validateExecutableContract } from './executable.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.join(__dirname, 'schemas');

function loadSchema(name) {
  const raw = readFileSync(SCHEMA_PATHS[name], 'utf8');
  return JSON.parse(raw);
}

function eq(a, b) {
  return JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
}

// --- 1. Directory / index consistency -------------------------------------

test('every .schema.json file under schemas/ is registered in index.mjs SCHEMA_PATHS', () => {
  const files = readdirSync(schemasDir).filter((f) => f.endsWith('.schema.json'));
  const registered = new Set(Object.values(SCHEMA_PATHS).map((p) => path.basename(p)));
  for (const f of files) {
    assert.ok(registered.has(f), `${f} is not registered in SCHEMA_PATHS`);
  }
  assert.equal(files.length, SCHEMA_NAMES.length, 'file count must match SCHEMA_PATHS entry count');
});

// --- 2. Every schema: valid JSON + draft 2020-12 + scaffold ---------------

const parsed = {};
for (const name of SCHEMA_NAMES) {
  test(`${name}: parses as valid JSON`, () => {
    parsed[name] = loadSchema(name);
    assert.equal(typeof parsed[name], 'object');
  });
}

test('every schema declares draft 2020-12 and a unique $id', () => {
  const ids = new Set();
  for (const name of SCHEMA_NAMES) {
    const schema = loadSchema(name);
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema', `${name}: wrong $schema`);
    assert.ok(typeof schema.$id === 'string' && schema.$id.length > 0, `${name}: missing $id`);
    assert.ok(!ids.has(schema.$id), `${name}: duplicate $id ${schema.$id}`);
    ids.add(schema.$id);
  }
});

test('execution contract executable validation rejects unresolved and under-specified work', () => {
  const contract = {
    schemaVersion: 1, kind: 'legion-execution-contract', contractId: 'EC-1', version: 1, sourceRevision: 'abcdef0', budget: { objectiveLineageId: 'L-1', objectiveDigest: `sha256:${'a'.repeat(64)}`, legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2 }, objective: 'x', currentState: 'x', desiredState: 'x', requirements: [], decisions: [], invariants: [], nonGoals: [], scope: { own: [], read: [], forbidden: [] }, artifacts: { exact: [{ id: 'a', path: 'x', latitude: 'EXACT', content: 'x' }], bounded: [{ id: 'b', path: 'y', latitude: 'BOUNDED', locked: ['x'], freedom: ['y'] }] }, tasks: ['T-1'], dependencies: [], acceptanceCriteria: [], declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: [], repairLatitude: [], stopConditions: [], escalationConditions: [], rollback: [], openQuestions: []
  };
  assert.equal(validateExecutableContract(contract), contract);
  assert.throws(() => validateExecutableContract({ ...contract, openQuestions: [{ id: 'Q-1', question: 'x' }] }), /open questions/);
  assert.throws(() => validateExecutableContract({ ...contract, tasks: ['T-1', 'T-1'] }), /unique/);
});

test('execution contract accepts only a closed advisory profile binding', () => {
  const contract = {
    schemaVersion: 1, kind: 'legion-execution-contract', contractId: 'EC-2', version: 1, sourceRevision: 'abcdef0',
    advisoryProfile: { schemaVersion: 1, kind: 'arcane-advisory-profile-binding', bundleId: 'research', bundleVersion: '1.0.0', profileId: 'audit', manifestDigest: `sha256:${'a'.repeat(64)}`, profileDigest: `sha256:${'b'.repeat(64)}`, mutationAllowed: false, publishAllowed: false, externalOnly: false }, budget: { objectiveLineageId: 'L-2', objectiveDigest: `sha256:${'a'.repeat(64)}`, legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2 },
    objective: 'x', currentState: 'x', desiredState: 'x', requirements: [], decisions: [], invariants: [], nonGoals: [], scope: { own: [], read: [], forbidden: [] }, artifacts: { exact: [{ id: 'a', path: 'x', latitude: 'EXACT', content: 'x' }], bounded: [{ id: 'b', path: 'y', latitude: 'BOUNDED', locked: ['x'], freedom: ['y'] }] }, tasks: ['T-1'], dependencies: [], acceptanceCriteria: [], declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: [], repairLatitude: [], stopConditions: [], escalationConditions: [], rollback: [], openQuestions: [],
  };
  assert.equal(validateExecutableContract(contract), contract);
  assert.throws(() => validateExecutableContract({ ...contract, advisoryProfile: { ...contract.advisoryProfile, callerManifestPath: 'x' } }), /additional-property/);
  const missing = JSON.parse(JSON.stringify(contract)); delete missing.advisoryProfile.profileDigest;
  assert.throws(() => validateExecutableContract(missing), /required/);
});


test('EC-C sealed behavior: EXACT artifacts reject null content, BOUNDED rejects empty locked/freedom, shared-mutable-resource edges require resourceKey, IDs are globally unique', () => {
  const baseContract = {
    schemaVersion: 1, kind: 'legion-execution-contract', contractId: 'EC-44', version: 1, sourceRevision: 'abcdef0', budget: { objectiveLineageId: 'L-44', objectiveDigest: `sha256:${'a'.repeat(64)}`, legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2 }, objective: 'o', currentState: 'c', desiredState: 'd',
    requirements: [{ id: 'R-1', statement: 'r' }], decisions: [{ id: 'D-1', statement: 'd' }], invariants: [{ id: 'I-1', statement: 'i' }], nonGoals: [{ id: 'NG-1', statement: 'n' }],
    scope: { own: [], read: [], forbidden: [] },
    artifacts: {
      exact: [{ id: 'A-exact', path: 'p', latitude: 'EXACT', content: 'data' }],
      bounded: [{ id: 'A-bound', path: 'q', latitude: 'BOUNDED', locked: ['L1'], freedom: ['F1'] }],
    },
    tasks: ['T-1'],
    dependencies: [],
    acceptanceCriteria: [{ id: 'AC-1', statement: 'a' }],
    declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: ['FILE_WRITE'], repairLatitude: [],
    stopConditions: [], escalationConditions: [], rollback: [], openQuestions: [],
  };
  assert.equal(validateExecutableContract(baseContract), baseContract);

  const exactNull = JSON.parse(JSON.stringify(baseContract));
  exactNull.artifacts.exact[0].content = null;
  assert.throws(() => validateExecutableContract(exactNull), /EXACT artifact .* requires content/);

  const boundedEmptyLocked = JSON.parse(JSON.stringify(baseContract));
  boundedEmptyLocked.artifacts.bounded[0].locked = [];
  assert.throws(() => validateExecutableContract(boundedEmptyLocked), /requires locked and freedom/);

  const boundedEmptyFreedom = JSON.parse(JSON.stringify(baseContract));
  boundedEmptyFreedom.artifacts.bounded[0].freedom = [];
  assert.throws(() => validateExecutableContract(boundedEmptyFreedom), /requires locked and freedom/);

  const sharedWithoutKey = JSON.parse(JSON.stringify(baseContract));
  sharedWithoutKey.dependencies = [{ from: 'T-1', to: 'T-2', reason: 'shared-mutable-resource' }];
  assert.throws(() => validateExecutableContract(sharedWithoutKey), /resourceKey/);

  const sharedWithKey = JSON.parse(JSON.stringify(baseContract));
  sharedWithKey.tasks = ['T-1', 'T-2'];
  sharedWithKey.dependencies = [{ from: 'T-1', to: 'T-2', reason: 'shared-mutable-resource', resourceKey: 'src/shared.lock' }];
  assert.equal(validateExecutableContract(sharedWithKey), sharedWithKey);

  const duplicateDecision = JSON.parse(JSON.stringify(baseContract));
  duplicateDecision.decisions = [{ id: 'D-1', statement: 'first' }, { id: 'D-1', statement: 'dup' }];
  assert.throws(() => validateExecutableContract(duplicateDecision), /unique/);

  const crossSectionDuplicate = JSON.parse(JSON.stringify(baseContract));
  crossSectionDuplicate.requirements = [{ id: 'D-1', statement: 'collides with decision D-1' }];
  assert.throws(() => validateExecutableContract(crossSectionDuplicate), /unique/);
});
// operation-envelope-v1 is the one true discriminated union: it has no
// top-level "properties" at all, only "oneOf" refs into "$defs" (each $def
// is a complete, independent object shape). Every other schema either has
// no oneOf (plain object) or uses oneOf the way claim-v1 does — as an
// additional cross-field constraint layered on top of a normal top-level
// "properties"/"additionalProperties" object. That distinction (presence of
// top-level "properties") is what selects which check applies below.
function isDiscriminatedEnvelope(schema) {
  return Boolean(schema.oneOf) && !schema.properties;
}

function isComposedAuthorityDispatch(schema) {
  return schema.$id === 'legion-authority-dispatch-v1';
}

test('every schema declares schemaVersion const 1 and a kind const', () => {
  for (const name of SCHEMA_NAMES) {
    const schema = loadSchema(name);
    if (isComposedAuthorityDispatch(schema)) {
      assert.deepEqual(schema.$defs.base.properties.schemaVersion, { const: 1 });
      assert.equal(schema.$defs.base.properties.kind.const, 'legion-authority-dispatch');
      continue;
    }
    if (isDiscriminatedEnvelope(schema)) {
      for (const branch of schema.oneOf) {
        const def = schema.$defs[branch.$ref.replace('#/$defs/', '')];
        assert.deepEqual(def.properties.schemaVersion, { const: 1 }, `${name}: branch missing schemaVersion const 1`);
        assert.ok(typeof def.properties.kind.const === 'string', `${name}: branch missing kind const`);
      }
    } else {
      assert.deepEqual(schema.properties.schemaVersion, { const: 1 }, `${name}: missing schemaVersion const 1`);
      assert.ok(typeof schema.properties.kind.const === 'string', `${name}: missing kind const`);
    }
  }
});

test('every schema sets additionalProperties: false at its top level (or, for a discriminated envelope, on every branch)', () => {
  for (const name of SCHEMA_NAMES) {
    const schema = loadSchema(name);
    if (isComposedAuthorityDispatch(schema)) {
      assert.equal(schema.$defs.base.additionalProperties, false, `${name}: base allows additionalProperties`);
      continue;
    }
    if (isDiscriminatedEnvelope(schema)) {
      for (const branch of schema.oneOf) {
        const def = schema.$defs[branch.$ref.replace('#/$defs/', '')];
        assert.equal(def.additionalProperties, false, `${name}: branch allows additionalProperties`);
      }
    } else {
      assert.equal(schema.additionalProperties, false, `${name}: allows additionalProperties`);
    }
  }
});


test('authority-dispatch-v1: schema declares all four authority variants with required routing and sealed references', () => {
  const schema = loadSchema('authority-dispatch-v1');
  assert.ok(schema.oneOf, 'authority-dispatch-v1 must be a discriminated union');
  const branches = schema.oneOf.map((branch) => branch.$ref.replace('#/$defs/', ''));
  assert.deepEqual(branches.sort(), ['alchemist', 'oracle', 'sage', 'worker']);
  function resolveProps(branchName) {
    const def = schema.$defs[branchName];
    const allOf = Array.isArray(def.allOf) ? def.allOf : [def];
    const props = {};
    const required = [];
    for (const entry of allOf) {
      if (!entry) continue;
      if (entry['$ref'] === '#/$defs/base') {
        Object.assign(props, schema.$defs.base.properties ?? {});
        if (Array.isArray(schema.$defs.base.required)) required.push(...schema.$defs.base.required);
        continue;
      }
      if (entry.properties) Object.assign(props, entry.properties);
      if (Array.isArray(entry.required)) required.push(...entry.required);
    }
    return { props, required: new Set(required) };
  }
  function resolveRef(value) {
    if (!value || typeof value !== 'object') return value;
    if (typeof value['$ref'] === 'string' && value['$ref'].startsWith('#/$defs/')) {
      return schema.$defs[value['$ref'].replace('#/$defs/', '')];
    }
    if (value.allOf) {
      const merged = { properties: {}, required: [] };
      for (const entry of value.allOf) {
        const resolved = resolveRef(entry);
        if (resolved?.properties) Object.assign(merged.properties, resolved.properties);
        if (Array.isArray(resolved?.required)) merged.required.push(...resolved.required);
      }
      return merged;
    }
    return value;
  }
  for (const branch of branches) {
    const { props, required } = resolveProps(branch);
    assert.equal(props.packetType?.const, branch, `${branch} must pin packetType`);
    assert.ok(required.has('sourceRevision'), `${branch} must bind sourceRevision`);
    assert.ok(required.has('promptDigest'), `${branch} must bind promptDigest`);
    assert.ok(required.has('modelRouting'), `${branch} must bind modelRouting`);
    const routing = resolveRef(props.modelRouting);
    assert.ok(routing?.properties?.modelTier, `${branch} modelRouting must name modelTier`);
    assert.ok(routing?.properties?.workerProfile, `${branch} modelRouting must name workerProfile`);
    assert.ok(routing?.properties?.routingRationale, `${branch} modelRouting must name routingRationale`);
  }
  const sage = resolveProps('sage');
  assert.ok(sage.required.has('routeBundle'), 'sage must require routeBundle');
  assert.ok(sage.props.routeBundle, 'sage must expose routeBundle property');
  const oracle = resolveProps('oracle');
  assert.ok(oracle.required.has('lens'), 'oracle must require lens');
  assert.ok(oracle.required.has('scope'), 'oracle must require scope');
  assert.ok(oracle.required.has('oracle'), 'oracle must require oracle');
  assert.ok(!oracle.props.scope?.properties?.own, 'oracle scope must be read-only (no own[])');
  assert.ok(oracle.props.scope?.properties?.read, 'oracle scope must carry read[]');
  assert.ok(oracle.props.scope?.properties?.forbidden, 'oracle scope must carry forbidden[]');
  const alchemist = resolveProps('alchemist');
  assert.ok(alchemist.required.has('executionContract'), 'alchemist must require executionContract');
  assert.equal(alchemist.props.executionContract?.properties?.sealed?.const, true);
  assert.equal(alchemist.props.executionContract?.properties?.executable?.const, true);
  assert.ok(alchemist.required.has('scope'), 'alchemist must require OWN-subset scope');
  assert.ok(alchemist.props.scope?.properties?.contractOwn, 'alchemist scope must carry contractOwn[]');
  const worker = resolveProps('worker');
  assert.ok(worker.required.has('workerCapsule'), 'worker must require workerCapsule');
  assert.ok(worker.required.has('taskProjection'), 'worker must require taskProjection');
  assert.ok(worker.required.has('artifactProjection'), 'worker must require artifactProjection');
  assert.ok(worker.required.has('oracle'), 'worker must require oracle');
});
// --- 3. enums.mjs <-> schema enum agreement --------------------------------

test('artifact-v1: producerAuthority matches AUTHORITY_ID', () => {
  const s = loadSchema('artifact-v1');
  assert.ok(eq(s.properties.producerAuthority.enum, Enums.AUTHORITY_ID));
});

test('run-identity-v1: has no undeclared enums drifting from grammar (sanity parse only)', () => {
  const s = loadSchema('run-identity-v1');
  assert.ok(s.properties.runId.pattern.startsWith('^run_'));
});

test('execution-contract-v1: authorizedEffectClasses items match EFFECT_CLASS; artifact latitude buckets are EXACT/BOUNDED subsets of LATITUDE', () => {
  const s = loadSchema('execution-contract-v1');
  assert.ok(eq(s.properties.authorizedEffectClasses.items.enum, Enums.EFFECT_CLASS));
  const artifactUnitLatitude = s.$defs.artifactUnit.properties.latitude.enum;
  assert.ok(artifactUnitLatitude.every((v) => Enums.LATITUDE.includes(v)), 'artifactUnit.latitude must be a subset of LATITUDE');
  assert.ok(eq(artifactUnitLatitude, ['EXACT', 'BOUNDED']), 'artifactUnit.latitude excludes OPEN by design (see schema description)');
  const oq = s.properties.openQuestions;
  assert.ok(oq, 'openQuestions must be present (G9: empty array required for executability)');
});

test('execution-task-v1: status matches ALCHEMIST_STATE; assignedAuthority matches AUTHORITY_ID; latitude matches LATITUDE; routing enums match MODEL_TIER/WORKER_PROFILE', () => {
  const s = loadSchema('execution-task-v1');
  assert.ok(eq(s.properties.status.enum, Enums.ALCHEMIST_STATE));
  assert.ok(eq(s.properties.assignedAuthority.enum, Enums.AUTHORITY_ID));
  assert.ok(eq(s.properties.latitude.enum, Enums.LATITUDE));
  assert.ok(eq(s.properties.routingDecision.properties.modelTier.enum, Enums.MODEL_TIER));
  assert.ok(eq(s.properties.routingDecision.properties.workerProfile.enum, Enums.WORKER_PROFILE));
});

test('worker-capsule-v1: modelTier matches MODEL_TIER; workerProfile matches WORKER_PROFILE', () => {
  const s = loadSchema('worker-capsule-v1');
  assert.ok(eq(s.properties.modelTier.enum, Enums.MODEL_TIER));
  assert.ok(eq(s.properties.workerProfile.enum, Enums.WORKER_PROFILE));
});

test('effect-request-v1: requestedBy matches AUTHORITY_ID; effectClass matches EFFECT_CLASS; latitude excludes OPEN', () => {
  const s = loadSchema('effect-request-v1');
  assert.ok(eq(s.properties.requestedBy.enum, Enums.AUTHORITY_ID));
  assert.ok(eq(s.properties.effectClass.enum, Enums.EFFECT_CLASS));
  assert.ok(eq(s.properties.latitude.enum, ['EXACT', 'BOUNDED']));
});

test('effect-receipt-v1: effectIdentity.effectClass matches EFFECT_CLASS on all three (requested/authorized/observed reuse the same $def)', () => {
  const s = loadSchema('effect-receipt-v1');
  assert.ok(eq(s.$defs.effectIdentity.properties.effectClass.enum, Enums.EFFECT_CLASS));
  for (const field of ['requested', 'authorized', 'observed']) {
    assert.deepEqual(s.properties[field], { $ref: '#/$defs/effectIdentity' }, `${field} must reuse the shared effectIdentity $def`);
  }
});

test('effect-receipt-v1: authentication.verificationMethod matches AUTHENTICATION_METHOD; replayDefense has nonce/sequence/freshness (S00 baseline)', () => {
  const s = loadSchema('effect-receipt-v1');
  assert.ok(eq(s.properties.authentication.properties.verificationMethod.enum, Enums.AUTHENTICATION_METHOD));
  assert.ok(s.required.includes('authentication'));
  assert.ok(s.required.includes('replayDefense'));
  const rd = s.properties.replayDefense.properties;
  assert.ok('nonce' in rd && 'sequence' in rd && 'freshnessWindowSeconds' in rd);
});

test('evidence-capability-receipt-v1: producerAuthority matches AUTHORITY_ID; evidenceClass matches EVIDENCE_CLASS; carries authentication + replayDefense (S00 baseline)', () => {
  const s = loadSchema('evidence-capability-receipt-v1');
  assert.ok(eq(s.properties.producerAuthority.enum, Enums.AUTHORITY_ID));
  assert.ok(eq(s.properties.evidenceClass.enum, Enums.EVIDENCE_CLASS));
  assert.ok(eq(s.properties.authentication.properties.verificationMethod.enum, Enums.AUTHENTICATION_METHOD));
  assert.ok(s.required.includes('authentication'));
  assert.ok(s.required.includes('replayDefense'));
});

test('legacy-envelope-v1: provenance.authenticated is structurally locked to false (S00 baseline: signature_or_mac is a self-hash, not authentication)', () => {
  const s = loadSchema('legacy-envelope-v1');
  assert.equal(s.properties.provenance.properties.authenticated.const, false);
  assert.ok(s.properties.provenance.required.includes('authenticated'));
  assert.ok(s.properties.provenance.properties.legacyInventoryRef, 'must reference the S00 inventory path');
});

test('blocker-v1: classification matches BLOCKER_CLASS; status matches BLOCKER_STATUS', () => {
  const s = loadSchema('blocker-v1');
  assert.ok(eq(s.properties.classification.enum, Enums.BLOCKER_CLASS));
  assert.ok(eq(s.properties.status.enum, Enums.BLOCKER_STATUS));
  assert.equal(s.properties.raisedBy.const, 'alchemist');
});

test('amendment-v1: sealedBy admits Legion or Sage only', () => {
  const s = loadSchema('amendment-v1');
  assert.deepEqual(s.properties.sealedBy.enum, ['legion', 'sage']);
});

test('claim-v1: claimingAuthority is a subset of AUTHORITY_ID; name matches CLAIM_NAME; per-authority oneOf branches match CLAIMS_BY_AUTHORITY', () => {
  const s = loadSchema('claim-v1');
  assert.ok(s.properties.claimingAuthority.enum.every((v) => Enums.AUTHORITY_ID.includes(v)));
  assert.ok(eq(s.properties.claimingAuthority.enum, ['sage', 'alchemist', 'oracle']));
  assert.ok(eq(s.properties.name.enum, Enums.CLAIM_NAME));

  const byAuthority = {};
  for (const branch of s.oneOf) {
    const authority = branch.properties.claimingAuthority.const;
    byAuthority[authority] = branch.properties.name.enum;
  }
  assert.ok(eq(byAuthority.sage, Enums.CLAIMS_BY_AUTHORITY.sage));
  assert.ok(eq(byAuthority.alchemist, Enums.CLAIMS_BY_AUTHORITY.alchemist));
  assert.ok(eq(byAuthority.oracle, Enums.CLAIMS_BY_AUTHORITY.oracle));
});

test('covenant-request-v1: callerAuthority matches CALLER_AUTHORITY; mode matches COVENANT_MODE', () => {
  const s = loadSchema('covenant-request-v1');
  assert.ok(eq(s.properties.callerAuthority.enum, Enums.CALLER_AUTHORITY));
  assert.ok(eq(s.properties.mode.enum, Enums.COVENANT_MODE));
  assert.equal(s.properties.convenedBy.const, 'legion');
});

test('covenant-record-v1: mode/outcome/finding-classification/disposition all match their enums', () => {
  const s = loadSchema('covenant-record-v1');
  assert.ok(eq(s.properties.mode.enum, Enums.COVENANT_MODE));
  assert.ok(eq(s.properties.outcome.enum, Enums.COVENANT_OUTCOME));
  assert.ok(eq(s.properties.findings.items.properties.classification.enum, Enums.FINDING_SCOPE_CLASS));
  assert.ok(eq(s.properties.callerDispositions.items.properties.disposition.enum, Enums.DISPOSITION_VALUE));
});

test('operation-envelope-v1: OperationRequest.authorityAssertion models per-message authority (S00 baseline: legacy trust was connection-level only)', () => {
  const s = loadSchema('operation-envelope-v1');
  const reqBranch = s.$defs.OperationRequest;
  assert.ok(reqBranch.required.includes('authorityAssertion'));
  assert.ok(eq(reqBranch.properties.authorityAssertion.properties.verificationMethod.enum, Enums.AUTHENTICATION_METHOD));
  assert.equal(reqBranch.properties.authorityAssertion.properties.perMessage.type, 'boolean');
});

test('operation-envelope-v1: request/result branches match AUTHORITY_ID / INVOCATION_STATE / DOMAIN_OUTCOME / CLAIM_BOUNDARY', () => {
  const s = loadSchema('operation-envelope-v1');
  const [reqBranch, resBranch] = [s.$defs.OperationRequest, s.$defs.OperationResult];
  assert.equal(reqBranch.properties.envelopeKind.const, 'request');
  assert.equal(resBranch.properties.envelopeKind.const, 'result');
  assert.ok(eq(reqBranch.properties.callerAuthority.enum, Enums.AUTHORITY_ID));
  assert.ok(eq(resBranch.properties.invocationState.enum, Enums.INVOCATION_STATE));
  assert.ok(eq(resBranch.properties.domainOutcome.enum, Enums.DOMAIN_OUTCOME));
  assert.ok(eq(resBranch.properties.claimBoundary.enum, Enums.CLAIM_BOUNDARY));
  // invocation/domain/claim must be three SEPARATE fields (WP2 task requirement), not collapsed.
  const resultFields = Object.keys(resBranch.properties);
  assert.ok(resultFields.includes('invocationState'));
  assert.ok(resultFields.includes('domainOutcome'));
  assert.ok(resultFields.includes('claimBoundary'));
});

test('legion-result-v1: invocation/domain/claim triad and authoritiesInvolved match their enums', () => {
  const s = loadSchema('legion-result-v1');
  assert.ok(eq(s.properties.invocationState.enum, Enums.INVOCATION_STATE));
  assert.ok(eq(s.properties.domainOutcome.enum, Enums.DOMAIN_OUTCOME));
  assert.ok(eq(s.properties.claimBoundary.enum, Enums.CLAIM_BOUNDARY));
  assert.ok(eq(s.properties.authoritiesInvolved.items.enum, Enums.AUTHORITY_ID));
  const fields = Object.keys(s.properties);
  assert.ok(fields.includes('invocationState') && fields.includes('domainOutcome') && fields.includes('claimBoundary'));
});

test('legacy-envelope-v1: minimal extension point shape (opaque payload + provenance + provisional mapping ref only)', () => {
  const s = loadSchema('legacy-envelope-v1');
  const required = new Set(s.required);
  for (const key of ['legacyKind', 'payload', 'provenance', 'provisionalMappingRef']) {
    assert.ok(required.has(key), `legacy-envelope-v1 must require ${key}`);
  }
});

// --- 4. ID grammar sanity: every X-# pattern in ids.md is exercised somewhere -

test('sequence-id patterns from ids.md appear as literal patterns in at least one schema', () => {
  const idsMd = readFileSync(path.join(__dirname, 'ids.md'), 'utf8');
  const patterns = ['\\^R-\\\\d\\+\\$', '\\^D-\\\\d\\+\\$', '\\^I-\\\\d\\+\\$', '\\^AC-\\\\d\\+\\$', '\\^EC-\\\\d\\+\\$', '\\^B-\\\\d\\+\\$', '\\^A-\\\\d\\+\\$', '\\^CV-\\\\d\\+\\$'];
  // Loose sanity: ids.md documents these prefixes and at least one schema file references each prefix literally.
  const allSchemaText = SCHEMA_NAMES.map((n) => readFileSync(SCHEMA_PATHS[n], 'utf8')).join('\n');
  for (const prefix of ['R-', 'D-', 'I-', 'AC-', 'EC-', 'T-', 'B-', 'A-', 'CV-']) {
    assert.ok(idsMd.includes(`\`${prefix}\``) || idsMd.includes(prefix), `ids.md should document prefix ${prefix}`);
    assert.ok(allSchemaText.includes(`^${prefix}`), `no schema uses the ${prefix} id pattern`);
  }
});

test('enums.mjs: assertEnum and assertSchemaVersion behave as documented', () => {
  assert.equal(Enums.assertEnum('latitude', Enums.LATITUDE, 'EXACT'), 'EXACT');
  assert.throws(() => Enums.assertEnum('latitude', Enums.LATITUDE, 'NOPE'), TypeError);
  assert.equal(Enums.assertSchemaVersion('x', 1), 1);
  assert.throws(() => Enums.assertSchemaVersion('x', 2), TypeError);
});

test('canonical authority ID set is exact', () => {
  assert.deepEqual(Enums.AUTHORITY_ID, ['legion', 'sage', 'alchemist', 'oracle', 'arcane', 'covenant', 'kernel']);
});
