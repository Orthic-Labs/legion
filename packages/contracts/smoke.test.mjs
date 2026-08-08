// Legion shared-contract smoke test — WP2 freeze.
//
// Nemesis has no ajv dependency and this task adds none. These are
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

test('every schema declares schemaVersion const 1 and a kind const', () => {
  for (const name of SCHEMA_NAMES) {
    const schema = loadSchema(name);
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

test('amendment-v1: sealedBy is sage-only', () => {
  const s = loadSchema('amendment-v1');
  assert.equal(s.properties.sealedBy.const, 'sage');
});

test('claim-v1: claimingAuthority is a subset of AUTHORITY_ID; name matches CLAIM_NAME; per-authority oneOf branches match CLAIMS_BY_AUTHORITY', () => {
  const s = loadSchema('claim-v1');
  assert.ok(s.properties.claimingAuthority.enum.every((v) => Enums.AUTHORITY_ID.includes(v)));
  assert.ok(eq(s.properties.claimingAuthority.enum, ['sage', 'alchemist', 'seer']));
  assert.ok(eq(s.properties.name.enum, Enums.CLAIM_NAME));

  const byAuthority = {};
  for (const branch of s.oneOf) {
    const authority = branch.properties.claimingAuthority.const;
    byAuthority[authority] = branch.properties.name.enum;
  }
  assert.ok(eq(byAuthority.sage, Enums.CLAIMS_BY_AUTHORITY.sage));
  assert.ok(eq(byAuthority.alchemist, Enums.CLAIMS_BY_AUTHORITY.alchemist));
  assert.ok(eq(byAuthority.seer, Enums.CLAIMS_BY_AUTHORITY.seer));
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

test('naming guard: no produced contract object (schemas + index.mjs) contains superseded archive naming (Sorcerer/Sentinel)', () => {
  // Scoped to the actual contract surface, not enums.mjs/ids.md/this file:
  // those three necessarily *name* the banned terms in order to document
  // and enforce the ban (same reason 00-CANON.md's naming-record table
  // spells them out) — scanning them would make the guard fail on its own
  // policy text. What must never leak the superseded names is the contract
  // objects downstream lanes actually consume: the schemas and index.mjs.
  const files = [...SCHEMA_NAMES.map((n) => SCHEMA_PATHS[n]), path.join(__dirname, 'index.mjs')];
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    assert.ok(!/Sorcerer/i.test(text), `${f} contains superseded naming 'Sorcerer'`);
    assert.ok(!/Sentinel/i.test(text), `${f} contains superseded naming 'Sentinel'`);
  }
});
