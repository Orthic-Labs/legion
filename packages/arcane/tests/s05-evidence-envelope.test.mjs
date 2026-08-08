// S05 — evidence-envelope.mjs
//
// Covers: sealEvidence produces a valid evidence-capability-receipt-v1 plus a
// richer Arcane-side envelope; the DEPENDENCY_DIMENSION set and its
// projection down to the frozen 6-value dependsOn[].kind enum; envelopeDigest
// determinism/tamper-detection; and legacy-import trust non-inheritance
// (S00 finding: a legacy self-hash never becomes real authentication).

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEPENDENCY_DIMENSION,
  DEPENDENCY_KIND_PROJECTION,
  UNFAITHFUL_DIMENSIONS,
  sealEvidence,
  envelopeDigest,
  importLegacyEvidence,
} from '../lib/evidence-envelope.mjs';
import { assertValid } from '../lib/validate.mjs';
import { mintId } from '../lib/ids.mjs';
import { ArcaneError } from '../lib/errors.mjs';

function baseArgs(overrides = {}) {
  return {
    runId: mintId('run'),
    taskId: null,
    contractId: null,
    producerAuthority: 'alchemist',
    capability: 'test-run',
    observation: { command: 'node --test', exitCode: 0 },
    evidenceClass: 'deterministic',
    sourceRevision: '0123456789abcdef0123456789abcdef01234567',
    dependencies: [],
    authentication: {
      issuerIdentity: 'host:claude-code',
      verificationMethod: 'host-connection-trust',
      perMessage: false,
      verifiedAt: null,
    },
    replayDefense: { nonce: null, sequence: null, freshnessWindowSeconds: null, freshAt: null },
    observedAt: new Date().toISOString(),
    ...overrides,
  };
}

test('sealEvidence produces a receipt that satisfies evidence-capability-receipt-v1', () => {
  const { receipt } = sealEvidence(baseArgs());
  assertValid('evidence-capability-receipt-v1', receipt); // throws on failure
  assert.equal(receipt.stale, false);
  assert.match(receipt.evidenceId, /^ev_[0-9A-HJKMNP-TV-Z]{26}$/);
});

test('sealEvidence returns an envelope richer than the receipt, carrying the full dimension set losslessly', () => {
  const { receipt, envelope } = sealEvidence(
    baseArgs({
      dependencies: [
        { dimension: 'worktree-dirty', ref: 'wt:main', digest: 'sha256:' + '0'.repeat(64) },
        { dimension: 'environment', ref: 'host:ci-1', digest: 'sha256:' + '1'.repeat(64) },
      ],
    }),
  );
  assert.equal(envelope.dependencies.length, 2);
  assert.equal(envelope.dependencies[0].dimension, 'worktree-dirty');
  assert.equal(envelope.dependencies[1].dimension, 'environment');
  // receipt collapses to the frozen 6-value kind enum but keeps the fact
  // recoverable in `ref`.
  assert.equal(receipt.dependsOn.length, 2);
  for (const d of receipt.dependsOn) {
    assert.match(d.ref, /^(worktree-dirty|environment):/);
  }
});

test('sealEvidence rejects an unknown dependency dimension', () => {
  assert.throws(
    () => sealEvidence(baseArgs({ dependencies: [{ dimension: 'not-a-real-dimension', ref: 'x', digest: 'sha256:' + '0'.repeat(64) }] })),
    (err) => err instanceof ArcaneError && err.code === 'ARC_DEPENDENCY_UNKNOWN',
  );
});

test('DEPENDENCY_DIMENSION carries the full §6.2 set including the evidence transitive-edge dimension', () => {
  const expected = [
    'source-digest',
    'git-revision',
    'worktree-dirty',
    'lockfile-version',
    'config-digest',
    'schema-version',
    'fixture-digest',
    'tool-version',
    'environment',
    'method-fingerprint',
    'policy-version',
    'topology',
    'external-source-revision',
    'approval-authority',
    'upstream-contract-revision',
    'evidence',
  ];
  assert.deepEqual([...DEPENDENCY_DIMENSION].sort(), [...expected].sort());
});

test('every dependency dimension has a projection into the frozen dependsOn[].kind enum', () => {
  const frozenKinds = new Set(['decision', 'source-revision', 'config-digest', 'tool-digest', 'policy-digest', 'evidence']);
  for (const dim of DEPENDENCY_DIMENSION) {
    const proj = DEPENDENCY_KIND_PROJECTION[dim];
    assert.ok(proj, `missing projection for dimension ${dim}`);
    assert.ok(frozenKinds.has(proj.kind), `projection kind ${proj.kind} for ${dim} is not in the frozen enum`);
    assert.equal(typeof proj.faithful, 'boolean');
  }
  // At least the dimensions we know have no faithful bucket are flagged.
  assert.ok(UNFAITHFUL_DIMENSIONS.includes('worktree-dirty'));
  assert.ok(UNFAITHFUL_DIMENSIONS.includes('environment'));
  assert.ok(UNFAITHFUL_DIMENSIONS.length > 0);
});

test('envelopeDigest is deterministic and idempotent across re-attachment', () => {
  const { envelope } = sealEvidence(baseArgs());
  const d1 = envelopeDigest(envelope);
  const d2 = envelopeDigest({ ...envelope, envelopeDigest: 'sha256:' + 'f'.repeat(64) });
  assert.equal(d1, d2);
  assert.equal(d1, envelope.envelopeDigest);
});

test('envelopeDigest changes when envelope content changes', () => {
  const { envelope: e1 } = sealEvidence(baseArgs());
  const { envelope: e2 } = sealEvidence(baseArgs({ capability: 'different-capability' }));
  assert.notEqual(envelopeDigest(e1), envelopeDigest(e2));
});

test('importLegacyEvidence accepts a legacy-envelope-v1-shaped record and marks it never-qualifying', () => {
  const legacy = {
    schemaVersion: 1,
    kind: 'legion-legacy-envelope',
    legacyKind: 'evidence',
    payload: { signature_or_mac: 'deadbeef', outcome: 'pass' },
    provenance: {
      source: 'forge',
      capturedAt: new Date().toISOString(),
      sourceRevision: null,
      importedBy: 'legacy-importer',
      authenticated: false,
    },
    provisionalMappingRef: null,
  };
  const envelope = importLegacyEvidence(legacy, { runId: mintId('run') });
  assert.equal(envelope.trustClass, 'legacy-unauthenticated');
  assert.equal(envelope.neverQualifying, true);
  assert.equal(envelope.authentication.verificationMethod, 'unauthenticated');
});

test('importLegacyEvidence refuses a record that is not legacy-envelope-v1 shaped', () => {
  assert.throws(
    () => importLegacyEvidence({ kind: 'something-else' }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_SCHEMA_INVALID',
  );
});

test('importLegacyEvidence refuses a record that claims authenticated: true (cannot exist under the frozen schema, but must not be trusted here either)', () => {
  assert.throws(
    () =>
      importLegacyEvidence({
        kind: 'legion-legacy-envelope',
        legacyKind: 'evidence',
        payload: {},
        provenance: { source: 'forge', capturedAt: new Date().toISOString(), authenticated: true },
        provisionalMappingRef: null,
      }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_AUTH_LEGACY_DIGEST',
  );
});
