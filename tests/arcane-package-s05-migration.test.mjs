// S05 — evidence-migration.mjs
//
// WP4 S05 action 8 gap: evidence-envelope.mjs ships a single-record import
// path (`importLegacyEvidence`) but no batch-migration/parity/rollback
// pipeline. This file covers the batch wrapper: `migrateLegacyEvidence`
// (import a whole batch, register every import into a DependencyLedger as
// untrusted, quarantine what cannot be read, emit one deterministic receipt)
// and `verifyMigration` (re-run the projection and diff against a prior
// receipt).
//
// Hard properties under test, each isolated: deterministic, rollback-safe,
// old records never gain trust, corruption is quarantined without aborting
// the batch, and parity detects a tampered record by name.

import test from 'node:test';
import assert from 'node:assert/strict';

import { migrateLegacyEvidence, verifyMigration } from '../src/lib/verification/arcane/evidence-migration.mjs';
import { DependencyLedger } from '../src/lib/verification/arcane/invalidation.mjs';
import { ArcaneError } from '../src/lib/contracts/arcane/errors.mjs';

const CAPTURED_AT = '2026-01-01T00:00:00.000Z';
const MAPPING_VERSION = 'forge-to-arcane@s01.v1';

function legacyRecord(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-legacy-envelope',
    legacyKind: 'evidence',
    payload: { signature_or_mac: 'deadbeef', outcome: 'pass' },
    provenance: {
      source: 'forge',
      capturedAt: '2025-06-01T00:00:00.000Z',
      sourceRevision: 'abc123def456',
      importedBy: 'legacy-importer',
      authenticated: false,
    },
    provisionalMappingRef: null,
    ...overrides,
  };
}

function corruptRecord() {
  // payload.corrupt is a non-finite number: canonical.mjs's encode() rejects
  // it (ARC_CANONICALIZATION_FAILED) when importLegacyEvidence digests the
  // payload — a genuine "cannot be read" case, not a contrived one.
  return legacyRecord({ payload: { corrupt: NaN } });
}

function fakeAuthenticatedRecord() {
  return legacyRecord({
    provenance: {
      source: 'forge',
      capturedAt: '2025-06-01T00:00:00.000Z',
      authenticated: true, // never legal for a legacy envelope; importLegacyEvidence must refuse it
    },
  });
}

test('migrateLegacyEvidence imports well-formed records, registers them untrusted, and counts match', () => {
  const ledger = new DependencyLedger({ clock: () => CAPTURED_AT });
  const records = [legacyRecord(), legacyRecord({ payload: { outcome: 'fail' } })];

  const { receipt, imported, quarantined, rejected } = migrateLegacyEvidence({
    records,
    ledger,
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  assert.equal(imported.length, 2);
  assert.equal(quarantined.length, 0);
  assert.equal(rejected.length, 0);
  assert.equal(receipt.source.recordCount, 2);
  assert.equal(receipt.destination.count, 2);
  assert.equal(receipt.source.recordCount, receipt.destination.count);
  assert.equal(receipt.parity.recordCountMatches, true);
  assert.equal(receipt.mappingVersion, MAPPING_VERSION);
  assert.equal(receipt.capturedAt, CAPTURED_AT);

  // Every imported record is actually registered in the ledger, untrusted.
  for (const rec of imported) {
    assert.equal(ledger.isStale(rec.evidenceId), false);
  }
});

test('deterministic: two runs over identical input produce byte-identical receipts', () => {
  const records = [legacyRecord(), legacyRecord({ payload: { outcome: 'fail' } })];

  const run1 = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger({ clock: () => CAPTURED_AT }),
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });
  const run2 = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger({ clock: () => CAPTURED_AT }),
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  assert.deepEqual(run1.receipt, run2.receipt);

  // Sanity: the volatile Kernel-minted evidenceId is real and independently
  // minted per run (proves determinism holds despite that, not because
  // imports were skipped/cached).
  assert.notEqual(run1.imported[0].evidenceId, run2.imported[0].evidenceId);
});

test('rollback-safe: receipt names its rollback source and the original records are recoverable unchanged', () => {
  const records = [legacyRecord(), corruptRecord()];
  const before = JSON.parse(JSON.stringify(records));

  const { receipt } = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger({ clock: () => CAPTURED_AT }),
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  // Nothing in the source was rewritten.
  assert.deepEqual(JSON.parse(JSON.stringify(records)), before);

  assert.equal(typeof receipt.rollback.source, 'string');
  assert.ok(receipt.rollback.source.length > 0);
  assert.equal(typeof receipt.rollback.method, 'string');
  assert.equal(receipt.rollback.reversible, true);
  assert.equal(receipt.destructive, false);
});

test('old records never gain trust: imported evidence stays untrusted and the receipt trust tally is zero', () => {
  const ledger = new DependencyLedger({ clock: () => CAPTURED_AT });
  const records = [legacyRecord()];

  const { receipt, imported } = migrateLegacyEvidence({
    records,
    ledger,
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  assert.equal(receipt.trust.trustGranted, 0);

  const [rec] = imported;
  assert.equal(rec.trustClass, 'legacy-unauthenticated');
  assert.equal(rec.neverQualifying, true);

  ledger.link(rec.evidenceId, { criterionId: 'AC-migrated' });
  const eligibility = ledger.proofEligibility('AC-migrated');
  assert.notEqual(eligibility.status, 'proven');
  assert.equal(eligibility.status, 'insufficient');
  assert.ok(eligibility.reasons.some((r) => r.includes(rec.evidenceId) && r.includes('untrusted')));
});

test('corruption: a corrupt/unparseable record is quarantined by exact id, blocks strong claims, and does not abort the migration', () => {
  const ledger = new DependencyLedger({ clock: () => CAPTURED_AT });
  const records = [legacyRecord(), corruptRecord(), legacyRecord({ payload: { outcome: 'fail' } })];

  const { receipt, imported, quarantined, rejected } = migrateLegacyEvidence({
    records,
    ledger,
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  // Migration proceeded past the corrupt record — readable history preserved
  // for both neighbors.
  assert.equal(imported.length, 2);
  assert.equal(rejected.length, 0);
  assert.equal(quarantined.length, 1);

  // Exact affected id reported.
  assert.equal(quarantined[0].recordId, 'legacy-evidence#1');
  assert.deepEqual(receipt.quarantine.ids, ['legacy-evidence#1']);
  assert.equal(receipt.quarantine.count, 1);
  assert.equal(quarantined[0].code, 'ARC_CANONICALIZATION_FAILED');

  // Readable history: the corrupt record's shape is still visible, not dropped.
  assert.ok(quarantined[0].snapshot);
  assert.equal(quarantined[0].snapshot.legacyKind, 'evidence');

  // Total accounted for.
  assert.equal(records.length, imported.length + quarantined.length + rejected.length);
  assert.equal(receipt.parity.recordCountMatches, true);

  // The corrupt record never entered the ledger at all — it cannot back a
  // strong claim because there is no evidence id to link.
  const untouchedCriterion = ledger.proofEligibility('AC-none-linked-to-corrupt');
  assert.equal(untouchedCriterion.status, 'insufficient');
});

test('a legacy record that claims authenticated:true is rejected (not merely quarantined) and never imported', () => {
  const ledger = new DependencyLedger({ clock: () => CAPTURED_AT });
  const records = [legacyRecord(), fakeAuthenticatedRecord()];

  const { receipt, imported, quarantined, rejected } = migrateLegacyEvidence({
    records,
    ledger,
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  assert.equal(imported.length, 1);
  assert.equal(quarantined.length, 0);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].recordId, 'legacy-evidence#1');
  assert.equal(rejected[0].code, 'ARC_AUTH_LEGACY_DIGEST');
  assert.deepEqual(receipt.rejected.ids, ['legacy-evidence#1']);
});

test('parity: verifyMigration returns ok:true against unmodified records, and no volatile evidenceId leaks into the receipt', () => {
  const records = [legacyRecord(), legacyRecord({ payload: { outcome: 'fail' } })];
  const { receipt } = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger({ clock: () => CAPTURED_AT }),
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  const result = verifyMigration(receipt, { records, capturedAt: CAPTURED_AT, mappingVersion: MAPPING_VERSION });
  assert.equal(result.ok, true);
  assert.deepEqual(result.mismatches, []);

  assert.equal(JSON.stringify(receipt).includes('"evidenceId"'), false);
});

test('parity: a deliberately altered record makes verifyMigration return ok:false, naming that record', () => {
  const records = [legacyRecord(), legacyRecord({ payload: { outcome: 'fail' } })];
  const { receipt } = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger({ clock: () => CAPTURED_AT }),
    capturedAt: CAPTURED_AT,
    mappingVersion: MAPPING_VERSION,
  });

  const tampered = JSON.parse(JSON.stringify(records));
  tampered[1].payload.outcome = 'tampered';

  const result = verifyMigration(receipt, { records: tampered, capturedAt: CAPTURED_AT, mappingVersion: MAPPING_VERSION });
  assert.equal(result.ok, false);
  assert.ok(result.mismatches.length > 0);
  assert.ok(result.mismatches.some((m) => m.recordId === 'legacy-evidence#1'));
  // The untouched record must not be named.
  assert.ok(!result.mismatches.some((m) => m.recordId === 'legacy-evidence#0'));
});

test('migrateLegacyEvidence rejects malformed input defensively', () => {
  const ledger = new DependencyLedger();
  assert.throws(
    () => migrateLegacyEvidence({ records: 'nope', ledger, capturedAt: CAPTURED_AT, mappingVersion: MAPPING_VERSION }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_SCHEMA_INVALID',
  );
  assert.throws(
    () => migrateLegacyEvidence({ records: [], ledger: null, capturedAt: CAPTURED_AT, mappingVersion: MAPPING_VERSION }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_SCHEMA_INVALID',
  );
  assert.throws(
    () => migrateLegacyEvidence({ records: [], ledger, capturedAt: '', mappingVersion: MAPPING_VERSION }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_SCHEMA_INVALID',
  );
  assert.throws(
    () => migrateLegacyEvidence({ records: [], ledger, capturedAt: CAPTURED_AT, mappingVersion: '' }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_SCHEMA_INVALID',
  );
});
