// S01 — Forge compatibility mapping + runtime bridge.
//
// Acceptance (03-SENTINEL-WP4-DISPATCH.md, S01):
//   - the schema map has no unresolved legacy item that can affect signoff,
//     authority, invalidation, or compatibility;
//   - golden legacy fixtures produce semantically equivalent state;
//   - known legacy defects remain fixed, not reproduced;
//   - old store read is deterministic;
//   - migration is reversible;
//   - alias calls and canonical calls converge on the same Arcane state.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  SCHEMA_MAP,
  OPERATION_MAP,
  DISPOSITIONS,
  dispositionFor,
  envelopeFor,
  bridgeStoreSnapshot,
  bridgeOperationResponse,
  migrationDryRun,
  parityReport,
  reverseEnvelope,
  FIXTURES_DIR,
} from '../lib/legacy-bridge.mjs';
import { validateAgainst } from '../lib/validate.mjs';
import { canonicalJson, digestValue } from '../lib/canonical.mjs';
import { ArcaneError } from '../lib/errors.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CAPTURED_AT = '2026-08-06T02:31:10.000Z'; // S00 baseline commit date — fixed, so runs are deterministic
const PROVENANCE = {
  source: 'forge',
  capturedAt: CAPTURED_AT,
  sourceRevision: '947d5b89a45049fe18ffb6ffdda085d19479431e',
  importedBy: 'arcane/legacy-bridge@1',
};

test('S01: the schema map covers every record type in the S00 inventory', () => {
  const inventory = JSON.parse(
    readFileSync(path.join(FIXTURES_DIR, '..', 'legacy-semantic-inventory.json'), 'utf8'),
  );
  const inventoryNames = inventory.record_types.map((r) => r.name).sort();
  const mapped = SCHEMA_MAP.recordTypes.map((r) => r.legacyKind).sort();
  assert.deepEqual(mapped, inventoryNames);
});

test('S01: no unresolved legacy item, and every trust-bearing field is canonical-with-target or rejected-with-reason', () => {
  assert.deepEqual(SCHEMA_MAP.unresolved, []);
  const TRUST_AXES = ['signoff', 'authority', 'invalidation', 'compatibility'];
  for (const rt of SCHEMA_MAP.recordTypes) {
    for (const f of rt.fields) {
      assert.ok(
        DISPOSITIONS.includes(f.disposition),
        `${rt.legacyKind}.${f.legacyField} has an unknown disposition: ${f.disposition}`,
      );
      const trustBearing = Array.isArray(f.affects) && f.affects.some((a) => TRUST_AXES.includes(a));
      if (!trustBearing) continue;
      if (f.disposition === 'rejected') {
        assert.ok(f.reason && f.reason.length > 40, `${rt.legacyKind}.${f.legacyField} rejected without a sourced reason`);
      } else if (f.disposition === 'canonical') {
        assert.ok(f.canonicalTarget, `${rt.legacyKind}.${f.legacyField} canonical without a target`);
      } else {
        // compatibility-only / deprecated on a trust axis must say why it is safe
        assert.ok(
          f.note || f.reason_not_canonical,
          `${rt.legacyKind}.${f.legacyField} touches ${f.affects} but explains nothing`,
        );
      }
    }
  }
});

test('S01: the three S00 trust findings are rejected, never carried across', () => {
  assert.equal(dispositionFor('orthic.tool-receipt.v1', 'signature_or_mac'), 'rejected');
  assert.equal(dispositionFor('evidence', 'trust_class'), 'rejected');
  assert.equal(dispositionFor('evidence', 'attested'), 'rejected');
  assert.equal(dispositionFor('checks', 'status'), 'rejected');
  assert.equal(dispositionFor('checks', 'receipt'), 'rejected');
  assert.equal(dispositionFor('runs', 'authority'), 'rejected');
});

test('S01: bridging a real S00 store-snapshot fixture yields valid envelopes with authenticated:false', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const result = bridgeStoreSnapshot(snapshot, PROVENANCE);

  assert.ok(result.envelopes.length >= 9, 'expected one envelope per stored row');
  for (const env of result.envelopes) {
    const { valid, issues } = validateAgainst('legacy-envelope-v1', env);
    assert.ok(valid, `envelope invalid: ${issues.join(', ')}`);
    assert.equal(env.provenance.authenticated, false);
    assert.equal(env.provisionalMappingRef, null);
    assert.equal(
      env.provenance.legacyInventoryRef,
      'src/packages/arcane/compatibility/forge/schema-map.json',
    );
  }
});

test('S01: bridging preserves the legacy payload byte-for-byte', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const { envelopes } = bridgeStoreSnapshot(snapshot, PROVENANCE);
  const runEnvelope = envelopes.find((e) => e.legacyKind === 'runs');
  assert.equal(canonicalJson(runEnvelope.payload), canonicalJson(snapshot.runs[0]));
});

test('S01: reverseEnvelope round-trips — migration is reversible', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const { envelopes } = bridgeStoreSnapshot(snapshot, PROVENANCE);
  for (const env of envelopes) {
    const back = reverseEnvelope(env);
    assert.equal(canonicalJson(back.payload), canonicalJson(env.payload));
    assert.equal(back.legacyKind, env.legacyKind);
  }
});

test('S01: reading the legacy store is deterministic — same input, identical digest', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const a = bridgeStoreSnapshot(snapshot, PROVENANCE);
  const b = bridgeStoreSnapshot(snapshot, PROVENANCE);
  assert.equal(digestValue(a.envelopes), digestValue(b.envelopes));
});

test('S01: every S00 operation-response fixture bridges to a typed compatibility result', () => {
  const files = readdirSync(FIXTURES_DIR).filter((f) => /^\d\d-/.test(f) && f.endsWith('.json'));
  assert.equal(files.length, 12, 'S00 produced 12 fixtures');
  for (const f of files) {
    if (f === '08-store-snapshot-scoped.json') continue;
    const body = JSON.parse(readFileSync(path.join(FIXTURES_DIR, f), 'utf8'));
    const out = bridgeOperationResponse(body, PROVENANCE);
    assert.ok(out.canonicalOperationId || out.disposition, `${f} produced no canonical mapping or disposition`);
    const { valid, issues } = validateAgainst('legacy-envelope-v1', out.envelope);
    assert.ok(valid, `${f}: ${issues.join(', ')}`);
    assert.equal(out.envelope.provenance.authenticated, false);
  }
});

test('S01: a legacy authority claim in an alias payload is a typed compatibility error, not a silent drop', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const { rejections } = bridgeStoreSnapshot(snapshot, PROVENANCE);
  const authorityRejections = rejections.filter((r) => r.legacyField === 'authority');
  assert.ok(authorityRejections.length > 0, 'runs.authority must surface as an explicit rejection');
  for (const r of authorityRejections) {
    assert.equal(r.code, 'ARC_AUTHORITY_MODEL_CLAIMED');
    assert.ok(r.reason.length > 0);
  }
});

test('S01: legacy trust fields present in a fixture are reported as rejected, with their values quarantined in the payload', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const { rejections, envelopes } = bridgeStoreSnapshot(snapshot, PROVENANCE);
  const trustRejects = rejections.filter((r) => r.legacyField === 'trust_class' || r.legacyField === 'attested');
  assert.ok(trustRejects.length >= 2, 'evidence trust fields must be rejected');
  // ...but the value itself is still readable in the envelope payload (no data loss).
  const ev = envelopes.find((e) => e.legacyKind === 'evidence');
  assert.ok('trust_class' in ev.payload);
});

test('S01: the bridge contains no independent policy decision (alias rule)', () => {
  const src = readFileSync(path.join(__dirname, '..', 'lib', 'legacy-bridge.mjs'), 'utf8');
  // The bridge translates and reports. It must never return an allow/deny verdict itself.
  assert.equal(/\ballowed\s*:\s*true\b/.test(src), false, 'bridge must not mint an allow decision');
  assert.equal(/\bdecision\s*\(/.test(src), false, 'bridge must not call decision() — policy lives in lib/policy.mjs');
});

test('S01: migrationDryRun is a projection with source/destination counts and digests, and writes nothing', () => {
  const report = migrationDryRun({ capturedAt: CAPTURED_AT });
  assert.equal(report.schema, 'arcane.forge-migration-dry-run.v1');
  assert.equal(report.destructive, false);
  assert.ok(report.source.recordCount > 0);
  assert.equal(report.source.recordCount, report.destination.envelopeCount);
  assert.match(report.source.digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(report.destination.digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(report.rollback.source.length > 0);
  assert.equal(report.destination.authenticatedCount, 0, 'no imported record may be authenticated');
  // Deterministic
  assert.equal(digestValue(migrationDryRun({ capturedAt: CAPTURED_AT })), digestValue(report));
});

test('S01: parityReport tallies dispositions and asserts zero unresolved', () => {
  const report = parityReport();
  assert.equal(report.schema, 'arcane.forge-parity-report.v1');
  assert.equal(report.unresolvedCount, 0);
  assert.ok(report.totals.rejected > 0, 'legacy trust fields must be rejected, not all-canonical');
  assert.ok(report.totals.canonical > 0);
  assert.equal(report.recordTypes.length, SCHEMA_MAP.recordTypes.length);
  for (const d of report.knownDefectsNotReproduced) assert.ok(d.length > 20);
});

test('S01: an unknown legacy kind is a typed error, never a silent passthrough', () => {
  assert.throws(
    () => envelopeFor('not-a-forge-record', { x: 1 }, PROVENANCE),
    (e) => e instanceof ArcaneError && e.code === 'ARC_SCHEMA_INVALID',
  );
});

test('S01: the runtime bridge mints no private ids while the Kernel is unbound', () => {
  const snapshot = JSON.parse(readFileSync(path.join(FIXTURES_DIR, '08-store-snapshot-scoped.json'), 'utf8'));
  const { correspondence, kernel } = bridgeStoreSnapshot(snapshot, PROVENANCE);
  assert.equal(kernel.bound, false);
  for (const c of correspondence) {
    assert.equal(c.canonicalId, null, 'no canonical id may be allocated without the Kernel identity interface');
    assert.equal(c.allocator, 'kernel-unbound');
    assert.ok(c.legacyId);
  }
});

test('S01: the operation map preserves the retired sole-open-run heuristic and refuses purge', () => {
  const resolve = OPERATION_MAP.operations.find((o) => o.legacyOperation === 'resolveSession');
  assert.match(resolve.preservedBehavior.join(' '), /retired/i);
  const purge = OPERATION_MAP.operations.find((o) => o.legacyOperation === 'purge');
  assert.equal(purge.disposition, 'rejected');
  assert.equal(purge.canonicalOperationId, null);
});

test('S01: the dispatcher fail-open defect is explicitly NOT reproduced', () => {
  const hook = OPERATION_MAP.operations.find((o) => /hook dispatch/.test(o.legacyOperation));
  const conflict = hook.conflicts.find((c) => /timeout|budget/i.test(c.legacy));
  assert.ok(conflict, 'the 1500ms fail-open bypass must be named');
  assert.match(conflict.resolution, /fail closed|ARC_GATE_UNAVAILABLE/i);
  assert.ok(
    SCHEMA_MAP.knownLegacyDefectsNotReproduced.some((d) => /bypassed_delayed_verifier|fail-open/i.test(d)),
  );
});
