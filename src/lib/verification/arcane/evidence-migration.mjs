// S05 — batch legacy-evidence migration receipt (WP4 S05 action 8, plus the
// batch half of action 7 and the migration side of action 9).
//
// evidence-envelope.mjs already ships `importLegacyEvidence`: a single-record
// import path, legacy-envelope-v1 in, never-qualifying Arcane evidence out.
// The WP4 dispatch's S05 action 8 ("Generate migration receipt with source
// counts/digests, destination counts/digests, mapping version, parity
// result, and rollback source") was left unbuilt — only the one-record path
// existed. This module is that batch wrapper: run `importLegacyEvidence`
// over a whole batch, register every import into a DependencyLedger as
// untrusted, quarantine what cannot be read rather than aborting, and emit
// one deterministic migration receipt.
//
// Same family as legacy-bridge.mjs's `migrationDryRun` / `parityReport`
// (S01): same digest convention (`digestValue` from canonical.mjs), same
// honesty about what did not carry across (a reported list, never a silent
// drop), same read-only relationship to its input, same
// `{schema, deliverable, lane, destructive, rollback}` receipt shape. It does
// not reuse S01's code directly: S01 bridges a whole legacy *store snapshot*
// into `legacy-envelope-v1` records; this module starts one step later, from
// already-enveloped legacy *evidence* records, and stays inside what S05 owns
// (evidence + invalidation).
//
// Determinism note: `importLegacyEvidence` mints its `evidenceId` via the
// Kernel binding's provisional allocator (kernel-binding.mjs), which is
// time/randomness-based whenever no Kernel is bound (the normal case here —
// see ARC_KERNEL_PRIMITIVE_UNAVAILABLE). That id is real and is exactly what
// callers need to link imported evidence into a DependencyLedger, so it is
// kept on `imported[]`. It is NOT deterministic, so it is deliberately
// excluded from every digest this module computes for the receipt. Per-record
// identity *in the receipt* is instead the input record's position
// (`legacy-evidence#<index>`) — stable, available even for a record too
// corrupt to parse, and never minted.

import { ArcaneError } from '../../contracts/arcane/errors.mjs';
import { digest, digestValue } from '../../contracts/arcane/canonical.mjs';
import { kernelStatus } from '../../core/kernel-binding.mjs';
import { importLegacyEvidence } from './evidence-envelope.mjs';
import { DependencyLedger } from './invalidation.mjs';

/**
 * Best-effort digest: falls back to an index-seeded digest for content that
 * cannot be canonically serialized (e.g. a corrupt record whose payload
 * carries a non-finite number). A corrupt record still gets a deterministic
 * identity in the receipt instead of aborting digest computation for the
 * whole batch.
 */
function safeDigest(value, fallbackSeed) {
  try {
    return digestValue(value);
  } catch {
    return digest(`unencodable:${fallbackSeed}`);
  }
}

/**
 * Best-effort JSON snapshot for "readable history" (WP4 S05 acceptance:
 * corruption must "preserve readable history", not drop it). Standard
 * JSON.stringify tolerates the things canonical.mjs deliberately rejects
 * (NaN/Infinity serialize as null, exactly like JSON.stringify always has);
 * only a genuinely circular or BigInt-bearing value falls through to null.
 */
function readableSnapshot(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return null;
  }
}

/**
 * Deterministic projection of an imported record for parity/digest purposes:
 * drops the volatile Kernel-minted `evidenceId`, keeps everything else
 * (including the position-stable `recordId`).
 */
function projectForParity(envelopeWithRecordId) {
  const { evidenceId, recordId, ...rest } = envelopeWithRecordId;
  return { recordId, ...rest };
}

/**
 * Batch-migrate legacy-envelope-v1-shaped evidence records into Arcane
 * evidence, registering every import into `ledger` as untrusted, and produce
 * one deterministic migration receipt.
 *
 * @param {object} args
 * @param {object[]} args.records legacy-envelope-v1-shaped records (the shape
 *   `importLegacyEvidence` already accepts), in stable order. A record may be
 *   malformed/corrupt — it is quarantined or rejected, never allowed to abort
 *   the batch.
 * @param {DependencyLedger} args.ledger evidence is registered here with
 *   `{trusted:false}` — this is the ledger-side half of "old records never
 *   gain trust".
 * @param {string} args.capturedAt ISO timestamp for the whole batch. Passed
 *   through to every record's `observedAt` instead of each record's own
 *   `provenance.capturedAt`, so the receipt never depends on Date.now() or on
 *   per-record clock drift — determinism requires taking this as a parameter.
 * @param {string} args.mappingVersion caller-asserted mapping/schema version
 *   this batch was translated under (e.g. legacy-bridge.mjs's
 *   `SCHEMA_MAP.schema`).
 * @returns {{receipt: object, imported: object[], quarantined: object[], rejected: object[]}}
 */
export function migrateLegacyEvidence({ records, ledger, capturedAt, mappingVersion }) {
  if (!Array.isArray(records)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'migrateLegacyEvidence requires records to be an array', {
      records: typeof records,
    });
  }
  if (!ledger || typeof ledger.register !== 'function') {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'migrateLegacyEvidence requires a DependencyLedger instance', {});
  }
  if (typeof capturedAt !== 'string' || capturedAt.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'migrateLegacyEvidence requires capturedAt as a non-empty ISO string', {
      capturedAt: typeof capturedAt,
    });
  }
  if (typeof mappingVersion !== 'string' || mappingVersion.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'migrateLegacyEvidence requires mappingVersion as a non-empty string', {
      mappingVersion: typeof mappingVersion,
    });
  }

  const imported = [];
  const quarantined = [];
  const rejected = [];
  const perRecord = [];

  records.forEach((record, index) => {
    const recordId = `legacy-evidence#${index}`;
    const sourceDigest = safeDigest(record, recordId);

    try {
      const envelope = importLegacyEvidence(record, {
        runId: null,
        capability: 'legacy-migration',
        observedAt: capturedAt,
      });
      // Untrusted by construction (WP4 S05 acceptance: "old records never
      // gain trust"). importLegacyEvidence already sets trustClass:
      // 'legacy-unauthenticated' / neverQualifying:true on the envelope;
      // registering with trusted:false is the ledger-side half of the same
      // guarantee.
      ledger.register(envelope.evidenceId, envelope.dependencies ?? [], { trusted: false });

      const withId = { ...envelope, recordId };
      imported.push(withId);
      const destinationDigest = digestValue(projectForParity(withId));
      perRecord.push({ recordId, status: 'imported', sourceDigest, destinationDigest });
    } catch (err) {
      const code = err instanceof ArcaneError ? err.code : null;
      const reason = err instanceof Error ? err.message : String(err);
      const entry = { recordId, sourceDigest, code, reason, snapshot: readableSnapshot(record) };
      if (code === 'ARC_AUTH_LEGACY_DIGEST') {
        // Not corruption — an active (and blocked) attempt to claim real
        // authentication for a legacy self-hash. Reported separately from
        // ordinary quarantine so the two causes are never conflated.
        rejected.push(entry);
        perRecord.push({ recordId, status: 'rejected', sourceDigest, destinationDigest: null, code });
      } else {
        // Everything else (schema-invalid shape, unencodable payload, or any
        // other unexpected failure) is treated as corruption: preserved,
        // reported by exact id, and never allowed to abort the batch.
        quarantined.push(entry);
        perRecord.push({ recordId, status: 'quarantined', sourceDigest, destinationDigest: null, code });
      }
    }
  });

  const sourceDigestAgg = digestValue(perRecord.map((r) => r.sourceDigest));
  const destinationDigestAgg = digestValue(imported.map(projectForParity));

  // Trust tally: must always read 0. Recomputed from what was actually
  // imported (not hardcoded), so a future regression in importLegacyEvidence
  // that stopped setting trustClass/neverQualifying correctly would flip this
  // to a nonzero, test-visible number instead of silently laundering trust.
  const trustGranted = imported.filter(
    (e) => e.trustClass !== 'legacy-unauthenticated' || e.neverQualifying !== true,
  ).length;

  const receiptCore = {
    schema: 'arcane.evidence-migration-receipt.v1',
    deliverable: 'S05',
    lane: 'E-ARCANE',
    destructive: false,
    mappingVersion,
    capturedAt,
    source: {
      recordCount: records.length,
      digest: sourceDigestAgg,
    },
    destination: {
      namespace: 'arcane',
      count: imported.length,
      digest: destinationDigestAgg,
    },
    parity: {
      recordCountMatches: records.length === imported.length + quarantined.length + rejected.length,
      perRecord,
    },
    quarantine: {
      count: quarantined.length,
      ids: quarantined.map((q) => q.recordId),
      entries: quarantined,
    },
    rejected: {
      count: rejected.length,
      ids: rejected.map((r) => r.recordId),
      entries: rejected,
    },
    trust: {
      trustGranted,
      assertion:
        'every imported record is registered into DependencyLedger with {trusted:false}, and ' +
        'importLegacyEvidence sets trustClass:"legacy-unauthenticated"/neverQualifying:true; ' +
        'trustGranted counts imports that violate that invariant and must always be 0.',
    },
    rollback: {
      source: 'the `records` array passed to migrateLegacyEvidence, unmodified',
      method:
        'migration performs no destructive rewrite — records[index] recovers the exact original ' +
        'legacy-envelope-v1 record for recordId `legacy-evidence#<index>` (same convention as ' +
        'legacy-bridge.mjs migrationDryRun.rollback)',
      reversible: true,
    },
    kernel: kernelStatus(),
  };

  const receipt = { ...receiptCore, receiptDigest: digestValue(receiptCore) };

  return { receipt, imported, quarantined, rejected };
}

/**
 * Re-run the migration projection over `records` and diff against a
 * previously issued `receipt`. Never trusts the receipt's own claims —
 * recomputes from scratch (with a scratch ledger; verification does not need
 * lasting invalidation state) and compares.
 * @returns {{ok: boolean, mismatches: object[]}}
 */
export function verifyMigration(receipt, { records, capturedAt, mappingVersion }) {
  if (!receipt || typeof receipt !== 'object') {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'verifyMigration requires a receipt object', {});
  }

  const fresh = migrateLegacyEvidence({
    records,
    ledger: new DependencyLedger(),
    capturedAt,
    mappingVersion,
  });

  const mismatches = [];

  const compareField = (path, expected, actual) => {
    if (expected !== actual) mismatches.push({ field: path, expected: expected ?? null, actual });
  };
  compareField('source.recordCount', receipt.source?.recordCount, fresh.receipt.source.recordCount);
  compareField('source.digest', receipt.source?.digest, fresh.receipt.source.digest);
  compareField('destination.count', receipt.destination?.count, fresh.receipt.destination.count);
  compareField('destination.digest', receipt.destination?.digest, fresh.receipt.destination.digest);

  const originalByRecordId = new Map((receipt.parity?.perRecord ?? []).map((r) => [r.recordId, r]));
  for (const freshRec of fresh.receipt.parity.perRecord) {
    const orig = originalByRecordId.get(freshRec.recordId);
    if (!orig) {
      mismatches.push({ field: 'parity.perRecord', recordId: freshRec.recordId, reason: 'missing from original receipt' });
      continue;
    }
    if (
      orig.status !== freshRec.status ||
      orig.sourceDigest !== freshRec.sourceDigest ||
      orig.destinationDigest !== freshRec.destinationDigest
    ) {
      mismatches.push({
        field: 'parity.perRecord',
        recordId: freshRec.recordId,
        expected: { status: orig.status, sourceDigest: orig.sourceDigest, destinationDigest: orig.destinationDigest },
        actual: { status: freshRec.status, sourceDigest: freshRec.sourceDigest, destinationDigest: freshRec.destinationDigest },
      });
    }
  }

  return { ok: mismatches.length === 0, mismatches };
}
