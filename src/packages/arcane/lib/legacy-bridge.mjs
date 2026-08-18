// S01 — Forge compatibility adapter: mapping lookup + runtime bridge.
//
// This module TRANSLATES. It does not adjudicate. Every allow/deny answer in
// Arcane comes from lib/policy.mjs or lib/preeffect-gate.mjs; the bridge only
// reshapes legacy records into `legacy-envelope-v1` and reports, per field,
// which disposition the frozen mapping assigns. That separation is S01 action 7
// ("compatibility aliases contain no independent policy") and is asserted by
// tests/s01-bridge.test.mjs, which greps this file for verdict-minting code.
//
// Two hard rules the code enforces structurally rather than by convention:
//   1. Every emitted envelope has provenance.authenticated === false. The
//      frozen schema pins it to const:false, so a laundered legacy trust value
//      cannot even be represented. (S00 finding 1.)
//   2. No canonical identifier is allocated here. Legacy run ids are recorded
//      as correspondence pairs whose canonical side stays null until the Kernel
//      identity interface is bound (S01 action 2: no private ID allocator).

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ArcaneError } from './errors.mjs';
import { canonicalJson, digestValue } from './canonical.mjs';
import { assertValid } from './validate.mjs';
import { kernelStatus } from './kernel-binding.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.dirname(here);
const compatDir = path.join(packageRoot, 'compatibility', 'forge');

/** Repo-relative location of the S00 baseline, found by walking up. */
const S00_RELATIVE = path.join('docs', 'plans', 'legion', 's00-baseline', 'fixtures');

function findS00Fixtures(startDir) {
  let dir = startDir;
  for (let i = 0; i < 12; i++) {
    const candidate = path.join(dir, S00_RELATIVE);
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new ArcaneError('ARC_SCHEMA_INVALID', 'S00 baseline fixtures not found from this checkout', {
    searchedFrom: startDir,
    expectedRelative: S00_RELATIVE,
  });
}

/** The S00 baseline fixture directory — real Forge output, not fabricated JSON. */
export const FIXTURES_DIR = process.env.ARCANE_S00_FIXTURES
  ? path.resolve(process.env.ARCANE_S00_FIXTURES)
  : findS00Fixtures(here);

export const SCHEMA_MAP = JSON.parse(readFileSync(path.join(compatDir, 'schema-map.json'), 'utf8'));
export const OPERATION_MAP = JSON.parse(readFileSync(path.join(compatDir, 'operation-map.json'), 'utf8'));

export const DISPOSITIONS = Object.freeze(Object.keys(SCHEMA_MAP.dispositionVocabulary));

const LEGACY_INVENTORY_REF = 'docs/plans/legion/s00-baseline/legacy-semantic-inventory.json';

/** Legacy store table name -> the record-type entry that describes it. */
const BY_KIND = new Map(SCHEMA_MAP.recordTypes.map((rt) => [rt.legacyKind, rt]));

/**
 * A store snapshot's table names are bare (`session_bindings`), while the
 * inventory names one entry for the pair (`session_bindings / task_bindings`).
 */
const TABLE_ALIAS = Object.freeze({
  session_bindings: 'session_bindings / task_bindings',
  task_bindings: 'session_bindings / task_bindings',
});

/** Operation-response envelopes are not store rows; they get their own kinds. */
const OPERATION_RESPONSE_KINDS = Object.freeze([
  'forge.operation-response.assess',
  'forge.operation-response.checkpoint',
  'forge.operation-response.verify',
  'forge.operation-response.close',
  'forge.operation-response.resolveSession',
]);

/**
 * Which typed refusal a rejected field raises when a caller presents it as a
 * canonical fact. The mapping's `reason` says why; this says how it surfaces.
 */
const REJECTION_CODE = Object.freeze({
  authority: 'ARC_AUTHORITY_MODEL_CLAIMED',
  executor: 'ARC_AUTHORITY_MODEL_CLAIMED',
  origin: 'ARC_AUTHORITY_MODEL_CLAIMED',
  issuer_id: 'ARC_AUTHORITY_MODEL_CLAIMED',
  issuer_capability_digest: 'ARC_AUTHORITY_MODEL_CLAIMED',
  fingerprint: 'ARC_AUTHORITY_MODEL_CLAIMED',
  error_fingerprint: 'ARC_AUTHORITY_MODEL_CLAIMED',
  signature_or_mac: 'ARC_AUTH_LEGACY_DIGEST',
  trust_class: 'ARC_EVIDENCE_INSUFFICIENT',
  attested: 'ARC_EVIDENCE_INSUFFICIENT',
  status: 'ARC_HOST_EVENT_UNTRUSTED', // checks.status; claims.status re-routed below
  receipt: 'ARC_HOST_EVENT_UNTRUSTED',
  waiver: 'ARC_CLAIM_PREREQUISITE_UNMET',
});

function resolveRejectionCode(legacyKind, legacyField) {
  if (legacyField === 'status' && legacyKind === 'claims') return 'ARC_CLAIM_PREREQUISITE_UNMET';
  return REJECTION_CODE[legacyField] ?? 'ARC_SCHEMA_INVALID';
}

function recordTypeFor(legacyKind) {
  return BY_KIND.get(TABLE_ALIAS[legacyKind] ?? legacyKind) ?? null;
}

/**
 * Disposition of a legacy field per the frozen mapping.
 * @returns {'canonical'|'compatibility-only'|'deprecated'|'rejected'|'unmapped'}
 */
export function dispositionFor(legacyKind, legacyField) {
  const rt = recordTypeFor(legacyKind);
  if (!rt) return 'unmapped';
  const f = rt.fields.find((x) => x.legacyField === legacyField);
  return f ? f.disposition : 'unmapped';
}

/** The full mapping entry for one legacy field, or null. */
export function fieldMapping(legacyKind, legacyField) {
  const rt = recordTypeFor(legacyKind);
  return rt?.fields.find((x) => x.legacyField === legacyField) ?? null;
}

const KNOWN_KINDS = new Set([
  ...BY_KIND.keys(),
  ...Object.keys(TABLE_ALIAS),
  ...OPERATION_RESPONSE_KINDS,
]);

/**
 * Wrap one legacy payload in a `legacy-envelope-v1` record.
 * Throws ARC_SCHEMA_INVALID for a legacy kind the mapping does not describe —
 * an unknown record family is never passed through silently.
 */
export function envelopeFor(legacyKind, payload, provenance) {
  if (!KNOWN_KINDS.has(legacyKind)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `no S01 mapping for legacy kind '${legacyKind}'`, {
      legacyKind,
      known: [...KNOWN_KINDS].sort(),
    });
  }
  const inventoryType = recordTypeFor(legacyKind)?.inventoryRecordType ?? null;
  const envelope = {
    schemaVersion: 1,
    kind: 'legion-legacy-envelope',
    legacyKind,
    payload,
    provenance: {
      source: provenance.source ?? 'forge',
      capturedAt: provenance.capturedAt,
      sourceRevision: provenance.sourceRevision ?? null,
      importedBy: provenance.importedBy ?? 'arcane/legacy-bridge@1',
      legacyInventoryRef: LEGACY_INVENTORY_REF,
      legacyInventoryRecordType: inventoryType,
      // const:false in the frozen schema — no import path can assert otherwise.
      authenticated: false,
    },
    // Null by design: final incorporation happens at coordinator seal, and S00
    // deliberately produced no canonical target binding.
    provisionalMappingRef: null,
  };
  return assertValid('legacy-envelope-v1', envelope, `legacy envelope for ${legacyKind}`);
}

/** Recover the legacy record from an envelope — migration is reversible. */
export function reverseEnvelope(envelope) {
  return { legacyKind: envelope.legacyKind, payload: envelope.payload };
}

function collectRejections(legacyKind, payload) {
  const rt = recordTypeFor(legacyKind);
  if (!rt) return [];
  const out = [];
  for (const f of rt.fields) {
    if (f.disposition !== 'rejected') continue;
    if (!Object.prototype.hasOwnProperty.call(payload, f.legacyField)) continue;
    out.push({
      legacyKind,
      legacyField: f.legacyField,
      code: resolveRejectionCode(legacyKind, f.legacyField),
      reason: f.reason,
      affects: f.affects ?? [],
      // The value is NOT dropped — it stays readable in envelope.payload. It
      // simply carries no canonical meaning.
      quarantinedInPayload: true,
    });
  }
  return out;
}

function correspondenceFor(legacyKind, payload) {
  const out = [];
  const kernel = kernelStatus();
  const legacyId = legacyKind === 'runs' ? payload.id : payload.run_id;
  if (legacyId) {
    out.push({
      family: 'run',
      legacyId,
      legacyKind,
      // Null until the Kernel identity interface exists. Arcane never mints a
      // canonical handle behind the Kernel's back (S01 action 2).
      canonicalId: null,
      allocator: kernel.identity ? 'kernel' : 'kernel-unbound',
    });
  }
  return out;
}

/**
 * Bridge a raw Forge store snapshot (fixture 08 shape: table name -> rows[]).
 * Read-only: nothing is written, nothing in the source is rewritten (S01 action 5).
 */
export function bridgeStoreSnapshot(snapshot, provenance) {
  const envelopes = [];
  const rejections = [];
  const correspondence = [];
  for (const table of Object.keys(snapshot).sort()) {
    const rows = snapshot[table];
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      envelopes.push(envelopeFor(table, row, provenance));
      rejections.push(...collectRejections(table, row));
      correspondence.push(...correspondenceFor(table, row));
    }
  }
  return { envelopes, rejections, correspondence, kernel: kernelStatus() };
}

/**
 * Identify which legacy operation produced a response body, from its shape.
 * All Forge responses carry `operation: 'forge'`, so the discriminator is the
 * response-specific field set, not the operation name.
 */
export function classifyOperationResponse(body) {
  if ('via' in body) return 'resolveSession';
  if ('trigger_score' in body) return 'assess';
  if ('preflight' in body || 'rubric_id' in body) return 'verify';
  if ('gate' in body || 'ledger_hash' in body || 'idempotent' in body || body.decision === 'closed') return 'close';
  return 'checkpoint';
}

/**
 * Bridge one legacy operation response into an envelope plus the canonical
 * operation identity the operation map assigns it.
 */
export function bridgeOperationResponse(body, provenance) {
  const legacyOperation = classifyOperationResponse(body);
  const entry = OPERATION_MAP.operations.find((o) => o.legacyOperation === legacyOperation);
  const envelope = envelopeFor(`forge.operation-response.${legacyOperation}`, body, provenance);
  const rejections = [];
  if ('authority' in body) {
    rejections.push({
      legacyKind: `forge.operation-response.${legacyOperation}`,
      legacyField: 'authority',
      code: 'ARC_AUTHORITY_MODEL_CLAIMED',
      reason: 'Response-level authority is a caller-supplied string; canonical authority is kernel-asserted per turn.',
      affects: ['authority'],
      quarantinedInPayload: true,
    });
  }
  return {
    legacyOperation,
    canonicalOperationId: entry?.canonicalOperationId ?? null,
    canonicalOperationVersion: entry?.canonicalOperationVersion ?? null,
    disposition: entry?.disposition ?? null,
    conflicts: entry?.conflicts ?? [],
    envelope,
    rejections,
  };
}

function listFixtures() {
  return readdirSync(FIXTURES_DIR)
    .filter((f) => /^\d\d-/.test(f) && f.endsWith('.json'))
    .sort();
}

/**
 * S01 action 6 — migration dry-run projection over the real S00 fixtures.
 * Pure projection: reads fixtures, writes nothing, mutates nothing. Two runs
 * over the same inputs produce byte-identical output.
 */
export function migrationDryRun({ capturedAt }) {
  const provenance = {
    source: 'forge',
    capturedAt,
    sourceRevision: SCHEMA_MAP.baseline.forgeCommit,
    importedBy: 'arcane/legacy-bridge@1',
  };
  const sourceRecords = [];
  const envelopes = [];
  const rejections = [];
  const correspondence = [];
  const perFixture = [];

  for (const file of listFixtures()) {
    const body = JSON.parse(readFileSync(path.join(FIXTURES_DIR, file), 'utf8'));
    if (file === '08-store-snapshot-scoped.json') {
      const r = bridgeStoreSnapshot(body, provenance);
      for (const table of Object.keys(body).sort()) {
        if (Array.isArray(body[table])) sourceRecords.push(...body[table]);
      }
      envelopes.push(...r.envelopes);
      rejections.push(...r.rejections);
      correspondence.push(...r.correspondence);
      perFixture.push({ file, kind: 'store-snapshot', records: r.envelopes.length, rejections: r.rejections.length });
    } else {
      const r = bridgeOperationResponse(body, provenance);
      sourceRecords.push(body);
      envelopes.push(r.envelope);
      rejections.push(...r.rejections);
      perFixture.push({
        file,
        kind: 'operation-response',
        legacyOperation: r.legacyOperation,
        canonicalOperationId: r.canonicalOperationId,
        records: 1,
        rejections: r.rejections.length,
      });
    }
  }

  const reversedMatches = envelopes.every(
    (e, i) => canonicalJson(reverseEnvelope(e).payload) === canonicalJson(sourceRecords[i]),
  );

  return {
    schema: 'arcane.forge-migration-dry-run.v1',
    deliverable: 'S01',
    lane: 'E-ARCANE',
    destructive: false,
    mappingVersion: SCHEMA_MAP.schema,
    baseline: SCHEMA_MAP.baseline,
    capturedAt,
    source: {
      root: 'docs/plans/legion/s00-baseline/fixtures',
      fixtureCount: perFixture.length,
      recordCount: sourceRecords.length,
      digest: digestValue(sourceRecords),
    },
    destination: {
      namespace: 'arcane',
      envelopeCount: envelopes.length,
      digest: digestValue(envelopes),
      authenticatedCount: envelopes.filter((e) => e.provenance.authenticated !== false).length,
      canonicalIdsAllocated: correspondence.filter((c) => c.canonicalId !== null).length,
    },
    parity: {
      recordCountMatches: sourceRecords.length === envelopes.length,
      payloadsPreservedByteForByte: reversedMatches,
      rejectedFieldCount: rejections.length,
      rejectedFields: [...new Set(rejections.map((r) => `${r.legacyKind}.${r.legacyField}`))].sort(),
    },
    perFixture,
    rollback: {
      source: 'docs/plans/legion/s00-baseline/fixtures (unmodified; the legacy store is read-only to this bridge)',
      method: 'reverseEnvelope(envelope) restores the legacy payload exactly; no destructive rewrite occurred, so rollback is a no-op on the source.',
      reversible: reversedMatches,
    },
    kernel: kernelStatus(),
  };
}

/** S01 action 6 — parity report over the mapping itself. */
export function parityReport() {
  const totals = Object.fromEntries(DISPOSITIONS.map((d) => [d, 0]));
  const recordTypes = SCHEMA_MAP.recordTypes.map((rt) => {
    const counts = Object.fromEntries(DISPOSITIONS.map((d) => [d, 0]));
    for (const f of rt.fields) {
      counts[f.disposition] = (counts[f.disposition] ?? 0) + 1;
      totals[f.disposition] = (totals[f.disposition] ?? 0) + 1;
    }
    return {
      legacyKind: rt.legacyKind,
      primaryCanonicalTarget: rt.primaryCanonicalTarget,
      fieldCount: rt.fields.length,
      counts,
      trustBearingRejected: rt.fields.filter((f) => f.disposition === 'rejected').map((f) => f.legacyField),
    };
  });
  return {
    schema: 'arcane.forge-parity-report.v1',
    deliverable: 'S01',
    lane: 'E-ARCANE',
    mappingVersion: SCHEMA_MAP.schema,
    baseline: SCHEMA_MAP.baseline,
    unresolvedCount: SCHEMA_MAP.unresolved.length,
    totals,
    recordTypes,
    vocabularyMappings: SCHEMA_MAP.vocabularyMappings.length,
    operationsMapped: OPERATION_MAP.operations.length,
    knownDefectsNotReproduced: SCHEMA_MAP.knownLegacyDefectsNotReproduced,
  };
}
