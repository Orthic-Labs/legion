// Evidence envelope — seals evidence-capability receipts and carries the
// full Arcane-side dependency record the frozen receipt cannot express.
//
// Arcane tracks dependency edges across a much wider set of dimensions than
// the frozen `evidence-capability-receipt-v1` schema's
// `dependsOn[].kind` enum allows (six values only: decision | source-revision
// | config-digest | tool-digest | policy-digest | evidence). Per
// INTERFACES.md's frozen-contract constraint, this module never edits that
// schema. Instead:
//
//   - the full dimension set lives here as DEPENDENCY_DIMENSION and is what
//     `invalidation.mjs`'s DependencyLedger actually indexes and cascades on;
//   - `sealEvidence` projects each dependency down to one of the six legal
//     `kind` values via the explicit DEPENDENCY_KIND_PROJECTION table below,
//     and folds the original dimension into the receipt's free-form `ref`
//     string (`"<dimension>:<ref>"`) so no information is silently discarded
//     even where the *kind* bucket is lossy;
//   - the lossless dependency list (dimension + ref + digest, untouched)
//     lives on the `envelope` returned alongside the receipt;
//   - every dimension whose projection is not faithful is flagged in the
//     table (`faithful: false`) — see the proposed contract amendment in the
//     S05 lane report, and PROPOSED_CONTRACT_AMENDMENT below for the same
//     text in code.

import { mintId as mintKernelId } from '../../core/kernel-binding.mjs';
import { assertValid, loadSchema } from '../../contracts/arcane/validate.mjs';
import { digestValue } from '../../contracts/arcane/canonical.mjs';
import { ArcaneError } from '../../contracts/arcane/errors.mjs';

// ---------------------------------------------------------------------------
// Dependency dimensions (canonical list; see INTERFACES.md evidence envelope)
// ---------------------------------------------------------------------------

/**
 * The full dependency-dimension set Arcane tracks for invalidation. This is
 * deliberately richer than the frozen receipt's `dependsOn[].kind` enum —
 * see the projection table below. 'evidence' is the transitive-cascade edge
 * kind: an evidence record that depends on another evidence record via this
 * dimension is invalidated whenever that other record goes stale, regardless
 * of digest (DependencyLedger cascades structurally through these edges).
 */
export const DEPENDENCY_DIMENSION = Object.freeze([
  'source-digest', // source/file/object digest
  'git-revision', // git revision
  'worktree-dirty', // worktree dirty state
  'lockfile-version', // lockfile/dependency version
  'config-digest', // config
  'schema-version', // schema (of the artifact/contract under evidence, not this package's own schemas)
  'fixture-digest', // fixture/test data
  'tool-version', // tool/provider/runtime version
  'environment', // environment/host/platform
  'method-fingerprint', // method fingerprint
  'policy-version', // policy/catalog/schema version
  'topology', // target/component topology
  'external-source-revision', // external source revision
  'approval-authority', // approval/waiver authority
  'upstream-contract-revision', // upstream contract revision
  'evidence', // transitive edge onto another evidence record
]);

const DIMENSION_SET = new Set(DEPENDENCY_DIMENSION);

// ---------------------------------------------------------------------------
// Projection table: full dimension -> frozen receipt `dependsOn[].kind`
// ---------------------------------------------------------------------------

// Derived from the frozen schema itself (never hardcoded) so this table can
// never silently drift from what evidence-capability-receipt-v1.schema.json
// actually allows.
const FROZEN_KIND = Object.freeze(
  loadSchema('evidence-capability-receipt-v1').properties.dependsOn.items.properties.kind.enum,
);

function kind(value) {
  if (!FROZEN_KIND.includes(value)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `projection target not in frozen dependsOn[].kind enum: ${value}`, {
      value,
      allowed: FROZEN_KIND,
    });
  }
  return value;
}

/**
 * dimension -> { kind, faithful, note }. `faithful: false` means the six-value
 * enum has no bucket that actually means this dimension — the projection is a
 * best-fit placement so the fact is not lost, not a claim of semantic
 * equivalence. See PROPOSED_CONTRACT_AMENDMENT.
 */
export const DEPENDENCY_KIND_PROJECTION = Object.freeze({
  'source-digest': { kind: kind('source-revision'), faithful: true, note: 'a content digest identifying source state is what source-revision means' },
  'git-revision': { kind: kind('source-revision'), faithful: true, note: 'exact match' },
  'worktree-dirty': { kind: kind('source-revision'), faithful: false, note: 'a dirty/clean flag is not a revision identifier; no faithful bucket exists' },
  'lockfile-version': { kind: kind('config-digest'), faithful: false, note: 'dependency-graph version is a distinct concept from generic config' },
  'config-digest': { kind: kind('config-digest'), faithful: true, note: 'exact match' },
  'schema-version': { kind: kind('config-digest'), faithful: false, note: 'a contract/schema version is not config' },
  'fixture-digest': { kind: kind('source-revision'), faithful: false, note: 'test/fixture data digest conflated with source-code revision' },
  'tool-version': { kind: kind('tool-digest'), faithful: true, note: 'version stands in for digest; close enough' },
  'environment': { kind: kind('tool-digest'), faithful: false, note: 'host/platform identity is not a tool' },
  'method-fingerprint': { kind: kind('tool-digest'), faithful: false, note: 'describes the producer\'s method, not tool identity' },
  'policy-version': { kind: kind('policy-digest'), faithful: true, note: 'version stands in for digest; close enough' },
  'topology': { kind: kind('config-digest'), faithful: false, note: 'structural target/component topology is not a config value' },
  'external-source-revision': { kind: kind('source-revision'), faithful: true, note: 'exact match' },
  'approval-authority': { kind: kind('decision'), faithful: false, note: 'an approval/waiver authority binding is not itself a sealed decision' },
  'upstream-contract-revision': { kind: kind('decision'), faithful: false, note: 'a contract revision is closer to source-revision than decision, but contracts derive from decisions; ambiguous either way' },
  evidence: { kind: kind('evidence'), faithful: true, note: 'exact match; the only dimension the frozen enum models precisely for transitive edges' },
});

// Dimensions with no faithful projection — the exact list the lane report's
// proposed contract amendment must justify extending the enum for.
export const UNFAITHFUL_DIMENSIONS = Object.freeze(
  Object.entries(DEPENDENCY_KIND_PROJECTION)
    .filter(([, v]) => !v.faithful)
    .map(([d]) => d),
);

/**
 * Proposed contract amendment text (also reproduced in the lane report).
 * Not applied anywhere — packages/contracts/ is read-only to this lane.
 */
export const PROPOSED_CONTRACT_AMENDMENT =
  'Extend evidence-capability-receipt-v1.dependsOn[].kind with a 7th value, ' +
  '"dimension-digest", paired with a new required-when-kind-is-dimension-digest ' +
  'sibling field `dimension` drawn from the full DEPENDENCY_DIMENSION set ' +
  '(packages/arcane/lib/evidence-envelope.mjs). This avoids re-litigating the ' +
  'enum every time a new invalidation dimension is discovered (9 of 16 current ' +
  'dimensions already have no faithful bucket: ' +
  Object.keys(DEPENDENCY_KIND_PROJECTION).filter((d) => !DEPENDENCY_KIND_PROJECTION[d].faithful).join(', ') +
  '), while leaving the existing 6 literal kinds untouched for callers that do ' +
  'not need dimension-level precision.';

function projectDependency({ dimension, ref, digest }) {
  if (!DIMENSION_SET.has(dimension)) {
    throw new ArcaneError('ARC_DEPENDENCY_UNKNOWN', `unknown dependency dimension: ${dimension}`, { dimension });
  }
  if (typeof ref !== 'string' || ref.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'dependency ref must be a non-empty string', { dimension, ref });
  }
  const projection = DEPENDENCY_KIND_PROJECTION[dimension];
  // Fold the original dimension into `ref` so the projection never silently
  // discards which dimension actually changed, even though `kind` collapses
  // several dimensions into the same bucket.
  return { kind: projection.kind, ref: `${dimension}:${ref}` };
}

// ---------------------------------------------------------------------------
// sealEvidence / envelopeDigest (INTERFACES.md §S05, binding signatures)
// ---------------------------------------------------------------------------

/**
 * Seal an observation into an evidence-capability receipt plus the richer
 * Arcane-side envelope.
 * @returns {{receipt: object, envelope: object}}
 */
export function sealEvidence({
  runId,
  taskId = null,
  contractId = null,
  producerAuthority,
  capability,
  observation,
  evidenceClass,
  sourceRevision,
  dependencies = [],
  authentication,
  replayDefense,
  observedAt,
}) {
  const { id: evidenceId, provisional } = mintKernelId('evidenceReceipt');
  const dependsOn = dependencies.map(projectDependency);

  const receipt = {
    schemaVersion: 1,
    kind: 'legion-evidence-capability-receipt',
    evidenceId,
    runId,
    taskId,
    contractId,
    producerAuthority,
    capability,
    observation,
    evidenceClass,
    authentication,
    replayDefense,
    sourceRevision,
    dependsOn,
    stale: false,
    observedAt,
  };
  assertValid('evidence-capability-receipt-v1', receipt);

  const envelopeCore = {
    evidenceId,
    runId,
    taskId,
    contractId,
    producerAuthority,
    capability,
    observation,
    evidenceClass,
    sourceRevision,
    // Lossless dependency list — full dimension set, untouched digests.
    dependencies: dependencies.map((d) => ({ dimension: d.dimension, ref: d.ref, digest: d.digest })),
    authentication,
    replayDefense,
    observedAt,
    stale: false,
    provisionalId: provisional,
    trustClass: authentication?.verificationMethod === 'unauthenticated' ? 'unauthenticated' : 'authenticated',
    receiptDigest: digestValue(receipt),
  };

  const envelope = { ...envelopeCore, envelopeDigest: envelopeDigest(envelopeCore) };
  return { receipt, envelope };
}

/** Digest of an envelope's content (excludes any pre-existing envelopeDigest field, so it is idempotent to call on an already-digested envelope). */
export function envelopeDigest(envelope) {
  const { envelopeDigest: _drop, ...rest } = envelope;
  return digestValue(rest);
}

// ---------------------------------------------------------------------------
// Legacy import (WP4 action 7) — additive helper, not in the binding list.
// ---------------------------------------------------------------------------

/**
 * Import a legacy-envelope-v1-shaped record as an Arcane evidence envelope
 * that can never gain trust. S00 finding: every legacy predecessor
 * `signature_or_mac` is a self-hash with no secret key — a legacy envelope's
 * `provenance.authenticated` is structurally `false` (the frozen
 * legacy-envelope-v1 schema enforces this with `const: false`). Migration
 * never upgrades that; it is not re-emitted as a
 * `evidence-capability-receipt-v1` claiming real authentication (that would
 * be the exact trust-laundering S00 warns against). It becomes an
 * envelope-only record, `trustClass: 'legacy-unauthenticated'`,
 * `neverQualifying: true`, importable into DependencyLedger only with
 * `{ trusted: false }` so it can be tracked/cascaded against but can never
 * make a criterion `proven`.
 */
export function importLegacyEvidence(legacyEnvelope, { runId = null, capability = 'legacy-import', observedAt } = {}) {
  if (!legacyEnvelope || legacyEnvelope.kind !== 'legion-legacy-envelope') {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'expected a legacy-envelope-v1 shaped record (kind: legion-legacy-envelope)', {
      kind: legacyEnvelope?.kind ?? null,
    });
  }
  if (legacyEnvelope.provenance?.authenticated !== false) {
    throw new ArcaneError('ARC_AUTH_LEGACY_DIGEST', 'legacy envelope provenance.authenticated must be false', {
      authenticated: legacyEnvelope.provenance?.authenticated ?? null,
    });
  }
  const { id: evidenceId } = mintKernelId('evidenceReceipt');
  return Object.freeze({
    evidenceId,
    runId,
    legacyKind: legacyEnvelope.legacyKind,
    capability,
    observation: Object.freeze({ legacyPayloadDigest: digestValue(legacyEnvelope.payload) }),
    evidenceClass: 'external',
    sourceRevision: legacyEnvelope.provenance.sourceRevision ?? null,
    dependencies: [],
    authentication: Object.freeze({
      issuerIdentity: legacyEnvelope.provenance.source,
      verificationMethod: 'unauthenticated',
      perMessage: false,
      verifiedAt: null,
    }),
    trustClass: 'legacy-unauthenticated',
    neverQualifying: true,
    provisionalMappingRef: legacyEnvelope.provisionalMappingRef ?? null,
    observedAt: observedAt ?? legacyEnvelope.provenance.capturedAt,
    stale: false,
  });
}
