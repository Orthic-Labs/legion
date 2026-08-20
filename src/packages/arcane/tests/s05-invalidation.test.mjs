// S05 — invalidation.mjs
//
// Headline test covers Arcane's transitive invalidation cascade:
// source revision -> evidence A -> evidence B -> criterion C -> claim.
// Changing the source revision must stale A, cascade-stale B transitively
// through the dimension:'evidence' edge, mark C unproven, invalidate the
// claim, and leave an unrelated evidence D explicitly listed in `unaffected`
// and still non-stale — all from exactly one observeChange() call/event.

import test from 'node:test';
import assert from 'node:assert/strict';

import { DependencyLedger } from '../lib/invalidation.mjs';
import { importLegacyEvidence, envelopeDigest } from '../lib/evidence-envelope.mjs';
import { ArcaneError } from '../lib/errors.mjs';

const SRC_DIGEST_1 = 'sha256:' + '1'.repeat(64);
const SRC_DIGEST_2 = 'sha256:' + '2'.repeat(64);

test('source revision change stales A, cascades to B, unproves C, invalidates the claim, leaves D unaffected — exactly one event', () => {
  const ledger = new DependencyLedger({ clock: () => '2026-01-01T00:00:00.000Z' });

  // A depends directly on the source revision.
  ledger.register('ev_A', [{ dimension: 'git-revision', ref: 'repo:main', digest: SRC_DIGEST_1 }]);
  // B depends transitively on A via the 'evidence' dimension.
  ledger.register('ev_B', [{ dimension: 'evidence', ref: 'ev_A', digest: 'sha256:' + 'a'.repeat(64) }]);
  // D is unrelated — depends on a different dimension/ref entirely.
  ledger.register('ev_D', [{ dimension: 'config-digest', ref: 'config:app', digest: 'sha256:' + 'd'.repeat(64) }]);

  ledger.link('ev_B', { criterionId: 'AC-1', claimId: 'clm_1' });

  const events = [];
  const event = ledger.observeChange({ dimension: 'git-revision', ref: 'repo:main', digest: SRC_DIGEST_2 });
  events.push(event);

  // Exactly one event emitted for this call.
  assert.equal(events.length, 1);

  assert.deepEqual(event.staledEvidence, ['ev_A']);
  assert.deepEqual(event.cascadedEvidence, ['ev_B']);
  assert.deepEqual(event.affectedCriteria, ['AC-1']);
  assert.deepEqual(event.affectedClaims, ['clm_1']);
  assert.deepEqual(event.unaffected, ['ev_D']);
  assert.equal(event.changed.dimension, 'git-revision');
  assert.equal(event.changed.ref, 'repo:main');
  assert.equal(event.changed.from, SRC_DIGEST_1);
  assert.equal(event.changed.to, SRC_DIGEST_2);

  assert.equal(ledger.isStale('ev_A'), true);
  assert.equal(ledger.isStale('ev_B'), true);
  assert.equal(ledger.isStale('ev_D'), false);

  const eligibility = ledger.proofEligibility('AC-1');
  assert.equal(eligibility.status, 'unproven');
  assert.deepEqual(eligibility.staleEvidence, ['ev_B']);
});

test('changing a different dimension stales exactly the evidence bound to it and nothing else', () => {
  const ledger = new DependencyLedger();
  ledger.register('ev_1', [{ dimension: 'config-digest', ref: 'config:x', digest: 'sha256:' + '1'.repeat(64) }]);
  ledger.register('ev_2', [{ dimension: 'policy-version', ref: 'policy:y', digest: 'sha256:' + '2'.repeat(64) }]);
  ledger.register('ev_3', [{ dimension: 'config-digest', ref: 'config:other', digest: 'sha256:' + '3'.repeat(64) }]);

  const event = ledger.observeChange({ dimension: 'config-digest', ref: 'config:x', digest: 'sha256:' + 'f'.repeat(64) });

  assert.deepEqual(event.staledEvidence, ['ev_1']);
  assert.deepEqual(event.cascadedEvidence, []);
  assert.ok(event.unaffected.includes('ev_2'));
  assert.ok(event.unaffected.includes('ev_3'));
  assert.equal(ledger.isStale('ev_1'), true);
  assert.equal(ledger.isStale('ev_2'), false);
  assert.equal(ledger.isStale('ev_3'), false);
});

test('historical preservation: the prior evidence record remains readable with its original digest after invalidation', () => {
  const ledger = new DependencyLedger();
  const originalDigest = 'sha256:' + '7'.repeat(64);
  ledger.register('ev_hist', [{ dimension: 'source-digest', ref: 'file:a.js', digest: originalDigest }]);

  ledger.observeChange({ dimension: 'source-digest', ref: 'file:a.js', digest: 'sha256:' + '8'.repeat(64) });

  const rec = ledger.getEvidence('ev_hist');
  assert.equal(rec.stale, true);
  // The original bound dependency digest is untouched — never silently refreshed.
  assert.equal(rec.dependencies[0].digest, originalDigest);
  assert.equal(rec.staleEvents.length, 1);
  assert.equal(rec.staleEvents[0].from, originalDigest);
});

test('an imported legacy record can never become qualifying evidence, even when linked to a criterion', () => {
  const ledger = new DependencyLedger();
  const legacy = importLegacyEvidence({
    kind: 'legion-legacy-envelope',
    legacyKind: 'evidence',
    payload: { signature_or_mac: 'deadbeef' },
    provenance: { source: 'forge', capturedAt: new Date().toISOString(), authenticated: false },
    provisionalMappingRef: null,
  });

  ledger.register(legacy.evidenceId, [], { trusted: false });
  ledger.link(legacy.evidenceId, { criterionId: 'AC-legacy' });

  const eligibility = ledger.proofEligibility('AC-legacy');
  assert.notEqual(eligibility.status, 'proven');
  assert.equal(eligibility.status, 'insufficient');
  assert.ok(eligibility.reasons.some((r) => r.includes(legacy.evidenceId)));
});

test('a corrupt ledger entry blocks strong claims and reports the exact affected ids', () => {
  const ledger = new DependencyLedger();
  ledger.register('ev_ok', [{ dimension: 'config-digest', ref: 'config:z', digest: 'sha256:' + '0'.repeat(64) }]);
  ledger.link('ev_ok', { criterionId: 'AC-corrupt' });

  assert.equal(ledger.proofEligibility('AC-corrupt').status, 'proven');

  ledger.markCorrupt('ev_ok', 'digest chain broken at sequence 4');

  const eligibility = ledger.proofEligibility('AC-corrupt');
  assert.equal(eligibility.status, 'insufficient');
  assert.ok(eligibility.reasons.some((r) => r.includes('ev_ok') && r.includes('digest chain broken at sequence 4')));

  const quarantined = ledger.quarantined();
  assert.equal(quarantined.length, 1);
  assert.equal(quarantined[0].evidenceId, 'ev_ok');

  // History is preserved, not dropped.
  const rec = ledger.getEvidence('ev_ok');
  assert.equal(rec.corrupt, true);
  assert.equal(rec.dependencies.length, 1);
});

test('register/link/isStale reject an unknown evidenceId with ARC_DEPENDENCY_UNKNOWN', () => {
  const ledger = new DependencyLedger();
  assert.throws(() => ledger.link('ev_missing', { criterionId: 'AC-x' }), (err) => err instanceof ArcaneError && err.code === 'ARC_DEPENDENCY_UNKNOWN');
  assert.throws(() => ledger.isStale('ev_missing'), (err) => err instanceof ArcaneError && err.code === 'ARC_DEPENDENCY_UNKNOWN');
});

test('proofEligibility on a criterion with no linked evidence is insufficient', () => {
  const ledger = new DependencyLedger();
  const eligibility = ledger.proofEligibility('AC-none');
  assert.equal(eligibility.status, 'insufficient');
});

test('snapshot exposes evidence/criteria/claims/quarantined state consistently with individual accessors', () => {
  const ledger = new DependencyLedger();
  ledger.register('ev_snap', [{ dimension: 'tool-version', ref: 'tool:node', digest: 'sha256:' + '9'.repeat(64) }]);
  ledger.link('ev_snap', { criterionId: 'AC-snap', claimId: 'clm_snap' });

  const snap = ledger.snapshot();
  assert.ok(snap.evidence.some((e) => e.evidenceId === 'ev_snap'));
  assert.ok(snap.criteria.some((c) => c.criterionId === 'AC-snap' && c.evidence.includes('ev_snap')));
  assert.ok(snap.claims.some((c) => c.claimId === 'clm_snap' && c.criteria.includes('AC-snap')));
  assert.deepEqual(snap.quarantined, []);
});

// Sanity: sealEvidence's envelope digest is a stable input a real dependency
// entry of dimension:'evidence' would reference as `digest`.
test('envelopeDigest can be used as the digest for an evidence dimension edge', () => {
  const ledger = new DependencyLedger();
  const fakeEnvelope = { evidenceId: 'ev_x', capability: 'probe', observedAt: '2026-01-01T00:00:00.000Z' };
  const digest = envelopeDigest(fakeEnvelope);
  ledger.register('ev_x', []);
  ledger.register('ev_y', [{ dimension: 'evidence', ref: 'ev_x', digest }]);
  assert.equal(ledger.isStale('ev_y'), false);
});
