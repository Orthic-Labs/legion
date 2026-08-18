// S02 — canonical policy bundle + authority boundary.
//
// Acceptance (03-SENTINEL-WP4-DISPATCH.md, S02):
//   - changing a valid policy changes runtime behavior without code edits;
//   - malformed/unknown policy fields fail closed for protected operations;
//   - model/API payload cannot set trusted authority;
//   - adapters do not contain divergent allow/deny logic;
//   - compatibility aliases obey the active policy.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  loadPolicy,
  validatePolicyBundle,
  PolicyEngine,
  failClosedEngine,
  DEFAULT_POLICY_PATH,
  policyDuplicationAudit,
  capabilityIssuanceAudit,
  EFFECT_CLASS_RECONCILIATION,
} from '../lib/policy.mjs';
import { AuthorityLedger, extractAuthorityFromPayload, requireAuthority } from '../lib/authority.mjs';
import { EFFECT_CLASS, AUTHENTICATION_METHOD } from '../../contracts/index.mjs';
import { ArcaneError } from '../lib/errors.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const libDir = path.join(__dirname, '..', 'lib');

// ---------------------------------------------------------------- policy load

test('S02: the shipped policy bundle loads, validates, and carries id/version/digest', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  assert.equal(loaded.bundle.kind, 'arcane-policy-bundle');
  assert.match(loaded.policyId, /^POL-\d+$/);
  assert.ok(Number.isInteger(loaded.version) && loaded.version >= 1);
  assert.match(loaded.digest, /^sha256:[0-9a-f]{64}$/);
});

test('S02: the bundle covers every frozen EFFECT_CLASS value — no effect is unruled', () => {
  const { bundle } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const ruled = bundle.effectRules.map((r) => r.effectClass).sort();
  assert.deepEqual(ruled, [...EFFECT_CLASS].sort());
});

test('S02: every trustMinimum in the bundle is a value of the frozen AUTHENTICATION_METHOD enum', () => {
  const { bundle } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  for (const r of bundle.effectRules) {
    assert.ok(AUTHENTICATION_METHOD.includes(r.trustMinimum), `${r.effectClass}: ${r.trustMinimum}`);
  }
});

// ------------------------------------------------------------ fail-closed

test('S02: an unknown top-level field fails closed with ARC_POLICY_UNKNOWN_FIELD', () => {
  const { bundle } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const tampered = { ...bundle, somethingNobodyDeclared: true };
  const { valid, issues } = validatePolicyBundle(tampered);
  assert.equal(valid, false);
  assert.ok(issues.some((i) => /additional-property/.test(i)));
  assert.throws(
    () => new PolicyEngine({ bundle: tampered, policyId: 'POL-1', version: 1, digest: 'sha256:' + '0'.repeat(64) }),
    (e) => e instanceof ArcaneError && e.code === 'ARC_POLICY_UNKNOWN_FIELD' && e.failClosed === true,
  );
});

test('S02: a malformed bundle fails closed with ARC_POLICY_MALFORMED', () => {
  const { bundle } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const broken = { ...bundle, effectRules: 'not-an-array' };
  assert.throws(
    () => new PolicyEngine({ bundle: broken, policyId: 'POL-1', version: 1, digest: 'sha256:' + '0'.repeat(64) }),
    (e) => e instanceof ArcaneError && e.code === 'ARC_POLICY_MALFORMED' && e.failClosed === true,
  );
});

test('S02: with no policy at all, protected operations are denied and read-only degrades honestly', () => {
  const engine = failClosedEngine('no policy bundle loaded');
  const mutation = engine.effectDecision('FILE_WRITE');
  assert.equal(mutation.allowed, false);
  assert.equal(mutation.code, 'ARC_POLICY_UNAVAILABLE');
  assert.equal(mutation.failClosed, true);
  assert.equal(mutation.enforcementHealth, 'unsupported');
});

// --------------------------------------------- policy drives behavior, not code

test('S02: changing the bundle changes runtime behavior with no code edit', () => {
  const { bundle, policyId, version, digest } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const permissive = new PolicyEngine({ bundle, policyId, version, digest });
  const before = permissive.effectDecision('FILE_WRITE');

  const edited = {
    ...bundle,
    effectRules: bundle.effectRules.map((r) => (r.effectClass === 'FILE_WRITE' ? { ...r, rule: 'deny' } : r)),
  };
  const stricter = new PolicyEngine({ bundle: edited, policyId, version, digest });
  const after = stricter.effectDecision('FILE_WRITE');

  assert.equal(before.allowed, true);
  assert.equal(after.allowed, false);
  assert.equal(after.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
});

test('S02: an effect class the bundle does not rule is refused, never bucketed into a catch-all', () => {
  const { bundle, policyId, version, digest } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine({ bundle, policyId, version, digest });
  const d = engine.effectDecision('SOMETHING_UNMODELLED');
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
  assert.equal(bundle.unclassifiedEffect, 'deny');
});

test('S02: approval-required effects surface ARC_APPROVAL_REQUIRED when no approval digest is bound', () => {
  const { bundle, policyId, version, digest } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine({ bundle, policyId, version, digest });
  const needsApproval = bundle.effectRules.find((r) => r.approvalRequired);
  assert.ok(needsApproval, 'at least one effect class must require approval');
  const d = engine.effectDecision(needsApproval.effectClass, { approvalDigest: null });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_APPROVAL_REQUIRED');
  const ok = engine.effectDecision(needsApproval.effectClass, { approvalDigest: 'sha256:' + 'a'.repeat(64) });
  assert.equal(ok.allowed, true);
});

test('S02: approval-required classes are one frozen projection of validated policy', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  const expected = loaded.bundle.effectRules.filter(({ approvalRequired }) => approvalRequired).map(({ effectClass }) => effectClass);
  const actual = engine.approvalRequiredEffectClasses();
  assert.equal(Object.isFrozen(actual), true);
  assert.deepEqual(actual, expected);
  assert.throws(() => actual.push('FILE_WRITE'), TypeError);
});

test('S02: policy id/version/digest bind into every capability and receipt', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  const bound = engine.bindPolicy({ capabilityId: 'cap_1' });
  assert.equal(bound.policyId, loaded.policyId);
  assert.equal(bound.policyVersion, loaded.version);
  assert.equal(bound.policyDigest, loaded.digest);
});

test('S02: capability and replay limits come from the bundle, not from constants in code', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  assert.equal(engine.capabilityLimits().ttlSeconds, loaded.bundle.capability.ttlSeconds);
  assert.equal(engine.replayLimits().freshnessWindowSeconds, loaded.bundle.replay.freshnessWindowSeconds);
  assert.equal(engine.replayLimits().maxSkewSeconds, loaded.bundle.replay.maxSkewSeconds);
});

test('S02: degradation behavior is data-driven and mutation never silently passes', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  assert.equal(engine.degradation('preEffectGateUnavailable'), 'fail-closed');
  assert.notEqual(engine.degradation('preEffectGateUnavailable'), 'allow');
});

// ------------------------------------------------------- claim prerequisites

test('S02: claim prerequisites are evaluated from the bundle — stale evidence blocks a signoff claim', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  const ok = engine.evaluateClaimPrerequisites('signoff', {
    evidenceClasses: ['deterministic'],
    staleEvidenceCount: 0,
    enforcementHealth: 'strong',
    covenantVerdict: null,
  });
  assert.equal(ok.allowed, true);

  const stale = engine.evaluateClaimPrerequisites('signoff', {
    evidenceClasses: ['deterministic'],
    staleEvidenceCount: 1,
    enforcementHealth: 'strong',
    covenantVerdict: null,
  });
  assert.equal(stale.allowed, false);
  assert.equal(stale.code, 'ARC_EVIDENCE_STALE');
});

test('S02: a signoff claim on degraded enforcement is refused, not quietly downgraded', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  const d = engine.evaluateClaimPrerequisites('signoff', {
    evidenceClasses: ['deterministic'],
    staleEvidenceCount: 0,
    enforcementHealth: 'read_only',
    covenantVerdict: null,
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
});

test('S02: the highRisk claim level preserves Forge’s intent/blast-radius/why-safe triple', () => {
  const { bundle } = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const hr = bundle.claimLevels.highRisk;
  assert.deepEqual([...hr.requiredFields].sort(), ['blastRadius', 'intentRestatement', 'whySafe']);
});

test('S02: waiver authority is named by policy and a non-named authority cannot waive', () => {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const engine = new PolicyEngine(loaded);
  assert.equal(engine.mayWaive('sage').allowed, true);
  const denied = engine.mayWaive('alchemist');
  assert.equal(denied.allowed, false);
  assert.equal(denied.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
});

// ------------------------------------------------------------------ authority

test('S02: authority is kernel-asserted per turn and readable back for that turn only', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  ledger.assertForTurn({
    turnId: 't1',
    authority: 'alchemist',
    assertedBy: 'kernel:proc-42',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });
  assert.equal(ledger.current('t1').authority, 'alchemist');
  assert.equal(ledger.current('t2'), null);
});

test('S02: a model/API payload cannot set trusted authority', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  assert.throws(
    () => ledger.assertForTurn({
      turnId: 't1',
      authority: 'oracle',
      assertedBy: 'model',
      verificationMethod: 'capability-signature',
      perMessage: true,
      source: 'model',
    }),
    (e) => e instanceof ArcaneError && e.code === 'ARC_AUTHORITY_MODEL_CLAIMED',
  );
  assert.throws(
    () => extractAuthorityFromPayload({ authority: 'operator' }),
    (e) => e instanceof ArcaneError && e.code === 'ARC_AUTHORITY_MODEL_CLAIMED',
  );
});

test('S02: an unknown authority value is refused even from the kernel', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  assert.throws(
    () => ledger.assertForTurn({
      turnId: 't1',
      authority: 'operator', // legacy Forge value, not a Legion AUTHORITY_ID
      assertedBy: 'kernel:proc-42',
      verificationMethod: 'capability-signature',
      perMessage: true,
      source: 'kernel',
    }),
    (e) => e instanceof ArcaneError && e.code === 'ARC_AUTHORITY_MODEL_CLAIMED',
  );
});

test('S02: a payload whose claimed authority differs from the kernel assertion is refused', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  ledger.assertForTurn({
    turnId: 't1',
    authority: 'alchemist',
    assertedBy: 'kernel:proc-42',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });
  const d = requireAuthority(ledger, 't1', ['alchemist'], { claimedAuthority: 'sage' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_AUTHORITY_MODEL_CLAIMED');
});

test('S02: with no assertion for the turn, authority-bearing work is refused', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  const d = requireAuthority(ledger, 'no-such-turn', ['alchemist']);
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_AUTHORITY_NOT_ASSERTED');
  assert.equal(d.failClosed, false, 'a missing assertion is a denial, not an enforcement outage');
});

test('S02: connection-level trust is recorded honestly as perMessage:false', () => {
  const ledger = new AuthorityLedger({ clock: () => 1000 });
  ledger.assertForTurn({
    turnId: 't1',
    authority: 'alchemist',
    assertedBy: 'host:mcp-connection',
    verificationMethod: 'host-connection-trust',
    perMessage: false,
    source: 'host',
  });
  const a = ledger.current('t1');
  assert.equal(a.perMessage, false);
  assert.equal(a.verificationMethod, 'host-connection-trust');
});

// -------------------------------------------------------------- drift audit

test('S02: no adapter duplicates policy — the bridge holds no allow/deny logic', () => {
  const audit = policyDuplicationAudit([
    path.join(libDir, 'legacy-bridge.mjs'),
    path.join(libDir, 'evidence-envelope.mjs'),
  ]);
  assert.equal(audit.violations.length, 0, JSON.stringify(audit.violations));
  assert.ok(audit.scanned.length >= 2);
});

test('S02: no module outside preeffect-gate.mjs / receipt-store.mjs mints a capability', () => {
  const files = readdirSync(libDir)
    .filter((name) => name.endsWith('.mjs'))
    .map((name) => path.join(libDir, name));
  const audit = capabilityIssuanceAudit(files);
  assert.equal(audit.violations.length, 0, JSON.stringify(audit.violations));
  assert.ok(audit.scanned.length >= 10);
});

test('S02: the policy engine is the only module that reads effectRules', () => {
  const bridgeSrc = readFileSync(path.join(libDir, 'legacy-bridge.mjs'), 'utf8');
  assert.equal(/effectRules/.test(bridgeSrc), false);
});

// ----------------------------------------------- SEAL Q4 EFFECT_CLASS reconcile

test('S02: EFFECT_CLASS reconciliation (SEAL Q4) is recorded, with every frozen value dispositioned', () => {
  const r = EFFECT_CLASS_RECONCILIATION;
  assert.equal(r.sealQuestion, 'Q4');
  const dispositioned = r.frozenValues.map((v) => v.effectClass).sort();
  assert.deepEqual(dispositioned, [...EFFECT_CLASS].sort());
  for (const v of r.frozenValues) {
    assert.ok(['keep', 'keep-with-caveat', 'split-proposed'].includes(v.disposition), v.effectClass);
    assert.ok(v.brokerSurface.length > 10, `${v.effectClass} names no real broker surface`);
  }
  assert.ok(r.proposedAdditions.length > 0, 'the broker found at least one unrepresentable effect');
  for (const p of r.proposedAdditions) {
    assert.ok(p.name && p.why.length > 40 && p.evidence.length > 10);
  }
});

test('S02: FILE_READ is proposed — §24a’s read-only downgrade path is unrepresentable without it', () => {
  const names = EFFECT_CLASS_RECONCILIATION.proposedAdditions.map((p) => p.name);
  assert.ok(names.includes('FILE_READ'));
});
