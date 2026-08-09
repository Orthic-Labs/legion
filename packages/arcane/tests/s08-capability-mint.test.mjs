// CONTRACT A — capability mint authority.
//
// The defect: CapabilityStore.issue() performs no authorization check.
// PreEffectGate.authorize() closes it structurally — it runs the identical
// steps evaluate() runs, and only when they pass does it mint a capability,
// scoped to exactly what it validated, and immediately self-checks the
// capability it just minted through the real CapabilityStore.check().

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { PreEffectGate } from '../lib/preeffect-gate.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH, capabilityIssuanceAudit } from '../lib/policy.mjs';
import { AuthorityLedger } from '../lib/authority.mjs';
import { CapabilityStore } from '../lib/receipt-store.mjs';

const NOW = Date.parse('2026-08-08T12:00:00.000Z');
const ISO = (ms = NOW) => new Date(ms).toISOString();

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';

function contract(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-execution-contract',
    contractId: 'EC-44',
    version: 2,
    sourceRevision: '0123abcdef',
    objective: 'ship',
    currentState: 'a',
    desiredState: 'b',
    requirements: [],
    decisions: [],
    invariants: [],
    nonGoals: [],
    scope: { own: ['src/**'], read: ['docs/**'], forbidden: ['src/secrets/**'] },
    artifacts: {
      exact: [{ id: 'a1', path: 'src/exact.ts', latitude: 'EXACT', content: 'x' }],
      bounded: [],
    },
    tasks: ['T-1'],
    dependencies: [],
    acceptanceCriteria: [],
    declaredChecks: [],
    evidenceRequirements: [],
    authorizedEffectClasses: ['FILE_WRITE'],
    repairLatitude: [],
    stopConditions: [],
    escalationConditions: [],
    rollback: [],
    openQuestions: [],
    ...overrides,
  };
}

function request(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-effect-request',
    requestId: 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    runId: RUN_ID,
    contractId: 'EC-44',
    taskId: 'T-1',
    requestedBy: 'alchemist',
    effectClass: 'FILE_WRITE',
    target: 'src/exact.ts',
    operation: 'write',
    latitude: 'EXACT',
    sourceRevision: '0123abcdef',
    requestedAt: ISO(),
    ...overrides,
  };
}

function wire({ now = NOW, enforcementMode = 'enforcing' } = {}) {
  const policy = new PolicyEngine(loadPolicy({ path: DEFAULT_POLICY_PATH }));
  const capabilityStore = new CapabilityStore();
  const authorityLedger = new AuthorityLedger({ clock: () => now });
  authorityLedger.assertForTurn({
    turnId: 'turn-1',
    authority: 'alchemist',
    assertedBy: 'kernel:proc-1',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });
  const gate = new PreEffectGate({ policy, capabilityStore, authorityLedger, clock: () => now, enforcementMode });
  return { policy, capabilityStore, authorityLedger, gate };
}

// ---------------------------------------------------------------- (a) mint

test('S08(a): authorize() mints a capability nobody supplied and self-checks it', () => {
  const w = wire();
  const d = w.gate.authorize(request(), { contract: contract(), turnId: 'turn-1' });
  assert.equal(d.allowed, true, d.message);
  assert.equal(d.enforcementHealth, 'strong');
  assert.ok(d.detail.capabilityId, 'a capability id was minted');

  // The minted capability is real: CapabilityStore itself grants it.
  const check = w.capabilityStore.check(d.detail.capabilityId, {
    operation: 'write',
    effectClass: 'FILE_WRITE',
    target: 'src/exact.ts',
    runId: RUN_ID,
    taskId: 'T-1',
    now: ISO(),
  });
  assert.equal(check.allowed, true, check.message);

  // And evaluate() accepts it exactly like any other capability.
  const evalCall = w.gate.evaluate(request(), {
    contract: contract(), turnId: 'turn-1', capabilityId: d.detail.capabilityId,
  });
  assert.equal(evalCall.allowed, true, evalCall.message);
});

test('S08(a): authorize() denies (and mints nothing) in enforcing mode when a real check fails', () => {
  const w = wire();
  const d = w.gate.authorize(request({ target: 'src/secrets/key.pem' }), {
    contract: contract(), turnId: 'turn-1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_PATH_FORBIDDEN');
  assert.equal(d.detail.capabilityId, undefined);
});

test('S08(a): authorize() fails closed (no mint attempted) when the gate is unavailable', () => {
  const w = wire();
  const down = new PreEffectGate({ policy: w.policy, capabilityStore: null, authorityLedger: w.authorityLedger });
  const d = down.authorize(request(), { contract: contract(), turnId: 'turn-1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_GATE_UNAVAILABLE');
  assert.equal(d.failClosed, true);
});

test('S08(a): evaluate() is unchanged — it still requires a pre-existing capability', () => {
  const w = wire();
  const d = w.gate.evaluate(request(), { contract: contract(), turnId: 'turn-1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CAPABILITY_UNKNOWN');
});

// -------------------------------------------------------------- (b) audit

test('S08(b): capabilityIssuanceAudit flags a fabricated caller of .issue() outside the two allowed files', () => {
  const fabricatedPath = fileURLToPath(new URL('./fixtures-s08-fabricated-issuer.mjs', import.meta.url));
  writeFileSync(fabricatedPath, "export function rogueMint(store, id) { return store.issue({ capabilityId: id }); }\n", 'utf8');
  try {
    const audit = capabilityIssuanceAudit([fabricatedPath]);
    assert.equal(audit.violations.length, 1, JSON.stringify(audit.violations));
    assert.equal(audit.violations[0].file, fabricatedPath);
  } finally {
    rmSync(fabricatedPath, { force: true });
  }
});

// ----------------------------------------------------------- (c) advisory

test('S08(c): advisory mode returns allowed:true with enforcementHealth advisory and the real denial verbatim', () => {
  const w = wire({ enforcementMode: 'advisory' });
  const d = w.gate.authorize(request({ target: 'src/secrets/key.pem' }), {
    contract: contract(), turnId: 'turn-1',
  });
  assert.equal(d.allowed, true, d.message);
  assert.equal(d.enforcementHealth, 'advisory');
  assert.ok(d.detail.capabilityId, 'advisory mode still mints');
  assert.equal(d.detail.wouldHaveDenied.code, 'ARC_PATH_FORBIDDEN');
  assert.ok(d.detail.wouldHaveDenied.message.length > 0);

  // And the mint is real: a fresh capability actually exists and self-checks.
  const check = w.capabilityStore.check(d.detail.capabilityId, {
    operation: 'write',
    effectClass: 'FILE_WRITE',
    runId: RUN_ID,
    taskId: 'T-1',
    now: ISO(),
  });
  assert.equal(check.allowed, true, check.message);
});

test('S08(c): advisory mode mints nothing extra and reports strong when the request would truly pass', () => {
  const w = wire({ enforcementMode: 'advisory' });
  const d = w.gate.authorize(request(), { contract: contract(), turnId: 'turn-1' });
  assert.equal(d.allowed, true);
  assert.equal(d.enforcementHealth, 'strong');
  assert.equal(d.detail.wouldHaveDenied, undefined);
});

// ------------------------------------------------------- (d) claim gating

test('S08(d): evaluateClaimPrerequisites at read_only+ rejects an advisory enforcementHealth', () => {
  const w = wire();
  const result = w.policy.evaluateClaimPrerequisites('signoff', {
    evidenceClasses: ['deterministic'],
    staleEvidenceCount: 0,
    enforcementHealth: 'advisory',
  });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  assert.equal(result.detail.required, 'strong');
  assert.equal(result.detail.actual, 'advisory');
});
