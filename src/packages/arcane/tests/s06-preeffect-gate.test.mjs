// Deliverable 6 — the pre-effect gate.
//
// Arcane's pre-effect gate checks capability, path ownership, effect-class
// authorization, contract version, & latitude class (EXACT/BOUNDED). If gate
// is unavailable, mutation-bearing operations fail closed; read-only operations
// may continue with a recorded enforcement-health downgrade.
//
// Alchemist never mutates product state without a bounded executable
// contract. Open decisions make a contract non-executable.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PreEffectGate, pathMatches, isMutating } from '../lib/preeffect-gate.mjs';
import { loadPolicy, PolicyEngine, failClosedEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';
import { AuthorityLedger } from '../lib/authority.mjs';
import { assertValid } from '../lib/validate.mjs';

const NOW = Date.parse('2026-08-08T12:00:00.000Z');
const clock = () => NOW;

function engine() {
  return new PolicyEngine(loadPolicy({ path: DEFAULT_POLICY_PATH }));
}

function ledgerWithAlchemist(turnId = 'turn-1') {
  const l = new AuthorityLedger({ clock });
  l.assertForTurn({
    turnId,
    authority: 'alchemist',
    assertedBy: 'kernel:proc-1',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });
  return l;
}

function ledgerWithOracle(turnId = 'turn-1') {
  const l = new AuthorityLedger({ clock });
  l.assertForTurn({
    turnId,
    authority: 'oracle',
    assertedBy: 'kernel:proc-1',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });
  return l;
}

function contract(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-execution-contract',
    contractId: 'EC-44',
    version: 2,
    sourceRevision: '0123abcdef',
    objective: 'ship the thing',
    currentState: 'not shipped',
    desiredState: 'shipped',
    requirements: [],
    decisions: [],
    invariants: [],
    nonGoals: [],
    scope: { own: ['src/**'], read: ['docs/**'], forbidden: ['src/secrets/**'] },
    artifacts: {
      exact: [{ id: 'a1', path: 'src/exact.ts', latitude: 'EXACT', content: 'x' }],
      bounded: [{ id: 'a2', path: 'src/bounded.ts', latitude: 'BOUNDED', locked: ['signature'], freedom: ['impl'] }],
    },
    tasks: ['T-1'],
    dependencies: [],
    acceptanceCriteria: [],
    declaredChecks: [],
    evidenceRequirements: [],
    authorizedEffectClasses: ['FILE_WRITE', 'FILE_MOVE', 'COMMAND_EXEC'],
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
    runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    contractId: 'EC-44',
    taskId: 'T-1',
    requestedBy: 'alchemist',
    effectClass: 'FILE_WRITE',
    target: 'src/exact.ts',
    operation: 'write',
    latitude: 'EXACT',
    sourceRevision: '0123abcdef',
    requestedAt: new Date(NOW).toISOString(),
    ...overrides,
  };
}

/** Minimal stand-in for S03's CapabilityStore, to the INTERFACES.md contract. */
function capabilityStore({ allow = true, code = 'ARC_CAPABILITY_UNKNOWN' } = {}) {
  return {
    check: () => (allow
      ? { allowed: true, code: null, message: '', detail: {}, failClosed: false, enforcementHealth: 'strong' }
      : { allowed: false, code, message: code, detail: {}, failClosed: false, enforcementHealth: 'strong' }),
    consume: () => true,
  };
}

// ------------------------------------------------------------------- fixtures

test('gate fixtures are themselves valid against the frozen contracts', () => {
  assertValid('execution-contract-v1', contract());
  assertValid('effect-request-v1', request());
});

// ------------------------------------------------------------- happy path

test('an EXACT write inside scope.own with a valid capability is authorized', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, true, d.message);
  assert.equal(d.enforcementHealth, 'strong');
});

test('a BOUNDED write against a bounded artifact is authorized', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'src/bounded.ts', latitude: 'BOUNDED' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, true, d.message);
});

test('oracle is accepted as assurance authority by the pre-effect gate', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithOracle(), clock });
  const d = gate.evaluate(request({ requestedBy: 'oracle' }), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, true, d.message);
});

// -------------------------------------------------------------- Contract executability

test('mutation without a contract is denied — ARC_NO_CONTRACT', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request(), { contract: null, turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_NO_CONTRACT');
});

test('a contract with open questions is not executable', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const c = contract({ openQuestions: [{ id: 'q1', question: 'which db?' }] });
  const d = gate.evaluate(request(), { contract: c, turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CONTRACT_NOT_EXECUTABLE');
});

test('a request naming a different contract id is refused', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ contractId: 'EC-99' }), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CONTRACT_VERSION_MISMATCH');
});

test('a request pinned to a superseded contract version is refused', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1', expectedContractVersion: 1 });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CONTRACT_VERSION_MISMATCH');
});

// ------------------------------------------------------- path ownership

test('a write outside scope.own is denied — ARC_PATH_NOT_OWNED', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'other/file.ts', latitude: 'BOUNDED' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_PATH_NOT_OWNED');
});

test('forbidden beats own — a path in both is denied as forbidden', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'src/secrets/key.ts', latitude: 'BOUNDED' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_PATH_FORBIDDEN');
});

test('FILE_MOVE checks BOTH source and destination ownership', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ effectClass: 'FILE_MOVE', operation: 'move', target: 'src/bounded.ts', latitude: 'BOUNDED' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1', destination: 'escaped/out.ts',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_PATH_NOT_OWNED');
  assert.equal(d.detail.which, 'destination');
});

test('pathMatches: ** spans depth, * stays in one segment, exact is exact', () => {
  assert.equal(pathMatches('src/**', 'src/a/b/c.ts'), true);
  assert.equal(pathMatches('**/*.mjs', 'top.mjs'), true, '**/ also spans zero directories');
  assert.equal(pathMatches('src/*', 'src/a/b.ts'), false);
  assert.equal(pathMatches('src/*', 'src/a.ts'), true);
  assert.equal(pathMatches('src/a.ts', 'src/a.ts'), true);
  assert.equal(pathMatches('src/a.ts', 'src/ab.ts'), false);
  assert.equal(pathMatches('src/', 'src/deep/x.ts'), true, 'trailing slash means directory prefix');
  // Traversal must not escape an owned prefix.
  assert.equal(pathMatches('src/**', 'src/../etc/passwd'), false);
  assert.equal(pathMatches('src/**', 'src\\a\\b.ts'), true, 'windows separators normalize');
});

// ------------------------------------------------- effect-class authorization

test('an effect class the contract does not authorize is denied', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ effectClass: 'FILE_DELETE', operation: 'delete', latitude: 'BOUNDED', target: 'src/bounded.ts' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1', approvalDigest: `sha256:${'a'.repeat(64)}`,
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
  assert.equal(d.detail.deniedBy, 'contract');
});

test('an effect class the policy denies is denied even when the contract allows it', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  // CREDENTIAL_ACCESS, not VCS_PUSH: this pins that a policy `deny` outranks
  // both a permissive contract AND an approval digest. VCS_PUSH is now
  // allow+approvalRequired — its own note had asked for that, while `deny`
  // silently made the field unreachable — so it no longer demonstrates the
  // property. CREDENTIAL_ACCESS is the class that must stay unappealable.
  const c = contract({ authorizedEffectClasses: ['FILE_WRITE', 'CREDENTIAL_ACCESS'] });
  const d = gate.evaluate(request({ effectClass: 'CREDENTIAL_ACCESS', operation: 'read-secret', target: 'src/bounded.ts', latitude: 'BOUNDED' }), {
    contract: c, turnId: 'turn-1', capabilityId: 'cap_1', approvalDigest: `sha256:${'a'.repeat(64)}`,
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
  assert.equal(d.detail.deniedBy, 'policy');
});

test('an approval-required effect without an approval digest is denied', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const c = contract({ authorizedEffectClasses: ['FILE_DELETE'] });
  const d = gate.evaluate(request({ effectClass: 'FILE_DELETE', operation: 'delete', target: 'src/bounded.ts', latitude: 'BOUNDED' }), {
    contract: c, turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_APPROVAL_REQUIRED');
});

// ------------------------------------------------------------------ latitude

test('EXACT latitude against a BOUNDED artifact is a latitude violation', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'src/bounded.ts', latitude: 'EXACT' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_LATITUDE_VIOLATION');
});

test('BOUNDED latitude against an EXACT artifact is a latitude violation', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'src/exact.ts', latitude: 'BOUNDED' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_LATITUDE_VIOLATION');
});

test('a target owned by scope but named by no artifact unit may not claim EXACT', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ target: 'src/unlisted.ts', latitude: 'EXACT' }), {
    contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1',
  });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_LATITUDE_VIOLATION');
});

// ---------------------------------------------------------------- capability

test('capability failures propagate with their own codes', () => {
  for (const code of ['ARC_CAPABILITY_EXPIRED', 'ARC_CAPABILITY_EXHAUSTED', 'ARC_CAPABILITY_REVOKED', 'ARC_CAPABILITY_UNKNOWN']) {
    const gate = new PreEffectGate({
      policy: engine(), capabilityStore: capabilityStore({ allow: false, code }), authorityLedger: ledgerWithAlchemist(), clock,
    });
    const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
    assert.equal(d.allowed, false);
    assert.equal(d.code, code);
  }
});

test('a mutation with no capability id at all is denied', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: null });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CAPABILITY_UNKNOWN');
});

// ----------------------------------------------------------------- authority

test('an effect on a turn with no kernel-asserted authority is denied', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: new AuthorityLedger({ clock }), clock });
  const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_AUTHORITY_NOT_ASSERTED');
});

test('a request whose requestedBy differs from the kernel assertion is refused as model-claimed', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ requestedBy: 'sage' }), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_AUTHORITY_MODEL_CLAIMED');
});

// ------------------------------------------------------------- fail closed

test('gate unavailable: a MUTATION fails closed', () => {
  const gate = new PreEffectGate({ policy: failClosedEngine('bundle missing'), capabilityStore: null, authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_GATE_UNAVAILABLE');
  assert.equal(d.failClosed, true);
  assert.equal(d.enforcementHealth, 'unsupported');
});

test('gate unavailable: a READ-ONLY operation continues with a recorded downgrade', () => {
  const gate = new PreEffectGate({ policy: failClosedEngine('bundle missing'), capabilityStore: null, authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluateReadOnly({ target: 'docs/x.md', turnId: 'turn-1' });
  assert.equal(d.allowed, true);
  assert.notEqual(d.enforcementHealth, 'strong');
  assert.equal(d.detail.degraded, true);
});

test('isMutating classifies every frozen effect class, and read-only is not inferred from a tool name', () => {
  assert.equal(isMutating('FILE_WRITE'), true);
  assert.equal(isMutating('VCS_PUSH'), true);
  assert.equal(isMutating('COMMAND_EXEC'), true);
  // The frozen enum has no read class; every value in it mutates or may mutate.
  assert.equal(isMutating('NETWORK_EGRESS'), true);
});

test('a structurally invalid effect request is refused before any policy is consulted', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const bad = request();
  delete bad.sourceRevision;
  const d = gate.evaluate(bad, { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_SCHEMA_INVALID');
});

test('the gate never authorizes when the contract source revision differs from the request', () => {
  const gate = new PreEffectGate({ policy: engine(), capabilityStore: capabilityStore(), authorityLedger: ledgerWithAlchemist(), clock });
  const d = gate.evaluate(request({ sourceRevision: 'deadbeef99' }), { contract: contract(), turnId: 'turn-1', capabilityId: 'cap_1' });
  assert.equal(d.allowed, false);
  assert.equal(d.code, 'ARC_CONTRACT_VERSION_MISMATCH');
});
