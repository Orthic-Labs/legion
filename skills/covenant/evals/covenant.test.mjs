import assert from 'node:assert/strict';
import test from 'node:test';

import {
  covenantGateSatisfied,
  createCovenantRecord,
  createCovenantRequest,
  validateCovenantRecord,
  validateCovenantRequest,
} from '../lib/contracts.mjs';
import {
  PACKET_ONLY_MARKER,
  executeBlockerConsult,
  executeDecisionChallenge,
  executePacketOnly,
  runSeats,
} from '../lib/flows.mjs';

const ID = '01ARZ3NDEKTSV4RRFFQ69G5FAV';

function baseRequest(overrides = {}) {
  return createCovenantRequest({
    requestId: `req_${ID}`,
    runId: `run_${ID}`,
    callerAuthority: 'SAGE',
    mode: 'DECISION_CHALLENGE',
    subjectType: 'execution-contract',
    subjectId: 'EC-21',
    subjectVersion: '1',
    sourceRevision: 'abcdef1',
    userIntent: {
      verbatim: 'Pressure-test this decision before sealing it.',
      interpretedSuccessCriteria: 'Decision survives independent challenge.',
    },
    question: 'Does this decision satisfy its acceptance criteria?',
    constraints: ['read-only review'],
    invariants: ['caller retains authority'],
    nonGoals: [],
    evidenceRefs: ['decision.md'],
    embeddedEvidence: ['D-1: choose adapter boundary'],
    knownUnknowns: [],
    knownWeaknesses: [],
    alternativesConsidered: ['direct integration'],
    requestedOutcome: 'SUPPORTED | REVISE | UNRESOLVED',
    seatPolicy: { seatCount: 2, lensRequirements: ['risk', 'scope'], requireFreshVerdict: true },
    riskClass: 'high',
    ...overrides,
  });
}

function finding(id = 'F-1') {
  return {
    findingId: id,
    lens: 'scope',
    statement: 'Acceptance evidence is incomplete.',
    severity: 'material',
    evidenceRefs: ['decision.md'],
    affectedDecisions: ['D-1'],
    affectedAcceptance: ['AC-1'],
    failurePath: 'Gate could pass without proof.',
    recommendedAction: 'Add executable evidence.',
    confidence: 0.9,
    classification: 'MISSING_EVIDENCE',
  };
}

function safeProposal(overrides = {}) {
  return {
    changesSealedDecision: false,
    changesLockedInvariant: false,
    changesAcceptance: false,
    expandsScope: false,
    addsMaterialDependency: false,
    changesPublicBehavior: false,
    altersSecurity: false,
    exceedsEffectClass: false,
    ...overrides,
  };
}

function baseRecord(request, overrides = {}) {
  return createCovenantRecord(request, {
    recordId: 'CV-1',
    seatRecords: [
      { seatId: 'seat-1', lens: 'risk', isolated: true, providerId: 'p1', reusedModel: false, position: 'support' },
    ],
    synthesis: 'Evidence supports decision.',
    findings: [],
    disagreements: [],
    missingEvidence: [],
    risks: [],
    outcome: 'SUPPORTED',
    callerDispositions: [],
    lane: 'V-COVENANT',
    providerMetadata: {},
    timing: null,
    integrity: { digestVerified: true, mutationDetected: false },
    ...overrides,
  });
}

test('typed request constructs against frozen schema & rejects digest mismatch', () => {
  const request = baseRequest();
  assert.deepEqual(validateCovenantRequest(request), []);
  assert.match(request.packetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(validateCovenantRequest({ ...request, question: 'tampered' }).join('\n'), /packetDigest/);
});

test('typed record validates mode outcomes & authority tokens', () => {
  const request = baseRequest();
  const valid = baseRecord(request);
  assert.deepEqual(validateCovenantRecord(valid, request), []);
  assert.match(
    validateCovenantRecord({ ...valid, outcome: 'CONTRACT_SAFE' }, request).join('\n'),
    /outcome.*DECISION_CHALLENGE/,
  );
  assert.match(
    validateCovenantRecord({ ...valid, synthesis: 'DECISION_SEALED' }, request).join('\n'),
    /forbidden authority token/,
  );
});

test('convenedBy records Legion without granting caller authority', () => {
  const request = baseRequest({ convenedBy: 'legion' });
  assert.equal(request.callerAuthority, 'SAGE');
  assert.deepEqual(validateCovenantRequest(request), []);
  assert.throws(() => baseRequest({ callerAuthority: 'LEGION' }), /callerAuthority/);
  assert.throws(() => baseRequest({ convenedBy: null }), /convenedBy/);
});

test('COV-SAGE-01 routine architecture does not auto-trigger Covenant', () => {
  assert.equal(executePacketOnly.shouldAutoInvoke('How should this helper be structured?'), false);
});

test('COV-SAGE-02 decision challenge isolates initial seats & fresh verdict', async () => {
  const request = baseRequest();
  const seen = [];
  const result = await executeDecisionChallenge({
    request,
    seats: [
      { seatId: 'one', lens: 'risk', providerId: 'p1' },
      { seatId: 'two', lens: 'scope', providerId: 'p2' },
    ],
    seatRunner: async (seat, packet, stage) => {
      seen.push({ seat, packet, stage });
      return { position: `${stage}-${seat.seatId}`, findings: stage === 'positions' ? [finding(`F-${seat.seatId === 'one' ? 1 : 2}`)] : [] };
    },
    synthesize: async () => ({ synthesis: 'Revise evidence.', outcome: 'REVISE' }),
    callerDisposition: async () => ({
      dispositions: [
        { findingId: 'F-1', disposition: 'ACCEPT' },
        { findingId: 'F-2', disposition: 'REJECT', rationale: 'Existing proof covers it.' },
      ],
      revisedSubject: { decision: 'revised', evidence: ['test'] },
      revisionSubjectId: 'EC-21-v2',
    }),
    verdictSeats: [
      { seatId: 'fresh-1', lens: 'verdict', providerId: 'p3' },
      { seatId: 'fresh-2', lens: 'verdict', providerId: 'p4' },
    ],
    verdictRunner: async (seat, packet, stage) => {
      seen.push({ seat, packet, stage });
      assert.equal('firstPanelVotes' in packet, false);
      assert.equal('reviewerIdentities' in packet, false);
      assert.equal('callerDesiredVerdict' in packet, false);
      return { position: 'SUPPORTED', findings: [] };
    },
  });
  assert.equal(result.record.outcome, 'REVISE');
  assert.equal(result.freshVerdict.outcome, 'SUPPORTED');
  assert.equal(seen.filter((x) => x.stage === 'positions').length, 2);
  assert.equal(seen.filter((x) => x.stage === 'fresh-verdict').length, 2);
});

test('COV-SAGE-03 Covenant cannot seal or emit control pass', () => {
  const request = baseRequest();
  const valid = baseRecord(request);
  for (const token of ['DECISION_SEALED', 'CONTROL_PASS']) {
    const errors = validateCovenantRecord({ ...valid, synthesis: token }, request);
    assert.match(errors.join('\n'), /forbidden authority token/);
  }
});

test('COV-SAGE-04 stale verdict fails current gate query', () => {
  const request = baseRequest();
  const record = baseRecord(request);
  assert.equal(covenantGateSatisfied(record, request, { outcomes: ['SUPPORTED'] }), true);
  const changed = baseRequest({ embeddedEvidence: ['D-1 materially changed'] });
  assert.equal(covenantGateSatisfied(record, changed, { outcomes: ['SUPPORTED'] }), false);
});

test('disposition completeness rejects noted, missing, reject rationale, & defer owner', () => {
  const request = baseRequest();
  const valid = baseRecord(request, {
    findings: [finding()],
    callerDispositions: [{ findingId: 'F-1', disposition: 'ACCEPT' }],
  });
  const cases = [
    [],
    [{ findingId: 'F-1', disposition: 'noted' }],
    [{ findingId: 'F-1', disposition: 'REJECT' }],
    [{ findingId: 'F-1', disposition: 'DEFER_TO_PHASE' }],
  ];
  for (const callerDispositions of cases) {
    const errors = validateCovenantRecord({ ...valid, callerDispositions }, request);
    assert.ok(errors.length > 0);
  }
});

test('incomplete dispositions block fresh panel execution', async () => {
  let freshCalls = 0;
  await assert.rejects(executeDecisionChallenge({
    request: baseRequest({ seatPolicy: { seatCount: 1, lensRequirements: ['risk'], requireFreshVerdict: true } }),
    seats: [{ seatId: 'one', lens: 'risk' }],
    seatRunner: async () => ({ position: 'revise', findings: [finding()] }),
    synthesize: async () => ({ synthesis: 'Revise.', outcome: 'REVISE' }),
    callerDisposition: async () => ({ dispositions: [], revisedSubject: { decision: 'changed' } }),
    verdictSeats: [{ seatId: 'fresh', lens: 'verdict' }],
    verdictRunner: async () => { freshCalls += 1; return { position: 'SUPPORTED' }; },
  }), /missing terminal disposition/);
  assert.equal(freshCalls, 0);
});

test('COV-ALCH-01 contract-safe blocker stays within every mechanical boundary', async () => {
  const request = baseRequest({
    callerAuthority: 'ALCHEMIST',
    mode: 'BLOCKER_CONSULT',
    subjectType: 'blocker',
    subjectId: 'TASK-9',
    seatPolicy: { seatCount: 1, lensRequirements: ['contract'], requireFreshVerdict: false },
    requestedOutcome: 'CONTRACT_SAFE | AMENDMENT_REQUIRED | INSUFFICIENT_EVIDENCE',
  });
  const result = await executeBlockerConsult({
    request,
    seats: [{ seatId: 'one', lens: 'contract', providerId: 'p1' }],
    seatRunner: async () => ({ position: 'Use existing adapter.', findings: [] }),
    synthesize: async () => ({
      synthesis: 'Existing adapter is sufficient.',
      evidenceSufficient: true,
      proposal: safeProposal(),
    }),
  });
  assert.equal(result.record.outcome, 'CONTRACT_SAFE');
});

test('COV-ALCH-02 semantic change requires amendment', async () => {
  const request = baseRequest({ callerAuthority: 'ALCHEMIST', mode: 'BLOCKER_CONSULT', subjectType: 'blocker', seatPolicy: { seatCount: 1 } });
  const result = await executeBlockerConsult({
    request,
    seats: [{ seatId: 'one', lens: 'contract' }],
    seatRunner: async () => ({ position: 'Change interface.', findings: [] }),
    synthesize: async () => ({ synthesis: 'Interface change needed.', evidenceSufficient: true, proposal: safeProposal({ changesPublicBehavior: true }) }),
  });
  assert.equal(result.record.outcome, 'AMENDMENT_REQUIRED');
});

test('COV-ALCH-03 out-of-scope cleanup cannot expand execution', async () => {
  const request = baseRequest({ callerAuthority: 'ALCHEMIST', mode: 'BLOCKER_CONSULT', subjectType: 'blocker', seatPolicy: { seatCount: 1 } });
  const result = await executeBlockerConsult({
    request,
    seats: [{ seatId: 'one', lens: 'scope' }],
    seatRunner: async () => ({ position: 'Clean adjacent module.', findings: [finding()] }),
    synthesize: async () => ({ synthesis: 'Cleanup expands scope.', evidenceSufficient: true, proposal: safeProposal({ expandsScope: true }) }),
  });
  assert.equal(result.record.outcome, 'AMENDMENT_REQUIRED');
});

test('COV-ALCH-04 reviewer agreement grants no authority', () => {
  const request = baseRequest({ callerAuthority: 'ALCHEMIST', mode: 'BLOCKER_CONSULT', subjectType: 'blocker' });
  const valid = baseRecord(request, { outcome: 'CONTRACT_SAFE' });
  const errors = validateCovenantRecord({ ...valid, outcome: 'SUPPORTED', synthesis: 'Three reviewers authorize interface change.' }, request);
  assert.match(errors.join('\n'), /outcome.*BLOCKER_CONSULT/);
});

test('COV-SEER-01 routine Seer cannot call Covenant', () => {
  assert.throws(() => baseRequest({ callerAuthority: 'SEER' }), /callerAuthority/);
});

test('COV-SEER-02 explicit dispute review stays advisory', () => {
  const request = baseRequest({ callerAuthority: 'USER_OVERRIDE', mode: 'DISPUTE_REVIEW', subjectType: 'audit-finding' });
  assert.deepEqual(validateCovenantRequest(request), []);
  const valid = baseRecord(request);
  assert.match(validateCovenantRecord({ ...valid, synthesis: 'CONTROL_PASS' }, request).join('\n'), /forbidden authority token/);
});

test('packet-only accepts the canonical marker without executing seats', async () => {
  let calls = 0;
  const request = baseRequest({ mode: 'PACKET_ONLY', callerAuthority: 'USER_OVERRIDE', seatPolicy: { seatCount: 1 } });
  const result = await executePacketOnly({ request, marker: PACKET_ONLY_MARKER, seatRunner: async () => { calls += 1; } });
  assert.equal(result.record, null);
  assert.equal(calls, 0);
});

test('seat stage runs independent providers concurrently & serializes same concurrency key', async () => {
  let active = 0;
  let maxActive = 0;
  const order = [];
  const seats = [
    { seatId: 'a', lens: 'one', providerId: 'p', concurrencyKey: 'quota-p' },
    { seatId: 'b', lens: 'two', providerId: 'p', concurrencyKey: 'quota-p' },
    { seatId: 'c', lens: 'three', providerId: 'q', concurrencyKey: 'quota-q' },
  ];
  const { seatRecords } = await runSeats(seats, {}, async (seat) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    order.push(`start-${seat.seatId}`);
    await new Promise((resolve) => setTimeout(resolve, 15));
    order.push(`end-${seat.seatId}`);
    active -= 1;
    return { position: seat.seatId, findings: [] };
  }, 'positions');
  assert.equal(maxActive, 2);
  assert.ok(order.indexOf('end-a') < order.indexOf('start-b'));
  assert.ok(seatRecords.every((seat) => seat.isolated));
});

test('provider failure is recorded as explicit degradation', async () => {
  const { seatRecords, providerMetadata } = await runSeats(
    [{ seatId: 'fail', lens: 'risk', providerId: 'down' }],
    {},
    async () => { throw new Error('provider unavailable'); },
    'positions',
  );
  assert.equal(providerMetadata.degraded, true);
  assert.equal(providerMetadata.failures.length, 1);
  assert.match(seatRecords[0].position, /PROVIDER_FAILURE/);
  const request = baseRequest();
  const record = baseRecord(request, { providerMetadata });
  assert.equal(covenantGateSatisfied(record, request, { outcomes: ['SUPPORTED'] }), false);
});

test('empty or no-output panels cannot produce supported evidence', async () => {
  await assert.rejects(runSeats([], {}, async () => ({ position: 'SUPPORTED' }), 'positions'), /at least one seat/);
  const result = await runSeats([{ seatId: 'empty', lens: 'risk' }], {}, async () => null, 'positions');
  assert.equal(result.providerMetadata.degraded, true);
  assert.match(result.seatRecords[0].position, /PROVIDER_FAILURE/);
});

test('same-provider seats serialize without caller-supplied keys', async () => {
  let active = 0;
  let maxActive = 0;
  await runSeats([
    { seatId: 'a', lens: 'one', providerId: 'shared' },
    { seatId: 'b', lens: 'two', providerId: 'shared' },
  ], {}, async (seat) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    return { position: seat.seatId };
  }, 'positions');
  assert.equal(maxActive, 1);
});

test('incomplete blocker checklist cannot classify CONTRACT_SAFE', async () => {
  const request = baseRequest({ callerAuthority: 'ALCHEMIST', mode: 'BLOCKER_CONSULT', subjectType: 'blocker', seatPolicy: { seatCount: 1 } });
  const result = await executeBlockerConsult({
    request,
    seats: [{ seatId: 'one', lens: 'contract' }],
    seatRunner: async () => ({ position: 'safe' }),
    synthesize: async () => ({ synthesis: 'Incomplete.', evidenceSufficient: true, proposal: {} }),
  });
  assert.equal(result.record.outcome, 'INSUFFICIENT_EVIDENCE');
  assert.equal(result.record.providerMetadata.missingContractSafetyChecks.length, 8);
});

test('non-boolean blocker checklist cannot classify CONTRACT_SAFE', async () => {
  const request = baseRequest({ callerAuthority: 'ALCHEMIST', mode: 'BLOCKER_CONSULT', subjectType: 'blocker', seatPolicy: { seatCount: 1 } });
  const proposal = safeProposal({ expandsScope: 'false' });
  const result = await executeBlockerConsult({
    request,
    seats: [{ seatId: 'one', lens: 'contract' }],
    seatRunner: async () => ({ position: 'safe' }),
    synthesize: async () => ({ synthesis: 'Malformed checklist.', evidenceSufficient: true, proposal }),
  });
  assert.equal(result.record.outcome, 'INSUFFICIENT_EVIDENCE');
  assert.deepEqual(result.record.providerMetadata.invalidContractSafetyChecks, ['expandsScope']);
});

test('degraded initial challenge cannot retain SUPPORTED outcome', async () => {
  const request = baseRequest({ seatPolicy: { seatCount: 1, requireFreshVerdict: true } });
  const result = await executeDecisionChallenge({
    request,
    seats: [{ seatId: 'down', lens: 'risk', providerId: 'p1' }],
    seatRunner: async () => { throw new Error('provider unavailable'); },
    synthesize: async () => ({ synthesis: 'Unsupported synthesis.', outcome: 'SUPPORTED' }),
    callerDisposition: async () => ({ dispositions: [], revisedSubject: { decision: 'unchanged' } }),
    verdictSeats: [{ seatId: 'fresh', lens: 'verdict', providerId: 'p2' }],
    verdictRunner: async () => ({ position: 'SUPPORTED', findings: [] }),
  });
  assert.equal(result.record.outcome, 'UNRESOLVED');
});

test('mutation receipt invalidates record', () => {
  const request = baseRequest();
  const record = { ...baseRecord(request), integrity: { digestVerified: true, mutationDetected: true } };
  assert.match(validateCovenantRecord(record, request).join('\n'), /mutationDetected/);
  assert.equal(covenantGateSatisfied(record, request, { outcomes: ['SUPPORTED'] }), false);
});
