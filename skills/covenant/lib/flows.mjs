import {
  createCovenantRecord,
  createCovenantRequest,
  digestValue,
  validateCovenantRequest,
} from './contracts.mjs';

export const PACKET_ONLY_MARKER = 'PACKET_ONLY — DO_NOT_RUN_COVENANT';

const CONTRACT_BOUNDARIES = Object.freeze([
  'changesSealedDecision',
  'changesLockedInvariant',
  'changesAcceptance',
  'expandsScope',
  'addsMaterialDependency',
  'changesPublicBehavior',
  'altersSecurity',
  'exceedsEffectClass',
]);

function assertRequest(request, mode) {
  const errors = validateCovenantRequest(request);
  if (errors.length) throw new TypeError(`Invalid CovenantRequest: ${errors.join('; ')}`);
  if (request.mode !== mode) throw new TypeError(`Expected ${mode}, received ${request.mode}`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    Object.values(value).forEach(freeze);
  }
  return value;
}

export async function runSeats(seats, packet, runner, stage) {
  if (!Array.isArray(seats) || seats.length === 0) throw new TypeError(`${stage} requires at least one seat`);
  const tails = new Map();
  const failures = [];
  let mutationDetected = false;
  const jobs = seats.map((seat) => {
    const key = seat.concurrencyKey ?? (seat.providerId ? `provider:${seat.providerId}` : `seat:${seat.seatId}`);
    const prior = tails.get(key) ?? Promise.resolve();
    const job = prior.then(async () => {
      const isolatedPacket = clone(packet);
      const before = digestValue(isolatedPacket);
      try {
        const output = await runner(freeze(clone(seat)), isolatedPacket, stage);
        if (!output?.position) throw new Error('seat returned no position');
        if (digestValue(isolatedPacket) !== before) {
          mutationDetected = true;
          failures.push({ seatId: seat.seatId, providerId: seat.providerId ?? null, reason: 'subject mutation detected' });
          return { seat, output: { position: 'MUTATION_DETECTED', findings: [] } };
        }
        return { seat, output: output ?? { position: 'NO_OUTPUT', findings: [] } };
      } catch (error) {
        failures.push({ seatId: seat.seatId, providerId: seat.providerId ?? null, reason: error instanceof Error ? error.message : String(error) });
        return { seat, output: { position: `PROVIDER_FAILURE: ${error instanceof Error ? error.message : String(error)}`, findings: [] } };
      }
    });
    tails.set(key, job.catch(() => undefined));
    return job;
  });
  const results = await Promise.all(jobs);
  return {
    seatRecords: results.map(({ seat, output }) => ({
      seatId: seat.seatId,
      lens: seat.lens,
      isolated: true,
      providerId: seat.providerId ?? null,
      reusedModel: seat.reusedModel ?? false,
      position: output.position || 'NO_POSITION',
    })),
    findings: results.flatMap(({ output }) => output.findings ?? []),
    providerMetadata: { degraded: failures.length > 0, failures, mutationDetected },
  };
}

export async function executeDecisionChallenge(options) {
  const { request } = options;
  assertRequest(request, 'DECISION_CHALLENGE');
  requireSeatCount(options.seats, request.seatPolicy.seatCount, 'positions');
  requireSeatCount(options.verdictSeats, request.seatPolicy.seatCount, 'fresh-verdict');
  const initialPacket = freeze(clone(request));
  const positions = await runSeats(options.seats, initialPacket, options.seatRunner, 'positions');
  const synthesis = await options.synthesize({
    packetDigest: request.packetDigest,
    seatRecords: clone(positions.seatRecords),
    findings: clone(positions.findings),
  });
  const disposition = await options.callerDisposition({
    synthesis: synthesis.synthesis,
    findings: clone(positions.findings),
  });
  if (!disposition?.revisedSubject) throw new TypeError('DECISION_CHALLENGE requires revisedSubject before fresh verdict');
  const revisionDigest = digestValue(disposition.revisedSubject);
  const recordInput = {
    recordId: options.recordId ?? 'CV-1',
    seatRecords: positions.seatRecords,
    synthesis: synthesis.synthesis,
    findings: positions.findings,
    disagreements: synthesis.disagreements ?? [],
    missingEvidence: synthesis.missingEvidence ?? [],
    risks: synthesis.risks ?? [],
    outcome: positions.providerMetadata.degraded ? 'UNRESOLVED' : synthesis.outcome,
    callerDispositions: disposition.dispositions ?? [],
    revisionSubjectId: disposition.revisionSubjectId ?? request.subjectId,
    revisionDigest,
    freshVerdictRecordId: null,
    lane: 'V-COVENANT',
    providerMetadata: positions.providerMetadata,
    timing: null,
    integrity: { digestVerified: true, mutationDetected: positions.providerMetadata.mutationDetected },
  };
  createCovenantRecord(request, recordInput); // Completeness gate precedes fresh panel execution.
  const freshRequest = createCovenantRequest({
    ...request,
    subjectId: disposition.revisionSubjectId ?? request.subjectId,
    subjectVersion: `${request.subjectVersion ?? '0'}-revision`,
    embeddedEvidence: [JSON.stringify(disposition.revisedSubject)],
  });
  const freshPacket = freeze({
    requestId: request.requestId,
    mode: request.mode,
    sourceRevision: request.sourceRevision,
    subjectId: freshRequest.subjectId,
    revisedSubject: clone(disposition.revisedSubject),
    revisionDigest,
    userIntent: clone(request.userIntent),
    successCriteria: request.userIntent.interpretedSuccessCriteria,
  });
  const verdict = await runSeats(options.verdictSeats, freshPacket, options.verdictRunner, 'fresh-verdict');
  const freshOutcome = aggregateDecisionVerdict(verdict.seatRecords);
  const freshVerdict = createCovenantRecord(freshRequest, {
    recordId: options.freshRecordId ?? 'CV-2',
    seatRecords: verdict.seatRecords,
    synthesis: `Fresh verdict: ${freshOutcome}`,
    findings: verdict.findings,
    disagreements: [],
    missingEvidence: [],
    risks: [],
    outcome: freshOutcome,
    callerDispositions: [],
    revisionSubjectId: freshRequest.subjectId,
    revisionDigest,
    freshVerdictRecordId: null,
    lane: 'V-COVENANT',
    providerMetadata: verdict.providerMetadata,
    timing: null,
    integrity: { digestVerified: true, mutationDetected: verdict.providerMetadata.mutationDetected },
  });
  const record = createCovenantRecord(request, { ...recordInput, freshVerdictRecordId: freshVerdict.recordId });
  return { record, freshRequest, freshVerdict };
}

function aggregateDecisionVerdict(seatRecords) {
  const positions = seatRecords.map((seat) => seat.position.toUpperCase());
  if (positions.some((position) => position.includes('PROVIDER_FAILURE') || position.includes('UNRESOLVED'))) return 'UNRESOLVED';
  if (positions.some((position) => position.includes('REVISE') || position.includes('MUTATION_DETECTED'))) return 'REVISE';
  return 'SUPPORTED';
}

export async function executeBlockerConsult(options) {
  const { request } = options;
  assertRequest(request, 'BLOCKER_CONSULT');
  requireSeatCount(options.seats, request.seatPolicy.seatCount, 'positions');
  const positions = await runSeats(options.seats, freeze(clone(request)), options.seatRunner, 'positions');
  const synthesis = await options.synthesize({ seatRecords: clone(positions.seatRecords), findings: clone(positions.findings) });
  const missingChecks = CONTRACT_BOUNDARIES.filter((field) => !Object.hasOwn(synthesis.proposal ?? {}, field));
  const invalidChecks = CONTRACT_BOUNDARIES.filter((field) => Object.hasOwn(synthesis.proposal ?? {}, field) && typeof synthesis.proposal[field] !== 'boolean');
  let outcome = 'CONTRACT_SAFE';
  if (!synthesis.evidenceSufficient || positions.providerMetadata.degraded || missingChecks.length || invalidChecks.length) outcome = 'INSUFFICIENT_EVIDENCE';
  else if (CONTRACT_BOUNDARIES.some((field) => synthesis.proposal?.[field] === true)) outcome = 'AMENDMENT_REQUIRED';
  const record = createCovenantRecord(request, {
    recordId: options.recordId ?? 'CV-1',
    seatRecords: positions.seatRecords,
    synthesis: synthesis.synthesis,
    findings: positions.findings,
    disagreements: synthesis.disagreements ?? [],
    missingEvidence: synthesis.missingEvidence ?? [],
    risks: synthesis.risks ?? [],
    outcome,
    callerDispositions: [],
    revisionSubjectId: null,
    revisionDigest: null,
    freshVerdictRecordId: null,
    lane: 'V-COVENANT',
    providerMetadata: {
      ...positions.providerMetadata,
      missingContractSafetyChecks: missingChecks,
      invalidContractSafetyChecks: invalidChecks,
      contractSafety: Object.fromEntries(CONTRACT_BOUNDARIES.map((field) => [field, Object.hasOwn(synthesis.proposal ?? {}, field) ? synthesis.proposal[field] : null])),
    },
    timing: null,
    integrity: { digestVerified: true, mutationDetected: positions.providerMetadata.mutationDetected },
  });
  return { record };
}

export async function executePacketOnly({ request, marker = PACKET_ONLY_MARKER }) {
  assertRequest(request, 'PACKET_ONLY');
  if (marker !== PACKET_ONLY_MARKER) throw new TypeError('Invalid packet-only marker');
  return { marker, packet: freeze(clone(request)), record: null };
}

executePacketOnly.shouldAutoInvoke = (prompt) => /\b(?:covenant|council|jury|external review|multi-model panel)\b/i.test(prompt);

function requireSeatCount(seats, expected, stage) {
  if (!Array.isArray(seats) || seats.length !== expected) {
    throw new TypeError(`${stage} requires exactly seatPolicy.seatCount (${expected}) seats`);
  }
}
