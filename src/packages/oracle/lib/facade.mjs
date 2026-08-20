import { canonicalJson, clone, deepFreeze, wrapArtifact } from './artifact.mjs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { buildJudgmentPacket } from '../../../lib/core/judgment-packets.mjs';
import { traceDiffBlastRadius } from './blueprint-impact.mjs';

const API = Object.freeze({
  inspect: 'inspectProduct',
  plan: 'buildPlan',
  audit: 'audit',
  verify: 'verifyRun',
  explain: 'explain',
});
const MUTATION = /(?:source[._-]?(?:write|mutat)|apply[._-]?(?:effect|patch)|effect[._-]?request)/i;

export function createOracle({ core, clock = { now: () => new Date() }, receiptStore = null, traceDiff = traceDiffBlastRadius }) {
  const facade = {};
  for (const [operation, api] of Object.entries(API)) {
    facade[operation] = async (request, { host } = {}) => invoke({ request, operation, api, core, host, clock, receiptStore: host?.receiptStore ?? receiptStore, traceDiff });
  }
  return Object.freeze(facade);
}

async function invoke({ request, operation, api, core, host, clock, receiptStore, traceDiff }) {
  validateRequest(request, operation);
  const context = forwardedContext(request);
  if (hasMutationCapability(request.input)) {
    return failedPair(request, context, clock, {
      code: 'ORACLE_MUTATION_CAPABILITY_REJECTED',
      message: 'Oracle accepts frozen read-only audit inputs; source mutation capability is forbidden',
      remediation: 'Submit remediation as an artifact for a separate mutation authority',
    });
  }
  if (typeof core?.[api] !== 'function') {
    return failedPair(request, context, clock, {
      code: 'ORACLE_CORE_API_UNAVAILABLE',
      message: `canonical core API ${api} is unavailable through the supplied public core surface`,
      remediation: `Coordinator must expose ${api}; facade core changes are forbidden`,
    });
  }
  try {
    const blastRadius = await diffBlastRadius(request, operation, traceDiff);
    const output = await core[api](forwardedInput(request, context, blastRadius), host);
    const pair = completedPair(request, context, output, clock, `oracle.${operation}.core-output`, blastRadius);
    return attachFeedback(pair, output, receiptStore);
  } catch (error) {
    return failedPair(request, context, clock, {
      code: 'ORACLE_CORE_INVOCATION_FAILED',
      message: error?.message ?? String(error),
      remediation: null,
    });
  }
}

export function translateLegacyReport(request, legacyReport, { clock = { now: () => new Date() } } = {}) {
  validateRequest(request, 'audit');
  const context = forwardedContext(request);
  if (hasMutationCapability(request.input)) {
    return failedPair(request, context, clock, {
      code: 'ORACLE_MUTATION_CAPABILITY_REJECTED',
      message: 'Oracle accepts frozen read-only audit inputs; source mutation capability is forbidden',
      remediation: 'Submit remediation as an artifact for a separate mutation authority',
    });
  }
  return completedPair(request, context, legacyReport, clock, 'oracle.audit.legacy-output');
}

function completedPair(request, context, output, clock, artifactKind, blastRadius = null) {
  const completedAt = clock.now().toISOString();
  const artifact = wrapArtifact({ value: output, artifactKind, sourceRevision: request.sourceRevision, createdAt: completedAt });
  const observedBoundary = output?.claimBoundary ?? output?.report?.claimBoundary ?? output?.report?.claim_boundary ?? 'UNPROVEN';
  const claimBoundary = blastRadius?.state === 'unproven' ? 'UNPROVEN' : observedBoundary;
  const warnings = Array.isArray(output?.warnings) ? [...output.warnings] : [];
  if (blastRadius?.state === 'unproven') warnings.push('blueprint-impact-unproven');
  return Object.freeze({
    request,
    ...context,
    ...(blastRadius ? { blastRadius } : {}),
    result: resultEnvelope(request, {
      invocationState: 'COMPLETED',
      domainOutcome: output?.domainOutcome ?? 'COMPLETE',
      claimBoundary,
      artifacts: [artifact.record.artifactId],
      warnings,
      nextActions: Array.isArray(output?.nextActions) ? clone(output.nextActions) : [],
      error: null,
      completedAt,
    }),
    artifacts: Object.freeze([artifact]),
  });
}

function failedPair(request, context, clock, error) {
  const completedAt = clock.now().toISOString();
  return Object.freeze({
    request,
    ...context,
    result: resultEnvelope(request, {
      invocationState: 'FAILED_INVOCATION',
      domainOutcome: 'FAILED_CONTRACT',
      claimBoundary: 'UNPROVEN',
      artifacts: [],
      warnings: [],
      nextActions: [],
      error: { ...error, retriable: false },
      completedAt,
    }),
    artifacts: Object.freeze([]),
  });
}

function resultEnvelope(request, fields) {
  return deepFreeze({
    schemaVersion: 1,
    kind: 'legion-operation-envelope',
    envelopeKind: 'result',
    operationId: request.operationId,
    operationVersion: request.operationVersion,
    requestId: request.requestId,
    runId: request.runId,
    ...(request.taskId !== undefined ? { taskId: request.taskId } : {}),
    ...fields,
    sourceRevision: request.sourceRevision,
  });
}

function forwardedContext(request) {
  return {
    runIdentity: deepFreeze(clone(request.input.runIdentity)),
    workingContext: deepFreeze(clone(request.input.workingContext)),
  };
}

function forwardedInput(request, context, blastRadius = null) {
  const options = request.input?.options;
  const lens = needsLens(request.operationId) ? sealedLens(request.input?.lens) : null;
  return Object.freeze({
    ...((options && typeof options === 'object' && !Array.isArray(options)) ? clone(options) : {}),
    runIdentity: context.runIdentity,
    workingContext: context.workingContext,
    ...(lens ? { lens, judgmentPacket: buildJudgmentPacket({ subject: { id: request.requestId }, reviewerRole: 'oracle', budget: null, lens }) } : {}),
    ...(blastRadius ? { blastRadius } : {}),
  });
}

async function diffBlastRadius(request, operation, traceDiff) {
  if (!needsLens(request.operationId) || !['audit', 'verify'].includes(operation)) return null;
  const changedPaths = request.input?.diff?.changedPaths;
  if (!Array.isArray(changedPaths) || !changedPaths.length) return null;
  const identity = request.input.runIdentity;
  const repoRoot = resolve(identity.workspace, identity.repository ?? '.');
  return deepFreeze(await traceDiff({ repoRoot, changedPaths }));
}

function findingOutcomes(output) {
  const lists = [output?.findings, output?.report?.findings];
  for (const provider of output?.provider_reconciliation?.providerResults ?? output?.report?.provider_reconciliation?.providerResults ?? []) lists.push(provider.findings);
  const seen = new Set(); const outcomes = [];
  for (const finding of lists.flatMap((value) => Array.isArray(value) ? value : [])) {
    const findingId = finding.id ?? finding.findingId ?? finding.ruleId ?? null;
    const verdict = finding.verdict ?? finding.claim ?? finding.status ?? 'unproven';
    const key = canonicalJson({ findingId, verdict, ruleId: finding.ruleId ?? null });
    if (seen.has(key)) continue;
    seen.add(key);
    outcomes.push({ findingId, ruleId: finding.ruleId ?? null, verdict, severity: finding.severity ?? null });
  }
  return outcomes;
}

function attachFeedback(pair, output, receiptStore) {
  if (!receiptStore) return Object.freeze({ ...pair, feedbackReceipt: null });
  const recordBase = {
    schemaVersion: 1,
    kind: 'oracle-verdict-outcome-receipt',
    runId: pair.result.runId,
    requestId: pair.result.requestId,
    operationId: pair.result.operationId,
    sourceRevision: pair.result.sourceRevision,
    invocationState: pair.result.invocationState,
    domainOutcome: pair.result.domainOutcome,
    claimBoundary: pair.result.claimBoundary,
    artifactIds: [...pair.result.artifacts],
    outcomes: findingOutcomes(output),
    blastRadiusDigest: pair.blastRadius?.digest ?? null,
    recordedAt: pair.result.completedAt,
  };
  const id = `oracle_${createHash('sha256').update(canonicalJson(recordBase)).digest('hex').slice(0, 26)}`;
  const record = deepFreeze({ ...recordBase, id });
  const stored = receiptStore.append(record);
  return Object.freeze({ ...pair, feedbackReceipt: deepFreeze({ record, ...stored }) });
}

function needsLens(operationId) { return operationId === 'oracle.audit' || operationId === 'oracle.verify'; }
function sealedLens(lens) {
  if (!lens?.id || !lens.digest || typeof lens.content !== 'string') throw new TypeError('audit and verify require sealed lens content');
  const digest = `sha256:${createHash('sha256').update(lens.content).digest('hex')}`;
  if (lens.digest !== digest) throw new TypeError('lens digest mismatch');
  return deepFreeze({ id: lens.id, digest: lens.digest, content: lens.content });
}

function validateRequest(request, operation) {
  if (request?.schemaVersion !== 1 || request?.kind !== 'legion-operation-envelope' || request?.envelopeKind !== 'request') throw new TypeError('operation-envelope-v1 request required');
  if (request.operationId !== `oracle.${operation}`) throw new TypeError(`expected oracle.${operation} request`);
  if (!request.requestId || !request.runId || !request.sourceRevision) throw new TypeError('request identity is incomplete');
  if (request.input?.runIdentity?.runId !== request.runId || request.input.runIdentity.revision !== request.sourceRevision) throw new TypeError('frozen run identity does not match request');
  if (!request.input?.workingContext?.marker) throw new TypeError('separate working context marker required');
}

function hasMutationCapability(input) {
  const visit = (value, key = '') => {
    if (MUTATION.test(key)) return true;
    if (typeof value === 'string') return MUTATION.test(value);
    if (Array.isArray(value)) return value.some((entry) => visit(entry));
    if (value && typeof value === 'object') return Object.entries(value).some(([nestedKey, nested]) => visit(nested, nestedKey));
    return false;
  };
  return visit(input ?? {});
}
