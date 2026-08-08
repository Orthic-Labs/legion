import { clone, deepFreeze, wrapArtifact } from './artifact.mjs';

const API = Object.freeze({
  inspect: 'inspectProduct',
  plan: 'buildPlan',
  audit: 'audit',
  verify: 'verifyRun',
  explain: 'explain',
});
const MUTATION = /(?:source[._-]?(?:write|mutat)|apply[._-]?(?:effect|patch)|effect[._-]?request)/i;

export function createSeer({ core, clock = { now: () => new Date() } }) {
  const facade = {};
  for (const [operation, api] of Object.entries(API)) {
    facade[operation] = async (request, { host } = {}) => invoke({ request, operation, api, core, host, clock });
  }
  return Object.freeze(facade);
}

async function invoke({ request, operation, api, core, host, clock }) {
  validateRequest(request, operation);
  const context = forwardedContext(request);
  if (hasMutationCapability(request.input)) {
    return failedPair(request, context, clock, {
      code: 'SEER_MUTATION_CAPABILITY_REJECTED',
      message: 'Seer accepts frozen read-only audit inputs; source mutation capability is forbidden',
      remediation: 'Submit remediation as an artifact for a separate mutation authority',
    });
  }
  if (typeof core?.[api] !== 'function') {
    return failedPair(request, context, clock, {
      code: 'SEER_CORE_API_UNAVAILABLE',
      message: `canonical core API ${api} is unavailable through the supplied public core surface`,
      remediation: `Coordinator must expose ${api}; facade core changes are forbidden`,
    });
  }
  try {
    const output = await core[api](forwardedInput(request, context), host);
    return completedPair(request, context, output, clock, `seer.${operation}.core-output`);
  } catch (error) {
    return failedPair(request, context, clock, {
      code: 'SEER_CORE_INVOCATION_FAILED',
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
      code: 'SEER_MUTATION_CAPABILITY_REJECTED',
      message: 'Seer accepts frozen read-only audit inputs; source mutation capability is forbidden',
      remediation: 'Submit remediation as an artifact for a separate mutation authority',
    });
  }
  return completedPair(request, context, legacyReport, clock, 'seer.audit.legacy-output');
}

function completedPair(request, context, output, clock, artifactKind) {
  const completedAt = clock.now().toISOString();
  const artifact = wrapArtifact({ value: output, artifactKind, sourceRevision: request.sourceRevision, createdAt: completedAt });
  const claimBoundary = output?.claimBoundary ?? output?.report?.claimBoundary ?? output?.report?.claim_boundary ?? 'UNPROVEN';
  return Object.freeze({
    request,
    ...context,
    result: resultEnvelope(request, {
      invocationState: 'COMPLETED',
      domainOutcome: output?.domainOutcome ?? 'COMPLETE',
      claimBoundary,
      artifacts: [artifact.record.artifactId],
      warnings: Array.isArray(output?.warnings) ? [...output.warnings] : [],
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

function forwardedInput(request, context) {
  const options = request.input?.options;
  return Object.freeze({
    ...((options && typeof options === 'object' && !Array.isArray(options)) ? clone(options) : {}),
    runIdentity: context.runIdentity,
    workingContext: context.workingContext,
  });
}

function validateRequest(request, operation) {
  if (request?.schemaVersion !== 1 || request?.kind !== 'legion-operation-envelope' || request?.envelopeKind !== 'request') throw new TypeError('operation-envelope-v1 request required');
  if (request.operationId !== `seer.${operation}`) throw new TypeError(`expected seer.${operation} request`);
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
