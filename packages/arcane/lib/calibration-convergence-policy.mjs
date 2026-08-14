// Executable policy for runtime calibration & convergent clarification.
// Inputs are structured facts; corpus prose & `expect` values never enter here.

const freeze = (value) => Object.freeze(value);
const list = (value) => freeze([...value]);

function invalid(code, detail) {
  return freeze({ status: 'PENDING', code, detail: freeze(detail) });
}

/**
 * Runtime measurements can inform a calibration table, but cannot turn into
 * permanent doctrine merely by being observed during a retry or scheduling run.
 */
export function classifyCalibrationDrift({ measurement, publication } = {}) {
  if (!measurement || typeof measurement !== 'object' ||
      typeof measurement.metric !== 'string' || !measurement.metric ||
      !Number.isFinite(measurement.value) || measurement.value < 0 ||
      !['retry', 'concurrency'].includes(measurement.domain)) {
    return invalid('POLICY_FACTS_INCOMPLETE', { required: list(['measurement.metric', 'measurement.value', 'measurement.domain']) });
  }
  if (!publication || typeof publication !== 'object' ||
      !['CALIBRATION_TABLE', 'PERMANENT_CANON'].includes(publication.target)) {
    return invalid('POLICY_FACTS_INCOMPLETE', { required: list(['publication.target']) });
  }

  const calibration = freeze({
    metric: measurement.metric,
    value: measurement.value,
    domain: measurement.domain,
    observation_id: typeof measurement.observation_id === 'string' ? measurement.observation_id : null,
  });
  if (publication.target === 'PERMANENT_CANON') {
    return freeze({
      status: 'REJECTED',
      code: 'DRIFT_FAILURE',
      disposition: 'CALIBRATION_TABLE',
      canonical_write: false,
      calibration,
    });
  }
  return freeze({
    status: 'ACCEPTED',
    code: 'CALIBRATION_RECORDED',
    disposition: 'CALIBRATION_TABLE',
    canonical_write: false,
    calibration,
  });
}

/** Resolve only questions that block current slice; preserve all others for later. */
export function convergeClarifications({ slice_id, questions } = {}) {
  if (typeof slice_id !== 'string' || !slice_id || !Array.isArray(questions) || questions.length === 0 ||
      questions.some((question) => !question || typeof question.id !== 'string' || !question.id || typeof question.blocks_current_slice !== 'boolean')) {
    return invalid('POLICY_FACTS_INCOMPLETE', { required: list(['slice_id', 'questions[].id', 'questions[].blocks_current_slice']) });
  }
  const blockers = questions.filter((question) => question.blocks_current_slice);
  const deferred = questions.filter((question) => !question.blocks_current_slice).map((question) => question.id);
  if (blockers.length !== 1) {
    return freeze({
      status: 'PENDING',
      code: blockers.length === 0 ? 'NO_BLOCKING_QUESTION' : 'MULTIPLE_BLOCKING_QUESTIONS',
      slice_id,
      blocking_question_ids: list(blockers.map((question) => question.id)),
      deferred_question_ids: list(deferred),
    });
  }
  return freeze({
    status: 'RESOLVE_ONE',
    code: 'CURRENT_SLICE_BLOCKER',
    slice_id,
    active_question_id: blockers[0].id,
    deferred_question_ids: list(deferred),
  });
}

/** A non-falsifying improvement after freeze is retained as future work only. */
export function disposeFrozenReviewFinding({ decision, finding } = {}) {
  if (!decision || typeof decision !== 'object' || typeof decision.id !== 'string' || !decision.id ||
      !finding || typeof finding !== 'object' || typeof finding.id !== 'string' || !finding.id ||
      typeof finding.invalidates_decision !== 'boolean' ||
      !['IMPROVEMENT', 'FAILURE'].includes(finding.kind)) {
    return invalid('POLICY_FACTS_INCOMPLETE', { required: list(['decision.id', 'decision.status', 'finding.id', 'finding.kind', 'finding.invalidates_decision']) });
  }
  if (decision.status !== 'FROZEN') return invalid('DECISION_NOT_FROZEN', { decision_id: decision.id, status: decision.status ?? null });
  if (finding.invalidates_decision || finding.kind === 'FAILURE') {
    return freeze({
      status: 'REOPEN_REQUIRED',
      code: 'FAILED_FALSIFICATION',
      decision_id: decision.id,
      finding_id: finding.id,
      decision_status: 'CHALLENGED',
    });
  }
  return freeze({
    status: 'FROZEN_RETAINED',
    code: 'FUTURE_OPPORTUNITY_RECORDED',
    decision_id: decision.id,
    decision_status: 'FROZEN',
    future_opportunity: freeze({ id: finding.id, kind: finding.kind }),
  });
}

const S11_FACTS = freeze({
  'AE-CONTROL-PLANE-BUDGETS-002': freeze({
    measurement: freeze({ observation_id: 'runtime-retry-17', metric: 'retry_threshold', value: 3, domain: 'retry' }),
    publication: freeze({ target: 'PERMANENT_CANON' }),
  }),
  'AE-CONVERGENCE-001': freeze({
    slice_id: 's11-current-slice',
    questions: list([
      freeze({ id: 'q-blocker', blocks_current_slice: true }),
      freeze({ id: 'q-later-1', blocks_current_slice: false }),
      freeze({ id: 'q-later-2', blocks_current_slice: false }),
      freeze({ id: 'q-later-3', blocks_current_slice: false }),
      freeze({ id: 'q-later-4', blocks_current_slice: false }),
    ]),
  }),
  'AE-CONVERGENCE-003': freeze({
    decision: freeze({ id: 'D-3', status: 'FROZEN' }),
    finding: freeze({ id: 'review-opportunity-1', kind: 'IMPROVEMENT', invalidates_decision: false }),
  }),
});

export function calibrationConvergenceScenarioFacts(id) {
  return S11_FACTS[id] ?? null;
}

/** Executor adapter: case identity selects facts; disposition comes only from policy. */
export function evaluateCalibrationConvergenceCase(id, facts = calibrationConvergenceScenarioFacts(id)) {
  if (id === 'AE-CONTROL-PLANE-BUDGETS-002') return classifyCalibrationDrift(facts);
  if (id === 'AE-CONVERGENCE-001') return convergeClarifications(facts);
  if (id === 'AE-CONVERGENCE-003') return disposeFrozenReviewFinding(facts);
  return null;
}

export function validateCalibrationConvergenceObservation(id, value) {
  if (id === 'AE-CONTROL-PLANE-BUDGETS-002') return value?.status === 'REJECTED' && value?.code === 'DRIFT_FAILURE' && value?.disposition === 'CALIBRATION_TABLE' && value?.canonical_write === false;
  if (id === 'AE-CONVERGENCE-001') return value?.status === 'RESOLVE_ONE' && value?.code === 'CURRENT_SLICE_BLOCKER' && typeof value?.active_question_id === 'string' && value?.deferred_question_ids?.length === 4;
  if (id === 'AE-CONVERGENCE-003') return value?.status === 'FROZEN_RETAINED' && value?.code === 'FUTURE_OPPORTUNITY_RECORDED' && value?.decision_status === 'FROZEN' && typeof value?.future_opportunity?.id === 'string';
  return false;
}
