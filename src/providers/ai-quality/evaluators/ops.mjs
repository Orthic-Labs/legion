// Latency, cost, human override, and feedback-loop closure.

function unproven(reason) {
  return { verdict: 'unproven', measurement: {}, limitations: [reason], uncertainty: [] };
}

export function scoreLatency(fixture) {
  const { p95Ms, budgetMs } = fixture ?? {};
  if (typeof p95Ms !== 'number' || typeof budgetMs !== 'number') return unproven('no p95/budget latency record recorded for this run');
  return {
    verdict: p95Ms <= budgetMs ? 'pass' : 'fail',
    measurement: { p95Ms, budgetMs },
    limitations: [],
    uncertainty: [],
  };
}

export function scoreCost(fixture) {
  const { costUsd, budgetUsd } = fixture ?? {};
  if (typeof costUsd !== 'number' || typeof budgetUsd !== 'number') return unproven('no cost/budget record recorded for this run');
  return {
    verdict: costUsd <= budgetUsd ? 'pass' : 'fail',
    measurement: { costUsd, budgetUsd },
    limitations: [],
    uncertainty: [],
  };
}

export function scoreHumanOverride(fixture) {
  const { overrideAvailable, overrideTestedSuccessfully } = fixture ?? {};
  if (typeof overrideAvailable !== 'boolean') return unproven('no human-override-availability record recorded for this run');
  if (!overrideAvailable) return { verdict: 'fail', measurement: { overrideAvailable }, limitations: [], uncertainty: [] };
  if (typeof overrideTestedSuccessfully !== 'boolean') {
    return { verdict: 'review-required', measurement: { overrideAvailable }, limitations: ['override is declared available but was not exercised in this run'], uncertainty: [] };
  }
  return {
    verdict: overrideTestedSuccessfully ? 'pass' : 'fail',
    measurement: { overrideAvailable, overrideTestedSuccessfully },
    limitations: [],
    uncertainty: [],
  };
}

export function scoreFeedbackLoop(fixture) {
  const { feedbackCaptured, feedbackAppliedToNextEvalVersion } = fixture ?? {};
  if (typeof feedbackCaptured !== 'boolean') return unproven('no feedback-capture record recorded for this run');
  if (!feedbackCaptured) return { verdict: 'fail', measurement: { feedbackCaptured }, limitations: [], uncertainty: [] };
  return {
    verdict: feedbackAppliedToNextEvalVersion === true ? 'pass' : 'fail',
    measurement: { feedbackCaptured, feedbackAppliedToNextEvalVersion: feedbackAppliedToNextEvalVersion ?? false },
    limitations: [],
    uncertainty: [],
  };
}
