import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateRoutingCases, runLiveGraderCommand, runLiveGrading, scoreRoutingCase } from '../scripts/run-skill-evals.mjs';

const fixture = {
  id: 'routing-all-dimensions',
  skill: 'dispatch',
  category: 'should_trigger',
  expected_skill: 'dispatch',
  routing: {
    shouldRoute: true,
    firstRankedCapability: 'dispatch',
    authority: { sage: false, alchemist: false, oracle: true },
    routeMode: 'DIRECT',
    semanticRequirement: 'REQUIRED',
    contextSelection: { required: ['blueprint'], forbidden: ['cortex'] },
  },
};

const matchingObservation = {
  shouldRoute: true,
  rankedCapabilities: ['dispatch', 'tasklist'],
  authority: { sage: false, alchemist: false, oracle: true },
  routeMode: 'DIRECT',
  semanticRequirement: 'REQUIRED',
  contextSelection: ['blueprint'],
};

test('deterministic routing scorer passes every declared fixture field', () => {
  const result = scoreRoutingCase(fixture, matchingObservation);
  assert.equal(result.status, 'PASS');
  assert.deepEqual(Object.fromEntries(Object.entries(result.checks).map(([key, value]) => [key, value.status])), {
    shouldRoute: 'PASS',
    firstRankedCapability: 'PASS',
    authority: 'PASS',
    routeMode: 'PASS',
    semanticRequirement: 'PASS',
    contextSelection: 'PASS',
  });
});

test('deterministic routing scorer identifies a failure in each declared field', () => {
  const mutations = {
    shouldRoute: { shouldRoute: false },
    firstRankedCapability: { rankedCapabilities: ['architect'] },
    authority: { authority: { sage: true, alchemist: false, oracle: true } },
    routeMode: { routeMode: 'MACHINERY' },
    semanticRequirement: { semanticRequirement: 'FORBIDDEN' },
    contextSelection: { contextSelection: ['ledger'] },
  };

  for (const [field, mutation] of Object.entries(mutations)) {
    const result = scoreRoutingCase(fixture, { ...matchingObservation, ...mutation });
    assert.equal(result.checks[field].status, 'FAIL', field);
    assert.equal(result.status, 'FAIL', field);
    for (const [otherField, check] of Object.entries(result.checks)) {
      if (otherField !== field) assert.equal(check.status, 'PASS', `${field} changed ${otherField}`);
    }
  }
});

test('should-NOT-route fixtures reject a route to their own capability', () => {
  const negative = {
    id: 'dispatch-negative',
    skill: 'dispatch',
    category: 'should_not_trigger',
    expected_skill: null,
  };
  const noRoute = scoreRoutingCase(negative, { rankedCapabilities: [] });
  assert.equal(noRoute.checks.shouldRoute.status, 'PASS');
  assert.equal(noRoute.checks.firstRankedCapability.status, 'PASS');

  const wronglyRouted = scoreRoutingCase(negative, { rankedCapabilities: ['dispatch'] });
  assert.equal(wronglyRouted.checks.shouldRoute.status, 'FAIL');
  assert.equal(wronglyRouted.checks.firstRankedCapability.status, 'FAIL');
  assert.equal(wronglyRouted.status, 'FAIL');

  const alternateRoute = {
    ...negative,
    expected_skill: 'architect',
  };
  const correctAlternate = scoreRoutingCase(alternateRoute, { rankedCapabilities: ['architect'] });
  assert.equal(correctAlternate.checks.shouldRoute.status, 'PASS');
  assert.equal(correctAlternate.checks.firstRankedCapability.status, 'PASS');
});

test('live grading fails loudly when explicitly requested without a grader', async () => {
  await assert.rejects(() => runLiveGrading([fixture]), (error) => error.code === 'LIVE_GRADER_UNAVAILABLE');
});

test('live grader rejects observations that omit route mode or context selection', async () => {
  await assert.rejects(
    () => runLiveGrading([fixture], async () => ({
      shouldRoute: true,
      rankedCapabilities: ['dispatch'],
      authority: { sage: false, alchemist: false, oracle: true },
      semanticRequirement: 'REQUIRED',
    })),
    (error) => error.code === 'LIVE_GRADER_INVALID_OBSERVATION'
      && error.message.includes('routeMode')
      && error.message.includes('contextSelection'),
  );
});

test('external live grader command receives opaque prompts and scores all six dimensions', async () => {
  const grader = String.raw`
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => input += chunk);
    process.stdin.on('end', () => {
      const batch = JSON.parse(input);
      if (batch.cases.some(entry => 'skill' in entry || 'expected_skill' in entry || 'routing' in entry)) process.exit(9);
      process.stdout.write(JSON.stringify({ observations: batch.cases.map(({ caseId }) => ({
        caseId,
        shouldRoute: true,
        rankedCapabilities: ['dispatch', 'tasklist'],
        authority: { sage: false, alchemist: false, oracle: true },
        routeMode: 'DIRECT',
        semanticRequirement: 'REQUIRED',
        contextSelection: ['blueprint'],
      })) }));
    });
  `;
  const results = await runLiveGraderCommand([fixture], {
    command: process.execPath,
    args: ['-e', grader],
    repositoryRoot: new URL('..', import.meta.url).pathname.replace(/^\/(?=[A-Za-z]:)/, ''),
    timeoutMs: 10_000,
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].status, 'PASS');
  assert.deepEqual(Object.values(results[0].checks).map(({ status }) => status), Array(6).fill('PASS'));
});

test('live grading is unreachable unless the caller explicitly opts in', async () => {
  let graderCalls = 0;
  const results = await evaluateRoutingCases([fixture], {
    grader: async () => {
      graderCalls += 1;
      return matchingObservation;
    },
  });
  assert.equal(graderCalls, 0);
  assert.equal(results[0].status, 'FAIL', 'missing observations must not silently pass');
});
