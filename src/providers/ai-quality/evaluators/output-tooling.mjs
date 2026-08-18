// Structured-output validity and tool-selection/argument correctness.

function unproven(reason) {
  return { verdict: 'unproven', measurement: {}, limitations: [reason], uncertainty: [] };
}

function typeMatches(value, expectedType) {
  if (expectedType === 'array') return Array.isArray(value);
  if (expectedType === 'null') return value === null;
  return typeof value === expectedType;
}

export function scoreStructuredOutputValidity(fixture) {
  const output = fixture?.output;
  const requiredFields = fixture?.requiredFields;
  if (output === undefined || !Array.isArray(requiredFields) || requiredFields.length === 0) {
    return unproven('no structured-output/required-field record recorded for this run');
  }
  const violations = requiredFields
    .filter((f) => !(f.name in (output ?? {})) || !typeMatches(output[f.name], f.type))
    .map((f) => f.name);
  return {
    verdict: violations.length === 0 ? 'pass' : 'fail',
    measurement: { requiredFieldCount: requiredFields.length, violatingFields: violations },
    limitations: [],
    uncertainty: ['Shallow required-field/type checking only; nested schema constraints are not evaluated here.'],
  };
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
  return value;
}

export function scoreToolSelectionArgumentCorrectness(fixture) {
  const { expectedTool, selectedTool, expectedArgs, actualArgs } = fixture ?? {};
  if (!expectedTool || !selectedTool) return unproven('no expected/selected tool record recorded for this run');
  const toolCorrect = expectedTool === selectedTool;
  const argsCorrect = JSON.stringify(canonical(expectedArgs ?? {})) === JSON.stringify(canonical(actualArgs ?? {}));
  return {
    verdict: toolCorrect && argsCorrect ? 'pass' : 'fail',
    measurement: { expectedTool, selectedTool, toolCorrect, argsCorrect },
    limitations: [],
    uncertainty: ['Argument equality is exact-match on canonicalized JSON; semantically-equivalent-but-differently-shaped arguments are marked incorrect.'],
  };
}
