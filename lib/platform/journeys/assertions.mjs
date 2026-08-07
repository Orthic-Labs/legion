export function evaluateInvariant(invariant, observed) {
  if (!invariant || typeof invariant !== 'object') return { status: 'unproven', reason: 'invariant-missing' };
  const actual = observed?.[invariant.path];
  if (Object.hasOwn(invariant, 'equals')) return { status: actual === invariant.equals ? 'pass' : 'fail', actual, expected: invariant.equals };
  if (Object.hasOwn(invariant, 'exists')) return { status: Boolean(actual) === invariant.exists ? 'pass' : 'fail', actual: Boolean(actual), expected: invariant.exists };
  return { status: 'unproven', reason: 'invariant-operator-unsupported' };
}
