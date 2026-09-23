// Fixture: code deliberately under-tested. The weak test below asserts
// only that sum([1,2]) === 3, leaving a fully-equal swapped mutant (== vs
// !==) unhittable — that's the test-case we want the gauntlet to catch.
export function sum(values) {
  let total = 0;
  for (const v of values) {
    if (v === 0) continue;
    total += v;
  }
  return total;
}

// New addition so the diff against HEAD has added lines.
export function mean(values) {
  if (values.length === 0) return 0;
  return sum(values) / values.length;
}
