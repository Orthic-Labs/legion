import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (relativePath) => readFileSync(resolve(root, relativePath));

// The dispatch and tasklist skill bundles each vendor a byte-identical copy of the
// canonical validator engine and its GoalRoute/Minimize authorities so they resolve
// correctly from an installed plugin root that carries only that one skill (no src/,
// no repository root above it — see skills/dispatch/scripts/validate-dispatch.py:20-27).
// A vendored copy that drifts from its source is a silent, hard-to-notice defect: this
// test keeps every copy byte-identical to its canonical src/lib origin.

test('dispatch bundle engine is byte-identical to the canonical dispatch validator', () => {
  assert.deepEqual(
    read('skills/dispatch/engine/validate-dispatch.py'),
    read('src/lib/dispatch-validator/validate-dispatch.py'),
  );
});

test('tasklist bundle engine is byte-identical to the dispatch bundle engine', () => {
  assert.deepEqual(
    read('skills/tasklist/engine/validate-dispatch.py'),
    read('skills/dispatch/engine/validate-dispatch.py'),
  );
});

for (const skill of ['dispatch', 'tasklist']) {
  test(`${skill} bundle vendors a byte-identical GoalRoute authority`, () => {
    assert.deepEqual(
      read(`skills/${skill}/goalroute/scripts/validate-route.py`),
      read('src/lib/goalroute/scripts/validate-route.py'),
    );
  });

  test(`${skill} bundle vendors a byte-identical Minimize authority`, () => {
    assert.deepEqual(
      read(`skills/${skill}/minimize/minimize_gate.py`),
      read('src/lib/minimize/minimize_gate.py'),
    );
    assert.deepEqual(
      read(`skills/${skill}/minimize/POLICY.md`),
      read('src/lib/minimize/POLICY.md'),
    );
  });
}
