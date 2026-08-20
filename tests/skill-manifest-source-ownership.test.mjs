import assert from 'node:assert/strict';
import test from 'node:test';

import { deriveParity } from '../scripts/refresh-local-skill-manifests.mjs';

test('generated manifest parity derives from canonical semantics & package files only', () => {
  const semantic = { description: 'Architect owns routine architecture craft directly.' };
  const parity = deriveParity('architect', semantic, ['SKILL.md', 'references/manual.md', 'evals/evals.json']);
  assert.deepEqual(parity.triggers, ['/architect', semantic.description]);
  assert.equal(parity.triggers.some((value) => /Sage Architect/.test(value)), false);
  assert.deepEqual(parity.outputs, ['references/manual.md']);
  assert.deepEqual(parity.evals, ['evals/evals.json']);
});
