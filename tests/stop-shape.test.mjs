// The stop-shape gate: a turn may end only on completed work or a stated
// reserved blocker. See hooks/stop-shape.mjs for the two production failure
// modes these tests pin against (format-grinding a correctly blocked agent,
// and blocking forever).
import assert from 'node:assert/strict';
import test from 'node:test';

import { evaluateStopShape } from '../hooks/stop-shape.mjs';

test('permission questions block', () => {
  for (const ending of [
    'Done mostly. Say go and I execute.',
    'Shall I proceed with the fix?',
    'Do you want me to wire it in?',
    'Awaiting your approval to continue.',
  ]) {
    assert.equal(evaluateStopShape(ending).block, true, ending);
  }
});

test('caveats and deferred promises block', () => {
  assert.equal(evaluateStopShape('Fixed. One caveat: the cache is stale.').block, true);
  assert.equal(evaluateStopShape("Tests green. I'll fix that later.").block, true);
  assert.equal(evaluateStopShape('Works, but the retry path remains to be built.').block, true);
});

test('completed work passes', () => {
  assert.equal(evaluateStopShape('Fixed the parser, 12/12 tests, committed abc123.').block, false);
});

test('a reserved blocker is a legal terminal state in ANY format', () => {
  // Format-grinding regression (Codex final-gate, 2026-08-10): ten valid
  // packets rejected over layout. Every one of these must pass.
  for (const ending of [
    'Deploy staged. HARD BLOCKER: the Cloudflare token only the operator can supply.',
    'BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication/production mutation)',
    'blocked-on-approval: new spend — the Hetzner upgrade needs your card',
    'Work verified.\nBLOCKED-ON-APPROVAL\n  category: destruction\n  action: drop the legacy table',
    'BLOCKED-ON-APPROVAL:\n{\n  "reserved_category": "reserved_decision"\n}',
  ]) {
    assert.equal(evaluateStopShape(ending).block, false, ending);
  }
});

test('a caveat resolved mid-turn does not block a clean ending', () => {
  const text = `${'One caveat existed here early on. '.padEnd(1300, 'x ')}\nAll of it is now fixed and verified, 44/44.`;
  assert.equal(evaluateStopShape(text).block, false);
});

test('block instructions escalate across pushes instead of repeating', () => {
  const first = evaluateStopShape('Say go and I execute.', { pushes: 0 });
  const second = evaluateStopShape('Say go and I execute.', { pushes: 1 });
  assert.equal(first.block, true);
  assert.equal(second.block, true);
  assert.notEqual(first.instruction, second.instruction);
  assert.match(first.instruction, /Sage/);
  assert.match(second.instruction, /Covenant/);
  assert.match(second.instruction, /CURRENT state/);
});

test('the push cap ends the loop rather than winning by attrition', () => {
  assert.equal(evaluateStopShape('Say go and I execute.', { pushes: 1 }).block, true);
  assert.equal(evaluateStopShape('Say go and I execute.', { pushes: 2 }).block, false);
});
