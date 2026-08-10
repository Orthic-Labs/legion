// The stop-shape gate: a turn may end only on completed work or a stated
// reserved blocker. See hooks/stop-shape.mjs for the two production failure
// modes these tests pin against (format-grinding a correctly blocked agent,
// and blocking forever).
import assert from 'node:assert/strict';
import test from 'node:test';

import { evaluateStopShape, recordedThisTurn } from '../hooks/stop-shape.mjs';

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

test('the deferral offer is caught — the exact Mac escape 2026-08-10', () => {
  const escaped = 'Next action: add export RIGHT_RELEASE_CACHE_ROOT=/Volumes/D/rightsuite-cache/release to your ~/.zshenv, or tell me to and I\'ll do it.';
  const verdict = evaluateStopShape(escaped);
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'deferral-offer');
  for (const variant of [
    'Or I can add it for you.',
    'If you want, I can wire that in.',
    'Tell me to and I\'ll do it.',
  ]) {
    assert.equal(evaluateStopShape(variant).block, true, variant);
  }
});

test('a genuine the operator-only next action still passes', () => {
  // Actions only the operator can perform must remain a legal ending.
  for (const ending of [
    'Done and verified. Next action for you: approve the $40/mo Hetzner upgrade in the console.',
    'Complete. You will need to enter the 2FA code on your phone to finish enrollment.',
  ]) {
    assert.equal(evaluateStopShape(ending).block, false, ending);
  }
});

test('a finding announced only in chat is blocked as unrecorded', () => {
  const v = evaluateStopShape('Fixed and verified. Worth noting for the pattern file: hooks are additive, so a duplicate registration denies every Write.', { recorded: false });
  assert.equal(v.block, true);
  assert.equal(v.shape, 'unrecorded-finding');
  assert.match(v.instruction, /GOTCHAS\.md/);
});

test('the same finding passes once it was written down', () => {
  const text = 'Fixed and verified. Worth noting for the pattern file: hooks are additive.';
  assert.equal(evaluateStopShape(text, { recorded: true }).block, false);
});

test('ordinary work reports do not trip the finding check', () => {
  for (const ending of [
    'Fixed the parser, 12/12 tests, committed abc123.',
    'Wired both machines and verified: 0 duplicates, exit 0.',
    'Note: the suite takes about 40 seconds.',
  ]) {
    assert.equal(evaluateStopShape(ending, { recorded: false }).block, false, ending);
  }
});

test('recordedThisTurn recognises the durable destinations', () => {
  assert.equal(recordedThisTurn('{"name":"Write","input":{"file_path":"D:/workspace/docs/GOTCHAS.md"}}'), true);
  assert.equal(recordedThisTurn('memright put arcane-key-bootstrap --scope claude'), true);
  assert.equal(recordedThisTurn('docs/plans/legion/HANDOFF.md'), true);
  assert.equal(recordedThisTurn('{"name":"Write","input":{"file_path":"src/app.mjs"}}'), false);
});
