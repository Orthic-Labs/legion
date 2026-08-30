// The stop-shape gate: a turn may end only on completed work or a stated
// reserved blocker. See src/lib/cognitive/arcane/stop-shape.mjs for the two production failure
// modes these tests pin against (format-grinding a correctly blocked agent,
// and blocking forever).
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  continueIntent,
  escalatedThisSession,
  evaluateStopShape,
  isPushGateLaundering,
  recordedThisTurn,
  reservedCategories,
  scopeCutMatch,
  toolDenialMatch,
  toolUseAfterLastUser,
  workLeftStuck,
} from '../src/lib/cognitive/arcane/stop-shape.mjs';

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
  // `escalated` is set because the ladder is a SUBSTANTIVE precondition,
  // orthogonal to layout — this test pins that format is never judged.
  for (const ending of [
    'Deploy staged. HARD BLOCKER: the Cloudflare token only the operator can supply.',
    'BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication/production mutation)',
    'blocked-on-approval: new spend — the Hetzner upgrade needs your card',
    'Work verified.\nBLOCKED-ON-APPROVAL\n  category: destruction\n  action: drop the legacy table',
    'BLOCKED-ON-APPROVAL:\n{\n  "reserved_category": "reserved_decision"\n}',
  ]) {
    assert.equal(evaluateStopShape(ending, { escalated: true }).block, false, ending);
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
  assert.doesNotMatch(second.instruction, /Covenant/);
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

function transcriptAfterUser(...blocks) {
  return [
    JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'record it' }] } }),
    ...blocks.map((block) => JSON.stringify(block)),
  ].join('\n');
}

test('recordedThisTurn requires a paired successful durable write after the latest user turn', () => {
  const write = { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'w1', name: 'Write', input: { file_path: 'D:/workspace/docs/GOTCHAS.md' } }] } };
  const ok = { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'w1', content: 'ok' }] } };
  const failed = { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'w1', is_error: true, content: 'failed' }] } };
  assert.equal(recordedThisTurn(transcriptAfterUser(write, ok)), true);
  assert.equal(recordedThisTurn(transcriptAfterUser(write)), false, 'an attempted write is not a receipt');
  assert.equal(recordedThisTurn(transcriptAfterUser(write, failed)), false);
  assert.equal(recordedThisTurn(transcriptAfterUser({ type: 'assistant', message: { content: [{ type: 'tool_use', id: 'r1', name: 'Read', input: { file_path: 'D:/workspace/docs/GOTCHAS.md' } }] } }, { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'r1' }] } })), false);
  assert.equal(recordedThisTurn(transcriptAfterUser({ type: 'assistant', message: { content: [{ type: 'text', text: 'docs/plans/legion/HANDOFF.md' }] } })), false);
});

test('recordedThisTurn accepts successful apply_patch & crypt writes only', () => {
  const patchUse = { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'p1', name: 'apply_patch', input: '*** Update File: docs/GOTCHAS.md' }] } };
  const patchResult = { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'p1' }] } };
  assert.equal(recordedThisTurn(transcriptAfterUser(patchUse, patchResult)), true);
  const memoryUse = { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'm1', name: 'Bash', input: { command: 'crypt put hook-lesson --scope claude' } }] } };
  const memoryResult = { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'm1' }] } };
  assert.equal(recordedThisTurn(transcriptAfterUser(memoryUse, memoryResult)), true);
  const retiredUse = { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'm2', name: 'Bash', input: { command: 'memright put hook-lesson --scope claude' } }] } };
  const retiredResult = { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'm2' }] } };
  assert.equal(recordedThisTurn(transcriptAfterUser(retiredUse, retiredResult)), false);
});

test('Codex response_item calls prove successful durable writes only', () => {
  const user = JSON.stringify({ type: 'response_item', payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'record it' }] } });
  const call = JSON.stringify({ type: 'response_item', payload: { type: 'custom_tool_call', call_id: 'c1', name: 'exec', input: 'text(await tools.apply_patch("*** Update File: D:/workspace/docs/GOTCHAS.md"));' } });
  const ok = JSON.stringify({ type: 'response_item', payload: { type: 'custom_tool_call_output', call_id: 'c1', output: [{ type: 'input_text', text: 'Script completed\\nOutput: {}' }] } });
  const failed = JSON.stringify({ type: 'response_item', payload: { type: 'custom_tool_call_output', call_id: 'c1', output: [{ type: 'input_text', text: 'Script failed\\nExit code: 1' }] } });
  assert.equal(recordedThisTurn([user, call, ok].join('\n')), true);
  assert.equal(recordedThisTurn([user, call, failed].join('\n')), false);
  assert.equal(toolUseAfterLastUser([user, call].join('\n')), true);
});

test('recordedThisTurn ignores durable writes from an earlier user turn', () => {
  const earlier = transcriptAfterUser(
    { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'w1', name: 'Write', input: { file_path: 'docs/GOTCHAS.md' } }] } },
    { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'w1' }] } },
  );
  const latest = JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'new question' }] } });
  assert.equal(recordedThisTurn(`${earlier}\n${latest}`), false);
});

test('an open circuit makes missing durability advisory instead of blocking again', () => {
  const verdict = evaluateStopShape('Fixed it. Worth noting for future reference: rename scans can explode.', { pushes: 2, recorded: false });
  assert.equal(verdict.block, false);
  assert.equal(verdict.reason, 'stop-circuit-open');
  assert.match(verdict.advisory, /no successful post-user write/i);
});

// Deferred-defect shape. The incident: a turn found sampleapp's committed
// AGENTS.md was stale doctrine and handed it back as "worth flagging for later
// / a separate cleanup whenever you want it" instead of fixing it. This table is
// the single source of stop-policy content; the rhook and Codex lanes carry a
// generated copy, so these cases pin all three.
test('deferring a found defect blocks', () => {
  for (const ending of [
    "Worth flagging for later: sampleapp's committed AGENTS.md is still stale doctrine on origin. That's a separate cleanup whenever you want it.",
    "I'll leave that for a follow-up.",
    'Someone should clean this up eventually.',
    'Out of scope for now, but note that the retry logic is flaky.',
    'TODO: fix later.',
    'Note for later: the cache eviction logic looks fragile.',
    'The duplicate config is worth doing at some point.',
  ]) {
    const verdict = evaluateStopShape(ending);
    assert.equal(verdict.block, true, ending);
    assert.equal(verdict.shape, 'deferred-defect', ending);
  }
});

test('legitimate deferral passes', () => {
  for (const ending of [
    'Worth flagging: the stale AGENTS.md — another agent is already working on that cleanup.',
    'Worth mentioning: the key rotation is overdue, but it needs your credentials to proceed.',
    'Worth mentioning: the broken link — already fixed it while I was in there.',
    "Worth flagging: sampleapp's AGENTS.md is stale — filed as a background task via spawn_task.",
    'Deploying the binary is a separate cleanup, and it is OPERATOR-ONLY per HANDOFF.',
  ]) {
    assert.equal(evaluateStopShape(ending).block, false, ending);
  }
});

test('carve-outs are paragraph-scoped, not whole-message', () => {
  const laundered = [
    'Fixed the parser and already fixed the lint config too.',
    '',
    "Worth flagging for later: the release lane still double-signs. That's a separate cleanup.",
  ].join('\n');
  assert.equal(evaluateStopShape(laundered).block, true, 'an unrelated carve-out must not launder a real deferral');
});

test('the override tag is honoured', () => {
  const text = 'Worth flagging for later: this is a separate cleanup. [deferred-ok: the operator owns this call]';
  assert.equal(evaluateStopShape(text).block, false);
});

test('a reserved blocker still wins over a deferral marker', () => {
  // The blocker must name a REAL category to win. "reserved to the operator per
  // <doc>" is not a sixth category — that laundering is pinned separately.
  const text = 'Worth flagging for later: the deploy is a separate cleanup.\n\nBLOCKED-ON-APPROVAL: publishing @rightkit/ax@0.1.1 (publication).';
  assert.equal(evaluateStopShape(text, { escalated: true }).block, false);
});

test('the push cap releases a deferral block too', () => {
  const text = "Worth flagging for later: that's a separate cleanup.";
  assert.equal(evaluateStopShape(text, { pushes: 2 }).block, false);
});

test('an invented reserved category does not launder a stop-short', () => {
  // Verbatim shape both agents used on 2026-08-10 while nothing was blocked.
  const v = evaluateStopShape('BLOCKED-ON-APPROVAL: installing ~/.claude/bin/rhook.exe for the fast-path twin — reserved to the operator per HANDOFF.');
  assert.equal(v.block, true);
  assert.equal(v.shape, 'unreserved-blocker');
  assert.match(v.instruction, /five/i);
});

test('genuine reserved categories still pass', () => {
  // Escalated: this test pins CATEGORY validity, not the ladder.
  for (const ending of [
    'BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication)',
    'BLOCKED-ON-APPROVAL: the Hetzner upgrade is new spend on your card',
    'BLOCKED-ON-APPROVAL: destruction — drop the legacy table',
    'BLOCKED-ON-APPROVAL: reserved decision — who may change the enforcement rules',
    'BLOCKED-ON-APPROVAL: needs your 2FA code (private input)',
    'HARD BLOCKER: the Cloudflare token only the operator can supply.',
  ]) {
    assert.equal(evaluateStopShape(ending, { escalated: true }).block, false, ending);
  }
});

test('reservedCategories identifies the canonical five', () => {
  assert.deepEqual(reservedCategories('this needs new spend of $40'), ['new-spend']);
  assert.deepEqual(reservedCategories('per HANDOFF this is reserved to the operator'), []);
});

// Naming a real category is necessary but not sufficient. The regression this
// pins: a packet claimed "reserved decision" for a question committed doctrine
// had already answered, matched the category word, and passed — twice in one
// session. The token was an unconditional exit, so emitting it was cheaper than
// working. Materially unresolved reserved decisions belong to Sage, so a
// blocker must show that authority was actually used.
test('a blocker with a real category but no escalation blocks', () => {
  const packet = 'BLOCKED-ON-APPROVAL: flipping VCS_PUSH from deny to allow — reserved decision, it changes what the enforcement plane permits globally.';
  const verdict = evaluateStopShape(packet, { escalated: false });
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'unescalated-blocker');
});

test('the same blocker passes once Sage was actually dispatched', () => {
  const packet = 'BLOCKED-ON-APPROVAL: flipping VCS_PUSH from deny to allow — reserved decision, it changes what the enforcement plane permits globally.';
  assert.equal(evaluateStopShape(packet, { escalated: true }).block, false);
});

test('HARD BLOCKER never requires escalation — a missing input cannot be escalated around', () => {
  const packet = 'HARD BLOCKER: the Azure signing profile name, which is not in any config I can read.';
  assert.equal(evaluateStopShape(packet, { escalated: false }).block, false);
});

test('an invented category still blocks even with escalation', () => {
  const packet = 'BLOCKED-ON-APPROVAL: deploying the binary — reserved to the operator per HANDOFF.';
  const verdict = evaluateStopShape(packet, { escalated: true });
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'unreserved-blocker');
});

test('escalation evidence comes from real dispatches, not prose claims', () => {
  assert.equal(escalatedThisSession('I considered dispatching Sage about this.'), false);
  assert.equal(escalatedThisSession('{"subagent_type":"sage","prompt":"..."}'), true);
  assert.equal(escalatedThisSession('{"subagent_type":"legion:covenant-seat"}'), false);
});

// The incident this closes: the operator said "Go on, fix it", and the turn still
// ended with BLOCKED-ON-APPROVAL asking him to choose a scope. The approval was
// in the transcript; nothing mechanical could read it, so it became a question.
test('a blocker is refused when the operator already said proceed', () => {
  const packet = 'BLOCKED-ON-APPROVAL: flipping VCS_PUSH to allow — reserved decision.';
  const verdict = evaluateStopShape(packet, { escalated: true, authorized: true, authorizedEvidence: 'Go on, fix it.' });
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'already-authorized');
  assert.match(verdict.instruction, /Go on, fix it/);
});

test('HARD BLOCKER outranks an authorization — a missing input is still missing', () => {
  const packet = 'HARD BLOCKER: the Cloudflare token only the operator can supply.';
  assert.equal(evaluateStopShape(packet, { authorized: true }).block, false);
});

test('without an authorization the ordinary blocker rules still apply', () => {
  const packet = 'BLOCKED-ON-APPROVAL: destruction — drop the legacy table.';
  assert.equal(evaluateStopShape(packet, { escalated: true, authorized: false }).block, false);
});

// AC-3 completion: the five selftest cases Oracle found unported, recovered
// from the retired enforce_work_left_guard.py.
test('the recovered closing-caveat selftest cases block after a done-claim', () => {
  for (const ending of [
    'All 9 repos pushed and verified. One thing that isn\'t in git: the runtime DB, because it is not a repository.',
    'The fix is in and green. That said, the hook is only pattern matching.',
    'Shipped. Keep in mind the Mac picks this up on next pull.',
  ]) {
    assert.equal(evaluateStopShape(ending, {}).block, true, ending);
  }
});

test('the recovered deferral-offer selftest cases block', () => {
  for (const ending of [
    'Let me know and I\'ll rebuild it.',
    'I can trace it if you want.',
  ]) {
    assert.equal(evaluateStopShape(ending, {}).block, true, ending);
  }
});

test('a closing-caveat phrase without a done-claim does not block', () => {
  // The Python guard required a completion claim; keeping that precondition is
  // what stops "keep in mind" in an ordinary answer from tripping the gate.
  const ending = 'The tradeoff differs per repo. Keep in mind pnpm resolves peers differently.';
  assert.equal(evaluateStopShape(ending, {}).block, false);
});

// The documentation-quote exemption (strip_code_spans in the Python guard):
// a turn REPORTING on the gate's own trigger phrases is not committing them.
test('quoted or fenced trigger phrases do not block the turn', () => {
  for (const ending of [
    'Triggers now include `shall I proceed`, `awaiting your approval`, `say go`.',
    'The hook blocks `say the word and I\'ll trace it`; verified and synced.',
    'Verified both ways: a plain "Shall I proceed with the commit?" still blocks, while the documented form passes.',
    'The guard now catches "do you want me to continue" as well; all suites pass.',
  ]) {
    assert.equal(evaluateStopShape(ending, {}).block, false, ending);
  }
});

test('the same trigger phrase unquoted still blocks', () => {
  assert.equal(evaluateStopShape('Everything is staged. Shall I proceed with the commit?', {}).block, true);
});

// D-1: push-gate-laundering (2026-07-26 incident fix). An ordinary git push
// must not satisfy destruction/publication merely by using "irreversible".
test('an ordinary git push worded as reserved is not a reserved blocker', () => {
  const packet = 'BLOCKED-ON-APPROVAL:\nGate: git push origin main in membrane (3 commits)\n'
    + 'Reserved-reason: pushing publishes to Orthic-Labs/Membrane; outward-facing and irreversible-in-effect\n'
    + 'Done: 4 commits made and verified locally\nRemaining: push both repos\nNo-ungated-work: true';
  const verdict = evaluateStopShape(packet, { escalated: true });
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'unreserved-blocker');
  assert.equal(isPushGateLaundering(packet), true);
});

test('a real publication is not laundered away by the ordinary-push exemption', () => {
  // "push" and "publish" co-occur here, but the reserved act is distribution.
  for (const gate of [
    'Gate: npm publish @rightkit/git 0.2.0, then push the tag to origin',
    'Gate: pushing the release upload to the npm registry',
    'Gate: push to origin and deploy to production',
  ]) {
    assert.equal(isPushGateLaundering(`BLOCKED-ON-APPROVAL:\n${gate}`), false, gate);
  }
});

test('a force-push history rewrite stays genuinely reserved', () => {
  const packet = 'BLOCKED-ON-APPROVAL:\nGate: git push --force to rewrite shared main history\n'
    + 'Reserved-reason: destructive history rewrite on a shared branch\n'
    + 'Done: local branch rebased and tested\nRemaining: the force push only\nNo-ungated-work: true';
  assert.equal(isPushGateLaundering(packet), false);
  assert.equal(evaluateStopShape(packet, { escalated: true }).block, false);
});

test('an authorized push-gate-laundering packet still clears via already-authorized', () => {
  const packet = 'BLOCKED-ON-APPROVAL: git push origin main — irreversible-in-effect publication.';
  const verdict = evaluateStopShape(packet, { authorized: true, authorizedEvidence: 'push it' });
  assert.equal(verdict.block, true);
  assert.equal(verdict.shape, 'already-authorized');
});

// D-2: CAVEAT_LEGITIMATE_PATTERNS carve-out on unresolved-caveat.
test('a caveat reporting a real failure or hard blocker is not a hedge', () => {
  for (const ending of [
    'One caveat: the integration tests are failing on main.',
    'One caveat: I hit an error connecting to the staging DB.',
    'One caveat: this needs your input before I can continue — HARD BLOCKER.',
  ]) {
    assert.equal(evaluateStopShape(ending).block, false, ending);
  }
});

test('an ordinary hedge caveat still blocks', () => {
  const v = evaluateStopShape('Fixed. One caveat: the cache is stale.');
  assert.equal(v.block, true);
  assert.equal(v.shape, 'unresolved-caveat');
});

// D-3: work-left-stuck, generic patterns only — GPU/clips/checkpoint jargon
// deliberately dropped (media-pipeline vocabulary, not this workspace's).
test('generic stuck/queued/pending work with no corrective action blocks', () => {
  for (const ending of [
    'The render is still queued and not running.',
    'The job is stuck; remaining: 12 items.',
    "I have not found the script that produces the export. That's the next thing to pin down.",
  ]) {
    const v = evaluateStopShape(ending);
    assert.equal(v.block, true, ending);
    assert.equal(v.shape, 'work-left-stuck', ending);
  }
});

test('work-left-stuck language with a done-negation or action-taken carve-out passes', () => {
  for (const ending of [
    'All done, nothing pending.',
    'Everything is complete; nothing left to do.',
    'I restarted the workers; verified now running.',
    'Blocked because credentials are missing; ran /review-self.',
  ]) {
    assert.equal(evaluateStopShape(ending).block, false, ending);
  }
});

test('workLeftStuck is a pure function usable directly', () => {
  assert.equal(workLeftStuck('The render is still queued and not running.'), true);
  assert.equal(workLeftStuck('gstack is a third-party skill bundle.'), false);
  assert.equal(workLeftStuck('All done, nothing pending.'), false);
});

// D-4: TOOL_DENIAL_PATTERNS, now enforced rather than an inert advisory.
test('claiming a tool is missing without verifying it blocks', () => {
  const v = evaluateStopShape("I don't have webfetch in this session, so I can't check the URL.");
  assert.equal(v.block, true);
  assert.equal(v.shape, 'tool-denial');
  assert.match(toolDenialMatch("I don't have web search."), /don'?t have/i);
});

// D-5: scope-cut-after-explicit-directive, reusing recentUserInstructions()
// and explicitDirective(). Only fires when the operator's own recent words carried
// the no-deferral directive — never on the phrase alone.
test('a scope cut after an explicit no-deferral directive blocks', () => {
  const v = evaluateStopShape('Given the time, I will drop the legacy models and ship 5 of 8 tonight.', {
    explicitDirectiveEvidence: ['no deferring, do all 8'],
  });
  assert.equal(v.block, true);
  assert.equal(v.shape, 'scope-cut');
  assert.match(v.instruction, /no deferring, do all 8/);
});

test('the same scope-cut language without an explicit directive does not trip D-5', () => {
  const v = evaluateStopShape('Given the time, I will drop the legacy models and ship 5 of 8 tonight.');
  assert.notEqual(v.shape, 'scope-cut');
});

test('scopeCutMatch is a pure function usable directly', () => {
  assert.match(scopeCutMatch('I will drop the models.'), /drop/);
  assert.equal(scopeCutMatch('Nothing scope-related here.'), null);
});

// Continue-intent (from the retired enforce_continue_intent.py). Its three
// selftest cases, ported: a question-phrased correction answered with a
// proposal blocks; acting first passes; a plain question answered passes.
test('a question-phrased correction answered with only a proposal blocks', () => {
  const evidence = continueIntent("Can't we make this a hook and include it in brief?");
  assert.ok(evidence);
  const v = evaluateStopShape('Yes, we can do that. I would add a Stop hook.', {
    continueIntentEvidence: evidence,
    continueToolsUsed: false,
  });
  assert.equal(v.block, true);
  assert.equal(v.shape, 'continue-intent');
});

test('acting on the correction passes', () => {
  const v = evaluateStopShape('I added the hook and verified it.', {
    continueIntentEvidence: continueIntent("Can't we make this a hook?"),
    continueToolsUsed: true,
  });
  assert.equal(v.block, false);
});

test('a plain informational question carries no continuation intent', () => {
  assert.equal(continueIntent('What is gstack?'), null);
});

test('tool use clears it unless the ending still hands the work back', () => {
  const opts = { continueIntentEvidence: continueIntent('why is the old hook still there?') };
  assert.equal(evaluateStopShape('Removed the stale registration; receipts attached.', { ...opts, continueToolsUsed: true }).block, false);
  const v = evaluateStopShape('I looked into it. I can remove the old registration next.', { ...opts, continueToolsUsed: true });
  assert.equal(v.block, true, 'acting and then handing back is the same stop-short');
});

test('a hard blocker clears continue-intent', () => {
  // The prose form "blocked because ..." is itself a stop-short (work-left-stuck
  // catches it, correctly — a real blocker carries the token). The sanctioned
  // form must pass even when the user turn carried continuation intent.
  const v = evaluateStopShape('HARD BLOCKER: rotating the signing key needs your 2FA code.', {
    continueIntentEvidence: continueIntent('can you fix the signing setup?'),
    continueToolsUsed: false,
  });
  assert.equal(v.block, false);
});

test('toolUseAfterLastUser reads the transcript shape correctly', () => {
  const lines = [
    JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'fix it' }] } }),
    JSON.stringify({ type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Edit' }] } }),
  ].join('\n');
  assert.equal(toolUseAfterLastUser(lines), true);
  const noTools = JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'fix it' }] } });
  assert.equal(toolUseAfterLastUser(noTools), false);
});

test('EC-503 non-compelling latest intent permits receipt-free plan & question terminals', () => {
  for (const intent of ['PLAN', 'QUESTION', 'REVOKE', 'SCOPE_NARROW', 'UNKNOWN']) {
    assert.equal(evaluateStopShape('Plan is ready; implementation remains pending. Say go to execute.', { intent }).block, false, intent);
  }
});

test('EC-503 paused host goal cannot turn an answered user question into a completion claim', () => {
  const answer = [
    'Microsoft login was for Azure Artifact Signing, not Windows access.',
    'No Microsoft login completed, no Windows binary was signed, & no artifact was uploaded.',
  ].join('\n');
  assert.equal(evaluateStopShape(answer, {
    intent: 'QUESTION',
    hostGoal: { status: 'paused' },
    hookFeedback: '[codex-final-gate] An active goal is not complete or closed.',
  }).block, false);
});

test('EC-503 execute & continue retain anti-stall enforcement', () => {
  assert.equal(evaluateStopShape('Implementation is ready. Say go and I execute.', { intent: 'EXECUTE' }).block, true);
  assert.equal(evaluateStopShape('Yes, we can do that. I would add a Stop hook.', {
    intent: 'CONTINUE', continueIntentEvidence: 'Can you fix the hook?', continueToolsUsed: false,
  }).block, true);
});
