#!/usr/bin/env node
// Legion stop-shape gate — deterministic "no stopping short" enforcement.
//
// Doctrine (docs/agent-rules/legion.md): a turn may end in exactly two states —
// the requested work is complete and verified, or a reserved blocker names the
// exact missing input only Adrian can supply. Ending with a permission question
// ("say go", "shall I"), an unresolved caveat, or a promise of future work is a
// stop-short: the agent should have resolved it (itself → Sage → Covenant →
// best judgement) before ending the turn.
//
// Two failure modes this gate must never have, both observed in production:
//
//   1. Grinding a CORRECTLY blocked agent. Codex's final-gate (2026-08-10)
//      rejected ten consecutive valid BLOCKED-ON-APPROVAL packets over packet
//      FORMAT, producing zero progress. Therefore the terminal-state match here
//      is deliberately loose: any line carrying the token and some substance
//      passes. There is no canonical layout to get wrong, and the block message
//      says so explicitly.
//   2. Blocking forever. An unconditional Stop blocker (this workspace, same
//      day) made every turn unendable. Therefore pushes are counted per
//      (session, workspace) and capped: after MAX_PUSHES the gate allows the
//      Stop regardless, degrading to today's behaviour rather than looping.
//
// Fail-open on missing evidence: if the transcript is unreadable or the final
// message cannot be located (e.g. a harness whose Stop payload shape is
// unverified), the gate allows. Blocking blind is the theatre this system
// exists to remove.

import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';

const MAX_PUSHES = 2;

// The legal blocked endings, matched LOOSELY on purpose (see failure mode 1):
//   HARD BLOCKER: <exact missing input only Adrian can supply>
//   BLOCKED-ON-APPROVAL: <what + reserved category: private input, new spend,
//     publication/production mutation, destruction, reserved decision>
// Content may follow on the same line or the next one; both pass.
const HARD_BLOCKER = /\b(?:HARD BLOCKER|BLOCKED-ON-APPROVAL)\b\s*:?\s*(?:\S|(?:\r?\n\s*)+\S)/i;

// Stop-short shapes. Deliberately narrow: a false block burns a turn, while a
// miss is bounded by the next turn's gate. Each names the failure it catches so
// the block reason can instruct precisely rather than generically.
const SHAPES = [
  {
    name: 'permission-question',
    instruction: 'Adrian pre-authorized in-scope reversible work; do it now instead of asking.',
    pattern: /\b(say (the word|go|yes)|shall i|want me to (proceed|continue|do|build|fix|run)|should i (proceed|continue|go ahead)|do you want me to|awaiting (your )?(approval|confirmation|go)|give me the go)\b/i,
  },
  {
    name: 'unresolved-caveat',
    instruction: 'Resolve the caveat yourself rather than reporting it.',
    pattern: /\b(one caveat|a caveat|with the caveat|caveats?:)\b/i,
  },
  {
    name: 'deferred-work-promise',
    instruction: 'Do the promised work now — a promise of future work is not a completed turn.',
    pattern: /\b(i('| wi)ll (do|fix|build|wire|handle|address) (this|that|it) (later|next|in a follow-?up)|left as a follow-?up|remains? to be (done|built|fixed))\b/i,
  },
  {
    name: 'approval-blocked',
    instruction: 'Approval for reversible in-scope work is pre-granted by doctrine. Only private input, new spend, publication/production mutation, destruction, or a reserved decision needs Adrian — name which one applies, or continue.',
    pattern: /\bblocked on (your )?(approval|a decision|sign-?off|confirmation)\b/i,
  },
];

// The escalation ladder (doctrine: resolve → Sage → Covenant → best call →
// stop). Each push instructs the NEXT rung and never repeats the last one: a
// gate that repeats itself teaches reformatting, not progress.
const ESCALATION = [
  'Resolve it yourself now; if it needs an engineering decision, dispatch Sage.',
  'Sage did not settle it: convene Covenant, or make the best decision yourself and record the reasoning. Re-verify the blocker against CURRENT state before re-asserting it — a blocker observed earlier in a session is often already stale.',
];

function lastAssistantText(transcriptPath) {
  const lines = readFileSync(transcriptPath, 'utf8').split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    let entry;
    try { entry = JSON.parse(lines[i]); } catch { continue; }
    const message = entry?.message;
    if (entry?.type !== 'assistant' || !message) continue;
    const content = Array.isArray(message.content) ? message.content : [];
    const text = content
      .filter((block) => block?.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text)
      .join('\n');
    if (text.length > 0) return text;
  }
  return null;
}

function pushCount(stateFile) {
  try { return JSON.parse(readFileSync(stateFile, 'utf8')).pushes ?? 0; } catch { return 0; }
}

export function evaluateStopShape(finalText, { pushes = 0 } = {}) {
  if (typeof finalText !== 'string' || finalText.length === 0) return { block: false, reason: 'no-final-text' };
  if (pushes >= MAX_PUSHES) return { block: false, reason: 'push-cap' };
  if (HARD_BLOCKER.test(finalText)) return { block: false, reason: 'reserved-blocker-stated' };
  // Judge the ENDING, not the whole turn: a caveat raised mid-report and then
  // resolved must not block. Take the last ~1200 characters.
  const tail = finalText.slice(-1200);
  for (const shape of SHAPES) {
    if (shape.pattern.test(tail)) {
      return {
        block: true,
        shape: shape.name,
        instruction: `${shape.instruction} ${ESCALATION[Math.min(pushes, ESCALATION.length - 1)]}`,
      };
    }
  }
  return { block: false, reason: 'clean-ending' };
}

function main() {
  let payload;
  try { payload = JSON.parse(readFileSync(0, 'utf8')); } catch { return; }
  if (payload?.hook_event_name !== 'Stop') return;

  const transcriptPath = payload.transcript_path;
  const sessionId = payload.session_id ?? 'unknown';
  const cwd = payload.cwd ?? process.cwd();
  if (typeof transcriptPath !== 'string' || transcriptPath.length === 0) return; // unverified harness shape -> fail open

  let finalText = null;
  try { finalText = lastAssistantText(transcriptPath); } catch { return; } // unreadable transcript -> fail open

  const stateFile = join(cwd, '.audit', 'legion', 'stop-shape', `${sessionId}.json`);
  const pushes = payload.stop_hook_active ? pushCount(stateFile) : 0;

  const verdict = evaluateStopShape(finalText, { pushes });
  if (!verdict.block) return;

  try {
    mkdirSync(dirname(stateFile), { recursive: true });
    writeFileSync(stateFile, `${JSON.stringify({ pushes: pushes + 1, lastShape: verdict.shape, at: new Date().toISOString() })}\n`);
  } catch { /* state loss weakens the cap by one turn; never block on it */ }

  process.stdout.write(`${JSON.stringify({
    decision: 'block',
    reason: `LEGION_STOP_SHORT (${verdict.shape}): ${verdict.instruction} End the turn only with completed, verified work — or one line: "HARD BLOCKER: <exact missing input>" or "BLOCKED-ON-APPROVAL: <what + reserved category>". Any format carrying that token passes; do not reformat a packet you already wrote.`,
  })}\n`);
}

const invokedAsScript = process.argv[1]
  && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (invokedAsScript) main();
