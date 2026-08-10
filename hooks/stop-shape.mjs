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
import { userIntent } from './user-intent.mjs';

const MAX_PUSHES = 2;

// The legal blocked endings, matched LOOSELY on purpose (see failure mode 1):
//   HARD BLOCKER: <exact missing input only Adrian can supply>
//   BLOCKED-ON-APPROVAL: <what + reserved category: private input, new spend,
//     publication/production mutation, destruction, reserved decision>
// Content may follow on the same line or the next one; both pass.
const HARD_BLOCKER = /\b(?:HARD BLOCKER|BLOCKED-ON-APPROVAL)\b\s*:?\s*(?:\S|(?:\r?\n\s*)+\S)/i;

// The FIVE canonical reserved categories (workspace rules: "Ask only for
// missing private input, new spend, unrequested publication or production
// mutation, destruction, or a reserved decision"). Everything else Adrian asks
// for is pre-authorized.
//
// Why this validation exists: the token alone used to be an unconditional pass,
// so any rule invented anywhere ("reserved to Adrian per HANDOFF") laundered a
// stop-short into a legitimate ending. Two agents did exactly that in one day
// while nothing was functionally blocked. A packet must now name a category
// that actually exists, which forces the claim to be checked against the list
// rather than against a habit.
//
// Still deliberately loose on FORMAT (failure mode 1): any phrasing carrying a
// category word passes. This validates the claim's SUBSTANCE, never its layout.
const RESERVED_CATEGORIES = [
  ['private-input', /\b(private|missing)\s+(input|credential|token|password|secret)\b|\bcredentials?\b|\b2fa\b|\bapi key\b/i],
  ['new-spend', /\bnew spend\b|\bspend\b|\bpurchase\b|\bpaid\b|\bbilling\b|\bcost(s|ing)?\s+(money|\$)|\$\d/i],
  ['publication', /\bpublicat\w+\b|\bpublish\w*\b|\bproduction mutation\b|\brelease\b|\bdeploy(ing|ment)?\s+to\s+prod\w*|\bnpm publish\b/i],
  ['destruction', /\bdestruct\w+\b|\bdelete\b|\bdrop\b|\bhard[- ]?reset\b|\bforce[- ]?push\b|\birreversible\b/i],
  // Separator-agnostic: packets arrive as prose, YAML and JSON, so
  // "reserved decision", "reserved_decision" and "reserved-decision" are one
  // claim. Format is never what this validation judges.
  ['reserved-decision', /\breserved[ _-]decision\b|\bpolicy[ _-](change|decision)\b|\bwho may\b|\bdelegat\w+ authority\b|\bchange the rule\b/i],
];

/** Which canonical reserved categories a blocker packet actually names. */
export function reservedCategories(text) {
  if (typeof text !== 'string') return [];
  return RESERVED_CATEGORIES.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

// Stop-short shapes. Deliberately narrow: a false block burns a turn, while a
// miss is bounded by the next turn's gate. Each names the failure it catches so
// the block reason can instruct precisely rather than generically.
const SHAPES = [
  {
    name: 'permission-question',
    instruction: 'Adrian pre-authorized in-scope reversible work; do it now instead of asking.',
    pattern: /\b(say (the word|go|yes)|shall i|want me to (proceed|continue|do|build|fix|run|add|set|apply|install|update|wire|write|edit|change|make)|should i (proceed|continue|go ahead)|do you want me to|awaiting (your )?(approval|confirmation|go)|give me the go)\b/i,
  },
  {
    // The deferral offer: the agent names the exact action, then hands it back
    // ("...or tell me to and I'll do it", "or I can add it for you"). Escaped
    // the first pattern set on the Mac 2026-08-10 — an agent that can state
    // the precise command it would run has no reason not to run it.
    name: 'deferral-offer',
    instruction: 'You named the exact action — perform it now instead of offering it.',
    pattern: /\b(or )?tell me( to)?,?( and)? i(['’])?ll (do|apply|add|set|handle|wire|edit) (it|this|that)\b|\bor i can (do|add|apply|set|make|wire|edit|write|install|update)\b|\bif you (want|like|prefer),? i can\b/i,
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

// Deferred-defect shapes: the turn FOUND a real, in-scope, actionable defect and
// handed it back in prose instead of fixing it ("worth flagging for later",
// "that's a separate cleanup whenever you want it"). Adrian's standing rule is
// that found issues get resolved in the turn that found them.
//
// This table is the single source of stop-policy CONTENT. The rhook fast path
// (tools/rhook, Rust) and Codex's final-gate carry a GENERATED copy of it — a
// fourth hand-written stop gate is how a rule ends up protecting one harness on
// one machine, which is the shape behind every parity outage this cycle.
//
// Deliberately excluded as markers: "whenever you want", "you may want to".
// They are said constantly about ordinary optional scope that was never a found
// defect, and regex cannot tell those apart; including them would trade a small
// false-negative gain for a large false-positive cost.
export const DEFERRED_DEFECT_MARKERS = [
  ['worth-flagging', /\bworth\s+(?:flagging|mentioning)\b/i],
  ['worth-doing-later', /\bworth\s+doing\s+(?:at\s+some\s+point|later|some\s*time)\b/i],
  ['leave-for-later', /\bi(?:'|’)?ll\s+leave\s+(?:that|this|it)\s+for\s+(?:a\s+)?(?:later|follow-?up|another\s+time)\b/i],
  ['someone-should', /\bsomeone\s+should\s+(?:clean|fix|address|look\s+at|handle|sync)\b/i],
  ['out-of-scope-for-now', /\bout\s+of\s+scope\s+for\s+now\b/i],
  ['todo-fix-later', /\bTODO:?\s*(?:fix|address|clean\s*up|sync)\s+(?:this\s+)?later\b/i],
  ['separate-cleanup', /\b(?:a\s+)?separate\s+cleanup\b/i],
  ['note-for-later', /\bnote\s+for\s+later\b/i],
];

// Legitimate deferral. Honoured only in the SAME paragraph as the marker, so an
// unrelated "already fixed X" elsewhere in a long report cannot launder a real
// deferred defect.
export const DEFERRED_DEFECT_CARVE_OUTS = [
  /\b(?:another|a\s+separate|the\s+other)\s+agent\b|\b(?:sage|alchemist|seer|covenant)\s+(?:is|will\s+be|has|already)\b|\bnot\s+(?:your|my)\s+lane\b/i,
  /\bneeds?\s+(?:your|adrian'?s|the\s+user'?s)\s+(?:input|decision|credentials|approval|confirmation|call|access)\b|\bblocked\s+on\s+(?:your|adrian'?s|the\s+user'?s)\b|\bADRIAN[- ]ONLY\b|\breserved\s+(?:to|for)\s+(?:you|adrian)\b/i,
  /\bwant\s+me\s+to\s+also\b|\bhappy\s+to\s+also\b/i,
  /\b(?:already|also)\s+(?:fixed|resolved|patched|corrected|addressed|recorded)\b/i,
  /\bspawn_task\b|\bspawned\s+a\s+(?:background\s+)?task\b|\bfiled\s+(?:as|a)\s+(?:background\s+)?task\b/i,
];

// The honest escape hatch: regex cannot judge intent in the residual cases.
export const DEFERRED_OK_TAG = /\[deferred-ok(?::[^\]]{0,200})?\]/i;

/**
 * Which deferred-defect markers fire, after dropping carved-out paragraphs and
 * respecting the override tag. Pure — this is the function the generated rhook
 * and Codex copies must reproduce.
 */
export function deferredDefectCodes(text) {
  if (typeof text !== 'string' || DEFERRED_OK_TAG.test(text)) return [];
  const codes = new Set();
  for (const paragraph of text.split(/\n\s*\n/).map((part) => part.trim()).filter(Boolean)) {
    if (DEFERRED_DEFECT_CARVE_OUTS.some((carveOut) => carveOut.test(paragraph))) continue;
    for (const [code, pattern] of DEFERRED_DEFECT_MARKERS) {
      if (pattern.test(paragraph)) codes.add(code);
    }
  }
  return [...codes].sort();
}

// Finding language: the turn is reporting something a future agent would need,
// in a place no future agent can read. Chat is not memory — a gotcha stated in
// a session and not written down is gone when the context rolls. Narrow on
// purpose: only phrasings that explicitly frame a durable lesson, never mere
// description of work done.
const FINDING_LANGUAGE = /\b(worth (noting|knowing|recording|your attention)|for (the )?(pattern file|future reference|posterity)|note for (the )?(future|next)|lesson (here|learned)|gotcha|trap for|bit(es|) us|cost (me|us) (an hour|hours|time)|next agent (should|will|needs)|remember (this|that) for)\b/i;

// Paths that count as recording a finding durably.
const RECORD_TARGETS = /(GOTCHAS?\.md|HANDOFF\.md|memright\b|\bmemory\/[\w-]+\.md)/i;

/**
 * Did this turn actually record something durable? Reads the transcript for a
 * tool call that wrote to a recognised destination. Deliberately generous: any
 * write to GOTCHAS.md / HANDOFF.md / a memright put counts, because the goal is
 * "it left the chat", not a particular format.
 */
export function recordedThisTurn(transcriptText) {
  return typeof transcriptText === 'string' && RECORD_TARGETS.test(transcriptText);
}

// Evidence that the escalation ladder was actually walked before blocking: a
// Sage or Covenant dispatch somewhere in this session. Matched against the raw
// transcript (which carries tool-call JSON), so it sees a real dispatch rather
// than the agent's prose claim of one — the same reason receipts beat sentences
// everywhere else in this system.
const ESCALATION_EVIDENCE = /"subagent_type"\s*:\s*"(?:legion:)?(?:sage|covenant-seat)"|\/covenant\b|(?:^|\s)@sage\b/i;

export function escalatedThisSession(transcriptText) {
  return typeof transcriptText === 'string' && ESCALATION_EVIDENCE.test(transcriptText);
}

// The escalation ladder (doctrine: resolve → Sage → Covenant → best call →
// stop). Each push instructs the NEXT rung and never repeats the last one: a
// gate that repeats itself teaches reformatting, not progress.
const ESCALATION = [
  'Resolve it yourself now; if it needs an engineering decision, dispatch Sage.',
  'Sage did not settle it: convene Covenant, or make the best decision yourself and record the reasoning. Re-verify the blocker against CURRENT state before re-asserting it — a blocker observed earlier in a session is often already stale.',
];

function lastAssistantText(raw) {
  const lines = raw.split('\n').filter(Boolean);
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

export function evaluateStopShape(finalText, { pushes = 0, recorded = false, escalated = false, authorized = false, authorizedEvidence = null } = {}) {
  if (typeof finalText !== 'string' || finalText.length === 0) return { block: false, reason: 'no-final-text' };
  if (pushes >= MAX_PUSHES) return { block: false, reason: 'push-cap' };
  if (HARD_BLOCKER.test(finalText)) {
    // A blocker packet must name a category that actually exists. `HARD BLOCKER`
    // (missing input only Adrian can supply) is self-describing and always
    // passes; `BLOCKED-ON-APPROVAL` must land in the canonical five, or it is a
    // stop-short wearing the right token.
    // `HARD BLOCKER` is self-describing — a missing input cannot be escalated
    // around, so it passes on its own.
    if (/\bHARD BLOCKER\b/i.test(finalText)) return { block: false, reason: 'hard-blocker-stated' };
    // Adrian's own recent words outrank any packet. The authorization is sitting
    // in the transcript; before this, nothing mechanical could read it, so it got
    // converted back into a question — twice in one session for things he had
    // explicitly asked for. `authorized` comes from an admitted user turn only
    // (hooks/user-intent.mjs), never from assistant text or tool output.
    if (authorized) {
      return {
        block: true,
        shape: 'already-authorized',
        instruction: `Adrian already told you to proceed in a recent turn${authorizedEvidence ? ` ("${authorizedEvidence.replace(/\s+/g, ' ').slice(0, 120)}")` : ''}. That IS the approval — asking again is the stop-short. Do the work and report the receipt. If a later instruction held you back, or the effect is genuinely outside what he asked for, say which and name it precisely.`,
      };
    }
    if (reservedCategories(finalText).length > 0) {
      // Naming a real category is necessary but NOT sufficient. Category
      // validation alone still let a settled question through: a packet claimed
      // "reserved decision" for something committed doctrine already answered,
      // matched the word, and passed. The token was an unconditional exit, so
      // emitting it was cheaper than doing the work — the gate taught the very
      // laundering it existed to stop.
      //
      // Doctrine's ladder is resolve -> Sage -> Covenant -> block. So a blocker
      // must SHOW the ladder was walked. This is not a format check: it looks
      // for an actual Sage/Covenant dispatch in the session transcript. If the
      // question was genuinely undecided, that dispatch already happened; if it
      // was already answered, Sage says so and no blocker is needed. Either way
      // blocking is now more expensive than resolving, which is the correct
      // gradient.
      if (escalated) return { block: false, reason: 'reserved-blocker-escalated' };
      return {
        block: true,
        shape: 'unescalated-blocker',
        instruction: 'Your blocker names a real category but shows no escalation. The ladder is: resolve it yourself, then dispatch Sage, then convene Covenant, and only then block. Nothing in this session shows Sage or Covenant was consulted. If Adrian asked for it, intended it, or it is obvious, it is not a reserved decision — do it. If it is genuinely ambiguous, dispatch Sage now and block only if Sage cannot settle it.',
      };
    }
    return {
      block: true,
      shape: 'unreserved-blocker',
      instruction: 'Your BLOCKED-ON-APPROVAL names no canonical reserved category. Only five exist: missing private input, new spend, unrequested publication or production mutation, destruction, or a reserved decision. A rule found in a doc is not a sixth category — if the work is reversible and in scope, Adrian already authorized it. Do it.',
    };
  }
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
  // Checked against the WHOLE message with paragraph-scoped carve-outs: a defect
  // is usually deferred mid-report, not in the closing line.
  const deferred = deferredDefectCodes(finalText);
  if (deferred.length > 0) {
    return {
      block: true,
      shape: 'deferred-defect',
      instruction: `You deferred a found issue instead of resolving it (matched: ${deferred.join(', ')}). Standing rule: found issues get fixed in the turn that found them. If it is fixable now, fix it and report the fixed state. If it genuinely is not yours, say which agent owns it, what input only Adrian can supply, or that you filed it as a background task. If deferring is still correct, tag the reply [deferred-ok: <reason>].`,
    };
  }
  // A finding announced only in chat is a finding lost. Checked against the
  // WHOLE message, not the tail: the lesson is often stated mid-report.
  if (!recorded && FINDING_LANGUAGE.test(finalText)) {
    return {
      block: true,
      shape: 'unrecorded-finding',
      instruction: 'You reported something a future agent needs, but only in chat — nothing here survives this session. Append it to docs/GOTCHAS.md (symptom, cause, fix), or to the relevant HANDOFF, or save it with memright.',
    };
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

  let raw = null;
  try { raw = readFileSync(transcriptPath, 'utf8'); } catch { return; } // unreadable transcript -> fail open
  const finalText = lastAssistantText(raw);

  const stateFile = join(cwd, '.audit', 'legion', 'stop-shape', `${sessionId}.json`);
  const pushes = payload.stop_hook_active ? pushCount(stateFile) : 0;

  // `recorded` is read from the WHOLE transcript, not this turn alone: a gotcha
  // written earlier in the session is already durable, and re-blocking for it
  // would be the grind this gate exists to avoid.
  const intent = userIntent(raw);
  const verdict = evaluateStopShape(finalText, {
    pushes,
    recorded: recordedThisTurn(raw),
    escalated: escalatedThisSession(raw),
    authorized: intent.intent === 'proceed',
    authorizedEvidence: intent.evidence,
  });
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
