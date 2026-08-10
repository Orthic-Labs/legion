#!/usr/bin/env node
// Legion stop-shape gate — deterministic "no stopping short" enforcement.
//
// Doctrine (docs/agent-rules/legion.md): a turn may end in exactly two states —
// the requested work is complete and verified, or a reserved blocker names the
// exact missing input only the operator can supply. Ending with a permission question
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
import { userIntent, recentUserInstructions, explicitDirective } from './user-intent.mjs';

const MAX_PUSHES = 2;

// The legal blocked endings, matched LOOSELY on purpose (see failure mode 1):
//   HARD BLOCKER: <exact missing input only the operator can supply>
//   BLOCKED-ON-APPROVAL: <what + reserved category: private input, new spend,
//     publication/production mutation, destruction, reserved decision>
// Content may follow on the same line or the next one; both pass.
const HARD_BLOCKER = /\b(?:HARD BLOCKER|BLOCKED-ON-APPROVAL)\b\s*:?\s*(?:\S|(?:\r?\n\s*)+\S)/i;

// The FIVE canonical reserved categories (workspace rules: "Ask only for
// missing private input, new spend, unrequested publication or production
// mutation, destruction, or a reserved decision"). Everything else the operator asks
// for is pre-authorized.
//
// Why this validation exists: the token alone used to be an unconditional pass,
// so any rule invented anywhere ("reserved to the operator per HANDOFF") laundered a
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

// D-1: push-gate-laundering pre-check (2026-07-26 incident: an ordinary `git
// push` to the operator's own remotes was worded "irreversible-in-effect" and passed
// the destruction/publication keyword match). A normal push of requested work
// is pre-approved; only a force-push or history rewrite on a shared branch is
// genuinely reserved.
const PUSH_GATE_PATTERN = /\bgit\s+push\b|\bpush(?:ing|es)?\b[^\n]{0,100}\b(?:publish\w*|origin|remotes?|repos?|repositor\w+|github|branch\w*|upstream|main)\b/i;
const FORCE_PUSH_PATTERN = /--force(?:-with-lease)?\b|\bforce[- ]push\w*|\bhistory rewrite\w*|\brewrit\w+[^\n]{0,40}\bhistory\b/i;

// The exemption must not swallow a real publication. `PUSH_GATE_PATTERN` looks
// for "publish" near "push" so it can recognise a push DESCRIBED as publishing —
// but that same wording appears when the reserved act genuinely is distribution
// (npm publish, a release upload, a production deploy). Those stay reserved, on
// the same footing as a force-push: naming one suppresses the exemption.
const RESERVED_PUBLICATION_PATTERN = /\b(?:npm|pnpm|yarn|cargo|twine)\s+publish\b|\bpublish\w*\b[^\n]{0,40}\b(?:npm|registry|crates|pypi|marketplace|app store|production|customers?|publicly)\b|\brelease\b[^\n]{0,40}\b(?:upload|publish\w*|production)\b|\bdeploy\w*\b[^\n]{0,40}\bproduction\b/i;

/** An ordinary push worded to sound reserved is not a reserved blocker. */
export function isPushGateLaundering(text) {
  return typeof text === 'string'
    && PUSH_GATE_PATTERN.test(text)
    && !FORCE_PUSH_PATTERN.test(text)
    && !RESERVED_PUBLICATION_PATTERN.test(text);
}

// Ported from enforce_continue_intent.py: the operator phrases corrections as
// questions ("can't we make this a hook?", "why is X still there?"). Those are
// instructions, not invitations to explain and stop. The user-turn patterns
// detect that intent; the reply-side patterns separate "I acted" from "I would
// act". Advisory in Python, enforced here — same upgrade as the other shapes.
const CONTINUE_INTENT_RE = new RegExp([
  /\bcan(?:'t|not)?\s+we\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b/,
  /\bwhy\s+don'?t\s+we\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b/,
  /\bshould\s+we\b.*\b(?:install|incorporate|remove|fix|scan|create|make|turn|hook|enforce)\b/,
  /\bcan\s+you\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b/,
  /\bplease\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b/,
  /\b(?:i\s+asked|asked\s+multiple\s+times|repeatedly\s+asked)\b.*\b(?:remove|delete|fix|stop|avoid|enforce)\b/,
  /\bwhy\s+is\b.*\bstill\s+(?:there|enabled|active|present|happening|broken|failing)\b/,
  /\bover\s+and\s+over\b.*\b(?:failure|fails?|problem|still)\b/,
  /\bclearly\s+the\s+intention\b.*\b(?:continue|act|finish|get\s+you\s+to\s+continue)\b/,
  /\b(?:do|fix|remove|scan|run|add|make|create|implement|wire)\s+it\b/,
].map((r) => r.source).join('|'), 'is');
const ACTION_DONE_RE = /\bI (?:added|updated|created|implemented|wired|registered|patched|fixed|removed|deleted|disabled|enabled|ran|scanned|verified|changed|installed|moved)\b|\b(?:added|updated|created|implemented|wired|registered|patched|fixed|removed|deleted|disabled|enabled|ran|scanned|verified|changed|installed|moved)\b.*\b(?:now|already|successfully|in|to|from)\b|\b(?:done|completed|finished)\b|\bverification\b.*\b(?:passed|clean|green|ok)\b|\bI'?m (?:continuing|working|doing it|on it)\b/is;
const STOP_ONLY_RE = /\b(?:I|we) (?:can|could|should)\b|\b(?:I'?ll|I will|we'?ll|we will)\b|\b(?:recommend|proposal|propose|would be|next step)\b|\bthat'?s (?:a )?good idea\b|\byes\b.*\b(?:can|should|would)\b/is;
const CONTINUE_BLOCKER_RE = /\bhard blocker\b|\bblocked because\b|\bneeds user input\b|\bneed(?:s)? (?:your|user) (?:input|approval|credentials|decision|confirmation)\b|\bI cannot proceed\b.*\bwithout\b|\bmissing (?:secret|credential|file|input|approval)\b/is;

/** The latest genuine user turn's continuation-intent evidence, if any. */
export function continueIntent(userText) {
  if (typeof userText !== 'string') return null;
  const match = CONTINUE_INTENT_RE.exec(userText.replace(/[’‘]/g, "'").replace(/[“”]/g, '"'));
  return match ? match[0].slice(0, 120) : null;
}

// Stop-short shapes. Deliberately narrow: a false block burns a turn, while a
// miss is bounded by the next turn's gate. Each names the failure it catches so
// the block reason can instruct precisely rather than generically.
const SHAPES = [
  {
    name: 'permission-question',
    instruction: 'the operator pre-authorized in-scope reversible work; do it now instead of asking.',
    pattern: /\b(say (the word|go|yes)|shall i|want me to (proceed|continue|do|build|fix|run|add|set|apply|install|update|wire|write|edit|change|make)|should i (proceed|continue|go ahead)|do you want me to|awaiting (your )?(approval|confirmation|go)|give me the go)\b/i,
  },
  {
    // The deferral offer: the agent names the exact action, then hands it back
    // ("...or tell me to and I'll do it", "or I can add it for you"). Escaped
    // the first pattern set on the Mac 2026-08-10 — an agent that can state
    // the precise command it would run has no reason not to run it.
    name: 'deferral-offer',
    instruction: 'You named the exact action — perform it now instead of offering it.',
    // The last two alternations are ported from enforce_work_left_guard.py's
    // APPROVAL_ASK_PATTERNS: "Let me know and I'll rebuild it.", "I can trace
    // it if you want." — offers of future work phrased as courtesy.
    pattern: /\b(or )?tell me( to)?,?( and)? i(['’])?ll (do|apply|add|set|handle|wire|edit) (it|this|that)\b|\bor i can (do|add|apply|set|make|wire|edit|write|install|update)\b|\bif you (want|like|prefer),? i can\b|\blet me know (if|whether|when|and)\b|\bi can [a-z]+ (it|this|that)\b[^\n]{0,30}\bif you (want|like)\b/i,
  },
  {
    name: 'unresolved-caveat',
    instruction: 'Resolve the caveat yourself rather than reporting it.',
    // The closing-caveat family ("one thing that isn't...", "that said,",
    // "keep in mind") is ported from enforce_work_left_guard.py. Its original
    // rule holds: either the thing is fixed or it is the blocker.
    // "worth flagging/noting/mentioning" is deliberately NOT here: that family
    // belongs to the unrecorded-finding shape, which has its own carve-outs for
    // legitimate deferral. Duplicating it there would block those.
    pattern: /\b(one caveat|a caveat|with the caveat|caveats?:)\b|\bone thing (that )?(isn'?t|is not|to note|to flag|to be aware)\b|\bwhat (isn'?t|is not) (fixed|covered|handled|done)\b|\bjust (be aware|so you know)\b|\b(keep|bear) in mind\b|\bthat said,|\bone last (thing|note)\b/i,
    // The closing-caveat phrasings only count against a turn that claims the
    // work is done (the Python guard's _DONE_CLAIM_RE precondition); without
    // it, any answer mentioning "keep in mind" would block, which is more
    // eager than the hook this replaces.
    requires: /\b(done|fixed|shipped|pushed|landed|complete|completed|resolved)\b|\bverified\b|\ball (tests? )?pass(ing|es|ed)?\b|\b\d+\/\d+ (tests? )?pass\w*\b|\bworks? now\b|\bis (in and )?green\b/i,
    // D-2: a caveat IS the outcome when it is reporting a real failure or a
    // hard blocker — that is an answer, not a hedge to resolve.
    carveOut: /\btests? (?:fail|failed|are failing)\b|\bfailing\b|\berror(?:ed)?\b|\bhard blocker\b|\bcould not be (?:fixed|resolved)\b|\bneeds? your (?:input|decision)\b|\bBLOCKED-ON-APPROVAL\b/i,
  },
  {
    name: 'deferred-work-promise',
    instruction: 'Do the promised work now — a promise of future work is not a completed turn.',
    pattern: /\b(i('| wi)ll (do|fix|build|wire|handle|address) (this|that|it) (later|next|in a follow-?up)|left as a follow-?up|remains? to be (done|built|fixed))\b/i,
  },
  {
    name: 'approval-blocked',
    instruction: 'Approval for reversible in-scope work is pre-granted by doctrine. Only private input, new spend, publication/production mutation, destruction, or a reserved decision needs the operator — name which one applies, or continue.',
    pattern: /\bblocked on (your )?(approval|a decision|sign-?off|confirmation)\b/i,
  },
];

// D-3: work-left-stuck. Ported from enforce_work_left_guard.py's GENERIC
// WORK_LEFT_PATTERNS only — GPU-percent, clips-per-sec and checkpoint jargon
// are media-pipeline vocabulary and are deliberately dropped.
const WORK_LEFT_PATTERN = /\bqueued\b|\bpending\b|\bnot (?:started|running|done|fixed|complete)\b|\bstill (?:waiting|stuck|pending|queued|not)\b|\b(?:stuck|wedged|blocked)\b|\bwill (?:start|rerun|continue|resume|fix)\b|\b(?:should|need to|needs to) (?:start|restart|fix|rerun|continue|resume|launch)\b|\bI (?:did not|didn't|haven't|have not) (?:touch|start|restart|fix|launch|change|kill)\b|\bI (?:have not|haven't|did not|didn't|could not|couldn't) (?:found|find|locate|identif\w+|trace)\b|\bthat'?s the next thing\b|\bnext (?:thing|step) (?:to|is to) (?:pin|find|trace|figure|determine)\b|\b(?:remaining|left):?\s+\d+\b/i;
const WORK_LEFT_NONSTATUS = /\b[\w./-]*pending[\w./-]*\.(?:md|json|ya?ml|txt|py|js|mjs|toml)\b|\bpending\s+(?:doc|document|note|plan|adr|spec|queue)s?\b/i;
const WORK_LEFT_DONE_NEGATION = /\b(?:nothing|none|no(?:t anything)?)\s+(?:is\s+)?(?:still\s+)?(?:left|pending|queued|remaining|outstanding|stuck|blocked|waiting|further)\b|\bno\s+(?:remaining|further|outstanding|pending)\s+(?:work|tasks?|steps?|actions?|items?)\b|\b(?:all|everything)\s+(?:is\s+)?(?:done|complete|completed|finished|verified|passing|green|shipped)\b|\bnothing (?:left|remains|remaining|further|else)\b/i;
const WORK_LEFT_ACTION_TAKEN = /\bI (?:fixed|patched|started|restarted|launched|killed|stopped|resumed|continued)\b|\b(?:fixed|patched|restarted|launched|resumed|continued) (?:it|them|the|all|workers?|jobs?|runs?|processes?)\b|\b(?:workers?|jobs?|runs?|processes?) (?:are|were) (?:fixed|patched|started|restarted|launched|resumed|continued)\b|\bnow running\b|\bverified\b|\bconfirmed\b|\bprogress(?:ing)? again\b|\bno safe corrective action\b|\bleft (?:it|them) untouched because\b/i;
const WORK_LEFT_HARD_BLOCKER_MENTION = /\bhard blocker\b|\bblocked because\b|\bneeds user input\b|\bneed(?:s)? (?:your|user) (?:input|approval|credentials|decision|confirmation)\b/i;
const WORK_LEFT_REVIEW_SELF = /\breview-self\b|\bself-review\b|\breviewed alternatives\b/i;

/** Unfinished-work language with no corrective action taken and no genuine done/blocked carve-out. */
export function workLeftStuck(text) {
  if (typeof text !== 'string') return false;
  const cleaned = text.replace(WORK_LEFT_NONSTATUS, ' ');
  if (!WORK_LEFT_PATTERN.test(cleaned)) return false;
  if (WORK_LEFT_DONE_NEGATION.test(cleaned)) return false;
  if (WORK_LEFT_ACTION_TAKEN.test(cleaned)) return false;
  if (WORK_LEFT_HARD_BLOCKER_MENTION.test(cleaned) && WORK_LEFT_REVIEW_SELF.test(cleaned)) return false;
  return true;
}

// D-4: tool-denial. Ported from detect_scope_cut.py's TOOL_DENIAL_PATTERNS,
// upgraded from an inert Python advisory to an enforced SHAPE.
const TOOL_DENIAL_PATTERN = /\bI don'?t have (?:web ?search|webfetch|web_search|web_fetch)\b|\bI don'?t have access to (?:web ?search|webfetch|the (?:web|internet))\b|\bI can'?t (?:search the web|use web ?search|use webfetch|browse the web|fetch URLs?)\b|\bno (?:web ?search|webfetch) (?:available|access) (?:in this|for this) session\b|\bI (?:cannot|can'?t) access (?:web ?search|webfetch|the (?:internet|web))\b/i;

/** The specific matched phrase claiming a tool is missing, or null. */
export function toolDenialMatch(text) {
  if (typeof text !== 'string') return null;
  const match = text.match(TOOL_DENIAL_PATTERN);
  return match ? match[0] : null;
}

// D-5: scope-cut-after-explicit-directive. Ported from detect_scope_cut.py's
// SCOPE_CUT_PATTERNS. Only fires when the CURRENT reply proposes a scope cut
// AND the operator issued an explicit no-deferral directive in a recent turn
// (explicitDirective(), reusing recentUserInstructions() for authenticity) —
// mirroring the Python advisory's own precondition, now enforced.
const SCOPE_CUT_PATTERN = /\b(?:5|four|five|six) (?:of|out of) (?:8|seven|eight|nine|ten)\b|\bskip(?:ping)? the (?:3|three|four|five) (?:NeMo |models?|options?)|\b(?:defer|punt|table) (?:these|them|the|this|that|it)\b|\bdrop(?:ping)? (?:the |these |\d+ )?(?:models?|options?|features?)\b|\bship (?:5 )?tonight\b|\bthis (?:is a |would be a |feels like a )?(?:tar pit|rabbit hole|deep hole)\b|\bno way forward\b|\b(?:will|would) take \d+(?:-\d+)? hours? to (?:fully )?(?:fix|sort|resolve)\b|\binstead of (?:all |the )?\d+\b|\bnot worth (?:saving|the time)\b|\bdo (?:bake-?off|test|run) with (?:5|fewer|just )\b/i;

/** The specific matched scope-cut phrase, or null. */
export function scopeCutMatch(text) {
  if (typeof text !== 'string') return null;
  const match = text.match(SCOPE_CUT_PATTERN);
  return match ? match[0] : null;
}

// Deferred-defect shapes: the turn FOUND a real, in-scope, actionable defect and
// handed it back in prose instead of fixing it ("worth flagging for later",
// "that's a separate cleanup whenever you want it"). the operator's standing rule is
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
  /\bneeds?\s+(?:your|operator'?s|the\s+user'?s)\s+(?:input|decision|credentials|approval|confirmation|call|access)\b|\bblocked\s+on\s+(?:your|operator'?s|the\s+user'?s)\b|\bOPERATOR[- ]ONLY\b|\breserved\s+(?:to|for)\s+(?:you|operator)\b/i,
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

/** Was any tool used after the last genuine (non-tool-result) user turn? */
export function toolUseAfterLastUser(transcriptText) {
  if (typeof transcriptText !== 'string') return false;
  const lines = transcriptText.split('\n').filter(Boolean);
  let lastUser = -1;
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    let entry;
    try { entry = JSON.parse(lines[i]); } catch { continue; }
    if (entry?.type !== 'user' || !entry?.message) continue;
    const content = entry.message.content;
    const blocks = Array.isArray(content) ? content : [];
    if (blocks.some((b) => b?.type === 'tool_result')) continue; // harness echo, not the operator
    lastUser = i;
    break;
  }
  if (lastUser < 0) return false;
  for (let i = lastUser + 1; i < lines.length; i += 1) {
    let entry;
    try { entry = JSON.parse(lines[i]); } catch { continue; }
    const content = entry?.message?.content;
    if (Array.isArray(content) && content.some((b) => b?.type === 'tool_use')) return true;
  }
  return false;
}

// A turn that DISCUSSES a trigger phrase must not trip the gate that enforces
// it: "the hook blocks `shall I proceed`" is a report, not an approval-ask.
// Ported from completion_evidence.strip_code_spans — fenced blocks, inline
// code, then short double-quoted spans, in that order. The deliberate
// tradeoff is unchanged from the Python guard: a phrase hidden in quotes can
// slip one turn, and the next turn's gate bounds the miss, whereas a false
// block on every status report about the gate burns turns forever.
export function stripCodeSpans(text) {
  return text
    .replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, ' ')
    .replace(/`[^`\n]*`/g, ' ')
    .replace(/["“][^"“”\n]{0,300}["”]/g, ' ');
}

export function evaluateStopShape(finalText, { pushes = 0, recorded = false, escalated = false, authorized = false, authorizedEvidence = null, explicitDirectiveEvidence = [], continueIntentEvidence = null, continueToolsUsed = false } = {}) {
  if (typeof finalText !== 'string' || finalText.length === 0) return { block: false, reason: 'no-final-text' };
  if (pushes >= MAX_PUSHES) return { block: false, reason: 'push-cap' };
  // Packet parsing stays on the RAW text: structured blockers legitimately
  // carry quoted JSON keys ("reserved_category": ...), and stripping them
  // would misread a valid packet as category-less. Only the prose heuristics
  // below use the stripped view.
  if (HARD_BLOCKER.test(finalText)) {
    // D-1: an ordinary push worded to sound reserved is not a reserved
    // blocker — checked before authorization/category logic so it cannot be
    // laundered through either path.
    if (!authorized && isPushGateLaundering(finalText)) {
      return {
        block: true,
        shape: 'unreserved-blocker',
        instruction: 'Your blocker gate is an ordinary git push, worded as reserved. A normal push of requested work to the operator\'s own remotes is pre-approved: using the word "irreversible" does not make it publication or destruction. Only a --force push or a history rewrite on a shared branch is genuinely reserved. Push it and report the receipt.',
      };
    }
    // A blocker packet must name a category that actually exists. `HARD BLOCKER`
    // (missing input only the operator can supply) is self-describing and always
    // passes; `BLOCKED-ON-APPROVAL` must land in the canonical five, or it is a
    // stop-short wearing the right token.
    // `HARD BLOCKER` is self-describing — a missing input cannot be escalated
    // around, so it passes on its own.
    if (/\bHARD BLOCKER\b/i.test(finalText)) return { block: false, reason: 'hard-blocker-stated' };
    // the operator's own recent words outrank any packet. The authorization is sitting
    // in the transcript; before this, nothing mechanical could read it, so it got
    // converted back into a question — twice in one session for things he had
    // explicitly asked for. `authorized` comes from an admitted user turn only
    // (hooks/user-intent.mjs), never from assistant text or tool output.
    if (authorized) {
      return {
        block: true,
        shape: 'already-authorized',
        instruction: `the operator already told you to proceed in a recent turn${authorizedEvidence ? ` ("${authorizedEvidence.replace(/\s+/g, ' ').slice(0, 120)}")` : ''}. That IS the approval — asking again is the stop-short. Do the work and report the receipt. If a later instruction held you back, or the effect is genuinely outside what he asked for, say which and name it precisely.`,
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
        instruction: 'Your blocker names a real category but shows no escalation. The ladder is: resolve it yourself, then dispatch Sage, then convene Covenant, and only then block. Nothing in this session shows Sage or Covenant was consulted. If the operator asked for it, intended it, or it is obvious, it is not a reserved decision — do it. If it is genuinely ambiguous, dispatch Sage now and block only if Sage cannot settle it.',
      };
    }
    return {
      block: true,
      shape: 'unreserved-blocker',
      instruction: 'Your BLOCKED-ON-APPROVAL names no canonical reserved category. Only five exist: missing private input, new spend, unrequested publication or production mutation, destruction, or a reserved decision. A rule found in a doc is not a sixth category — if the work is reversible and in scope, the operator already authorized it. Do it.',
    };
  }
  // Prose heuristics run on the stripped view: a turn that quotes or fences a
  // trigger phrase is reporting on the gate, not committing the failure.
  const prose = stripCodeSpans(finalText);
  // Judge the ENDING, not the whole turn: a caveat raised mid-report and then
  // resolved must not block. Take the last ~1200 characters.
  const tail = prose.slice(-1200);
  for (const shape of SHAPES) {
    if (shape.pattern.test(tail)) {
      if (shape.requires && !shape.requires.test(prose)) continue;
      if (shape.carveOut && shape.carveOut.test(prose)) continue;
      return {
        block: true,
        shape: shape.name,
        instruction: `${shape.instruction} ${ESCALATION[Math.min(pushes, ESCALATION.length - 1)]}`,
      };
    }
  }
  // D-4: a tool claimed missing without verification. Checked against the
  // whole message, since the denial is often stated mid-report.
  const toolDenial = toolDenialMatch(prose);
  if (toolDenial) {
    return {
      block: true,
      shape: 'tool-denial',
      instruction: `You claimed a tool is missing without verifying it against this session's tools list (detected: "${toolDenial}"). Check the available-tools list before claiming absence; if it is genuinely unavailable, say so precisely instead of "I don't have X".`,
    };
  }
  // D-5: a scope cut proposed after the operator explicitly said not to defer.
  if (explicitDirectiveEvidence.length > 0) {
    const scopeCut = scopeCutMatch(prose);
    if (scopeCut) {
      return {
        block: true,
        shape: 'scope-cut',
        instruction: `the operator issued an explicit no-deferral directive ("${explicitDirectiveEvidence[0].slice(0, 80)}") and this reply proposes a scope cut or deferral (detected: "${scopeCut}"). Execute the literal request. If genuinely blocked, report "tried [X]: [error]. trying [Y]." and keep moving — do not fork or defer.`,
      };
    }
  }
  // Continue-intent (from enforce_continue_intent.py): the latest user turn
  // was a correction phrased as a question, and this reply only proposes or
  // acknowledges. An action marker or hard blocker clears it; tool use after
  // the user turn clears it too unless the ending is still "I can/should/
  // I'll" — acting and then handing back is the same stop-short.
  if (continueIntentEvidence && !ACTION_DONE_RE.test(prose) && !CONTINUE_BLOCKER_RE.test(prose)
    && (!continueToolsUsed || STOP_ONLY_RE.test(prose))) {
    return {
      block: true,
      shape: 'continue-intent',
      instruction: `the operator's latest message ("${continueIntentEvidence}") is an instruction, not an invitation to explain and stop. Do the work now, or state a hard blocker with the exact missing input. Do not end on "we can/should/I will" when the missing work is safe to do.`,
    };
  }
  // D-3: unfinished work with no corrective action taken and no genuine
  // done/blocked carve-out.
  if (workLeftStuck(prose)) {
    return {
      block: true,
      shape: 'work-left-stuck',
      instruction: 'You reported unfinished work (stuck/queued/pending/no corrective action) without a hard blocker. Do NOT stop to ask whether to continue — keep working now, or state a HARD BLOCKER with the exact missing input.',
    };
  }
  // Checked against the WHOLE message with paragraph-scoped carve-outs: a defect
  // is usually deferred mid-report, not in the closing line.
  const deferred = deferredDefectCodes(finalText);
  if (deferred.length > 0) {
    return {
      block: true,
      shape: 'deferred-defect',
      instruction: `You deferred a found issue instead of resolving it (matched: ${deferred.join(', ')}). Standing rule: found issues get fixed in the turn that found them. If it is fixable now, fix it and report the fixed state. If it genuinely is not yours, say which agent owns it, what input only the operator can supply, or that you filed it as a background task. If deferring is still correct, tag the reply [deferred-ok: <reason>].`,
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
  // D-5: recent explicit no-deferral directives, from admitted user turns only.
  const explicitDirectiveEvidence = recentUserInstructions(raw, { limit: 6 })
    .flatMap((text) => explicitDirective(text));
  // Continue-intent reads only the LATEST genuine user turn: a correction
  // phrased as a question three turns ago was already answered or superseded.
  const [latestInstruction] = recentUserInstructions(raw, { limit: 1 });
  const verdict = evaluateStopShape(finalText, {
    pushes,
    recorded: recordedThisTurn(raw),
    escalated: escalatedThisSession(raw),
    authorized: intent.intent === 'proceed',
    authorizedEvidence: intent.evidence,
    explicitDirectiveEvidence,
    continueIntentEvidence: continueIntent(latestInstruction ?? ''),
    continueToolsUsed: toolUseAfterLastUser(raw),
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
