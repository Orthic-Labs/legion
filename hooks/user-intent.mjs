// Read the operator's recent instructions and decide, in the hook, whether a block is
// already authorized.
//
// The problem this removes: an agent hits a gate, and the cheapest way out is a
// blocker packet asking for permission that was already given two turns ago.
// The authorization exists — it is sitting in the transcript — but nothing
// mechanical could read it, so it got converted back into a question. Twice in
// one session, for things the operator had explicitly asked for.
//
// The security property, and why it is not naive: a transcript scan is
// self-certifying unless it can tell HAND-TYPED USER TEXT from everything else
// in the same file. The model writes into this transcript, and so do tool
// results — a model could phrase its own output to match, and a prompt-injected
// web page or file could carry "yes, force-push it". So a turn carries authority
// only when it is labelled `user`, is not a system injection, and its content
// does not lexically echo tool output, repo files, or assistant prose. The
// injection risk lives in the content, not the label.
//
// This is a SELF-CONTAINED implementation, deliberately. Adapt independently
// arrived at the same admission rule for durable preference authority, but adapt
// is a standalone, portable product: nothing here may import from it, and it may
// not import from here. A shared module would make adapt non-portable and put a
// cross-repo (and cross-language) dependency on the critical path of every Stop.
// The rule is small and well understood; two independent implementations are the
// correct cost. The tests below pin this one on its own terms.

// --- ported from adapt/authority.py -----------------------------------------

const TOOL_OUTPUT_ECHO = [
  /"tool_use_id"\s*:/,
  /"is_error"\s*:/,
  /^\$\s+\S/m,
  /\b(?:stdout|stderr)\b\s*:/i,
  /<tool_result>|<function_results>/i,
];

const REPO_FILE_ECHO = [
  /^\s*\d+\t/m,
  /^---\s*$[\s\S]{0,200}?^(?:name|description)\s*:/m,
  /\bcontents? of\b.{0,80}\.(?:md|py|json|ya?ml|txt)\b/i,
  /^#\s+(?:CLAUDE|AGENTS)\.md\b/im,
];

const ASSISTANT_AUTHORED = [
  /^(?:i'll|i will|let me|certainly!?|sure,? i(?:'ll| will))\b/i,
  /\bas (?:claude|the assistant|an ai)\b/i,
  /\bi(?:'ve| have) (?:implemented|added|fixed|updated|created)\b/i,
];

/**
 * Lexical signal that `text` is echoed repo/tool/assistant content rather than
 * hand-typed user text. Returns the origin it looks like, or null.
 */
export function classifyContentOriginHint(text) {
  const body = text ?? '';
  if (TOOL_OUTPUT_ECHO.some((pattern) => pattern.test(body))) return 'tool_output';
  if (REPO_FILE_ECHO.some((pattern) => pattern.test(body))) return 'repo_file';
  if (ASSISTANT_AUTHORED.some((pattern) => pattern.test(body))) return 'assistant_output';
  return null;
}

/** Only an authenticated user turn whose content is not echoed carries authority. */
export function admitsAuthority(text) {
  return typeof text === 'string' && text.trim().length > 0 && classifyContentOriginHint(text) === null;
}

// --- transcript reading ------------------------------------------------------

// System-injected turns arrive with `role: user` but are not the operator typing.
// Treating them as authority would let a reminder or a hook's own output
// authorize an effect.
const SYSTEM_INJECTED = [
  /<system-reminder>/i,
  /<cross-session-message\b/i,
  /\[SYSTEM NOTIFICATION - NOT USER INPUT\]/i,
  /<task-notification>/i,
  /^Stop hook feedback:/im,
  /^\[non-authoritative stop feedback\]/im,
  /^Caveat: The messages below were generated/im,
];

function isSystemInjected(text) {
  return SYSTEM_INJECTED.some((pattern) => pattern.test(text));
}

function entryText(entry) {
  const content = entry?.message?.content;
  return typeof content === 'string'
    ? content
    : (Array.isArray(content) ? content : [])
      .filter((block) => block?.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text)
      .join('\n');
}

/**
 * The most recent `limit` genuine user instructions, newest first. A turn is
 * genuine when the harness labelled it `user`, it is not a system injection,
 * and adapt's admission accepts its content.
 */
export function recentUserInstructions(transcriptText, { limit = 5 } = {}) {
  if (typeof transcriptText !== 'string') return [];
  const found = [];
  const lines = transcriptText.split('\n').filter(Boolean);
  for (let index = lines.length - 1; index >= 0 && found.length < limit; index -= 1) {
    let entry;
    try { entry = JSON.parse(lines[index]); } catch { continue; }
    if (entry?.type !== 'user' || !entry?.message) continue;
    const text = entryText(entry);
    if (!text.trim() || isSystemInjected(text) || !admitsAuthority(text)) continue;
    found.push(text);
  }
  return found;
}

/**
 * Latest structurally external user turn. Unlike legacy admission, lexical
 * tool/repo echoes do not erase a real current revocation or scope narrowing.
 */
export function latestExternalUserTurn(transcriptText) {
  if (typeof transcriptText !== 'string') return null;
  const lines = transcriptText.split('\n').filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    let entry;
    try { entry = JSON.parse(lines[index]); } catch { continue; }
    if (entry?.type !== 'user' || !entry?.message) continue;
    const text = entryText(entry);
    if (!text.trim() || isSystemInjected(text)) continue;
    return text;
  }
  return null;
}

// --- intent ------------------------------------------------------------------

// the operator telling the agent to act. Narrow on purpose: this CLEARS a block, so a
// false positive lets an agent proceed on something never asked for.
const EXECUTE = /^(?:please\s+|go ahead(?:\s+and)?\s+)?(?:fix|implement|create|add|remove|delete|update|wire|write|edit|change|build|run|scan|install|move|deploy|push|publish)\b/i;
const CONTINUE = /^(?:(?:ok,?\s+)?(?:go on|go ahead|do (?:it|that|this)|make it so|handle it|sort it out|get it done|ship it)\b|why (?:is|isn't|not) .+ still|can(?:'t|not)? (?:we|you) .*\b(?:fix|make|add|remove|update|wire|run))\b/i;
const PLAN = /\b(?:plan|design|architect(?:ure)?|proposal|propose|review|status|report|explain|answer|analyse|analy[sz]e)\b/i;

// the operator telling the agent to STOP. Must outrank a directive: "Don't make any
// changes" after "fix it" is a hold, and reading only the older turn would
// override an explicit stop.
const REVOKE = /\b(?:stop|pause|suspend|hold off|wait|cancel|make no changes|no changes)\b|\b(?:don'?t|do not)\s+(?:make|change|apply|touch|do)\s+(?:anything|any changes?)\b/i;
const SCOPE_NARROW = /\b(?:only|except|exclude|without)\b|\b(?:don'?t|do not)\b/i;

/** Quoted, fenced, and inline-code directives are evidence, never authority. */
export function stripNonAuthoritativeDirectiveText(text) {
  return typeof text === 'string' ? text
    .replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, ' ')
    .replace(/`[^`\n]*`/g, ' ')
    .replace(/["“][^"“”\n]{0,300}["”]/g, ' ') : '';
}

/** Classify exactly one admitted external turn; negative clauses dominate. */
export function classifyLatestUserIntent(transcriptText) {
  const text = latestExternalUserTurn(transcriptText);
  if (!text) return { intent: 'UNKNOWN', evidence: null };
  const directiveText = stripNonAuthoritativeDirectiveText(text);
  if (REVOKE.test(directiveText)) return { intent: 'REVOKE', evidence: text.slice(0, 300) };
  if (SCOPE_NARROW.test(directiveText)) return { intent: 'SCOPE_NARROW', evidence: text.slice(0, 300) };
  if (PLAN.test(directiveText)) return { intent: 'PLAN', evidence: text.slice(0, 300) };
  if (CONTINUE.test(directiveText)) return { intent: 'CONTINUE', evidence: text.slice(0, 300) };
  if (EXECUTE.test(directiveText)) return { intent: 'EXECUTE', evidence: text.slice(0, 300) };
  if (/\?$/.test(directiveText.trim())) return { intent: 'QUESTION', evidence: text.slice(0, 300) };
  return { intent: 'UNKNOWN', evidence: text.slice(0, 300) };
}

/**
 * Did the operator, within the recent window, tell the agent to act — and not since
 * tell it to stop? Newest turn wins, because an instruction is superseded by a
 * later one, never averaged with it.
 */
export function userIntent(transcriptText, { limit = 5 } = {}) {
  const latest = classifyLatestUserIntent(transcriptText);
  const intent = latest.intent === 'EXECUTE' || latest.intent === 'CONTINUE' ? 'proceed'
    : latest.intent === 'REVOKE' || latest.intent === 'SCOPE_NARROW' ? 'hold' : 'none';
  return { intent, evidence: latest.evidence };
}

/**
 * The question the hook actually asks: may this blocker be cleared because
 * the operator already authorized the work? True only on an explicit recent directive
 * with no later hold.
 */
export function alreadyAuthorized(transcriptText, { limit = 5 } = {}) {
  return userIntent(transcriptText, { limit }).intent === 'proceed';
}

// --- explicit-execution directive (ported from detect_explicit_directive.py) -
// Separate set, NOT authorization: detects the operator's no-deferral tone ("no
// deferring", "do all 8") but must never itself feed alreadyAuthorized() or
// let a generic phrase like "just do it" pre-authorize an unrelated effect —
// the already-authorized path above still requires a specific matching
// instruction; this set changes nothing about that.
const EXPLICIT_DIRECTIVE_PATTERNS = [
  "\\bno deferring\\b", "\\bdon'?t defer\\b", "\\bno deferral\\b",
  "\\ball (?:of them|\\d+|four|five|six|seven|eight|nine|ten)\\b", "\\bdo all\\b",
  "\\bif i ask(?:ed)? for (?:\\d+|all|both)\\b", "\\bi want \\d+\\b",
  "\\bdo as i (?:said|told)\\b", "\\bfight (?:through|it|that)\\b", "\\bjust do it\\b",
  "\\bdon'?t (?:drop|skip|punt|table|defer)\\b", "\\bstop deferring\\b", "\\byou disobeyed\\b",
  "\\byou (?:keep|kept) (?:doing|asking|deferring)\\b",
  "\\bwithout (?:my|your|the user'?s) say(?:[- ]?so)?\\b", "\\bget ?it ?done\\b",
];
// One alternation + matchAll, mirroring Python's re.finditer, so overlapping
// alternatives ("do all eight") yield one leftmost match, not one per pattern.
const EXPLICIT_DIRECTIVE = new RegExp(EXPLICIT_DIRECTIVE_PATTERNS.join('|'), 'gi');

/** Matched no-deferral phrases in `text` — evidence, never a boolean pre-auth. */
export function explicitDirective(text) {
  const body = typeof text === 'string' ? text : '';
  return [...body.matchAll(EXPLICIT_DIRECTIVE)].map((match) => match[0]);
}
