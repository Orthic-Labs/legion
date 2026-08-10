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
// This is a SELF-CONTAINED implementation, deliberately. Morph independently
// arrived at the same admission rule for durable preference authority, but morph
// is a standalone, portable product: nothing here may import from it, and it may
// not import from here. A shared module would make morph non-portable and put a
// cross-repo (and cross-language) dependency on the critical path of every Stop.
// The rule is small and well understood; two independent implementations are the
// correct cost. The tests below pin this one on its own terms.

// --- ported from morph/authority.py -----------------------------------------

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
  /^Caveat: The messages below were generated/im,
];

function isSystemInjected(text) {
  return SYSTEM_INJECTED.some((pattern) => pattern.test(text));
}

/**
 * The most recent `limit` genuine user instructions, newest first. A turn is
 * genuine when the harness labelled it `user`, it is not a system injection,
 * and morph's admission accepts its content.
 */
export function recentUserInstructions(transcriptText, { limit = 5 } = {}) {
  if (typeof transcriptText !== 'string') return [];
  const found = [];
  const lines = transcriptText.split('\n').filter(Boolean);
  for (let index = lines.length - 1; index >= 0 && found.length < limit; index -= 1) {
    let entry;
    try { entry = JSON.parse(lines[index]); } catch { continue; }
    if (entry?.type !== 'user' || !entry?.message) continue;
    const content = entry.message.content;
    const text = typeof content === 'string'
      ? content
      : (Array.isArray(content) ? content : [])
        .filter((block) => block?.type === 'text' && typeof block.text === 'string')
        .map((block) => block.text)
        .join('\n');
    if (!text.trim() || isSystemInjected(text) || !admitsAuthority(text)) continue;
    found.push(text);
  }
  return found;
}

// --- intent ------------------------------------------------------------------

// the operator telling the agent to act. Narrow on purpose: this CLEARS a block, so a
// false positive lets an agent proceed on something never asked for.
const DIRECTIVE = /\b(?:go on|go ahead|do it|fix it|fix everything|make it so|proceed|carry on|continue|ship it|just do it|yes,? do|please do|get it done|handle it|sort it out|deploy it|push it|publish it)\b/i;

// the operator telling the agent to STOP. Must outrank a directive: "Don't make any
// changes" after "fix it" is a hold, and reading only the older turn would
// override an explicit stop.
const HOLD = /\b(?:don'?t|do not)\s+(?:make|change|apply|touch|do|push|commit|deploy|publish)\b|\bno changes\b|\bhold off\b|\bstop\b|\bwait\b/i;

/**
 * Did the operator, within the recent window, tell the agent to act — and not since
 * tell it to stop? Newest turn wins, because an instruction is superseded by a
 * later one, never averaged with it.
 */
export function userIntent(transcriptText, { limit = 5 } = {}) {
  const instructions = recentUserInstructions(transcriptText, { limit });
  for (const text of instructions) {
    // Check HOLD first within a turn: "fix it, but don't push" is a hold on pushing.
    if (HOLD.test(text)) return { intent: 'hold', evidence: text.slice(0, 300) };
    if (DIRECTIVE.test(text)) return { intent: 'proceed', evidence: text.slice(0, 300) };
  }
  return { intent: 'none', evidence: null };
}

/**
 * The question the hook actually asks: may this blocker be cleared because
 * the operator already authorized the work? True only on an explicit recent directive
 * with no later hold.
 */
export function alreadyAuthorized(transcriptText, { limit = 5 } = {}) {
  return userIntent(transcriptText, { limit }).intent === 'proceed';
}
