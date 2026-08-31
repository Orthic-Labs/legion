// Absorbs gate_codex_escalation.py: the escalation ladder, enforced at the
// point of escalation.
//
// Doctrine says resolve it yourself, then dispatch. `codex exec` is the
// dispatch, so the gate asks for the "yourself" part in evidence: two distinct
// attempts, each paired with what actually went wrong. Prose intent is not
// evidence — "I tried a few things" names no attempt and no failure.
//
// The prompt is read from where the command actually carries it: an inline
// quoted argument, a heredoc body, or a file piped in on stdin. A prompt this
// gate cannot read is refused rather than waved through, because an unreadable
// source is exactly how the requirement would be bypassed.

const CODEX = /\bcodex(?:\.exe)?\s+exec\b/i;
// `python foo.py ... codex exec ...` is a script that MENTIONS codex, not an
// escalation: the interpreter owns the command line.
const INTERPRETER = /^\s*(?:py|python|python3|py\d|py\d\.\d+|node|nodejs|bash|sh|zsh|bun|tsx|deno|powershell|pwsh)(?:\.exe)?\b/i;
const STDIN = [
  /\|\s*codex(?:\.exe)?\s+exec\b/i,
  /codex(?:\.exe)?\s+exec\b[^<]*<\s*\S/i,
  /\bcodex(?:\.exe)?\s+exec\b[^|<>]*\s+-\s*$/im,
];
const FILES = [
  /\b(?:cat|type|Get-Content)\s+([^\s|<>]+)\s*\|\s*codex(?:\.exe)?\s+exec\b/i,
  /codex(?:\.exe)?\s+exec\b[^<]*<\s*([^\s|<>]+)/i,
];
const ATTEMPT = /\b(?:tried|attempted|ran|launched|installed|pip\s+install|docker\s+run|executed|invoked|tested|reproduced)\b/gi;
const RESULT = /(?:\bfailed\b|\berrors?\b|\bexception\b|\bcrashed?\b|\bhung\b|\bdidn'?t work\b|\b\w+Error\b|\b\w+Exception\b|\b(?:exit|return|rc)\s*(?:code\s*)?[1-9]\d*\b|\bdoesn'?t (?:exist|work|load|import|find)\b)/i;

export const REQUIRED_ATTEMPTS = 2;
const STRONGER_MODEL = Object.freeze({ fast: 'balanced', balanced: 'strong', strong: 'strong' });

export function selectStrongerWorkingModel({ uncertain = false, currentTier = 'balanced', priorEscalations = 0 } = {}) {
  if (!uncertain) return Object.freeze({ escalated: false, modelTier: currentTier, executions: 0, workflowArtifact: false });
  if (priorEscalations !== 0) throw Object.assign(new Error('route uncertainty escalation already consumed'), { code: 'ARC_ESCALATION_RECURSION' });
  return Object.freeze({ escalated: true, modelTier: STRONGER_MODEL[currentTier] ?? 'strong', executions: 1, workflowArtifact: false, responseMode: 'DIRECT' });
}

/**
 * Count attempts that name a real outcome. An attempt verb only counts when a
 * failure appears within the next 120 characters, and two verbs closer than 20
 * characters apart are one attempt described twice ("tried and tested").
 */
export function evidenceCount(prompt) {
  if (typeof prompt !== 'string' || prompt.length === 0) return 0;
  let count = 0;
  let last = -1000;
  ATTEMPT.lastIndex = 0;
  for (const match of prompt.matchAll(ATTEMPT)) {
    if (match.index - last < 20) continue;
    if (RESULT.test(prompt.slice(match.index, match.index + 120))) {
      count += 1;
      last = match.index;
    }
  }
  return count;
}

/** The prompt body carried inline: a heredoc, else the longest quoted string. */
export function promptArgument(command) {
  const match = CODEX.exec(command);
  if (!match) return '';
  const heredoc = /<<-?'?(\w+)'?\s*\n([\s\S]*?)\n\s*\1\s*$/m.exec(command);
  if (heredoc) return heredoc[2];
  const tail = command.slice(match.index + match[0].length);
  const quoted = [
    ...[...tail.matchAll(/"((?:\\.|[^"\\])*)"/g)].map((m) => m[1]),
    ...[...tail.matchAll(/'((?:\\.|[^'\\])*)'/g)].map((m) => m[1]),
  ].filter((value) => value.length >= 50 && !/^(?:-|[A-Za-z]:[/\\]|\/[a-z]+\/|\.{1,2}\/)/.test(value));
  return quoted.reduce((longest, value) => (value.length > longest.length ? value : longest), '');
}

/** The file a stdin-fed prompt comes from, if the command names one. */
export function sourceFile(command) {
  for (const pattern of FILES) {
    const match = pattern.exec(command);
    if (match) return match[1].replace(/^['"]|['"]$/g, '');
  }
  return '';
}

/**
 * @param {string} command the Bash command about to run
 * @param {(path: string) => string|null} readSource resolves a stdin-fed prompt
 * @returns {{allowed: true}|{allowed: false, reason: string}}
 */
export function evaluateCodexEscalation(command, readSource = () => null) {
  if (typeof command !== 'string' || !CODEX.test(command) || INTERPRETER.test(command)) {
    return { allowed: true };
  }
  let prompt;
  // Heredoc first, and deliberately AHEAD of the stdin check. `codex exec
  // <<'EOF'` matches the stdin patterns, but names no file, so the Python
  // original refused every heredoc as "unreadable source" — a false refusal,
  // since the prompt is sitting inline in the command. The evidence bar is
  // unchanged; only the place it is read from is fixed.
  const heredoc = promptArgument(command);
  if (heredoc) {
    prompt = heredoc;
  } else if (STDIN.some((pattern) => pattern.test(command))) {
    prompt = readSource(sourceFile(command));
    if (!prompt) {
      return {
        allowed: false,
        reason: 'BLOCKED [codex-escalation-gate]: stdin-fed prompt source could not be read for evidence verification; pass it inline with at least 2 tried-X/failed-Y logs.',
      };
    }
  }
  const found = evidenceCount(prompt);
  if (found >= REQUIRED_ATTEMPTS) return { allowed: true, evidence: found };
  return {
    allowed: false,
    evidence: found,
    reason: `BLOCKED [codex-escalation-gate]: codex exec requires evidence of at least ${REQUIRED_ATTEMPTS} self-attempts with actual failures in the prompt body. Found ${found}. Document two specific attempted approaches and their errors, then re-spawn.`,
  };
}
