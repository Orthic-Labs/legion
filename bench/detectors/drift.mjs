// Bench-local doc-drift detector (offline, deterministic).
// Extracts a specific numeric claim from the doc ("up to N times") and
// compares it against the actual MAX_RETRIES constant in code. This is a
// narrow, single-claim-shape check — production doc-drift detection is a
// reasoning-lens job (see references in SKILL.md), not a deterministic
// scanner; this bench detector exists only to give the drift class a
// measurable, offline signal.

/**
 * @param {string} docSource
 * @param {string} codeSource
 * @returns {{docClaim:number, codeValue:number} | null} non-null only when they disagree
 */
export function scanDrift(docSource, codeSource) {
  const docMatch = docSource.match(/up to \*{0,2}(\d+)\*{0,2} times/i);
  const codeMatch = codeSource.match(/MAX_RETRIES\s*=\s*(\d+)/);
  if (!docMatch || !codeMatch) return null;
  const docClaim = Number(docMatch[1]);
  const codeValue = Number(codeMatch[1]);
  if (docClaim === codeValue) return null;
  return { docClaim, codeValue };
}
