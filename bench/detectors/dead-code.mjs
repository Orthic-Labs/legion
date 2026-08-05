// Bench-local dead-code detector (offline, deterministic).
// Approximates knip/eslint's unreachable-code check: flags statements that
// follow an unconditional `return`/`throw` inside the same block, at the
// same or lesser indentation (i.e. still inside that block, not a sibling
// function). Deliberately narrow to avoid false positives on the negative
// control (AU20-006), which has no unreachable statements at all.

/**
 * @param {string} source
 * @returns {{line:number, text:string}[]}
 */
export function scanDeadCode(source) {
  const lines = source.split("\n");
  const findings = [];
  let sawReturnAtIndent = null; // indent level of the return/throw line

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const indent = line.length - line.trimStart().length;

    if (sawReturnAtIndent !== null) {
      if (trimmed === "" || trimmed.startsWith("//")) continue;
      if (indent < sawReturnAtIndent || trimmed === "}") {
        // Left the block the return was in — stop tracking.
        sawReturnAtIndent = null;
      } else {
        findings.push({ line: i + 1, text: trimmed });
        continue;
      }
    }

    if (/^(return\b.*;|throw\b.*;)/.test(trimmed)) {
      sawReturnAtIndent = indent;
    }
  }
  return findings;
}
