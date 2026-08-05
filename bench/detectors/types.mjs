// Bench-local type-error detector (offline, deterministic).
// HONEST LIMITATION: this is a narrow regex heuristic, not a real type
// checker. `tsc` is not installed/cached offline in this environment, so
// this only catches the specific obvious-literal-mismatch shape planted in
// AU20-009 (`const x: number = "a string literal"`). It is not a substitute
// for the production `types` check in collect-facts.mjs, which shells out
// to tsc/basedpyright/mypy. Documented as a bench gap in SKILL.md.

const STRING_LITERAL = /^"[^"]*"$|^'[^']*'$|^`[^`]*`$/;

/**
 * @param {string} source
 * @returns {{line:number, text:string}[]}
 */
export function scanTypes(source) {
  const findings = [];
  const lines = source.split("\n");
  lines.forEach((line, idx) => {
    const m = line.match(/const\s+\w+\s*:\s*number\s*=\s*(.+?);/);
    if (m && STRING_LITERAL.test(m[1].trim())) {
      findings.push({ line: idx + 1, text: line.trim() });
    }
    const m2 = line.match(/const\s+\w+\s*:\s*string\s*=\s*(-?\d+(\.\d+)?)\s*;/);
    if (m2) {
      findings.push({ line: idx + 1, text: line.trim() });
    }
  });
  return findings;
}
