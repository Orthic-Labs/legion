// Bench-local duplication detector (offline, deterministic).
// Approximates jscpd: extracts top-level function bodies and flags a pair
// whose normalized bodies are byte-identical (ignoring whitespace/blank
// lines). Two functions merely SHAPED alike (same if/return skeleton) with
// different literals/conditions are not flagged — see AU20-008.

function extractFunctionBodies(source) {
  const bodies = [];
  const fnRegex = /function\s+(\w+)\s*\([^)]*\)\s*\{/g;
  let match;
  while ((match = fnRegex.exec(source))) {
    const start = match.index + match[0].length;
    let depth = 1;
    let i = start;
    while (i < source.length && depth > 0) {
      if (source[i] === "{") depth++;
      else if (source[i] === "}") depth--;
      i++;
    }
    const body = source.slice(start, i - 1);
    bodies.push({ name: match[1], body });
  }
  return bodies;
}

function normalize(body) {
  return body
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .join("\n");
}

/**
 * @param {string} source
 * @returns {{a:string, b:string}[]} pairs of function names with identical normalized bodies
 */
export function scanDuplication(source) {
  const fns = extractFunctionBodies(source);
  const pairs = [];
  for (let i = 0; i < fns.length; i++) {
    for (let j = i + 1; j < fns.length; j++) {
      if (normalize(fns[i].body) === normalize(fns[j].body)) {
        pairs.push({ a: fns[i].name, b: fns[j].name });
      }
    }
  }
  return pairs;
}
