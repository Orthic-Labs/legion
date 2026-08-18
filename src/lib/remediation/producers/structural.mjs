// Qualified structural remediation producers (B7-031).
//
// Each producer is bound to specific rule ids and performs one narrow,
// well-understood rewrite. There is deliberately no generic search-and-replace
// producer: a transform that cannot name the rule it fixes does not belong
// here. Producers only PREVIEW — this module imports no filesystem API and has
// no apply path.

function editsFor(text, pattern, replacement) {
  const edits = [];
  text.split('\n').forEach((line, index) => {
    pattern.lastIndex = 0;
    const after = line.replace(pattern, replacement);
    if (after === line) return;
    edits.push({ line: index + 1, before: line, after });
  });
  return edits;
}

/**
 * Apply preview edits to text. Pure and idempotent: an edit whose `before` line
 * no longer matches is skipped rather than re-applied, and every unrelated byte
 * is copied through untouched.
 */
export function renderStructuralPreview(text, edits) {
  if (!edits?.length) return text;
  const lines = text.split('\n');
  for (const edit of edits) {
    const index = edit.line - 1;
    if (lines[index] !== edit.before) continue;
    lines[index] = edit.after;
  }
  return lines.join('\n');
}

const REJECT_UNAUTHORIZED = /\brejectUnauthorized\s*:\s*false\b/g;
const INNER_HTML_ASSIGN = /\.innerHTML(\s*)=/g;

export const STRUCTURAL_PRODUCERS = Object.freeze([
  Object.freeze({
    id: 'structural.tls-reject-unauthorized',
    version: '1.0.0',
    kind: 'structural',
    risk: 'low',
    ruleIds: Object.freeze(['insecure-defaults.tls-reject-unauthorized']),
    description: 'Restore TLS certificate verification by setting rejectUnauthorized back to true.',
    preconditions: Object.freeze([
      'the literal `rejectUnauthorized: false` appears in the finding file',
      'the enclosing object is a TLS/HTTPS agent or request option object',
    ]),
    expectedBehavior: Object.freeze(['TLS peer certificates are verified again']),
    affectedFamilies: Object.freeze(['security']),
    validationPlan: Object.freeze(['parse-check', 'affected-provider-rerun:security.insecure-defaults']),
    preview({ path, text }) {
      return { path, edits: editsFor(text, REJECT_UNAUTHORIZED, 'rejectUnauthorized: true'), publicSurfaceChanges: [] };
    },
  }),
  Object.freeze({
    id: 'structural.dom-innerhtml-to-textcontent',
    version: '1.0.0',
    kind: 'structural',
    risk: 'low',
    ruleIds: Object.freeze(['output-handling.dom-innerhtml']),
    description: 'Replace an innerHTML sink assignment with textContent so the value is not parsed as markup.',
    preconditions: Object.freeze([
      'the assignment target is a DOM element',
      'the assigned value is not intentionally-trusted markup',
    ]),
    expectedBehavior: Object.freeze(['the assigned value renders as text, not markup']),
    affectedFamilies: Object.freeze(['security', 'ux']),
    validationPlan: Object.freeze(['parse-check', 'affected-provider-rerun:security.output-handling']),
    preview({ path, text }) {
      return { path, edits: editsFor(text, INNER_HTML_ASSIGN, '.textContent$1='), publicSurfaceChanges: [] };
    },
  }),
]);
