// Qualified configuration remediation producers (B7-031).
//
// Configuration fixes address one exact key path with one known-safe value.
// Like the structural producers these only PREVIEW: no filesystem API is
// imported and no apply path exists here.

function getIn(value, keyPath) {
  return keyPath.reduce((node, key) => (node && typeof node === 'object' ? node[key] : undefined), value);
}

function setIn(value, keyPath, next) {
  const [head, ...rest] = keyPath;
  const base = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  return { ...base, [head]: rest.length === 0 ? next : setIn(base[head], rest, next) };
}

/**
 * Apply config preview edits. Pure and idempotent: an edit whose key already
 * holds the target value is skipped, unrelated keys are preserved, and the
 * document is re-serialized with the indentation it was read with.
 */
export function renderConfigPreview(text, edits) {
  if (!edits?.length) return text;
  let document = JSON.parse(text);
  for (const edit of edits) {
    if (getIn(document, edit.keyPath) === edit.value) continue;
    document = setIn(document, edit.keyPath, edit.value);
  }
  const indent = /\n(\s+)\S/.exec(text)?.[1]?.length ?? 2;
  const trailingNewline = text.endsWith('\n') ? '\n' : '';
  return JSON.stringify(document, null, indent) + trailingNewline;
}

function keySetProducer({ id, ruleIds, description, keyPath, value, expectedBehavior, affectedFamilies, preconditions, validationPlan }) {
  return Object.freeze({
    id,
    version: '1.0.0',
    kind: 'config',
    risk: 'low',
    ruleIds: Object.freeze([...ruleIds]),
    description,
    preconditions: Object.freeze([...preconditions]),
    expectedBehavior: Object.freeze([...expectedBehavior]),
    affectedFamilies: Object.freeze([...affectedFamilies]),
    validationPlan: Object.freeze([...validationPlan]),
    preview({ path, text }) {
      let document;
      try {
        document = JSON.parse(text);
      } catch {
        // An unparseable configuration is not a mechanical fix.
        return { path, edits: [], publicSurfaceChanges: [], unsupported: 'configuration is not valid JSON' };
      }
      if (getIn(document, keyPath) === value) return { path, edits: [], publicSurfaceChanges: [] };
      return {
        path,
        edits: [{ keyPath: [...keyPath], value, previous: getIn(document, keyPath) ?? null }],
        publicSurfaceChanges: [],
      };
    },
  });
}

export const CONFIG_PRODUCERS = Object.freeze([
  keySetProducer({
    id: 'config.cookie-samesite',
    ruleIds: ['browser-http.cookie-samesite'],
    description: 'Set the session cookie SameSite attribute to lax.',
    keyPath: ['cookie', 'sameSite'],
    value: 'lax',
    preconditions: ['the configuration declares a cookie object', 'no cross-site POST flow depends on SameSite=none'],
    expectedBehavior: ['session cookies are not sent on cross-site subrequests'],
    affectedFamilies: ['security'],
    validationPlan: ['config-schema-check', 'affected-provider-rerun:security.browser-client'],
  }),
  keySetProducer({
    id: 'config.content-type-nosniff',
    ruleIds: ['browser-http.content-type-nosniff'],
    description: 'Set the X-Content-Type-Options response header to nosniff.',
    keyPath: ['headers', 'X-Content-Type-Options'],
    value: 'nosniff',
    preconditions: ['the configuration declares a response headers object'],
    expectedBehavior: ['browsers stop MIME-sniffing responses'],
    affectedFamilies: ['security'],
    validationPlan: ['config-schema-check', 'affected-provider-rerun:security.http-protocol-cache'],
  }),
]);
