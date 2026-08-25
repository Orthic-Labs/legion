// React framework pack: hooks/effects/state/performance/a11y/security and
// changed-scope parity fixtures. Deterministic structural rules only; no
// proprietary rule copying.

// React package names this pack detects. Exact-name matching is used for every signal that
// Blueprint itself provides, so a sibling like `preact` or `react-native` never counts as React.
const REACT_PACKAGES = new Set(['react', 'react-dom']);

function recordName(item) {
  if (typeof item === 'string') return item.toLowerCase();
  return String(item?.name ?? item?.id ?? item?.framework ?? '').toLowerCase();
}

function blueprintRecordSelectsReact(record) {
  if (Array.isArray(record)) return record.some((item) => REACT_PACKAGES.has(recordName(item)));
  if (record && typeof record === 'object') {
    return Object.entries(record).some(([name, item]) => REACT_PACKAGES.has(name.toLowerCase())
      || REACT_PACKAGES.has(recordName(item))
      || (item && typeof item === 'object' && Array.isArray(item.evidencePaths) && REACT_PACKAGES.has(String(name).toLowerCase())));
  }
  return false;
}

function manifestDeclaresReact(manifest) {
  const depLists = [manifest?.dependencies, manifest?.devDependencies, manifest?.peerDependencies, manifest?.optionalDependencies];
  for (const list of depLists) {
    if (Array.isArray(list) && list.some((name) => REACT_PACKAGES.has(String(name)))) return true;
    if (list && typeof list === 'object' && Object.keys(list).some((name) => REACT_PACKAGES.has(name))) return true;
  }
  return false;
}

// Nested-workspace selection signal. Legacy detection only saw the ROOT package manifests that
// collect-facts snapshots into auditFacts.packageManifests — a monorepo whose React dependency lives
// in a child package was suppressed as "not a React project". When Blueprint's projection explicitly
// selects React (stack-graph frameworks, selected-framework hints, or nested workspace manifests),
// detection honors it instead of being silenced by root-only evidence.
function blueprintSelectsNestedReact(projection) {
  if (blueprintRecordSelectsReact(projection?.frameworks ?? projection?.blueprint?.frameworks ?? null)) return true;
  const hints = projection?.selectedFrameworks ?? projection?.auditFacts?.selectedFrameworks ?? [];
  if (Array.isArray(hints) && hints.some((item) => REACT_PACKAGES.has(recordName(item)))) return true;
  const nested = projection?.auditFacts?.nestedPackageManifests ?? projection?.auditFacts?.workspaceManifests ?? [];
  if (Array.isArray(nested) && nested.some((manifest) => manifestDeclaresReact(manifest))) return true;
  return false;
}

export default Object.freeze({
  id: 'framework.react',
  version: '1.0.0',
  detect({ projection }) {
    // Legacy signal preserved verbatim (root + any snapshotted manifests mentioning react).
    const deps = projection?.auditFacts?.packageManifests ?? [];
    if (deps.some((manifest) => JSON.stringify(manifest).includes('react'))) return true;
    // Blueprint-selected nested React must not be suppressed by the legacy root-only check above.
    return blueprintSelectsNestedReact(projection);
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.(jsx|tsx|js|ts)$/.test(file)) continue;
      const text = readFile(file) ?? '';
      // Hooks rule: conditional hook calls violate the rules of hooks.
      if (/if\s*\([^)]*\)\s*\{\s*(?:useState|useEffect|useMemo|useCallback)\s*\(/.test(text)) {
        observations.push({
          ruleId: 'react.hooks.conditional-call',
          severityHint: 'high',
          claim: 'A React hook is called conditionally, violating the rules of hooks.',
          file,
        });
      }
      // Effects rule: missing dependency array.
      if (/useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,600}?\}\s*\)(?!\s*,\s*\[)/.test(text)) {
        observations.push({
          ruleId: 'react.effects.missing-deps',
          severityHint: 'medium',
          claim: 'useEffect is called without a dependency array.',
          file,
        });
      }
      // A11y: images without alt.
      if (/<img\b(?![\s\S]{0,200}alt=)/.test(text)) {
        observations.push({
          ruleId: 'react.a11y.img-alt',
          severityHint: 'medium',
          claim: 'An img element has no alt attribute.',
          file,
        });
      }
      // Security: dangerouslySetInnerHTML.
      if (/dangerouslySetInnerHTML\s*=/.test(text)) {
        observations.push({
          ruleId: 'react.security.dangerous-html',
          severityHint: 'high',
          claim: 'Raw HTML rendering requires a proven sanitization boundary.',
          file,
        });
      }
    }
    return observations;
  },
});
