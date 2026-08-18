// Monorepo component identity per SNIP-MONOREPO-01. Component-aware provider
// denominators; the final report retains both component and repository scope.
// One failing/unmeasured package cannot be hidden by aggregate success.

import { createHash } from 'node:crypto';

export function stableId(namespace, value) {
  const body = JSON.stringify(value);
  return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
}

export function componentIdentity({ repoId, manifestPath, packageName }) {
  return {
    id: stableId('component', { repoId, manifestPath, packageName }),
    root: null,
    manifestPath,
    packageManager: inferPackageManager(manifestPath),
    languageIds: [],
    frameworkIds: [],
    dependencies: [],
    dependents: [],
    generatedPaths: [],
    vendoredPaths: [],
  };
}

export function inferPackageManager(manifestPath) {
  if (/package\.json$/.test(manifestPath)) return 'npm';
  if (/pyproject\.toml|setup\.py|requirements/.test(manifestPath)) return 'pip';
  if (/Cargo\.toml$/.test(manifestPath)) return 'cargo';
  if (/go\.mod$/.test(manifestPath)) return 'go';
  if (/pom\.xml$/.test(manifestPath)) return 'maven';
  if (/build\.gradle/.test(manifestPath)) return 'gradle';
  if (/Gemfile/.test(manifestPath)) return 'bundler';
  return 'unknown';
}

export function componentDenominator(components, { exclude = [] } = {}) {
  const kept = components.filter((component) => !exclude.includes(component.manifestPath));
  return {
    componentCount: kept.length,
    components: kept.map((component) => component.id).sort(),
    digest: stableId('component-denominator', kept.map((c) => c.id).sort()),
  };
}

export function reconcileComponents(components, results) {
  const byId = new Map(components.map((component) => [component.id, component]));
  const incomplete = [];
  for (const result of results ?? []) {
    if (!result.complete) {
      const component = byId.get(result.componentId);
      incomplete.push({ componentId: result.componentId, manifestPath: component?.manifestPath ?? null, status: result.status });
    }
  }
  return {
    schemaVersion: 1,
    kind: 'legion-component-reconciliation',
    componentCount: components.length,
    complete: incomplete.length === 0,
    incomplete,
  };
}
