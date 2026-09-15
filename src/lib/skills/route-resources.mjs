// Route/adapter-scoped resource tables.
//
// A bundle's `references/route-resources.json` declares resources that bind only
// inside a named scope — a provider, adapter, method, domain, or workflow — rather
// than for every use of the capability. Global requirements stay in SKILL.md
// `hostRequirements`; this table is where an optional adapter or a single research
// route keeps the host capabilities it alone needs.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const ROUTE_RESOURCES = 'references/route-resources.json';

const SCOPE_KINDS = Object.freeze({
  adapters: 'adapter',
  domains: 'domain',
  methods: 'method',
  providers: 'provider',
  workflows: 'workflow',
});

/** Load a bundle's route resource table, or null when it does not declare one. */
export function routeResourceTable(skillRoot) {
  const path = join(skillRoot, ROUTE_RESOURCES);
  if (!existsSync(path)) return null;
  try {
    const document = JSON.parse(readFileSync(path, 'utf8'));
    return document && typeof document === 'object' && !Array.isArray(document) ? document : null;
  } catch {
    return null;
  }
}

/** Capability ids a bundle declares only inside named route/adapter scopes. */
export function scopedHostCapabilities(skillRoot) {
  const scoped = new Set();
  const document = routeResourceTable(skillRoot);
  if (!document) return scoped;
  for (const table of Object.values(document)) {
    if (!table || typeof table !== 'object' || Array.isArray(table)) continue;
    for (const entries of Object.values(table)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        if (entry?.class === 'HOST_CAPABILITY' && typeof entry.capability === 'string') {
          scoped.add(entry.capability);
        }
      }
    }
  }
  return scoped;
}

/**
 * Scoped host requirements with their registry detail, one row per
 * (scope, capability) pair. `scope` names the binding (`provider:notebooklm`,
 * `adapter:omniroute-codex-worker`); `scopeKind` is the section singular.
 */
export function scopedRequirementDetails(skillRoot, registry, { id = '<unknown>' } = {}) {
  const document = routeResourceTable(skillRoot);
  if (!document) return [];
  const scoped = [];
  for (const [section, table] of Object.entries(document)) {
    if (!table || typeof table !== 'object' || Array.isArray(table)) continue;
    const scopeKind = SCOPE_KINDS[section] ?? section.replace(/s$/, '');
    for (const [key, entries] of Object.entries(table)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        if (entry?.class !== 'HOST_CAPABILITY' || typeof entry.capability !== 'string') continue;
        const capability = registry.capabilities?.[entry.capability];
        if (!capability) {
          throw new Error(`skills/${id}/${ROUTE_RESOURCES} declares host capability absent from registry: ${entry.capability}`);
        }
        scoped.push({
          scope: `${scopeKind}:${key}`,
          scopeKind,
          id: entry.capability,
          kind: capability.kind,
          summary: capability.summary,
          degradation: capability.degradation,
          remedy: capability.remedy,
          probe: capability.probe ?? null,
        });
      }
    }
  }
  return scoped.sort((a, b) => a.scope.localeCompare(b.scope) || a.id.localeCompare(b.id));
}
