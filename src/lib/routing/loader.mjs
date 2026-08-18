import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';

export const DOMAIN_IDS = Object.freeze(['engineering', 'commercial', 'research', 'editorial', 'design']);
export const ADVISORY_DOMAIN_IDS = Object.freeze(DOMAIN_IDS.filter((id) => id !== 'engineering'));

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Projects advisory children from the registry, which is the single source of
 * domain membership. A second hardcoded map used to shadow it, so registry
 * edits silently did nothing.
 *
 * `availability` is derived from whether the leaf can actually be reached: its
 * manifest must resolve inside the package and name an entrypoint that exists.
 * It was previously hardcoded 'unavailable', which let resolveDomain report a
 * domain 'resolved' while nothing under it could be dispatched.
 */
export function projectContentNodes(skillIndex, registryDomains = [], root = null) {
  const bundles = new Map((skillIndex?.bundles ?? []).map((bundle) => [bundle.id, bundle]));
  const childIds = new Map(registryDomains.map((domain) => [domain.id, (domain.children ?? []).map(({ id }) => id)]));
  return Object.fromEntries(ADVISORY_DOMAIN_IDS.map((domainId) => [domainId, (childIds.get(domainId) ?? [])
    .map((id) => bundles.get(id))
    .filter(Boolean)
    .map((bundle) => {
      const node = {
        id: bundle.id,
        kind: 'capability',
        targetType: 'content',
        targetRef: bundle.manifest,
      };
      node.availability = root && reachable(root, node) ? 'available' : 'unavailable';
      return node;
    })]));
}

export function loadRoutingGraph(root) {
  const registry = readJson(resolve(root, 'src/registry/routing/domains.json'));
  const skillIndex = readJson(resolve(root, 'src/registry/skills/index.json'));
  const content = projectContentNodes(skillIndex, registry.domains, root);
  const domains = registry.domains.map((domain) => ({
    ...domain,
    children: domain.id === 'engineering' ? (domain.children ?? []) : content[domain.id],
  }));
  return { root, domains, skillIndex };
}


/** A leaf is reachable when its manifest resolves and its entrypoint exists. */
function reachable(root, node) {
  if (!targetExists(root, node)) return false;
  try {
    const manifest = JSON.parse(readFileSync(resolve(root, node.targetRef), 'utf8'));
    if (typeof manifest.entry !== 'string' || !manifest.entry) return false;
    return existsSync(resolve(root, 'skills', node.id, manifest.entry));
  } catch { return false; }
}

export function targetExists(root, node) {
  if (typeof node?.targetRef !== 'string' || !node.targetRef || isAbsolute(node.targetRef)) return false;
  const target = resolve(root, node.targetRef);
  const targetRelative = relative(root, target);
  return Boolean(targetRelative) && !targetRelative.startsWith('..') && !isAbsolute(targetRelative) && existsSync(target);
}
