import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';

export const DOMAIN_IDS = Object.freeze(['engineering', 'commercial', 'research', 'editorial', 'design']);
export const ADVISORY_DOMAIN_IDS = Object.freeze(DOMAIN_IDS.filter((id) => id !== 'engineering'));

const BUNDLES_BY_DOMAIN = Object.freeze({
  commercial: ['ads', 'marketing', 'social', 'seo'],
  research: ['research'],
  editorial: ['writing', 'content'],
  design: ['designer', 'brand-identity', 'brand'],
});

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function projectContentNodes(skillIndex) {
  const bundles = new Map((skillIndex?.bundles ?? []).map((bundle) => [bundle.id, bundle]));
  return Object.fromEntries(ADVISORY_DOMAIN_IDS.map((domainId) => [domainId, (BUNDLES_BY_DOMAIN[domainId] ?? [])
    .map((id) => bundles.get(id))
    .filter(Boolean)
    .map((bundle) => ({
      id: bundle.id,
      kind: 'capability',
      targetType: 'content',
      targetRef: bundle.manifest,
      availability: 'unavailable',
    }))]));
}

export function loadRoutingGraph(root) {
  const registry = readJson(resolve(root, 'registry/routing/domains.json'));
  const skillIndex = readJson(resolve(root, 'registry/skills/index.json'));
  const content = projectContentNodes(skillIndex);
  const domains = registry.domains.map((domain) => ({
    ...domain,
    children: domain.id === 'engineering' ? (domain.children ?? []) : content[domain.id],
  }));
  return { root, domains, skillIndex };
}

export function targetExists(root, node) {
  if (typeof node?.targetRef !== 'string' || !node.targetRef || isAbsolute(node.targetRef)) return false;
  const target = resolve(root, node.targetRef);
  const targetRelative = relative(root, target);
  return Boolean(targetRelative) && !targetRelative.startsWith('..') && !isAbsolute(targetRelative) && existsSync(target);
}
