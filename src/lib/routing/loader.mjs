import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';

/**
 * Grouping-integrity loader (M-019). Domains are optional grouping metadata
 * only — they never decide routing. The routing registry is a generated
 * projection (scripts/generate-skill-catalog.mjs) grouping `kind: capability`
 * entries by their optional `domain` label.
 *
 * There is no fixed exactly-five-domain invariant, no engineering/advisory
 * distinction, and no role-as-domain-leaf semantics. Entrypoints and roles do
 * not appear in the grouping projection.
 */

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function loadRoutingGroups(root) {
  const registry = readJson(resolve(root, 'src/registry/routing/domains.json'));
  const skillIndex = readJson(resolve(root, 'src/registry/skills/index.json'));
  return { root, domains: registry.domains ?? [], skillIndex };
}

/** A child is a catalog capability id resolved through the canonical catalog. */
export function resolveGroupChild(skillIndex, childId) {
  const bundles = new Map((skillIndex?.bundles ?? []).map((bundle) => [bundle.id, bundle]));
  const bundle = bundles.get(childId);
  if (!bundle) return null;
  return { id: bundle.id, manifest: bundle.manifest };
}

/** Backwards-compatible reachability: a leaf is reachable when its manifest resolves. */
export function targetExists(root, node) {
  if (typeof node?.targetRef !== 'string' || !node.targetRef || isAbsolute(node.targetRef)) return false;
  const target = resolve(root, node.targetRef);
  const targetRelative = relative(root, target);
  return Boolean(targetRelative) && !targetRelative.startsWith('..') && !isAbsolute(targetRelative) && existsSync(target);
}
