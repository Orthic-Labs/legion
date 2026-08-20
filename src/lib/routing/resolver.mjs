import { loadRoutingGroups } from './loader.mjs';
import { validateRoutingGroups } from './validator.mjs';
import { resolveGroupChild } from './loader.mjs';

/** Grouping lookup only — domains never route (M-019). */
export function resolveDomain(root, domainId) {
  const graph = loadRoutingGroups(root);
  const validation = validateRoutingGroups(graph);
  if (!validation.ok) return { status: 'invalid', domainId, findings: validation.findings };
  const domain = graph.domains.find(({ id }) => id === domainId);
  if (!domain) return { status: 'not-found', domainId };
  const capabilities = (domain.children ?? [])
    .map((child) => resolveGroupChild(graph.skillIndex, child.id))
    .filter(Boolean);
  return { status: 'resolved', domainId, capabilities };
}
