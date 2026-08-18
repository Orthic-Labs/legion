import { loadRoutingGraph } from './loader.mjs';
import { validateRoutingGraph } from './validator.mjs';

export function resolveDomain(root, domainId) {
  const graph = loadRoutingGraph(root);
  const validation = validateRoutingGraph(graph);
  if (!validation.ok) return { status: 'invalid', domainId, findings: validation.findings };
  const domain = graph.domains.find(({ id }) => id === domainId);
  if (!domain) return { status: 'not-found', domainId };
  if (domain.availability === 'unavailable') {
    return { status: 'unavailable', domainId, availability: 'unavailable', capabilities: domain.children ?? [] };
  }
  return { status: 'resolved', domainId, capabilities: domain.children ?? [] };
}
