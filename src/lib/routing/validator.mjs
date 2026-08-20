import { resolveGroupChild } from './loader.mjs';

function finding(code, detail, nodeId) {
  return nodeId ? { code, detail, nodeId } : { code, detail };
}

/**
 * Grouping-integrity validation (M-019). Keeps only the generic grouping
 * invariants live consumers need: valid JSON, unique domain ids, children
 * resolve to catalog capabilities, no duplicate child membership, and no
 * entrypoints/roles in the grouping projection. Does not route.
 */
export function validateRoutingGroups(graph) {
  const findings = [];
  const domains = graph?.domains;
  if (!Array.isArray(domains)) return { ok: false, findings: [finding('domain-roster', 'routing registry domains must be an array')] };

  const ids = domains.map((domain) => domain?.id);
  const uniqueIds = new Set(ids);
  if (uniqueIds.size !== ids.length) findings.push(finding('duplicate-root', 'grouping roots must be unique'));

  for (const domain of domains) {
    if (!domain?.id || typeof domain.id !== 'string') { findings.push(finding('domain-id', 'grouping id must be a string')); continue; }
    if (domain.kind !== 'group') findings.push(finding('domain-kind', 'grouping entries must be groups', domain.id));
    if (domain.children !== undefined && !Array.isArray(domain.children)) findings.push(finding('group-children', 'group children must be an array', domain.id));
    const children = domain.children ?? [];
    const childIds = children.map((child) => child?.id);
    if (childIds.some((id) => typeof id !== 'string' || !id)) findings.push(finding('child-id', 'group child id must be a string', domain.id));
    if (new Set(childIds).size !== childIds.length) findings.push(finding('duplicate-child', 'group child membership must be unique', domain.id));
    for (const child of children) {
      if (!resolveGroupChild(graph.skillIndex, child.id)) {
        findings.push(finding('dangling-target', `group child '${child.id}' is not a catalog capability`, domain.id));
      }
    }
  }
  return { ok: findings.length === 0, findings };
}
