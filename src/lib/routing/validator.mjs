import { ADVISORY_DOMAIN_IDS, DOMAIN_IDS, targetExists } from './loader.mjs';

const DOMAIN_SET = new Set(DOMAIN_IDS);
const ADVISORY_SET = new Set(ADVISORY_DOMAIN_IDS);
const TARGET_TYPES = new Set(['agent-dispatch', 'content']);

function finding(code, detail, nodeId) {
  return nodeId ? { code, detail, nodeId } : { code, detail };
}

function validateNode(node, { root, domainId, findings }) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    findings.push(finding('node-shape', 'routing node must be an object'));
    return;
  }
  if (typeof node.id !== 'string' || !/^[a-z][a-z0-9-]*$/.test(node.id)) findings.push(finding('node-id', 'routing node id must be canonical', node.id));
  if (node.kind === 'router') {
    if ('targetType' in node || 'targetRef' in node) findings.push(finding('router-target', 'routers cannot have targets', node.id));
    if (node.children !== undefined && !Array.isArray(node.children)) findings.push(finding('router-children', 'router children must be an array', node.id));
    for (const child of node.children ?? []) validateNode(child, { root, domainId, findings });
    return;
  }
  if (node.kind !== 'capability') {
    findings.push(finding('node-kind', 'node kind must be router or capability', node.id));
    return;
  }
  if (node.children !== undefined) findings.push(finding('capability-children', 'capabilities cannot have children', node.id));
  if (!TARGET_TYPES.has(node.targetType)) findings.push(finding('target-type', 'capability target type must be agent-dispatch or content', node.id));
  if (typeof node.targetRef !== 'string' || !node.targetRef) findings.push(finding('target-ref', 'capability target ref is required', node.id));
  else if (!targetExists(root, node)) findings.push(finding('dangling-target', 'capability target does not exist', node.id));
  if (domainId === 'engineering' && node.targetType !== 'agent-dispatch') findings.push(finding('mixed-leaf-type', 'engineering may terminate only in agent dispatches', node.id));
  if (ADVISORY_SET.has(domainId) && node.targetType !== 'content') findings.push(finding('mixed-leaf-type', 'advisory domains may terminate only in content', node.id));
}

export function validateRoutingGraph(graph) {
  const findings = [];
  const domains = graph?.domains;
  if (!Array.isArray(domains)) return { ok: false, findings: [finding('domain-roster', 'routing registry domains must be an array')] };
  const ids = domains.map((domain) => domain?.id);
  const uniqueIds = new Set(ids);
  if (uniqueIds.size !== ids.length) findings.push(finding('duplicate-root', 'routing roots must be unique'));
  if (ids.length !== DOMAIN_IDS.length || DOMAIN_IDS.some((id) => !uniqueIds.has(id)) || ids.some((id) => !DOMAIN_SET.has(id))) {
    findings.push(finding('noncanonical-roots', 'routing registry must contain exactly five canonical domains'));
  }
  for (const domain of domains) {
    if (domain?.kind !== 'router') findings.push(finding('domain-kind', 'root domains must be routers', domain?.id));
    if (domain?.availability && !['available', 'unavailable'].includes(domain.availability)) findings.push(finding('availability', 'availability must be available or unavailable', domain?.id));
    validateNode(domain, { root: graph.root, domainId: domain?.id, findings });
  }
  return { ok: findings.length === 0, findings };
}
