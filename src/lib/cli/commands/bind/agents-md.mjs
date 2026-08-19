// AGENTS.md-only harness binding: for repos that carry AGENTS.md but no
// Claude Code (.claude/) — a generic bare-AGENTS.md consumer. Marker-
// delimited doctrine block in AGENTS.md. MCP registration is skipped: no
// existing "does this harness support MCP" probe exists anywhere in lib/ or
// an adapters/ dir to reuse, and the contract forbids inventing a new one.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { lowFidelityProjection } from '../../../roster/index.mjs';
import { capabilityCatalogBlock } from '../../../host-projection.mjs';
import { writeMarkerTarget } from './common.mjs';

export const NAME = 'agents-md';
export const FIDELITY_TIER = 'doctrine-only';
export const MCP_REGISTERED = false;

export function detect(root) {
  return existsSync(join(root, 'AGENTS.md')) && !existsSync(join(root, '.claude'));
}

// Roles alone were never Legion. This projection previously carried the three
// authorities and no capabilities at all, so a harness reaching Legion this way
// could route to Sage but had no idea `audit`, `architect`, or `designer`
// existed. The compact catalog (SSOT 23 layer 1) is added: names and one-line
// descriptions only, so selection is possible without preloading any method.
function agentsMdTarget(root) {
  const catalog = capabilityCatalogBlock();
  return {
    path: join(root, 'AGENTS.md'),
    kind: 'marker',
    reason: 'install low-fidelity Legion authority context and capability catalog in AGENTS.md',
    blockContent: catalog ? `${lowFidelityProjection()}\n\n${catalog}` : lowFidelityProjection(),
  };
}

export function targets(root) {
  return [agentsMdTarget(root)];
}

export function plan(root) {
  return targets(root).map(({ path, reason }) => ({ path, reason }));
}

export function write(root) {
  const wrote = [];
  for (const target of targets(root)) {
    writeMarkerTarget(target.path, target.blockContent);
    wrote.push(target.path);
  }
  return { wrote, wouldWrite: [], mcpRegistered: false };
}
