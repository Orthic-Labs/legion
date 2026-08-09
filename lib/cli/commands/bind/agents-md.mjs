// AGENTS.md-only harness binding: for repos that carry AGENTS.md but no
// Claude Code (.claude/) — a generic bare-AGENTS.md consumer. Marker-
// delimited doctrine block in AGENTS.md. MCP registration is skipped: no
// existing "does this harness support MCP" probe exists anywhere in lib/ or
// an adapters/ dir to reuse, and the contract forbids inventing a new one.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { doctrineText } from './doctrine.mjs';
import { writeMarkerTarget } from './common.mjs';

export const NAME = 'agents-md';
export const FIDELITY_TIER = 'doctrine-only';
export const MCP_REGISTERED = false;

export function detect(root) {
  return existsSync(join(root, 'AGENTS.md')) && !existsSync(join(root, '.claude'));
}

function agentsMdTarget(root) {
  return {
    path: join(root, 'AGENTS.md'),
    kind: 'marker',
    reason: 'reference Legion orchestrator doctrine from AGENTS.md',
    blockContent: doctrineText('legion.md'),
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
