// Codex harness binding: marker-delimited doctrine block appended to
// AGENTS.md. MCP registration would live in the user-global
// ~/.codex/config.toml (TOML read-modify-write), but this package has no
// TOML-parsing dependency in its tree and the contract forbids adding one —
// so the config.toml write is deferred (see bind's final report). The
// AGENTS.md doctrine block has no such dependency and is written normally.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { doctrineText } from './doctrine.mjs';
import { writeMarkerTarget } from './common.mjs';

export const NAME = 'codex';
export const FIDELITY_TIER = 'doctrine-only';

export function detect(root) {
  return existsSync(join(root, 'AGENTS.md'));
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
  return { wrote, wouldWrite: [], deferred: [{ target: '~/.codex/config.toml', reason: 'no TOML-parsing dependency in tree; adding one is out of scope' }] };
}
