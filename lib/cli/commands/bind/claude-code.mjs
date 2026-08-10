// Claude Code harness binding: doctrine agent files under .claude/agents/,
// an .mcp.json entry for the legion MCP server, and a marker-delimited
// doctrine include block in CLAUDE.md. Hook wiring into .claude/settings.json
// is deferred — no prior-art JSON shape exists in this repo or D:/Claude's
// settings.json to match against (see bind's final report).

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { doctrineText } from './doctrine.mjs';
import { upsertMarkerBlock, writeMarkerTarget, writeIfDifferent } from './common.mjs';
import { mcpInstallConfig } from '../../../../integrations/mcp/install.mjs';

export const NAME = 'claude-code';
export const FIDELITY_TIER = 'full';

export function detect(root) {
  return existsSync(join(root, '.claude'));
}

// { target: installed filename under .claude/agents/, source: doctrine/ filename }.
const AGENT_PROJECTIONS = [
  { target: 'sage.md', source: 'sage.md' },
  { target: 'alchemist.md', source: 'alchemist.md' },
  { target: 'oracle.md', source: 'oracle.md' },
  { target: 'covenant-seat.md', source: 'covenant-seat.md' },
];

function mcpTarget(root) {
  const path = join(root, '.mcp.json');
  let existing = {};
  if (existsSync(path)) {
    try { existing = JSON.parse(readFileSync(path, 'utf8')); } catch { existing = {}; }
  }
  const merged = { ...existing, mcpServers: { ...(existing.mcpServers ?? {}), legion: mcpInstallConfig().mcpServers.legion } };
  return { path, kind: 'whole', reason: 'register the legion MCP server in .mcp.json', content: `${JSON.stringify(merged, null, 2)}\n` };
}

function claudeMdTarget(root) {
  const path = join(root, 'CLAUDE.md');
  // Embedded verbatim (not an @-include pointer) so the block is
  // self-contained even when doctrine/ isn't shipped into the target repo.
  return { path, kind: 'marker', reason: 'include Legion orchestrator doctrine in CLAUDE.md', blockContent: doctrineText('legion.md') };
}

// Pure, read-only: derives the exact target list (paths, kinds, and the
// content each write would produce) from doctrine/ and current disk state.
export function targets(root) {
  const agentTargets = AGENT_PROJECTIONS.map(({ target, source }) => ({
    path: join(root, '.claude', 'agents', target),
    kind: 'whole',
    reason: `install ${target} doctrine agent`,
    content: doctrineText(source),
  }));
  return [...agentTargets, mcpTarget(root), claudeMdTarget(root)];
}

export function plan(root) {
  return targets(root).map(({ path, reason }) => ({ path, reason }));
}

export function write(root) {
  const wrote = [];
  for (const target of targets(root)) {
    if (target.kind === 'marker') {
      writeMarkerTarget(target.path, target.blockContent);
    } else {
      writeIfDifferent(target.path, target.content);
    }
    wrote.push(target.path);
  }
  return { wrote, wouldWrite: [] };
}
