// Claude Code harness binding — RETIRED as an installation path.
//
// The Claude plugin package (.claude-plugin/plugin.json) is now the single
// installation owner for Claude Code: it ships skills/, agents/, hooks/, and the
// legion MCP server natively, and scripts/verify-plugin-parity.mjs proves that
// surface resolves in full. `legion bind` previously ALSO wrote .claude/agents,
// .mcp.json, and a CLAUDE.md block for the same roles — two installers for one
// harness. That duplication is exactly what SSOT I-20 forbids, and it is what
// made the installed plugin's identity unreadable in practice.
//
// This module is kept only so the harness NAME still resolves for drift receipts
// and explicit-request handling. It detects nothing (so it is never an installer)
// and writes nothing. Development against the live tree uses the plugin, not
// bind: `npm run plugin:dev` prints the exact `claude --plugin-dir` invocation.
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export const NAME = 'claude-code';
export const FIDELITY_TIER = 'retired';
export const RETIRED = true;
export const RETIREMENT_NOTE =
  'Claude Code is installed by the Legion plugin package, not by legion bind. '
  + 'Use the plugin (npm run plugin:dev for the live-source dev command); '
  + 'bind no longer writes .claude/ for Claude Code (SSOT I-20: one installation path per harness).';

// Never auto-selected as an installer. A repo with .claude/ is a Claude Code
// repo, but its Legion installation owner is the plugin, so bind must not treat
// the directory's presence as a reason to write.
export function detect() {
  return false;
}

// Whether a Claude Code checkout is present at all — used only to decide whether
// the retirement note is worth surfacing when the harness is requested explicitly.
export function present(root) {
  return existsSync(join(root, '.claude'));
}

export function targets() {
  return [];
}

export function plan() {
  return [];
}

export function write() {
  return { wrote: [], wouldWrite: [] };
}
