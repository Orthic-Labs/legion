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


// QUARANTINED as an auto-selected installer (host/runtime cleanup, 2026-08-20).
//
// The descriptor-driven harness seam (src/lib/host/) is now the installer for
// this harness's AGENTS.md instructions block. Two installers competing for one surface is the
// failure the one-installation-owner invariant forbids and the precedent already applied to bind's Claude
// Code writer. `detect()` therefore returns false: `legion bind --write` with no
// explicit --harness will never select this writer.
//
// It is QUARANTINED rather than deleted because it still carries the legacy
// migration paths the seam does not have (the low-fidelity roster-only projection). Those run only when the
// operator asks for this harness by name. New installations use
// `legion harness install generic`.
export const QUARANTINED = true;
export const QUARANTINE_NOTE =
  'legion bind no longer auto-selects generic; the harness adapter seam installs it '
  + '(legion harness install generic). This writer remains reachable only via an explicit '
  + '--harness generic, for its legacy migration paths.';

// Never auto-selected. A repo with AGENTS.md is not evidence that bind should
// write it — the harness seam's instructions surface owns that file now.
export function detect() {
  return false;
}

/** Whether a bare-AGENTS.md repo is present at all; used only for reporting. */
export function present(root) {
  return existsSync(join(root, 'AGENTS.md')) && !existsSync(join(root, '.claude'));
}

// Roles alone were never Legion. This projection previously carried the three
// authorities and no capabilities at all, so a harness reaching Legion this way
// could route to Sage but had no idea `audit`, `architect`, or `designer`
// existed. The compact catalog is added: names and one-line
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
