// `legion doctor` host-projection diagnosis.
//
// An operator must be able to answer "why does my harness not see Legion?"
// without reading source. The failures this exists to name are all real and all
// were diagnosed by hand during the host-integration work:
//
//   - the plugin was disabled in settings, so no skill or agent was discovered;
//   - the installed copy was a stale snapshot with a different internal layout
//     than the working tree, while its version string was unchanged;
//   - two installation paths (the plugin package and `legion bind`) both owned
//     the same harness, so hook and agent registrations were duplicated;
//   - an effect gate was registered for tools it could not classify, and not
//     registered for tools it could.
//
// Read-only: this inspects state and reports, never repairs.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import * as harnessRegistry from '../../host/registry.mjs';

const readJson = (path) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; } };

const CODEX_HOOK_EVENTS = Object.freeze([
  'session_start', 'subagent_start', 'user_prompt_submit', 'post_compact',
  'pre_tool_use', 'post_tool_use', 'post_tool_use_failure', 'stop',
]);
const CODEX_TRUSTED_HASH = /^sha256:[0-9a-f]{64}$/;

/** Read Codex's native hook trust without writing or deriving trust hashes. */
export function codexHookTrust(home = homedir()) {
  const configPath = join(home, '.codex', 'config.toml');
  let text = '';
  try { text = readFileSync(configPath, 'utf8'); } catch { /* absent config is typed below */ }
  const trusted = new Set();
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    const table = /^\[hooks\.state\."([^"]+)"\]\s*$/.exec(line.trim());
    if (table) { current = table[1]; continue; }
    const hash = /^trusted_hash\s*=\s*"([^"]*)"\s*$/.exec(line.trim());
    if (hash && current && CODEX_HOOK_EVENTS.some((event) => current === `arcane@local-brief:hooks/hooks.json:${event}:0:0`) && CODEX_TRUSTED_HASH.test(hash[1])) trusted.add(current);
  }
  const required = CODEX_HOOK_EVENTS.map((event) => `arcane@local-brief:hooks/hooks.json:${event}:0:0`);
  const missing = required.filter((key) => !trusted.has(key));
  return {
    configPath,
    configPresent: Boolean(text),
    plugin: 'arcane@local-brief',
    required,
    trusted: [...trusted].sort(),
    missing,
    state: missing.length === 0 ? 'pass' : 'ARC_HOOK_TRUST_REQUIRED',
    remediation: missing.length === 0 ? null : 'Review & trust current Arcane hooks with Codex /hooks; setup never manufactures trusted_hash.',
  };
}

/**
 * Claude Code installation identity: which source is active, whether it is the
 * live tree or a packaged copy, and whether that copy still matches the tree.
 */
function claudeInstallation(root, home) {
  const settings = readJson(join(home, '.claude', 'settings.json')) ?? {};
  // installed_plugins.json is {version, plugins:{<id>:[record,...]}}; older
  // layouts put the ids at the top level, so accept both rather than silently
  // reporting "not installed" for a plugin that is.
  const installedFile = readJson(join(home, '.claude', 'plugins', 'installed_plugins.json')) ?? {};
  const installed = installedFile.plugins ?? installedFile;
  const manifest = readJson(join(root, '.claude-plugin', 'plugin.json'));
  const entries = [];
  for (const [pluginId, records] of Object.entries(installed)) {
    if (!pluginId.startsWith('legion@')) continue;
    for (const record of Array.isArray(records) ? records : [records]) {
      const installPath = record?.installPath ?? null;
      // A packaged copy whose layout differs from the source it claims to come
      // from cannot serve the source's manifest: the MCP entry point and hook
      // paths are resolved inside the copy.
      const layoutMatches = installPath && existsSync(installPath)
        ? existsSync(join(installPath, 'src', 'packages')) === existsSync(join(root, 'src', 'packages'))
        : null;
      entries.push({
        pluginId,
        enabled: settings.enabledPlugins?.[pluginId] === true,
        scope: record?.scope ?? null,
        installPath,
        installedVersion: record?.version ?? null,
        sourceVersion: manifest?.version ?? null,
        versionMatches: record?.version === manifest?.version,
        gitCommitSha: record?.gitCommitSha ?? null,
        installedAt: record?.installedAt ?? null,
        copyExists: Boolean(installPath && existsSync(installPath)),
        layoutMatchesSource: layoutMatches,
      });
    }
  }
  return entries;
}

/** What the packaged plugin would actually expose to Claude Code. */
function claudeDiscovery(root) {
  const manifest = readJson(join(root, '.claude-plugin', 'plugin.json'));
  const hooks = readJson(join(root, 'hooks', 'hooks.json'));
  const projection = readJson(join(root, 'src', 'registry', 'host-projection.json'));
  // The committed plugin surface: the structural digest that a packaged copy
  // must carry to prove it matches its version (scripts/verify-plugin-parity.mjs).
  const surface = readJson(join(root, 'src', 'registry', 'plugin-surface.json'));
  const mcpArgs = Object.values(manifest?.mcpServers ?? {}).flatMap((server) => server?.args ?? []);
  return {
    manifestPresent: Boolean(manifest),
    version: manifest?.version ?? null,
    surfaceDigest: surface?.digest ?? null,
    surfaceCounts: surface?.counts ?? null,
    surfaceProblems: surface?.problems ?? null,
    // A manifest that points at a path the package does not contain is the
    // stale-layout failure above, seen from the source side.
    mcpEntrypoints: mcpArgs.map((arg) => {
      const relative = arg.replace('${CLAUDE_PLUGIN_ROOT}/', '');
      return { path: relative, exists: existsSync(join(root, relative)) };
    }),
    capabilities: (projection?.capabilities ?? []).filter((c) => c.kind === 'domain-capability').length,
    entrypoints: (projection?.capabilities ?? []).filter((c) => c.kind === 'entrypoint').map((c) => c.id),
    agents: existsSync(join(root, 'agents'))
      ? readJson(join(root, 'agents')) ?? undefined
      : undefined,
    hookEvents: Object.keys(hooks?.hooks ?? {}),
  };
}

/**
 * Duplicate ownership of one harness. `legion bind` writes
 * .claude/agents while the plugin package ships agents/ for the same roles; both
 * active at once is the state that made installation identity unreadable.
 */
function installationConflicts(root) {
  const conflicts = [];
  const boundAgents = join(root, '.claude', 'agents');
  if (existsSync(boundAgents) && existsSync(join(root, 'agents'))) {
    conflicts.push({
      harness: 'claude-code',
      kind: 'duplicate-installation-path',
      detail: 'both the plugin package (agents/) and a legion bind projection (.claude/agents/) are present; one installation path must own each harness',
    });
  }
  return conflicts;
}

/** Declared fidelity per harness, derived from the adapter registry. */
function fidelity(root) {
  const projection = readJson(join(root, 'src', 'registry', 'host-projection.json'));
  if (!projection) return { present: false, harnesses: [] };
  return {
    present: true,
    harnesses: (projection.harnesses ?? []).map((h) => ({
      id: h.id,
      installOwner: h.installOwner,
      ...h.fidelity,
      mechanisms: h.mechanisms,
    })),
  };
}

/** Arcane runtime health: keys present, and which effects the hooks can actually gate. */
function arcaneHostHealth(root, home) {
  const keyDirs = [join(home, '.claude', 'arcane-keys'), join(home, '.codex', 'arcane-keys')];
  const canonicalKeyDir = join(home, '.codex', 'arcane-keys');
  const canonicalKeyIds = (() => {
    try { return readdirSync(canonicalKeyDir).filter((name) => name.endsWith('.key')).map((name) => name.slice(0, -4)).sort(); }
    catch { return []; }
  })();
  const hooks = readJson(join(root, 'hooks', 'hooks.json'));
  const matcherFor = (event) => hooks?.hooks?.[event]?.[0]?.matcher ?? null;
  return {
    keyDirs: keyDirs.map((dir) => ({ dir, present: existsSync(dir) })),
    canonicalVerificationKeyring: { dir: canonicalKeyDir, present: existsSync(canonicalKeyDir), keyIds: canonicalKeyIds },
    hookRegistration: {
      preToolUse: matcherFor('PreToolUse'),
      postToolUse: matcherFor('PostToolUse'),
      stop: Boolean(hooks?.hooks?.Stop),
    },
    adapterPresent: existsSync(join(root, 'src', 'packages', 'arcane', 'host', 'claude-code-adapter.mjs')),
    codexHookTrust: codexHookTrust(home),
  };
}

function harnessAdaptersSection(root) {
  let detected = [];
  try { detected = harnessRegistry.detectHarnesses(root); } catch { detected = []; }
  const capabilities = {};
  for (const id of harnessRegistry.ADAPTER_IDS) {
    try { capabilities[id] = harnessRegistry.capabilities(id, { root }); } catch { /* skip */ }
  }
  return { known: harnessRegistry.ADAPTER_IDS, detected, capabilities };
}

export function computeHostSection(root, { home = homedir() } = {}) {
  const projectionPath = join(root, 'src', 'registry', 'host-projection.json');
  return {
    projection: {
      path: 'src/registry/host-projection.json',
      present: existsSync(projectionPath),
      generatedAt: existsSync(projectionPath) ? statSync(projectionPath).mtime.toISOString() : null,
      driftCheck: 'node scripts/generate-host-projection.mjs --check',
    },
    installations: { 'claude-code': claudeInstallation(root, home) },
    discovery: { 'claude-code': claudeDiscovery(root) },
    conflicts: installationConflicts(root),
    fidelity: fidelity(root),
    // The live adapter seam: which harnesses this repo looks like, and each
    // detected harness's declared surface capabilities (read-only; doctor never
    // installs). This is the runtime view of what host-projection.json records.
    harnessAdapters: harnessAdaptersSection(root),
    arcane: arcaneHostHealth(root, home),
  };
}
