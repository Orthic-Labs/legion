#!/usr/bin/env node
// Proves the Claude plugin's discoverable surface actually resolves, and stamps
// a structural digest so a packaged copy cannot silently differ from its version.
//
// The failure this prevents was concrete: an installed plugin cache frozen at an
// older layout (pre-`src/`) shared version 0.1.0-dev.0 with a working tree whose
// manifest pointed the MCP server at a path the cache did not contain. Nothing
// signalled the drift because the version string was identical.
//
// The surface a Claude plugin exposes, by convention plus manifest:
//   skills/<id>/SKILL.md          capabilities and explicit entrypoints
//   agents/<name>.md              authority agents
//   .claude-plugin/plugin.json    mcpServers → the legion MCP server entry point
//   hooks/hooks.json              lifecycle hook command targets
//
// Every declared artifact must resolve on disk. The digest is computed over the
// surface's shape and the referenced entry points' relative paths — not their
// full contents — so a bump is required whenever the discoverable structure
// changes, which is exactly the invariant version numbers must carry.
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const SURFACE_FILE = 'src/registry/plugin-surface.json';

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

// Resolve a ${CLAUDE_PLUGIN_ROOT}-relative reference to a repo path.
const pluginRel = (ref) => ref.replace('${CLAUDE_PLUGIN_ROOT}/', '');

export function collectSurface(root = ROOT) {
  const problems = [];

  // Skills — every subdirectory that ships a SKILL.md. _shared and manifests are
  // support directories and legitimately carry none.
  const skillsDir = join(root, 'skills');
  const skills = readdirSync(skillsDir)
    .filter((id) => { try { return statSync(join(skillsDir, id)).isDirectory(); } catch { return false; } })
    .filter((id) => existsSync(join(skillsDir, id, 'SKILL.md')))
    .sort();

  // Agents — every markdown file under agents/, keyed by frontmatter name.
  const agentsDir = join(root, 'agents');
  const agents = existsSync(agentsDir)
    ? readdirSync(agentsDir).filter((f) => f.endsWith('.md')).sort().map((f) => {
        const text = readFileSync(join(agentsDir, f), 'utf8');
        const name = /^name:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? null;
        if (!name) problems.push(`agent ${f} has no frontmatter name`);
        return { file: `agents/${f}`, name };
      })
    : [];

  // MCP servers — declared in the manifest; each entry point must resolve.
  const manifest = readJson(join(root, '.claude-plugin', 'plugin.json'));
  const mcpServers = Object.entries(manifest.mcpServers ?? {}).map(([id, server]) => {
    const entry = (server.args ?? []).map(pluginRel).find((a) => a.endsWith('.mjs') || a.endsWith('.js'));
    if (!entry) problems.push(`mcp server ${id} declares no resolvable entry point`);
    else if (!existsSync(join(root, entry))) problems.push(`mcp server ${id} entry point missing: ${entry}`);
    return { id, entry: entry ?? null };
  });

  // Hooks — every command target referenced by hooks.json must resolve.
  const hooks = readJson(join(root, 'hooks', 'hooks.json'));
  const hookEvents = Object.keys(hooks.hooks ?? {}).sort();
  const hookTargets = new Set();
  for (const entries of Object.values(hooks.hooks ?? {})) {
    for (const entry of entries) {
      for (const hook of entry.hooks ?? []) {
        const m = /\$\{CLAUDE_PLUGIN_ROOT\}\/([^\s"]+)/.exec(hook.command ?? '');
        if (m) hookTargets.add(m[1]);
      }
    }
  }
  for (const target of hookTargets) {
    if (!existsSync(join(root, target))) problems.push(`hook command target missing: ${target}`);
  }

  return {
    version: manifest.version,
    skills,
    agents,
    mcpServers,
    hooks: { events: hookEvents, targets: [...hookTargets].sort() },
    problems,
  };
}

// Digest over structure and entry-point paths, NOT file contents: a bump is
// required when the discoverable shape changes, not on every content edit.
export function surfaceDigest(surface) {
  const shape = {
    skills: surface.skills,
    agents: surface.agents.map((a) => a.name),
    mcpServers: surface.mcpServers.map((s) => ({ id: s.id, entry: s.entry })),
    hooks: surface.hooks,
  };
  return `sha256:${createHash('sha256').update(JSON.stringify(shape)).digest('hex')}`;
}

export function buildSurfaceRecord(root = ROOT) {
  const surface = collectSurface(root);
  return {
    schemaVersion: 1,
    kind: 'legion-plugin-surface',
    version: surface.version,
    digest: surfaceDigest(surface),
    counts: {
      skills: surface.skills.length,
      agents: surface.agents.length,
      mcpServers: surface.mcpServers.length,
      hookEvents: surface.hooks.events.length,
    },
    surface: { skills: surface.skills, agents: surface.agents, mcpServers: surface.mcpServers, hooks: surface.hooks },
    problems: surface.problems,
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const record = buildSurfaceRecord();
  const target = join(ROOT, SURFACE_FILE);
  const rendered = `${JSON.stringify(record, null, 2)}\n`;

  if (record.problems.length) {
    process.stderr.write(`plugin surface does not resolve:\n  - ${record.problems.join('\n  - ')}\n`);
    process.exit(1);
  }

  if (process.argv.includes('--check')) {
    const current = existsSync(target) ? readJson(target) : null;
    if (!current) { process.stderr.write(`missing ${SURFACE_FILE}; run: node scripts/verify-plugin-parity.mjs\n`); process.exit(1); }
    // The lifecycle invariant: a changed structural digest REQUIRES a changed
    // version. Same digest + same version is fine; changed digest + same version
    // is the exact drift the packaged cache suffered.
    if (current.digest !== record.digest && current.version === record.version) {
      process.stderr.write(
        `plugin surface changed but version did not.\n` +
        `  recorded ${current.digest} @ ${current.version}\n` +
        `  current  ${record.digest} @ ${record.version}\n` +
        `Bump the version in .claude-plugin/plugin.json (and package.json), then rerun.\n`);
      process.exit(1);
    }
    if (JSON.stringify(current) !== JSON.stringify(record)) {
      process.stderr.write(`${SURFACE_FILE} is stale; run: node scripts/verify-plugin-parity.mjs\n`);
      process.exit(1);
    }
    process.stdout.write(`plugin surface: resolves, ${record.counts.skills} skills / ${record.counts.agents} agents / ${record.counts.mcpServers} mcp / ${record.counts.hookEvents} hook events, digest ${record.digest.slice(0, 19)}…\n`);
  } else {
    writeFileSync(target, rendered);
    process.stdout.write(`wrote ${SURFACE_FILE}: ${record.counts.skills} skills, ${record.counts.agents} agents, ${record.counts.mcpServers} mcp, ${record.counts.hookEvents} hook events\n`);
  }
}
