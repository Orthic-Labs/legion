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
import { delimiter, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const SURFACE_FILE = 'src/registry/plugin-surface.json';
const DISTRIBUTION_CONTRACT = 'release/distribution-contract.json';
const CHANNELS_FILE = 'packaging/channels.json';

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const ACTIVATION_PREFLIGHT = 'node scripts/verify-plugin-parity.mjs --check';

// The package-manager channels are optional aliases today. Keep their presence
// visible to the diagnostic without treating a manifest as proof that the
// command is already installed on PATH.
const PACKAGE_MANAGER_MANIFESTS = [
  { id: 'homebrew', directory: 'packaging/homebrew', extensions: ['.rb'] },
  { id: 'winget', directory: 'packaging/winget', extensions: ['.json', '.yaml', '.yml'] },
];

// Resolve a ${CLAUDE_PLUGIN_ROOT}-relative reference to a repo path.
const pluginRel = (ref) => ref.replace(`\${CLAUDE_PLUGIN_ROOT}/`, '');

function bareCommand(command) {
  if (typeof command !== 'string') return null;
  const value = command.trim();
  // A command with an argument, path, or shell interpolation is not a PATH
  // binary declaration. Path-relative targets are checked by the existing
  // hook-target check below.
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value) ? value : null;
}

function executableOnPath(command, env = process.env) {
  const pathValue = env.PATH ?? env.Path ?? '';
  const entries = pathValue.split(delimiter);
  const extensions = process.platform === 'win32'
    ? ['', ...(env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)]
    : [''];
  const candidates = [...new Set(extensions.map((extension) => `${command}${extension}`))];

  for (const entry of entries) {
    for (const candidate of candidates) {
      const path = resolve(entry || process.cwd(), candidate);
      try {
        const stat = statSync(path);
        // Windows resolves executable extensions without a Unix executable bit.
        if (stat.isFile() && (process.platform === 'win32' || (stat.mode & 0o111) !== 0)) return path;
      } catch { /* this PATH entry does not provide the binary */ }
    }
  }
  return null;
}

function manifestFiles(root, directory, extensions) {
  const found = [];
  const walk = (directoryPath) => {
    let entries;
    try { entries = readdirSync(directoryPath, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const path = join(directoryPath, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (extensions.some((extension) => entry.name.endsWith(extension))) found.push(path);
    }
  };
  walk(join(root, directory));
  return found;
}

function packageManagerManifestProviders(root) {
  return PACKAGE_MANAGER_MANIFESTS
    .filter(({ directory, extensions }) => manifestFiles(root, directory, extensions).length > 0)
    .map(({ id }) => id);
}

function declaredBootstrap(root) {
  let contract;
  let channels;
  try { contract = readJson(join(root, DISTRIBUTION_CONTRACT)); } catch { /* checked below */ }
  try { channels = readJson(join(root, CHANNELS_FILE)); } catch { /* checked below */ }

  const contractUrl = contract?.nativeRelease?.bootstrapAuthority;
  const channelUrl = channels?.bootstrap?.stableUrl;
  if (typeof contractUrl === 'string' && contractUrl === channelUrl) return contractUrl;
  if (typeof contractUrl === 'string') return contractUrl;
  if (typeof channelUrl === 'string') return channelUrl;
  return null;
}

function declaredPathBinaries(manifest, hooks) {
  const declarations = new Map();
  const add = (command, source) => {
    const binary = bareCommand(command);
    if (!binary) return;
    if (!declarations.has(binary)) declarations.set(binary, []);
    declarations.get(binary).push(source);
  };

  for (const [id, server] of Object.entries(manifest.mcpServers ?? {})) {
    add(server?.command, `.claude-plugin/plugin.json mcpServers.${id}`);
  }
  for (const [event, entries] of Object.entries(hooks.hooks ?? {})) {
    for (const entry of entries ?? []) {
      for (const [index, hook] of (entry.hooks ?? []).entries()) {
        add(hook?.command, `hooks/hooks.json ${event}[${index}]`);
      }
    }
  }
  return declarations;
}

/**
 * Check the external binaries that the plugin invokes by bare name. This is
 * deliberately a preflight: a package-manager manifest can document an
 * optional alias, but it cannot make a missing PATH command runnable. The
 * canonical recovery is therefore always named in the failure itself.
 */
export function checkPathBinaries(root = ROOT, { manifest, hooks, env = process.env } = {}) {
  const pluginManifest = manifest ?? readJson(join(root, '.claude-plugin', 'plugin.json'));
  const hookConfig = hooks ?? readJson(join(root, 'hooks', 'hooks.json'));
  const providers = packageManagerManifestProviders(root);
  const bootstrap = declaredBootstrap(root);
  const binaries = [];
  const problems = [];

  for (const [binary, sources] of declaredPathBinaries(pluginManifest, hookConfig)) {
    const resolved = executableOnPath(binary, env);
    const record = { binary, sources, resolved, packageManagerManifests: providers };
    binaries.push(record);
    if (!resolved && !bootstrap) {
      const packageNote = providers.length
        ? ` Package-manager metadata is present (${providers.join(', ')}), but it does not put the binary on PATH.`
        : ' No Homebrew or WinGet manifest is populated for this checkout (informational only; optional aliases are not required).';
      const bootstrapNote = `Plugin activation is gated by this preflight, but no bootstrap step is declared in the distribution SSOT; declare one before rerunning '${ACTIVATION_PREFLIGHT}'.`;
      problems.push(
        `plugin binary '${binary}' is not reachable on PATH (required by ${sources.join(', ')}).${packageNote} ${bootstrapNote}`,
      );
    }
  }

  return { binaries, problems };
}

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

  // MCP servers — source-backed entries must resolve. Installed-native entries
  // must use Legion's exact stdio launch contract.
  const manifest = readJson(join(root, '.claude-plugin', 'plugin.json'));
  const mcpServers = Object.entries(manifest.mcpServers ?? {}).map(([id, server]) => {
    const args = server.args ?? [];
    const native = server.command === 'legion' && JSON.stringify(args) === JSON.stringify(['serve', '--stdio']);
    const entry = args.map(pluginRel).find((a) => a.endsWith('.mjs') || a.endsWith('.js'));
    if (!native && !entry) problems.push(`mcp server ${id} declares neither installed native Legion nor a resolvable entry point`);
    else if (entry && !existsSync(join(root, entry))) problems.push(`mcp server ${id} entry point missing: ${entry}`);
    return { id, command: server.command ?? null, args, entry: entry ?? null };
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

  problems.push(...checkPathBinaries(root, { manifest, hooks }).problems);

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
    mcpServers: surface.mcpServers.map((s) => ({ id: s.id, command: s.command, args: s.args, entry: s.entry })),
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
