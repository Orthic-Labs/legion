#!/usr/bin/env node
// Builds the ONE canonical host projection every harness renderer consumes.
//
// SSOT 36.2: a host adapter is a renderer, not a second semantic owner. Before
// this existed, each binder in src/lib/cli/commands/bind/ hand-authored its own
// role text, so "what Legion contains" was defined four times and skills were
// defined nowhere outside the Claude plugin. This script derives the answer once
// from the canonical owners named in SSOT 19 and writes it as data.
//
// Inputs are canonical sources only:
//   skills/<id>/SKILL.md            domain capabilities   (SSOT 19.2)
//   src/roster/*.md                 role identity         (SSOT 19.3)
//   src/registry/capabilities.json  host capabilities     (SSOT 19.6)
//
// Output is a projection, never an authority (SSOT 19.7 / I-14).
//
// Run with --check to fail when the committed projection has drifted.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const OUT = 'src/registry/host-projection.json';

// Deliberately small: enough to select and compose a capability, and nothing a
// renderer would have to re-derive. Full method stays in SKILL.md and is loaded
// only after selection (SSOT 23, progressive disclosure).
function frontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end === -1) return {};
  const block = text.slice(4, end);
  const out = {};
  let key = null;
  for (const line of block.split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
    if (m) {
      key = m[1];
      let value = m[2].trim();
      if (value === '' || value === '>' || value === '|') { out[key] = ''; continue; }
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      out[key] = value;
    } else if (key && /^\s+\S/.test(line) && typeof out[key] === 'string') {
      out[key] = `${out[key]} ${line.trim()}`.trim();
    }
  }
  return out;
}

// A bundle with no SKILL.md is not a capability. `_shared` and `manifests` are
// support directories and must never surface as peer expertise (SSOT 18).
export function buildProjection(root = ROOT) {
  const skillsDir = join(root, 'skills');
  const capabilities = readdirSync(skillsDir)
    .filter((id) => existsSync(join(skillsDir, id, 'SKILL.md')))
    .sort()
    .map((id) => {
      const path = `skills/${id}/SKILL.md`;
      const fm = frontmatter(readFileSync(join(root, path), 'utf8'));
      // `skills/alchemist` and `skills/covenant` declare themselves compatibility
      // entrypoints into an authority, not domain capabilities (SSOT 6.1). They
      // are projected as internal so a slash command does not make an authority
      // appear as peer expertise in natural-language discovery.
      const roleEntrypoint = ['alchemist', 'covenant'].includes(id);
      return {
        id,
        name: fm.name ?? id,
        description: fm.description ?? '',
        kind: roleEntrypoint ? 'role-entrypoint' : 'domain-capability',
        discoverability: roleEntrypoint ? 'internal' : (fm.discoverability ?? 'public'),
        domain: fm.domain ?? null,
        source: path,
      };
    });

  const rosterDir = join(root, 'src/roster');
  const roles = readdirSync(rosterDir)
    .filter((f) => f.endsWith('.md') && f !== 'README.md')
    .sort()
    .map((f) => {
      const path = `src/roster/${f}`;
      const fm = frontmatter(readFileSync(join(root, path), 'utf8'));
      return { id: f.replace(/\.md$/, ''), description: fm.description ?? '', source: path };
    });

  const registry = JSON.parse(readFileSync(join(root, 'src/registry/capabilities.json'), 'utf8'));
  const hostCapabilities = Object.entries(registry.capabilities ?? {}).map(([id, value]) => ({
    id,
    degradation: value?.degradation ?? value?.degrades ?? null,
  })).sort((a, b) => a.id.localeCompare(b.id));

  return {
    schemaVersion: 1,
    kind: 'legion-host-projection',
    generatedFrom: ['skills/*/SKILL.md', 'src/roster/*.md', 'src/registry/capabilities.json'],
    capabilities,
    roles,
    hostCapabilities,
    referenceClasses: Object.keys(registry.classes ?? {}).sort(),
    // SSOT 36.5 — fidelity must be TRUE, not aspirational. A harness with no
    // hook mechanism declares Arcane `unsupported`; it does not claim `strong`
    // because doctrine says Arcane gates every effect. These values describe
    // what the repository actually ships today and are corrected as native
    // projections land, never rounded up.
    harnesses: [
      {
        id: 'claude-code',
        installPath: 'plugin package (.claude-plugin/plugin.json)',
        fidelity: { skillDiscovery: 'strong', authorityAgents: 'strong', mcp: 'strong', arcaneEnforcement: 'strong' },
        notes: 'Native plugin ships skills/, agents/, hooks/ and the legion MCP server.',
      },
      {
        id: 'codex',
        installPath: '.codex-plugin/plugin.json',
        fidelity: { skillDiscovery: 'unsupported', authorityAgents: 'degraded', mcp: 'unsupported', arcaneEnforcement: 'degraded' },
        notes: 'Manifest is metadata only. Roles reach Codex via legion bind (.codex/agents/*.toml); no skill or MCP projection exists, and the Arcane codex adapter ships but nothing installs its hook registration.',
      },
      {
        id: 'gemini',
        installPath: 'GEMINI.md + .gemini/commands/legion/*.toml',
        fidelity: { skillDiscovery: 'unsupported', authorityAgents: 'degraded', mcp: 'degraded', arcaneEnforcement: 'unsupported' },
        notes: 'Roles project as slash commands via legion bind. No skill projection. No hook mechanism is wired, so effect enforcement is absent, not degraded.',
      },
      {
        id: 'agents-md',
        installPath: 'AGENTS.md managed block',
        fidelity: { skillDiscovery: 'unsupported', authorityAgents: 'degraded', mcp: 'unsupported', arcaneEnforcement: 'unsupported' },
        notes: 'Deliberately lowest-fidelity projection: context text only.',
      },
    ],
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const projection = buildProjection();
  const rendered = `${JSON.stringify(projection, null, 2)}\n`;
  const target = join(ROOT, OUT);
  if (process.argv.includes('--check')) {
    const current = existsSync(target) ? readFileSync(target, 'utf8') : '';
    if (current !== rendered) {
      process.stderr.write(`host projection drift: ${OUT} does not match its canonical sources.\nRun: node scripts/generate-host-projection.mjs\n`);
      process.exit(1);
    }
    process.stdout.write('host projection: no drift\n');
  } else {
    writeFileSync(target, rendered);
    process.stdout.write(`wrote ${OUT} (${projection.capabilities.length} capabilities, ${projection.roles.length} roles, ${projection.harnesses.length} harnesses)\n`);
  }
}
