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
import { parseSkillFrontmatter } from './lib/skill-frontmatter.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
// Harness fidelity is derived from the adapter registry — the single source of
// truth for what each harness supports — not hand-maintained here (SSOT I-2).
import { fidelityMatrix } from '../src/lib/host/registry.mjs';
const OUT = 'src/registry/host-projection.json';

function rosterFrontmatter(text) {
  const end = text.indexOf('\n---', 4);
  const out = {};
  if (!text.startsWith('---\n') || end === -1) return out;
  for (const line of text.slice(4, end).split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
    if (!match) continue;
    const value = match[2].trim();
    out[match[1]] = ((value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))) ? value.slice(1, -1) : value;
  }
  return out;
}

// Deliberately small: enough to select and compose a capability, and nothing a
// renderer would have to re-derive. Full method stays in SKILL.md and is loaded
// only after selection (SSOT 23, progressive disclosure).
// A bundle with no SKILL.md is not a capability. `_shared` and `manifests` are
// support directories and must never surface as peer expertise (SSOT 18).
export function buildProjection(root = ROOT) {
  const skillsDir = join(root, 'skills');
  const capabilities = readdirSync(skillsDir)
    .filter((id) => existsSync(join(skillsDir, id, 'SKILL.md')))
    .sort()
    .map((id) => {
      const path = `skills/${id}/SKILL.md`;
      const fm = parseSkillFrontmatter(readFileSync(join(root, path), 'utf8'), { path });
      // Canonical SKILL metadata (M-012/M-021) decides classification. The host
      // projection is deliberately lossy for the frozen host consumer: public
      // capabilities project as public projectable rows; entrypoints do not.
      const kind = fm.kind ?? 'capability';
      const discoverability = fm.discoverability ?? 'public';
      const publicCapability = kind === 'capability' && discoverability === 'public';
      return {
        id,
        name: fm.name ?? id,
        description: fm.description ?? '',
        kind: publicCapability ? 'domain-capability' : 'entrypoint',
        discoverability: publicCapability ? 'public' : discoverability,
        domain: fm.domain === 'null' || fm.domain === '' ? null : (fm.domain ?? null),
        source: path,
      };
    });

  const rosterDir = join(root, 'src/roster');
  const roles = readdirSync(rosterDir)
    .filter((f) => f.endsWith('.md') && f !== 'README.md')
    .sort()
    .map((f) => {
      const path = `src/roster/${f}`;
      const fm = rosterFrontmatter(readFileSync(join(root, path), 'utf8'));
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
    // Derived from src/lib/host/registry.mjs. The projection reports the four
    // SSOT 36.5 axes; they map onto the adapter's five surfaces (instructions is
    // additionally carried for completeness). Truthful by construction: the
    // values are whatever the adapters declare, never rounded up here.
    harnesses: harnessFidelity(root)
  };
}


// Map each adapter's surface fidelity to the projection's reporting shape.
function harnessFidelity() {
  return fidelityMatrix().map((caps) => ({
    id: caps.id,
    installOwner: caps.installOwner,
    fidelity: {
      instructions: caps.surfaces.instructions.fidelity,
      skillDiscovery: caps.surfaces.skills.fidelity,
      authorityAgents: caps.surfaces.agents.fidelity,
      mcp: caps.surfaces.mcp.fidelity,
      arcaneEnforcement: caps.surfaces.hooks.fidelity,
    },
    mechanisms: Object.fromEntries(Object.entries(caps.surfaces).map(([k, v]) => [k, v.mechanism?.kind ?? 'none'])),
  }));
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
