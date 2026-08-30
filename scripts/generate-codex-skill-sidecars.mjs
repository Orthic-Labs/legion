#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSkillFrontmatter } from './lib/skill-frontmatter.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function displayName(id) {
  return id.split('-').map((part) => `${part[0].toUpperCase()}${part.slice(1)}`).join(' ');
}

function yamlString(value) {
  return JSON.stringify(String(value));
}

export function renderCodexSkillSidecar(id, metadata) {
  const implicit = metadata.discoverability === 'public';
  const description = metadata.description.replace(/\s+/g, ' ').trim();
  return [
    'interface:',
    `  display_name: ${yamlString(displayName(id))}`,
    `  short_description: ${yamlString(description)}`,
    `  default_prompt: ${yamlString(`Use $${id} when this request matches: ${description}`)}`,
    'policy:',
    `  allow_implicit_invocation: ${implicit}`,
    '',
  ].join('\n');
}

export function expectedCodexSidecars(root = ROOT) {
  const out = new Map();
  const skillsRoot = join(root, 'skills');
  for (const entry of readdirSync(skillsRoot, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue;
    const skillPath = join(skillsRoot, entry.name, 'SKILL.md');
    if (!existsSync(skillPath)) continue;
    const metadata = parseSkillFrontmatter(readFileSync(skillPath, 'utf8'), { path: `skills/${entry.name}/SKILL.md` });
    if (metadata.discoverability === 'internal') continue;
    out.set(entry.name, renderCodexSkillSidecar(entry.name, metadata));
  }
  return out;
}

// Codex intentionally has a smaller projection than Claude: MCP and lifecycle
// hooks are not part of the Codex binding. The shared identity fields still
// come from the Claude manifest, while these Codex-only interface fields are
// policy owned here rather than being hand-maintained in .codex-plugin.
const CODEX_INTERFACE = {
  category: 'Developer Tools',
  capabilities: ['Authority agents', 'Arcane lifecycle hooks', 'Covenant review'],
  defaultPrompt: 'Use Legion authority routing for repository or system-state changes.',
};
const CODEX_DESCRIPTION = 'Legion — the authority system for AI-assisted engineering. Orchestrates Sage (decisions), Alchemist (transformation), Oracle (assurance), and Arcane (the deterministic gate), plus the evidence-governed whole-repository audit engine that backs Oracle.';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function expectedCodexPlugin(root = ROOT) {
  const claude = readJson(join(root, '.claude-plugin', 'plugin.json'));
  const author = typeof claude.author === 'object' ? claude.author?.name : claude.author;
  return {
    name: claude.name,
    version: claude.version,
    author,
    description: CODEX_DESCRIPTION,
    license: claude.license,
    interface: {
      displayName: claude.displayName ?? displayName(claude.name),
      ...CODEX_INTERFACE,
    },
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
  }
  return value;
}

function sameJson(left, right) {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}

function existingSidecarIds(root) {
  const skillsRoot = join(root, 'skills');
  return readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .filter((entry) => existsSync(join(skillsRoot, entry.name, 'agents', 'openai.yaml')))
    .map((entry) => entry.name);
}

function main() {
  const check = process.argv.includes('--check');
  const expected = expectedCodexSidecars();
  const drift = [];
  const expectedPlugin = expectedCodexPlugin();
  const pluginPath = join(ROOT, '.codex-plugin', 'plugin.json');
  let currentPlugin = null;
  if (existsSync(pluginPath)) {
    try {
      currentPlugin = readJson(pluginPath);
    } catch {
      // Treat malformed generated metadata as drift so --check still reports
      // the artifact path instead of leaking a parser stack trace.
    }
  }
  if (!sameJson(currentPlugin, expectedPlugin) && check) drift.push('.codex-plugin/plugin.json');

  for (const [id, text] of expected) {
    const path = join(ROOT, 'skills', id, 'agents', 'openai.yaml');
    const current = existsSync(path) ? readFileSync(path, 'utf8') : '';
    if (current === text) continue;
    if (check) drift.push(`skills/${id}/agents/openai.yaml`);
    else {
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, text, 'utf8');
    }
  }
  for (const id of existingSidecarIds(ROOT)) {
    if (expected.has(id)) continue;
    const path = join(ROOT, 'skills', id, 'agents', 'openai.yaml');
    if (check) drift.push(`skills/${id}/agents/openai.yaml`);
    else unlinkSync(path);
  }

  if (!check) {
    mkdirSync(join(pluginPath, '..'), { recursive: true });
    writeFileSync(pluginPath, `${JSON.stringify(expectedPlugin, null, 2)}\n`, 'utf8');
  }
  if (drift.length) {
    process.stderr.write(`Codex skill sidecar drift:\n${[...new Set(drift)].map((path) => `- ${path}`).join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(check ? `Codex skill sidecars: no drift (${expected.size})\n` : `wrote ${expected.size} Codex skill sidecars\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) main();
