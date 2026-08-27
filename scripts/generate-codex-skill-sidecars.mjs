#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
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

function main() {
  const check = process.argv.includes('--check');
  const expected = expectedCodexSidecars();
  const drift = [];
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
  if (drift.length) {
    process.stderr.write(`Codex skill sidecar drift:\n${drift.map((path) => `- ${path}`).join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(check ? `Codex skill sidecars: no drift (${expected.size})\n` : `wrote ${expected.size} Codex skill sidecars\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) main();
