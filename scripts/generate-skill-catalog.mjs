#!/usr/bin/env node
// Deterministic skill-catalog generator (M-017).
//
// Inputs (canonical sources only):
//   skills/*/SKILL.md               canonical capability/entrypoint semantics
//   src/config/capability-aliases.json  explicit aliases (independently canonical)
//
// Outputs (projections, never semantic owners):
//   src/registry/skills/index.json      compact sorted catalog, all 23 packaged sources
//   src/registry/routing/domains.json   grouping-only metadata (kind=capability,
//                                       non-null domain only; no entrypoints/roles,
//                                       no targetType, no engineering/advisory split)
//
// Run with --check to fail when a committed projection has drifted.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const SKILLS_DIR = join(ROOT, 'skills');
const OUT_INDEX = 'src/registry/skills/index.json';
const OUT_DOMAINS = 'src/registry/routing/domains.json';

// The five optional grouping labels. Domain is metadata only — never routing.
const DOMAIN_LABELS = Object.freeze(['engineering', 'research', 'commercial', 'editorial', 'design']);

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
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
      out[key] = value;
    } else if (key && /^\s+\S/.test(line)) {
      if (Array.isArray(out[key])) out[key].push(line.trim());
      else if (typeof out[key] === 'string' && out[key] === '') out[key] = [line.trim()];
      else if (key === 'description' || key === 'name') out[key] = `${out[key]} ${line.trim()}`.trim();
    }
  }
  return out;
}

function listField(value) {
  if (Array.isArray(value)) return value.filter((v) => typeof v === 'string' && v.length);
  if (typeof value === 'string' && value.length) return value.split(/\s+/);
  return [];
}

function canonicalRecord(id, fm) {
  const kind = fm.kind === 'entrypoint' ? 'entrypoint' : 'capability';
  const capabilityClass = kind === 'capability'
    ? (['domain', 'workflow', 'context'].includes(fm.capabilityClass) ? fm.capabilityClass : null)
    : null;
  const discoverability = ['public', 'explicit', 'internal'].includes(fm.discoverability) ? fm.discoverability : 'public';
  const domain = fm.domain === 'null' || fm.domain === '' ? null : (DOMAIN_LABELS.includes(fm.domain) ? fm.domain : null);
  return {
    id,
    name: fm.name ?? id,
    description: fm.description ?? '',
    kind,
    capabilityClass,
    discoverability,
    domain,
    operations: listField(fm.operations),
    effects: listField(fm.effects),
    hostRequirements: listField(fm.hostRequirements),
    source: `skills/${id}/SKILL.md`,
  };
}

export function buildSkillCatalog(root = ROOT) {
  const ids = readdirSync(SKILLS_DIR)
    .filter((id) => existsSync(join(SKILLS_DIR, id, 'SKILL.md')))
    .sort();
  const bundles = ids.map((id) => {
    const fm = frontmatter(readFileSync(join(SKILLS_DIR, id, 'SKILL.md'), 'utf8'));
    return { ...canonicalRecord(id, fm), manifest: `skills/manifests/${id}.json` };
  });
  const index = {
    schemaVersion: 2,
    generatedFrom: ['skills/*/SKILL.md', 'src/config/capability-aliases.json'],
    bundles,
  };

  // Grouping-only domains: capabilities with a non-null domain. No entrypoints,
  // no roles, no targetType, no engineering/advisory distinction.
  const groups = new Map();
  for (const bundle of bundles) {
    if (bundle.kind !== 'capability' || bundle.domain == null) continue;
    if (!groups.has(bundle.domain)) groups.set(bundle.domain, []);
    groups.get(bundle.domain).push({ id: bundle.id });
  }
  const domains = {
    schemaVersion: 2,
    generatedFrom: ['src/registry/skills/index.json'],
    domains: [...groups.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, children]) => ({
        id,
        kind: 'group',
        children: children.sort((a, b) => a.id.localeCompare(b.id)),
      })),
  };

  return { index, domains };
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const { index, domains } = buildSkillCatalog();
  const indexText = render(index);
  const domainsText = render(domains);
  if (process.argv.includes('--check')) {
    const drift = [];
    for (const [path, expected] of [[OUT_INDEX, indexText], [OUT_DOMAINS, domainsText]]) {
      const target = join(ROOT, path);
      const current = existsSync(target) ? readFileSync(target, 'utf8') : '';
      if (current !== expected) drift.push(path);
    }
    if (drift.length) {
      process.stderr.write(`skill catalog drift: ${drift.join(', ')} do not match their canonical sources.\nRun: node scripts/generate-skill-catalog.mjs\n`);
      process.exit(1);
    }
    process.stdout.write(`skill catalog: no drift (${index.bundles.length} bundles, ${domains.domains.length} groups)\n`);
  } else {
    writeFileSync(join(ROOT, OUT_INDEX), indexText);
    writeFileSync(join(ROOT, OUT_DOMAINS), domainsText);
    process.stdout.write(`wrote ${OUT_INDEX} (${index.bundles.length} bundles) and ${OUT_DOMAINS} (${domains.domains.length} groups)\n`);
  }
}
