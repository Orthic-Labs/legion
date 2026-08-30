#!/usr/bin/env node
// Deterministic skill-catalog generator (M-017).
//
// Inputs (canonical sources only):
//   skills/*/SKILL.md               canonical capability/entrypoint semantics
//   src/config/capability-aliases.json  explicit aliases (independently canonical)
//   src/registry/capabilities.json      host requirement semantics and probes
//
// Outputs (projections, never semantic owners):
//   src/registry/skills/index.json      compact sorted catalog, every packaged source
//   src/registry/routing/domains.json   grouping-only metadata (kind=capability,
//                                       non-null domain only; no entrypoints/roles,
//                                       no targetType, no engineering/advisory split)
//
// Run with --check to fail when a committed projection has drifted.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSkillFrontmatter } from './lib/skill-frontmatter.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const OUT_INDEX = 'src/registry/skills/index.json';
const OUT_DOMAINS = 'src/registry/routing/domains.json';

function listField(value) {
  if (Array.isArray(value)) return value.filter((v) => typeof v === 'string' && v.length);
  if (typeof value === 'string' && value.length) return value.split(/\s+/);
  return [];
}

function canonicalRecord(id, fm, capabilityRegistry) {
  const kind = fm.kind;
  const capabilityClass = kind === 'capability' ? fm.capabilityClass : null;
  const discoverability = fm.discoverability;
  const domain = fm.domain === 'null' || fm.domain === '' ? null : fm.domain;
  const hostRequirements = listField(fm.hostRequirements);
  const hostRequirementDetails = hostRequirements.map((requirementId) => {
    const requirement = capabilityRegistry.capabilities?.[requirementId];
    if (!requirement) {
      throw new Error(`skills/${id}/SKILL.md declares host requirement absent from registry: ${requirementId}`);
    }
    return {
      id: requirementId,
      degradation: requirement.degradation,
      remedy: requirement.remedy,
      probe: requirement.probe ?? null,
    };
  });
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
    hostRequirements,
    hostRequirementDetails,
    source: `skills/${id}/SKILL.md`,
  };
}

export function buildSkillCatalog(root = ROOT) {
  const skillsDir = join(root, 'skills');
  const capabilityRegistry = readJson(join(root, 'src/registry/capabilities.json'));
  const ids = readdirSync(skillsDir)
    .filter((id) => existsSync(join(skillsDir, id, 'SKILL.md')))
    .sort();
  const bundles = ids.map((id) => {
    const source = join(skillsDir, id, 'SKILL.md');
    const fm = parseSkillFrontmatter(readFileSync(source, 'utf8'), { path: `skills/${id}/SKILL.md` });
    return { ...canonicalRecord(id, fm, capabilityRegistry), manifest: `skills/manifests/${id}.json` };
  });
  validateAliases(readJson(join(root, 'src/config/capability-aliases.json')), new Set(ids));
  const index = {
    schemaVersion: 2,
    generatedFrom: [
      'skills/*/SKILL.md',
      'src/config/capability-aliases.json',
      'src/registry/capabilities.json',
    ],
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

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function validateAliases(document, packagedIds) {
  const aliases = document?.aliases;
  if (!aliases || Array.isArray(aliases) || typeof aliases !== 'object') throw new Error('capability aliases must be an object');
  for (const [alias, declared] of Object.entries(aliases)) {
    if (!/^\/[a-z][a-z0-9-]*$/.test(alias) || typeof declared !== 'string') throw new Error(`invalid capability alias ${alias}`);
    let target = declared.split(/\s+/, 1)[0];
    const seen = new Set([alias]);
    while (target.startsWith('/') && aliases[target]) {
      if (seen.has(target)) throw new Error(`capability alias cycle at ${target}`);
      seen.add(target);
      target = aliases[target].split(/\s+/, 1)[0];
    }
    if (target.startsWith('/') && !packagedIds.has(target.slice(1))) throw new Error(`alias ${alias} targets missing package ${target}`);
    if (!target.startsWith('/') && !/^(hook|tool):[a-z][a-z0-9-]*$/.test(target)) throw new Error(`alias ${alias} has unsupported target ${target}`);
  }
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
