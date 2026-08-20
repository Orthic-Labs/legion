#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildSkillCatalog } from './generate-skill-catalog.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const EXCLUDED = new Set(['.DS_Store']);

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function files(root, current = root, out = []) {
  for (const name of readdirSync(current).sort()) {
    if (EXCLUDED.has(name) || name === '__pycache__' || name.endsWith('.pyc')) continue;
    const path = join(current, name);
    if (statSync(path).isDirectory()) files(root, path, out);
    else out.push(relative(root, path).replaceAll('\\', '/'));
  }
  return out;
}

export function refreshLocalSkillManifest(bundle) {
  const { manifestPath, manifest } = buildLocalSkillManifest(bundle);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifestPath;
}

function buildLocalSkillManifest(bundle) {
  const skillRoot = join(ROOT, 'skills', bundle);
  const manifestPath = join(ROOT, 'skills', 'manifests', `${bundle}.json`);
  if (!existsSync(join(skillRoot, 'SKILL.md'))) throw new Error(`missing skill entrypoint: ${bundle}`);
  const prior = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : {};
  const semantic = buildSkillCatalog().index.bundles.find(({ id }) => id === bundle);
  if (!semantic) throw new Error(`missing canonical catalog record: ${bundle}`);
  const packageFiles = files(skillRoot);
  const manifest = {
    schemaVersion: 1,
    id: bundle,
    version: prior.version ?? '1.0.0',
    entry: 'SKILL.md',
    rootUri: `legion-skill://${bundle}/`,
    provenance: prior.provenance ?? 'legion-authored',
    licenseState: prior.licenseState ?? 'licensed',
    rightsReceipt: prior.rightsReceipt ?? null,
    profiles: prior.profiles ?? {
      audit: { mutation: false, publish: false },
      authoring: { mutation: true, publish: false, externalOnly: true },
    },
    parity: deriveParity(bundle, semantic, packageFiles),
    files: packageFiles.map((path) => {
      const bytes = readFileSync(join(skillRoot, path));
      const hash = digest(bytes);
      return {
        path,
        uri: `legion-skill://${bundle}/${path}`,
        digest: hash,
      };
    }),
  };
  return { manifestPath, manifest };
}

export function deriveParity(bundle, semantic, packageFiles) {
  const selected = (predicate) => packageFiles.filter(predicate);
  return {
    triggers: [`/${bundle}`, semantic.description],
    outputs: selected((path) => path.startsWith('references/')),
    scripts: selected((path) => path.startsWith('scripts/') || path.startsWith('hooks/')),
    templates: selected((path) => /(^|\/)(assets|templates)\//.test(path) && /template/i.test(path)),
    schemas: selected((path) => /(^|\/)schemas?\//.test(path) || /\.schema\.json$/.test(path)),
    receipts: selected((path) => /\.receipt\.json$/.test(path)),
    evals: selected((path) => /(^|\/)evals?\//.test(path)),
    consumers: ['src/registry/skills/index.json', 'src/lib/skills/resolver.mjs', 'src/registry/routing/domains.json'],
  };
}

async function main() {
  const check = process.argv.includes('--check');
  const requested = process.argv.slice(2).filter((arg) => arg !== '--check');
  const bundles = requested.length
    ? requested
    : (check ? buildSkillCatalog().index.bundles.map(({ id }) => id) : []);
  if (!bundles.length) throw new Error('usage: refresh-local-skill-manifests.mjs [--check] BUNDLE...');
  if (check) {
    for (const bundle of bundles) {
      const { manifestPath, manifest } = buildLocalSkillManifest(bundle);
      const expected = `${JSON.stringify(manifest, null, 2)}\n`;
      const actual = existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : '';
      if (actual !== expected) throw new Error(`skill manifest drift: skills/manifests/${bundle}.json`);
    }
    console.log(`skill manifests: no drift (${bundles.length} bundles)`);
    return;
  }
  for (const bundle of bundles) console.log(refreshLocalSkillManifest(bundle));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
