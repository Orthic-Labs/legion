#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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
  const skillRoot = join(ROOT, 'skills', bundle);
  const manifestPath = join(ROOT, 'skills', 'manifests', `${bundle}.json`);
  if (!existsSync(join(skillRoot, 'SKILL.md'))) throw new Error(`missing skill entrypoint: ${bundle}`);
  const prior = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : {};
  const priorFiles = new Map((prior.files ?? []).map((record) => [record.path, record]));
  const manifest = {
    schemaVersion: 1,
    id: bundle,
    version: prior.version ?? '1.0.0',
    entry: 'SKILL.md',
    rootUri: `legion-skill://${bundle}/`,
    provenance: prior.provenance ?? 'workspace-authored-wrapper',
    licenseState: prior.licenseState ?? 'unresolved',
    rightsReceipt: prior.rightsReceipt ?? null,
    profiles: prior.profiles ?? {
      audit: { mutation: false, publish: false },
      authoring: { mutation: true, publish: false, externalOnly: true },
    },
    ...Object.fromEntries(Object.entries(prior).filter(([key]) => ![
      'schemaVersion', 'id', 'version', 'entry', 'rootUri', 'provenance',
      'licenseState', 'rightsReceipt', 'profiles', 'files',
    ].includes(key))),
    files: files(skillRoot).map((path) => {
      const bytes = readFileSync(join(skillRoot, path));
      const hash = digest(bytes);
      return {
        path,
        uri: `legion-skill://${bundle}/${path}`,
        sourceDigest: hash,
        outputDigest: hash,
        transformations: priorFiles.get(path)?.transformations ?? [],
      };
    }),
  };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifestPath;
}

async function main() {
  const bundles = process.argv.slice(2);
  if (!bundles.length) throw new Error('usage: refresh-local-skill-manifests.mjs BUNDLE...');
  for (const bundle of bundles) console.log(refreshLocalSkillManifest(bundle));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
