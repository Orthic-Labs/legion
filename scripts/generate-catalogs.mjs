#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const OUT = 'qualification/generated-catalogs.json';

export function buildCatalogs(root = ROOT) {
  const providers = JSON.parse(readFileSync(resolve(root, 'src/registry/providers.json'), 'utf8'));
  const coverage = JSON.parse(readFileSync(resolve(root, 'src/registry/coverage/index.json'), 'utf8'));
  return {
    schemaVersion: 1,
    generatedFrom: ['src/registry/providers.json', 'src/registry/coverage/index.json'],
    languages: coverage.records
      .filter(({ kind }) => kind === 'language')
      .map(({ id, tiers, limitations, providerVersions }) => ({ id, tiers, limitations, providerVersions })),
    frameworks: coverage.records
      .filter(({ kind }) => kind === 'framework')
      .map(({ id, tiers, limitations, providerVersions }) => ({ id, tiers, limitations, providerVersions })),
    providers: providers.providers
      .map(({ id, providerVersion, role, family, benchmark, selectable }) => ({ id, providerVersion, role, family, benchmark, selectable })),
    support: coverage.records
      .map(({ id, tiers, corpusDigest, artifactDigest, qualificationDigest }) => ({ id, tiers, corpusDigest, artifactDigest, qualificationDigest })),
  };
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const target = resolve(ROOT, OUT);
  const expected = render(buildCatalogs());
  if (process.argv.includes('--check')) {
    const actual = existsSync(target) ? readFileSync(target, 'utf8') : '';
    if (actual !== expected) {
      process.stderr.write(`catalog drift: ${OUT} does not match its canonical registry sources.\n`);
      process.exit(1);
    }
    process.stdout.write('qualification catalogs: no drift\n');
  } else {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, expected);
    process.stdout.write(`wrote ${OUT}\n`);
  }
}
