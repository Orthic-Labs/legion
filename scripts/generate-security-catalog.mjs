#!/usr/bin/env node
// Generates the human lens catalog from registry/rule metadata. Fails with
// --check when the committed catalog drifts.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function buildLensCatalog(registryPath = 'registry/security-lenses.json') {
  const registry = JSON.parse(readFileSync(resolve(registryPath), 'utf8'));
  return (registry.lenses ?? []).map((lens) => ({
    id: lens.id,
    family: lens.family,
    description: lens.description,
    implementationState: lens.implementationState,
    benchmarkStatus: lens.benchmark?.status ?? 'unproven',
    requiredForCleanClaim: lens.benchmark?.requiredForCleanClaim ?? true,
  })).sort((a, b) => a.id.localeCompare(b.id));
}

export function renderCatalog(rows) {
  const lines = [
    '# Nemesis security lens catalogue',
    '',
    'Generated from `registry/security-lenses.json`.',
    '',
    '| Lens | Family | Implementation | Benchmark | Clean-claim |',
    '|---|---|---|:---:|:---:|',
  ];
  for (const row of rows) {
    lines.push(`| ${row.id} | ${row.family} | ${row.implementationState} | ${row.benchmarkStatus} | ${row.requiredForCleanClaim ? 'required' : 'optional'} |`);
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const check = process.argv.includes('--check');
  const markdown = renderCatalog(buildLensCatalog());
  const target = resolve('references/security-lens-catalog.md');
  const committed = readFileSync(target, 'utf8');
  if (committed !== markdown) {
    if (check) {
      console.error('LENS CATALOG DRIFT: references/security-lens-catalog.md is stale; run node scripts/generate-security-catalog.mjs');
      process.exit(1);
    }
    writeFileSync(target, markdown);
    console.log('wrote references/security-lens-catalog.md');
  } else {
    console.log('lens catalog in sync');
  }
}

if (process.argv[1] && process.argv[1].endsWith('generate-security-catalog.mjs')) main();
