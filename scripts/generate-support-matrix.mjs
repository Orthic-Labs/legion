#!/usr/bin/env node
// Generates support claims (README fragments, legion languages tables) from
// the coverage registry only. Fails with --check when generated output drifts.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

export function buildSupportMatrix(registryPath = 'src/registry/coverage/coverage-registry.json') {
  const registry = JSON.parse(readFileSync(resolve(registryPath), 'utf8'));
  const rows = (registry.languages ?? []).map((record) => ({
    id: record.id,
    kind: record.kind,
    extensions: record.extensions ?? [],
    tiers: record.tiers,
    qualification: record.qualification?.status ?? 'unproven',
  })).sort((a, b) => a.id.localeCompare(b.id));
  return {
    schemaVersion: 2,
    kind: 'legion-support-matrix',
    source: 'coverage-registry',
    generatedAt: 'GENERATED', // normalized; timestamps are non-semantic
    rows,
    claim: 'Generated from measured registry state; never hand-edited.',
  };
}

export function renderMarkdown(matrix) {
  const lines = ['# Legion language support matrix', '', '| Language | Inventory | Parser | Native | Dataflow | Measured | Runtime | Remediation |', '|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|'];
  for (const row of matrix.rows) {
    const t = row.tiers;
    lines.push(`| ${row.id} | ${t.inventory} | ${t.parser} | ${t.nativeSemantics} | ${t.crossFileDataflow} | ${t.measuredPack} | ${t.runtime} | ${t.remediation} |`);
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const check = process.argv.includes('--check');
  const matrix = buildSupportMatrix();
  const markdown = renderMarkdown(matrix);
  const target = resolve('references/support-matrix.generated.md');
  if (!existsSync(target)) {
    writeFileSync(target, markdown);
    console.log('wrote references/support-matrix.generated.md');
    return;
  }
  const committed = readFileSync(target, 'utf8');
  if (committed !== markdown) {
    if (check) {
      console.error('SUPPORT MATRIX DRIFT: references/support-matrix.generated.md is stale; run node scripts/generate-support-matrix.mjs');
      process.exit(1);
    }
    writeFileSync(target, markdown);
    console.log('wrote references/support-matrix.generated.md');
  } else {
    console.log('support matrix in sync');
  }
}

if (process.argv[1]?.endsWith('generate-support-matrix.mjs')) main();
