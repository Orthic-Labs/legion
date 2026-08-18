#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { executeStage9Fixtures, stage9ProbeFor } from '../src/packages/arcane/lib/s09-runtime-executor.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const corpus = join(root, 'src', 'evals', 'architecture');
const digest = createHash('sha256');
const rows = [];
for (const name of readdirSync(corpus).filter((entry) => entry.endsWith('.jsonl')).sort()) {
  const raw = readFileSync(join(corpus, name), 'utf8');
  digest.update(`${name}\0${raw}`);
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const row = JSON.parse(line);
    if (row.execution === 'runtime') rows.push(row);
  }
}
const fixtures = executeStage9Fixtures();
const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const failed = fixtures.filter((result) => result.status !== 'PASS');
const output = {
  schemaVersion: 1,
  kind: 'arcane-s09-runtime-result',
  sourceRevision,
  corpusFingerprint: `sha256:${digest.digest('hex')}`,
  fixtureCount: fixtures.length,
  passedFixtures: fixtures.length - failed.length,
  failed: failed.length,
  fixtures,
  coverageInventory: rows.sort((left, right) => left.id.localeCompare(right.id)).map((row) => ({ id: row.id, family: row.family, probe: stage9ProbeFor(row.family) })),
};
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
process.exitCode = failed.length ? 1 : 0;
