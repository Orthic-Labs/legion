#!/usr/bin/env node
// Rights evidence is fail-closed: absent grants or digest mismatches block
// distribution and never become an inferred redistribution right.

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileDigest } from '../lib/distribution/release-manifest.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function verifySourceProvenance(manifest) {
  const sources = manifest?.sources ?? [];
  const blockers = [];
  for (const source of sources) {
    if (!source.id || !source.status || !source.digest) blockers.push({ kind: 'source-record-incomplete', source: source.id ?? null });
    if (source.shipped && source.redistributionGrant !== true) blockers.push({ kind: 'redistribution-right-unresolved', source: source.id });
    if (source.path && fileDigest(resolve(root, source.path)) !== source.digest) blockers.push({ kind: 'source-digest-mismatch', source: source.id });
  }
  if (!sources.length) blockers.push({ kind: 'source-provenance-absent' });
  return { schemaVersion: 1, kind: 'nemesis-source-provenance-qualification', decision: blockers.length ? 'BLOCKED' : 'QUALIFIED', blockers, sources: sources.map(({ path, ...source }) => source) };
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const input = resolve(root, process.argv[2] ?? 'references/source-provenance/creator-skills.json');
  const result = existsSync(input) ? verifySourceProvenance(JSON.parse(readFileSync(input, 'utf8'))) : verifySourceProvenance(null);
  const out = resolve(root, 'qualification/source-provenance.json');
  writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result));
  process.exit(result.decision === 'QUALIFIED' ? 0 : 1);
}
