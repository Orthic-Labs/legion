#!/usr/bin/env node
// Rights evidence is fail-closed: absent grants or digest mismatches block
// distribution and never become an inferred redistribution right.

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileDigest } from '../src/lib/distribution/release-manifest.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function verifySourceProvenance(manifest, { verifyFiles = true } = {}) {
  const sources = manifest?.sources ?? [];
  const blockers = [];
  for (const source of sources) {
    const digestPattern = /^sha256:[0-9a-f]{64}$/i;
    if (!source.id || !source.status || !source.digest) blockers.push({ kind: 'source-record-incomplete', source: source.id ?? null });
    if (!['reference-only', 'transformed', 'archived'].includes(source.status)) blockers.push({ kind: 'source-status-untyped', source: source.id ?? null });
    if (!digestPattern.test(source.digest ?? '') || !digestPattern.test(source.outputDigest ?? '')) blockers.push({ kind: 'source-digest-unresolved', source: source.id ?? null });
    if (source.shipped && source.redistributionGrant !== true) blockers.push({ kind: 'redistribution-right-unresolved', source: source.id });
    if (!source.outputDigest) blockers.push({ kind: 'transformation-manifest-incomplete', source: source.id });
    if (!Array.isArray(source.transformations) || !source.transformations.length) blockers.push({ kind: 'transformation-manifest-incomplete', source: source.id });
    if (source.promptProseShipped === true) blockers.push({ kind: 'creator-prompt-prose-shipped', source: source.id });
    if (['designer', 'writing'].includes(source.id) && source.userOwned !== true) blockers.push({ kind: 'source-ownership-unattested', source: source.id });
    if (!Array.isArray(source.categoryMappings) || !source.categoryMappings.length || source.originalRuleOwnership !== 'repository-original' || !Array.isArray(source.shippedOutputs)) blockers.push({ kind: 'transformation-proof-incomplete', source: source.id });
    if (verifyFiles && source.path && fileDigest(resolve(root, source.path)) !== source.digest) blockers.push({ kind: 'source-digest-mismatch', source: source.id });
  }
  if (!sources.length) blockers.push({ kind: 'source-provenance-absent' });
  return { schemaVersion: 1, kind: 'legion-source-provenance-qualification', decision: blockers.length ? 'BLOCKED' : 'QUALIFIED', blockers, sources: sources.map(({ path, ...source }) => source) };
}

export function writeSourceProvenanceQualification(manifest, outputPath, options = {}) {
  if (!outputPath) throw new Error('outputPath is required');
  const result = verifySourceProvenance(manifest, options);
  writeFileSync(resolve(outputPath), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  return result;
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const input = resolve(root, process.argv[2] ?? 'references/source-provenance/creator-skills.json');
  const result = existsSync(input) ? verifySourceProvenance(JSON.parse(readFileSync(input, 'utf8'))) : verifySourceProvenance(null);
  const outIndex = process.argv.indexOf('--out');
  if (outIndex >= 0) writeFileSync(resolve(process.argv[outIndex + 1]), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(JSON.stringify(result));
  process.exit(result.decision === 'QUALIFIED' ? 0 : 1);
}
