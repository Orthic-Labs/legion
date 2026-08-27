#!/usr/bin/env node
// Fails the build when a packaged skill references something that resolves into no declared
// dependency class: a private path, a dangling script, an unresolved TODO, a stale manifest
// consumer, or a host capability nobody declared.

import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { verifyDependencyClosure } from '../src/lib/skills/dependency-closure.mjs';

const packageRoot = resolve(import.meta.dirname, '..');
const manifestDir = join(packageRoot, 'skills/manifests');
const manifests = Object.fromEntries(
  readdirSync(manifestDir).filter((name) => name.endsWith('.json') && !name.endsWith('.import-receipt.json')).map((name) => {
    const manifest = JSON.parse(readFileSync(join(manifestDir, name), 'utf8'));
    return [manifest.id, manifest];
  }),
);

const { ok, findings, summary } = verifyDependencyClosure({ packageRoot, manifests });
if (ok) {
  console.log(`dependency closure ok: ${summary.dependencyDeclarations}/${summary.semanticBundles} declarations, ${summary.typedResources} typed resources`);
  process.exit(0);
}
for (const finding of findings) {
  console.error(`${finding.code}: ${finding.bundleId ?? '-'}/${finding.path ?? '-'} — ${finding.detail}`);
}
console.error(`\ndependency closure failed: ${findings.length} finding(s)`);
process.exit(6);
