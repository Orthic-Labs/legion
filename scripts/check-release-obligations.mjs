#!/usr/bin/env node
/**
 * Validates release/obligations.json: the machine-readable set of deterministic
 * obligations a Legion release must close.
 *
 * The manifest is only worth having if every obligation names a producer that
 * exists. A declared obligation whose evidence producer is missing is worse
 * than no manifest at all, because it reads as coverage that is not there.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_PATH = 'release/obligations.json';
const GRANTS = new Set(['BUILD_AUTHORIZED', 'SIGNING_AUTHORIZED', 'RELEASE_AUTHORIZED']);

export function checkReleaseObligations(root = ROOT) {
  const issues = [];
  const path = resolve(root, MANIFEST_PATH);
  if (!existsSync(path)) return { ok: false, issues: [`${MANIFEST_PATH} is missing`] };

  let manifest;
  try { manifest = JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { return { ok: false, issues: [`${MANIFEST_PATH} is invalid JSON: ${error.message}`] }; }

  if (manifest.schemaVersion !== 1 || manifest.kind !== 'legion-release-obligations' || manifest.product !== 'legion') {
    issues.push('release obligations manifest identity is invalid');
  }
  if (!Array.isArray(manifest.gates) || manifest.gates.length === 0) {
    return { ok: false, issues: [...issues, 'release obligations manifest declares no gates'] };
  }

  const scripts = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).scripts ?? {};
  const seenGates = new Set();
  const seenObligations = new Set();

  for (const gate of manifest.gates) {
    if (!gate?.id || !gate?.name) { issues.push('a gate is missing id or name'); continue; }
    if (seenGates.has(gate.id)) issues.push(`duplicate gate id: ${gate.id}`);
    seenGates.add(gate.id);
    if (gate.grant !== null && !GRANTS.has(gate.grant)) issues.push(`gate ${gate.id} declares an unknown grant: ${gate.grant}`);
    if (!Array.isArray(gate.obligations) || gate.obligations.length === 0) {
      issues.push(`gate ${gate.id} declares no obligations`);
      continue;
    }
    for (const obligation of gate.obligations) {
      if (!obligation?.id || !obligation?.requirement) {
        issues.push(`gate ${gate.id} has an obligation missing id or requirement`);
        continue;
      }
      // An obligation with no producer yet must say so explicitly and name the
      // gap. Silence would read as coverage; a named gap reads as backlog.
      if (obligation.implemented === false) {
        if (!obligation.gap) issues.push(`obligation ${obligation.id} is unimplemented but names no gap`);
        if (obligation.evidence) issues.push(`obligation ${obligation.id} is unimplemented but names evidence`);
        if (seenObligations.has(obligation.id)) issues.push(`duplicate obligation id: ${obligation.id}`);
        seenObligations.add(obligation.id);
        continue;
      }
      if (!obligation.evidence) {
        issues.push(`gate ${gate.id} obligation ${obligation.id} names no evidence and is not marked unimplemented`);
        continue;
      }
      if (seenObligations.has(obligation.id)) issues.push(`duplicate obligation id: ${obligation.id}`);
      seenObligations.add(obligation.id);
      // The evidence producer must be a real package script or a real file;
      // anything else is a claim with nothing behind it.
      const evidence = String(obligation.evidence);
      const isScript = evidence.startsWith('pnpm ')
        ? Boolean(scripts[evidence.slice('pnpm '.length).trim()])
        : Boolean(scripts[evidence]);
      const isFile = evidence.includes('/') && existsSync(resolve(root, evidence));
      const isArtifact = /^[a-z0-9-]+(\.json|-summary| readback| fetch)$/i.test(evidence) || evidence.endsWith('stage-summary');
      if (!isScript && !isFile && !isArtifact) {
        issues.push(`obligation ${obligation.id} names an evidence producer that does not exist: ${evidence}`);
      }
    }
  }

  // The three capability grants must each be claimed by exactly one gate, so a
  // single gate cannot quietly authorize build, signing and publication alike.
  for (const grant of GRANTS) {
    const owners = manifest.gates.filter((gate) => gate.grant === grant);
    if (owners.length !== 1) issues.push(`grant ${grant} must be owned by exactly one gate, found ${owners.length}`);
  }

  return { ok: issues.length === 0, issues };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const report = checkReleaseObligations();
  if (report.ok) process.stdout.write(`release obligations: consistent\n`);
  else for (const issue of report.issues) process.stderr.write(`${issue}\n`);
  process.exitCode = report.ok ? 0 : 1;
}
