#!/usr/bin/env node
// Public channels require an explicit grant bound to current shipped surface.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkPublicationSurface } from './check-publication-surface.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INTERNAL = new Set(['internal-pack', 'local-test', 'ci-test']);

function readJson(root, path) {
  return JSON.parse(readFileSync(resolve(root, path), 'utf8'));
}

export function publicationSurfaceDigest(root = ROOT) {
  const pkg = readJson(root, 'package.json');
  const manifest = readJson(root, 'MANIFEST.package.json');
  const canonical = JSON.stringify({
    files: pkg.files,
    allowlistedTopLevel: manifest.allowlistedTopLevel,
  });
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export function checkPublicationChannel(channel, root = ROOT) {
  if (!channel) return { status: 'error', exitCode: 4, message: 'usage: check-publication-policy.mjs --channel <name>' };
  if (INTERNAL.has(channel)) return { status: 'pass', exitCode: 0, message: `internal channel allowed: ${channel}` };
  const policyPath = resolve(root, 'release/publication-policy.json');
  if (!existsSync(policyPath)) return { status: 'blocked', exitCode: 5, message: `publication blocked: ${policyPath} is absent` };
  const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
  if (policy.schemaVersion !== 1 || policy.kind !== 'legion-publication-policy') {
    return { status: 'blocked', exitCode: 5, message: 'publication blocked: invalid policy' };
  }
  const grant = policy.channels?.[channel];
  if (grant?.allowed === false) {
    const evidence = (grant.requiredEvidence ?? []).join(', ');
    return {
      status: 'blocked', exitCode: 5,
      message: `publication blocked: channel ${channel} is denied (${grant.reason ?? 'no authorization'})${evidence ? `; required evidence: ${evidence}` : ''}`,
    };
  }
  if (!grant?.allowed || !grant.approvedBy || !grant.approvedAt || !grant.policyDigest) {
    return { status: 'blocked', exitCode: 5, message: `publication blocked: channel ${channel} has no complete grant` };
  }
  const observed = publicationSurfaceDigest(root);
  if (grant.policyDigest !== observed) {
    return {
      status: 'blocked',
      exitCode: 5,
      message: `publication blocked: channel ${channel} policy digest drift (declared ${grant.policyDigest}, current ${observed})`,
    };
  }
  const surface = checkPublicationSurface(root);
  if (surface.status !== 'pass') {
    return {
      status: 'blocked',
      exitCode: 5,
      message: `publication blocked: ${surface.message}`,
    };
  }
  return { status: 'pass', exitCode: 0, message: `publication channel allowed: ${channel}` };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const index = process.argv.indexOf('--channel');
  const result = checkPublicationChannel(index >= 0 ? process.argv[index + 1] : null);
  const output = result.exitCode === 0 ? process.stdout : process.stderr;
  output.write(`${result.message}\n`);
  process.exitCode = result.exitCode;
}
