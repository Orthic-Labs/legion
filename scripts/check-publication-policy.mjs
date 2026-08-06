#!/usr/bin/env node
// Publication policy guard. Public publication (npm, Homebrew, winget, MSI/MSIX,
// signed releases, public SDK channels) is blocked until a tracked
// release/publication-policy.json explicitly grants the channel. Only the
// internal pack/local-test/ci-test channels are always allowed.

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
const index = args.indexOf('--channel');
const channel = index >= 0 ? args[index + 1] : null;
if (!channel) {
  console.error('usage: check-publication-policy.mjs --channel <name>');
  process.exit(4);
}

const internal = new Set(['internal-pack', 'local-test', 'ci-test']);
if (internal.has(channel)) {
  console.log(`internal channel allowed: ${channel}`);
  process.exit(0);
}

const policyPath = resolve('release/publication-policy.json');
if (!existsSync(policyPath)) {
  console.error(`publication blocked: ${policyPath} is absent`);
  process.exit(5);
}

const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
if (policy.schemaVersion !== 1 || policy.kind !== 'nemesis-publication-policy') {
  console.error('publication blocked: invalid policy');
  process.exit(5);
}
const grant = policy.channels?.[channel];
if (!grant?.allowed || !grant.approvedBy || !grant.approvedAt || !grant.policyDigest) {
  console.error(`publication blocked: channel ${channel} has no complete grant`);
  process.exit(5);
}
console.log(`publication channel allowed: ${channel}`);
