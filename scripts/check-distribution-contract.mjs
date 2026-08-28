#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

const readJson = (root, path) => JSON.parse(readFileSync(resolve(root, path), 'utf8'));

export function validateDistributionContract(root = ROOT) {
  const contract = readJson(root, 'release/distribution-contract.json');
  const policy = readJson(root, 'release/publication-policy.json');
  const channels = readJson(root, 'packaging/channels.json');
  const pkg = readJson(root, 'package.json');
  const issues = [];
  if (contract.schemaVersion !== 2 || contract.kind !== 'legion-distribution-contract') issues.push('invalid release/distribution-contract.json');
  if (pkg.name !== contract.nodePackage?.name) issues.push('package name differs from distribution contract');
  if (contract.nodePackage?.public !== false || pkg.private !== true) issues.push('Node package must remain private development tooling');
  if (policy.contract !== 'release/distribution-contract.json') issues.push('publication policy is not bound to distribution contract');
  if (policy.channels?.npm?.allowed !== false) issues.push('npm publication must be denied');
  const native = contract.nativeRelease ?? {};
  const grant = policy.channels?.[native.channel];
  if (!grant || grant.allowed !== (native.status === 'available')) issues.push('native release policy differs from native release status');
  if (JSON.stringify(grant?.requiredEvidence ?? []) !== JSON.stringify(native.requiredEvidence ?? [])) issues.push('native release evidence list differs from distribution contract');
  if (native.channel !== 'direct-bootstrap') issues.push('native release must use direct-bootstrap');
  if (native.payloadAuthority !== 'immutable-github-release') issues.push('native payload authority must be immutable GitHub Releases');
  if (native.manifestAuthority !== 'release-manifest.json+release-manifest.sig') issues.push('signed release manifest must be sole release authority');
  if (native.requiredEvidence?.includes('package-manager-metadata')) issues.push('package-manager metadata cannot be required release evidence');
  if (channels.schemaVersion !== 2 || channels.kind !== 'legion-distribution-channels') issues.push('invalid packaging/channels.json');
  if (channels.contract !== 'release/distribution-contract.json') issues.push('distribution channel ledger is not bound to distribution contract');
  if (channels.channels?.[native.channel]?.status !== native.status) issues.push('primary distribution channel differs from native release status');
  if (channels.channels?.[native.channel]?.stableUrl !== native.bootstrapAuthority) issues.push('bootstrap URL differs from distribution contract');
  for (const [id, status] of Object.entries(contract.packageManagers ?? {})) {
    if (channels.channels?.[id]?.status !== status) issues.push(`${id} status differs from distribution contract`);
  }
  return { ok: issues.length === 0, issues };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const result = validateDistributionContract();
  if (!result.ok) {
    for (const issue of result.issues) process.stderr.write(`${issue}\n`);
    process.exit(1);
  }
  process.stdout.write('distribution contract: consistent\n');
}
