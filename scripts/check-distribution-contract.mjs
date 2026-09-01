#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const CONTRACT_PATH = 'release/distribution-contract.json';
const POLICY_PATH = 'release/publication-policy.json';
const CHANNELS_PATH = 'packaging/channels.json';
const RELEASE_CONFIG_PATH = 'right-release.config.mjs';
const BOOTSTRAP_URL = 'https://legion.orthiclabs.com/install.ps1';
const BOOTSTRAP_PROVIDER = 'rightkit-worker-r2';
const BOOTSTRAP_MODE = 'worker-r2-stable-object';
const BOOTSTRAP_OBJECT_KEY = 'legion/install.ps1';
const BOOTSTRAP_BUCKET = 'rightapps-downloads';
// Pages is a retired, conflicting control plane: RightKit Worker+R2 is the sole
// bootstrap channel, so any surviving product Pages wrapper must fail closed.
const RETIRED_PAGES_PATHS = ['docs/CNAME', 'docs/install.ps1', 'site/install.ps1'];
const PAYLOAD_AUTHORITY = 'immutable-github-release';
const MANIFEST_AUTHORITY = 'release-manifest.json+release-manifest.cat';
const MANIFEST_FILE = 'release-manifest.json';
const MANIFEST_SIGNATURE = 'release-manifest.cat';
const SIGNATURE_ALGORITHM = 'authenticode-catalog-sha256';
const SIGNATURE_PROVIDER = 'windows-authenticode-catalog';
const SIGNATURE_PROVIDER_VERSION = 1;
const CHECKSUMS_FILE = 'checksums.json';
const CHECKSUMS_ROLE = 'manifest-bound-convenience';
const PUBLISHER = 'rightkit-release';
const REQUIRED_EVIDENCE = [
  'platform-artifacts',
  'platform-signatures',
  'provenance-attestations',
  'signed-release-manifest',
  'bootstrap-transaction',
  'rollback-transaction',
  'client-integration-health',
  'channel-authorization',
];

const readJson = (root, path) => JSON.parse(readFileSync(resolve(root, path), 'utf8'));
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function checkManifestAuthority(value, issues, label) {
  if (value?.manifestAuthority !== MANIFEST_AUTHORITY) issues.push(`${label} must use release-manifest.json + release-manifest.cat`);
  const manifest = value?.manifest;
  if (manifest?.file !== MANIFEST_FILE || manifest?.signature !== MANIFEST_SIGNATURE) issues.push(`${label} manifest files are not release-manifest.json + release-manifest.cat`);
  if (manifest?.signatureAlgorithm !== SIGNATURE_ALGORITHM) issues.push(`${label} manifest signature algorithm is not Authenticode catalog SHA-256`);
  if (manifest?.signatureProvider !== SIGNATURE_PROVIDER || manifest?.signatureProviderVersion !== SIGNATURE_PROVIDER_VERSION) issues.push(`${label} manifest signature provider is not windows-authenticode-catalog v1`);
  const checksums = value?.checksums;
  if (checksums?.file !== CHECKSUMS_FILE || checksums?.role !== CHECKSUMS_ROLE) issues.push(`${label} checksums must be manifest-bound convenience evidence`);
}

function checkNoRetiredClaims(value, issues, label) {
  const text = JSON.stringify(value).toLowerCase();
  if (text.includes('release-manifest.sig')) issues.push(`${label} contains retired release-manifest.sig authority`);
  if (text.includes('cms')) issues.push(`${label} contains a detached CMS claim`);
  if (text.includes('bespoke uploader') || text.includes('custom uploader')) issues.push(`${label} contains a bespoke uploader claim`);
}

export function validateDistributionContract(root = ROOT) {
  const contract = readJson(root, CONTRACT_PATH);
  const policy = readJson(root, POLICY_PATH);
  const channels = readJson(root, CHANNELS_PATH);
  const pkg = readJson(root, 'package.json');
  const issues = [];
  if (contract.schemaVersion !== 2 || contract.kind !== 'legion-distribution-contract') issues.push('invalid release/distribution-contract.json');
  if (pkg.name !== contract.nodePackage?.name) issues.push('package name differs from distribution contract');
  if (contract.nodePackage?.access !== 'private-development-tooling' || contract.nodePackage?.public !== false || pkg.private !== true) issues.push('Node package must remain private development tooling');
  if (policy.schemaVersion !== 2 || policy.kind !== 'legion-publication-policy') issues.push('invalid release/publication-policy.json');
  if (policy.contract !== CONTRACT_PATH) issues.push('publication policy is not bound to distribution contract');
  if (policy.channels?.npm?.allowed !== false || policy.channels?.npm?.reason !== 'private-development-tooling') issues.push('npm publication must be denied as private development tooling');
  const native = contract.nativeRelease ?? {};
  const grant = policy.channels?.[native.channel];
  if (!grant || grant.allowed !== (native.status === 'available')) issues.push('native release policy differs from native release status');
  if (!same(grant?.requiredEvidence ?? [], native.requiredEvidence ?? [])) issues.push('native release evidence list differs from distribution contract');
  if (!same(native.requiredEvidence ?? [], REQUIRED_EVIDENCE)) issues.push('native release evidence is incomplete or reordered');
  if (native.channel !== 'direct-bootstrap') issues.push('native release must use direct-bootstrap');
  if (native.public !== true || native.status !== 'blocked') issues.push('native direct-bootstrap publication must remain blocked until evidence is complete');
  if (native.payloadAuthority !== PAYLOAD_AUTHORITY) issues.push('native payload authority must be immutable GitHub Releases');
  if (native.bootstrapAuthority !== BOOTSTRAP_URL) issues.push('native bootstrap authority must be the stable Worker route');
  if (native.manifestAuthority !== MANIFEST_AUTHORITY) issues.push('signed release manifest catalog must be sole release authority');
  if (native.requiredEvidence?.includes('package-manager-metadata')) issues.push('package-manager metadata cannot be required release evidence');
  checkManifestAuthority(policy.authority, issues, 'publication policy authority');
  if (policy.authority?.payload !== PAYLOAD_AUTHORITY || policy.authority?.bootstrap !== 'rightkit-worker-r2-stable-object' || policy.publisher !== PUBLISHER) issues.push('publication policy authority is not frozen to GitHub payloads, RightKit Worker+R2 bootstrap, and RightKit Release');
  if (grant?.payloadAuthority !== PAYLOAD_AUTHORITY || grant?.bootstrapProvider !== BOOTSTRAP_PROVIDER || grant?.bootstrapMode !== BOOTSTRAP_MODE || grant?.stableUrl !== BOOTSTRAP_URL || grant?.publisher !== PUBLISHER) issues.push('direct-bootstrap policy authority is incomplete');
  checkManifestAuthority(grant, issues, 'direct-bootstrap policy');

  if (channels.schemaVersion !== 2 || channels.kind !== 'legion-distribution-channels') issues.push('invalid packaging/channels.json');
  if (channels.contract !== CONTRACT_PATH) issues.push('distribution channel ledger is not bound to distribution contract');
  if (channels.versionSource !== 'release/version.json' || channels.artifactSource !== PAYLOAD_AUTHORITY) issues.push('distribution channel ledger is not bound to versioned immutable GitHub payloads');
  if (channels.publicationOwner !== 'RightKit Release') issues.push('distribution channel publisher must be RightKit Release');
  if (channels.bootstrap?.provider !== BOOTSTRAP_PROVIDER || channels.bootstrap?.mode !== BOOTSTRAP_MODE || channels.bootstrap?.stableUrl !== BOOTSTRAP_URL || channels.bootstrap?.objectKey !== BOOTSTRAP_OBJECT_KEY) issues.push('distribution channel bootstrap must be the RightKit Worker+R2 stable object only');
  checkManifestAuthority({ manifestAuthority: channels.manifest?.authority, manifest: channels.manifest, checksums: channels.checksums }, issues, 'distribution channel authority');
  if (channels.channels?.[native.channel]?.status !== native.status) issues.push('primary distribution channel differs from native release status');
  if (channels.channels?.[native.channel]?.stableUrl !== native.bootstrapAuthority) issues.push('bootstrap URL differs from distribution contract');
  const direct = channels.channels?.[native.channel];
  if (direct?.payloadAuthority !== PAYLOAD_AUTHORITY || direct?.bootstrapProvider !== BOOTSTRAP_PROVIDER || direct?.bootstrapMode !== BOOTSTRAP_MODE || direct?.manifestAuthority !== MANIFEST_AUTHORITY || direct?.publicationOwner !== 'RightKit Release') issues.push('direct-bootstrap channel authority is incomplete');
  checkManifestAuthority(direct, issues, 'direct-bootstrap channel');
  for (const [id, status] of Object.entries(contract.packageManagers ?? {})) {
    if (channels.channels?.[id]?.status !== status) issues.push(`${id} status differs from distribution contract`);
    if (channels.channels?.[id]?.required !== false) issues.push(`${id} cannot be a required release channel`);
  }
  const configPath = resolve(root, RELEASE_CONFIG_PATH);
  if (!existsSync(configPath)) issues.push('right-release.config.mjs is missing');
  else {
    const config = readFileSync(configPath, 'utf8');
    for (const marker of [
      'provider: "github-releases"',
      'repository: "Orthic-Labs/legion"',
      'payloadAuthority: "immutable-github-release"',
      'manifestAuthority: "release-manifest.json+release-manifest.cat"',
      'signatureAlgorithm: "authenticode-catalog-sha256"',
      'signatureProvider: "windows-authenticode-catalog"',
      'signatureProviderVersion: 1',
      'role: "manifest-bound-convenience"',
      'provider: "rightkit-worker-r2"',
      'mode: "worker-r2-stable-object"',
      'publisher: "rightkit-release"',
      'publishBlocked:',
    ]) if (!config.includes(marker)) issues.push(`right-release config is missing ${marker}`);
    if (/release-manifest\.sig|\bcms\b|bespoke uploader|custom uploader|packageManager:\s*"(?:winget|homebrew)"/i.test(config)) issues.push('right-release config contains a retired distribution authority');
  }
  // Source-to-object-key projection (Gate 0A). Every declaration must name the
  // same R2 object, and that object must be the one the public host resolves to.
  const declaredKeys = new Set([
    native.bootstrap?.stableKey,
    grant?.objectKey,
    channels.bootstrap?.objectKey,
    channels.channels?.[native.channel]?.objectKey,
  ].filter((value) => value !== undefined));
  if (declaredKeys.size !== 1 || !declaredKeys.has(BOOTSTRAP_OBJECT_KEY)) issues.push('bootstrap object key is missing or inconsistent across contract, policy, and channels');
  const host = (() => { try { return new URL(BOOTSTRAP_URL); } catch { return null; } })();
  if (!host || host.protocol !== 'https:') issues.push('bootstrap stable URL must be HTTPS');
  else if (`${host.hostname.split('.')[0]}${host.pathname}` !== BOOTSTRAP_OBJECT_KEY) issues.push(`bootstrap stable URL does not project onto ${BOOTSTRAP_OBJECT_KEY}`);
  for (const bucket of [native.bootstrap?.bucket, grant?.bucket, channels.bootstrap?.bucket]) {
    if (bucket !== BOOTSTRAP_BUCKET) issues.push('bootstrap R2 bucket is missing or not the shared downloads bucket');
  }
  for (const retired of RETIRED_PAGES_PATHS) {
    if (existsSync(resolve(root, retired))) issues.push(`retired GitHub Pages bootstrap path still present: ${retired}`);
  }
  checkNoRetiredClaims(policy, issues, 'publication policy');
  checkNoRetiredClaims(channels, issues, 'distribution channels');
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
