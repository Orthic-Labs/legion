import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256File, verifyReleaseManifest } from '../scripts/verify-release.mjs';
import {
  buildWindowsReleasePackage,
  normalizeWindowsArchitecture,
  qualificationEvidence,
  finalizeWindowsDirectRelease,
  windowsTargetIdentity,
} from '../scripts/package-windows-release.mjs';

function readFile(path) {
  return readFileSync(fileURLToPath(path), 'utf8');
}

test('verifyReleaseManifest rejects an unsigned manifest (no false clean)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-rel-'));
  try {
    writeFileSync(join(dir, 'legion'), 'binary');
    writeFileSync(join(dir, 'SHA256SUMS'), 'sums');
    writeFileSync(join(dir, 'legion.sbom.json'), '{}');
    writeFileSync(join(dir, 'THIRD_PARTY_NOTICES.md'), 'notices');
    writeFileSync(join(dir, 'attestation.jsonl'), '{"predicateType":"test"}\n');
    const digest = sha256File(join(dir, 'legion'));
    const manifest = {
      schemaVersion: 1, kind: 'legion-release-manifest',
      version: '0.0.0-test', sourceRevision: '0123456789abcdef',
      artifacts: [{ path: 'legion', digest }],
      checksums: ['SHA256SUMS'], sboms: ['legion.sbom.json'],
      notices: ['THIRD_PARTY_NOTICES.md'], attestations: ['attestation.jsonl'],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    // An unsigned, un-notarized manifest is NOT a valid release — asserting
    // valid:true here encoded a false clean. The verifier correctly demands
    // signatures, notarization, qualification artifacts, and per-entry digests.
    assert.equal(result.valid, false);
    const kinds = result.issues.map((issue) => issue.issue).sort();
    assert.ok(kinds.includes('missing'), 'unsigned manifest must report missing signature/notarization');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyReleaseManifest rejects digest mismatch', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-rel-'));
  try {
    writeFileSync(join(dir, 'legion'), 'changed');
    const manifest = {
      schemaVersion: 1, kind: 'legion-release-manifest',
      artifacts: [{ path: 'legion', digest: 'sha256:wrong' }],
      checksums: ['SHA256SUMS'], sboms: ['s.json'], notices: ['n.md'], attestations: ['a.jsonl'],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((issue) => issue.issue === 'digest-mismatch'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyReleaseManifest rejects missing required artifacts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-rel-'));
  try {
    const manifest = {
      schemaVersion: 1, kind: 'legion-release-manifest',
      artifacts: [], checksums: [], sboms: [], notices: [], attestations: [],
    };
    writeFileSync(join(dir, 'release-manifest.json'), JSON.stringify(manifest));
    const result = verifyReleaseManifest(join(dir, 'release-manifest.json'), { distDir: dir });
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((issue) => issue.issue === 'missing'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('right-release config keeps signing and publication fail-closed', () => {
  const config = readReleaseConfig();
  assert.match(config, /hostedWorkflows: "right-git-ci-only"/);
  assert.match(config, /version: releaseVersion/);
  assert.match(config, /signed: true/);
  assert.match(config, /targetTriple: selectedWindows\.targetTriple/);
  assert.match(config, /provider: "github-releases"/);
  assert.match(config, /repository: "Orthic-Labs\/legion"/);
  assert.match(config, /payloadAuthority: "immutable-github-release"/);
  assert.match(config, /manifestAuthority: "release-manifest\.json\+release-manifest\.cat"/);
  assert.match(config, /signatureAlgorithm: "authenticode-catalog-sha256"/);
  assert.match(config, /signatureProvider: "windows-authenticode-catalog"/);
  assert.match(config, /signatureProviderVersion: 1/);
  assert.match(config, /role: "manifest-bound-convenience"/);
  assert.match(config, /publisher: "rightkit-release"/);
  assert.match(config, /provider: "rightapps-downloads-r2"/);
  assert.match(config, /mode: "branded-bootstrap-only"/);
  assert.match(config, /objectKey: "legion\/install\.ps1"/);
  assert.match(config, /publishBlocked:/);
  assert.match(config, /signedProvenanceScheme: "rightkit-release"/);
  assert.match(config, /x86_64-pc-windows-msvc/);
  assert.match(config, /aarch64-pc-windows-msvc/);
  assert.match(config, /x86_64-apple-darwin/);
  assert.match(config, /aarch64-apple-darwin/);
  assert.match(config, /releaseArchitectures: \["x86_64", "arm64"\]/);
  assert.match(config, /RIGHT_GIT_RELEASE_ARCHITECTURE/);
  assert.doesNotMatch(config, /"AZURE_ARTIFACT_SIGNING_METADATA"/);
  assert.match(config, /packageKind: "portable-zip"/);
  assert.match(config, /legion-hook\.exe/);
  assert.match(config, /legion-mcp\.exe/);
  assert.doesNotMatch(config, /packageManager: "winget"|winget-portable\.json|WinGet architecture/);
  assert.doesNotMatch(config, /files:\s*\[/);
  assert.doesNotMatch(config, /release-manifest\.sig|\bcms\b|bespoke uploader|custom uploader/i);
  assert.match(config, /candidateInput: "exact-unsigned-candidate"/);
  assert.match(config, /releaseVerifier: "scripts\/verify-release\.mjs"/);
  assert.match(config, /prepare-windows-candidate-finalization\.mjs/);
  assert.match(config, /finalize-macos-candidate\.mjs/);
  assert.match(config, /macos-developer-id-notarized-portable-v1/);
  assert.match(config, /macos-\$\{macArchitecture\}-notarization\.json/);
  assert.match(config, /LEGION_UNSIGNED_CANDIDATE_ROOT/);
});

test('publication policy freezes immutable GitHub payloads, branded R2 bootstrap, and catalog authority', () => {
  const policy = JSON.parse(readFile(new URL('../release/publication-policy.json', import.meta.url)));
  const authority = policy.authority;
  const direct = policy.channels['direct-bootstrap'];
  assert.equal(policy.schemaVersion, 2);
  assert.equal(policy.kind, 'legion-publication-policy');
  assert.equal(policy.publisher, 'rightkit-release');
  assert.equal(authority.payload, 'immutable-github-release');
  assert.equal(authority.bootstrap, 'branded-r2-bootstrap-only');
  assert.equal(authority.manifestAuthority, 'release-manifest.json+release-manifest.cat');
  assert.deepEqual(authority.manifest, {
    file: 'release-manifest.json',
    signature: 'release-manifest.cat',
    signatureAlgorithm: 'authenticode-catalog-sha256',
    signatureProvider: 'windows-authenticode-catalog',
    signatureProviderVersion: 1,
  });
  assert.deepEqual(authority.checksums, { file: 'checksums.json', role: 'manifest-bound-convenience' });
  assert.equal(policy.channels.npm.allowed, false);
  assert.equal(policy.channels.npm.reason, 'private-development-tooling');
  assert.equal(direct.allowed, false);
  assert.equal(direct.payloadAuthority, 'immutable-github-release');
  assert.equal(direct.bootstrapProvider, 'rightapps-downloads-r2');
  assert.equal(direct.bootstrapMode, 'branded-bootstrap-only');
  assert.equal(direct.manifestAuthority, 'release-manifest.json+release-manifest.cat');
  assert.deepEqual(direct.checksums, { file: 'checksums.json', role: 'manifest-bound-convenience' });
  for (const alias of ['homebrew', 'winget']) {
    assert.equal(policy.channels[alias].allowed, false);
    assert.equal(policy.channels[alias].reason, 'optional-alias-not-required');
    assert.equal(policy.channels[alias].requiredEvidence, undefined);
  }
  assert.doesNotMatch(JSON.stringify(policy), /release-manifest\.sig|\bcms\b|bespoke uploader|custom uploader/i);
});

test('distribution channels keep package managers optional and bind direct bootstrap evidence', () => {
  const channels = JSON.parse(readFile(new URL('../packaging/channels.json', import.meta.url)));
  const direct = channels.channels['direct-bootstrap'];
  assert.equal(channels.schemaVersion, 2);
  assert.equal(channels.kind, 'legion-distribution-channels');
  assert.equal(channels.artifactSource, 'immutable-github-release');
  assert.equal(channels.publicationOwner, 'RightKit Release');
  assert.deepEqual(channels.bootstrap, {
    provider: 'rightapps-downloads-r2',
    mode: 'branded-bootstrap-only',
    stableUrl: 'https://legion.orthiclabs.com/install.ps1',
    objectKey: 'legion/install.ps1',
  });
  assert.deepEqual(channels.manifest, {
    authority: 'release-manifest.json+release-manifest.cat',
    file: 'release-manifest.json',
    signature: 'release-manifest.cat',
    signatureAlgorithm: 'authenticode-catalog-sha256',
    signatureProvider: 'windows-authenticode-catalog',
    signatureProviderVersion: 1,
  });
  assert.deepEqual(channels.checksums, { file: 'checksums.json', role: 'manifest-bound-convenience' });
  assert.equal(direct.status, 'blocked');
  assert.equal(direct.payloadAuthority, 'immutable-github-release');
  assert.equal(direct.manifestAuthority, 'release-manifest.json+release-manifest.cat');
  assert.equal(direct.bootstrapProvider, 'rightapps-downloads-r2');
  assert.equal(direct.bootstrapMode, 'branded-bootstrap-only');
  for (const alias of ['homebrew', 'winget']) {
    assert.equal(channels.channels[alias].status, 'optional-alias-not-required');
    assert.equal(channels.channels[alias].required, false);
  }
  assert.doesNotMatch(JSON.stringify(channels), /release-manifest\.sig|\bcms\b|bespoke uploader|custom uploader/i);
});

test('native skill assembly retains runtime helpers and excludes generated Python cache', () => {
  const assembly = readFile(new URL('../scripts/assemble-native-release.mjs', import.meta.url), 'utf8');
  assert.match(assembly, /function copySkillTree/);
  assert.match(assembly, /segments\.includes\("__pycache__"\)/);
  assert.match(assembly, /endsWith\("\.pyc"\)/);
  assert.match(assembly, /assemblePortableCore/);
  assert.match(assembly, /CLIENT_PROJECTION_KINDS/);
  assert.match(assembly, /validatePortableCore/);
  assert.doesNotMatch(assembly, /LEGACY_RUNTIME_EXTENSIONS/);
});

test('Windows direct package stages exact archive then fails closed without signing evidence', () => {
  const repositoryRoot = mkdtempSync(join(tmpdir(), 'legion-win-package-'));
  const input = join(repositoryRoot, 'assembled');
  const output = join(repositoryRoot, 'out');
  try {
    mkdirSync(join(repositoryRoot, 'release'), { recursive: true });
    mkdirSync(join(repositoryRoot, 'docs'), { recursive: true });
    mkdirSync(join(input, 'bin'), { recursive: true });
    mkdirSync(join(input, 'share', 'legion'), { recursive: true });
    writeFileSync(join(repositoryRoot, 'release', 'version.json'), JSON.stringify({ schemaVersion: 1, kind: 'legion-release-version', version: '0.1.0' }));
    writeFileSync(join(repositoryRoot, 'docs', 'THIRD_PARTY_NOTICES.md'), 'Legion notice\n');
    for (const name of ['legion.exe', 'legion-hook.exe', 'legion-mcp.exe']) writeFileSync(join(input, 'bin', name), `${name}\n`);
    const runtimeDigest = sha256File(join(input, 'bin', 'legion.exe')).slice('sha256:'.length);
    writeFileSync(join(input, 'share', 'legion', 'release.json'), JSON.stringify({
      releaseVersion: '0.1.0',
      runtime: { platform: 'windows', architecture: 'x86_64', sha256: runtimeDigest, provenance: 'local-build://windows-x86_64' },
    }));
    const createArchive = ({ outputPath }) => {
      writeFileSync(outputPath, 'portable archive bytes');
      return {
        path: outputPath,
        size: readFileSync(outputPath).length,
        sha256: sha256File(outputPath).slice('sha256:'.length),
      };
    };
    const result = buildWindowsReleasePackage({
      input,
      output,
      architecture: 'x86_64',
      repositoryRoot,
      sourceRevision: 'a'.repeat(40),
      force: true,
      createArchive,
    });
    assert.equal(result.status, 'archive-prepared');
    assert.equal(result.targetIdentity.targetTriple, 'x86_64-pc-windows-msvc');
    assert.equal(normalizeWindowsArchitecture('windows-x86_64'), 'x86_64');
    assert.ok(existsSync(result.archive));
    assert.throws(
      () => buildWindowsReleasePackage({
        input,
        output,
        architecture: 'x86_64',
        repositoryRoot,
        sourceRevision: 'a'.repeat(40),
        finalize: true,
      }),
      /protected Windows finalization requires an exact unsigned candidate root/,
    );
    const source = readFile(new URL('../scripts/package-windows-release.mjs', import.meta.url), 'utf8');
    for (const sharedApi of [
      'createPortableArchive', 'materializeCycloneDxSbom', 'materializeInTotoSlsaProvenance',
      'materializeDirectRelease', 'prepareGitHubDirectRelease', 'publishGitHubRelease',
      'renderPowerShellBootstrap', 'planBootstrapPublication', 'publishBootstrapPlan',
    ]) assert.match(source, new RegExp(`\\b${sharedApi}\\b`));
    assert.doesNotMatch(source, /winget|SHA256SUMS|function createPortableZip|buildSbom/);
  } finally {
    rmSync(repositoryRoot, { recursive: true, force: true });
  }
});

test('protected finalization requires an exact candidate source identity before any work', () => {
  const repositoryRoot = mkdtempSync(join(tmpdir(), 'legion-candidate-finalize-'));
  const candidate = join(repositoryRoot, 'candidate');
  try {
    mkdirSync(join(repositoryRoot, 'release'), { recursive: true });
    mkdirSync(candidate, { recursive: true });
    writeFileSync(join(repositoryRoot, 'release', 'version.json'), JSON.stringify({ schemaVersion: 1, kind: 'legion-release-version', version: '0.1.0' }));
    writeFileSync(join(candidate, 'candidate.json'), '{}');
    assert.throws(
      () => finalizeWindowsDirectRelease({ input: candidate, architecture: 'x86_64', repositoryRoot }),
      /--source-revision is required when consuming an exact unsigned candidate/,
    );
  } finally {
    rmSync(repositoryRoot, { recursive: true, force: true });
  }
});

test('Windows qualification evidence requires native identity, runner, digests, and exactly six passing gates', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-win-qualification-evidence-'));
  const evidencePath = join(dir, 'qualification.json');
  const identity = windowsTargetIdentity('x86_64');
  const archiveSha256 = `sha256:${'a'.repeat(64)}`;
  const runtimeSha256 = `sha256:${'b'.repeat(64)}`;
  const sourceRevision = 'c'.repeat(40);
  const installRoot = join(dir, 'install');
  const currentPath = join(installRoot, 'current');
  const executable = join(currentPath, 'bin', 'legion.exe');
  const versionsRoot = join(installRoot, 'versions');
  const currentVersionRoot = join(versionsRoot, '0.1.0-aaaaaaaaaaaa-fixture');
  const integrationJournalPath = join(installRoot, 'integration-journal.json');
  const generation = `0.1.0:${runtimeSha256.slice('sha256:'.length)}`;
  const binding = {
    origin: 'installed',
    installRoot,
    currentPath,
    executable,
    generation,
    resolvedVersionRoot: currentVersionRoot,
  };
  const integrationJournal = {
    kind: 'legion-integration-journal',
    origin: 'installed',
    installRoot,
    executable,
    generation,
    activeVersionRoot: currentVersionRoot,
    binding,
  };
  const gates = Object.fromEntries([
    'installed-product',
    'command-resolution',
    'client-integration',
    'update',
    'rollback',
    'uninstall',
  ].map((name) => [name, { name, status: 'pass' }]));
  const valid = {
    schemaVersion: 1,
    kind: 'legion-windows-installed-product-qualification',
    status: 'qualified',
    nativeExecution: true,
    executionMode: 'native',
    targetIdentity: identity,
    releaseVersion: '0.1.0',
    sourceRevision,
    archiveSha256,
    runtimeSha256,
    runner: { os: 'win32', architecture: 'x64', simulated: false },
    origin: 'installed',
    installRoot,
    executable,
    generation,
    binding,
    install: {
      origin: 'installed',
      root: installRoot,
      currentPath,
      executable,
      generation,
      versionsRoot,
      currentVersionRoot,
      integrationJournal: integrationJournalPath,
    },
    integrationJournal,
    gates,
  };
  try {
    writeFileSync(evidencePath, JSON.stringify(valid));
    assert.equal(
      qualificationEvidence({ evidencePath, archiveDigest: archiveSha256, runtimeDigest: runtimeSha256, identity, releaseVersion: '0.1.0', sourceRevision }).status,
      'verified',
    );

    const invalidCases = [
      { ...valid, nativeExecution: false },
      { ...valid, executionMode: 'simulated' },
      { ...valid, runner: { ...valid.runner, simulated: true } },
      { ...valid, kind: 'legion-windows-qualification-evidence' },
      { ...valid, gates: { ...gates, rollback: { name: 'rollback', status: 'fail' } } },
      { ...valid, gates: { ...gates, uninstall: undefined } },
      { ...valid, runner: { os: 'linux', architecture: 'x64' } },
    ];
    for (const invalid of invalidCases) {
      writeFileSync(evidencePath, JSON.stringify(invalid));
      assert.equal(
        qualificationEvidence({ evidencePath, archiveDigest: archiveSha256, runtimeDigest: runtimeSha256, identity, releaseVersion: '0.1.0', sourceRevision }).status,
        'invalid',
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('public Actions surface contains only right-git managed CI', () => {
  const workflow = readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.match(workflow, /^# Managed by right-git/);
  assert.doesNotMatch(workflow, /id-token: write|attestations: write|sign|publish/i);
});

test('macOS and Windows signing outlines are documented', () => {
  const mac = readFile(new URL('../packaging/macos/sign.md', import.meta.url), 'utf8');
  assert.match(mac, /codesign --force --options runtime --timestamp/);
  assert.match(mac, /notarytool submit/);
  assert.match(mac, /spctl --assess/);
  const win = readFile(new URL('../packaging/windows/sign.md', import.meta.url), 'utf8');
  assert.match(win, /signtool\.exe sign/);
  assert.match(win, /\/tr "http:\/\/timestamp\.acs\.microsoft\.com"/);
  assert.match(win, /signtool\.exe verify/);
});

function readReleaseConfig() {
  return readFile(new URL('../right-release.config.mjs', import.meta.url), 'utf8');
}
