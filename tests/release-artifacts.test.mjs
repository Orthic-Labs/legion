import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256File, verifyReleaseManifest } from '../scripts/verify-release.mjs';
import { buildWindowsReleasePackage, normalizeWindowsArchitecture } from '../scripts/package-windows-release.mjs';

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
  assert.match(config, /publishBlocked/);
  assert.match(config, /signedProvenanceScheme: "rightkit-release"/);
  assert.match(config, /x86_64-pc-windows-msvc/);
  assert.match(config, /aarch64-pc-windows-msvc/);
  assert.match(config, /packageKind: "portable-zip"/);
  assert.match(config, /legion-hook\.exe/);
  assert.match(config, /legion-mcp\.exe/);
  assert.doesNotMatch(config, /files:\s*\[/);
});

test('native skill assembly retains runtime helpers and excludes generated Python cache', () => {
  const assembly = readFile(new URL('../scripts/assemble-native-release.mjs', import.meta.url), 'utf8');
  assert.match(assembly, /function copySkillTree/);
  assert.match(assembly, /segments\.includes\("__pycache__"\)/);
  assert.match(assembly, /endsWith\("\.pyc"\)/);
  assert.doesNotMatch(assembly, /LEGACY_RUNTIME_EXTENSIONS/);
});

test('Windows package binds target identity and emits blocked evidence seams', () => {
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
    const result = buildWindowsReleasePackage({ input, output, architecture: 'x86_64', repositoryRoot, sourceRevision: 'a'.repeat(40), force: true });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.channel, 'BLOCKED');
    assert.equal(result.targetTriple, 'x86_64-pc-windows-msvc');
    assert.equal(normalizeWindowsArchitecture('windows-x86_64'), 'x86_64');
    assert.ok(existsSync(result.archive));
    const manifest = JSON.parse(readFileSync(result.manifest, 'utf8'));
    assert.equal(manifest.targetIdentity.architecture, 'x86_64');
    assert.equal(manifest.targetIdentity.targetTriple, 'x86_64-pc-windows-msvc');
    assert.equal(manifest.channels[0].decision, 'BLOCKED');
    assert.equal(manifest.signatures[0].status, 'missing');
    assert.equal(manifest.qualificationArtifacts[0].status, 'missing');
    assert.equal(manifest.provenance[0].status, 'missing');
    assert.ok(existsSync(join(output, 'SHA256SUMS')));
    assert.ok(existsSync(join(output, 'SBOM.cdx.json')));
    assert.ok(existsSync(join(output, 'winget-portable.json')));

    const receiptPath = join(repositoryRoot, '.right-release', 'receipts', 'windows-x86_64-raw-exe.json');
    mkdirSync(join(repositoryRoot, '.right-release', 'receipts'), { recursive: true });
    const signedFiles = ['legion.exe', 'legion-hook.exe', 'legion-mcp.exe'].map((name) => {
      const file = join(input, 'bin', name);
      return {
        file,
        after: { sha256: sha256File(file).slice('sha256:'.length), sizeBytes: readFileSync(file).length },
        authenticode: 'Valid',
        subject: 'CN=Damned Ventures LLC',
        timestampPresent: true,
      };
    });
    writeFileSync(receiptPath, JSON.stringify({ schema: 1, files: signedFiles }));
    const signedResult = buildWindowsReleasePackage({
      input,
      output: join(repositoryRoot, 'signed-out'),
      architecture: 'x86_64',
      repositoryRoot,
      sourceRevision: 'a'.repeat(40),
      signatureReceipt: receiptPath,
      requireSignature: true,
      force: true,
    });
    assert.equal(signedResult.evidence.signature, 'verified');
    const signedManifest = JSON.parse(readFileSync(signedResult.manifest, 'utf8'));
    assert.equal(signedManifest.signatures[0].status, 'verified');
    assert.equal(JSON.parse(readFileSync(join(signedResult.outputDir, 'signature.json'), 'utf8')).artifacts.length, 3);
    writeFileSync(receiptPath, JSON.stringify({ schema: 1, files: signedFiles.slice(0, 2) }));
    assert.throws(
      () => buildWindowsReleasePackage({
        input,
        output: join(repositoryRoot, 'invalid-out'),
        architecture: 'x86_64',
        repositoryRoot,
        sourceRevision: 'a'.repeat(40),
        signatureReceipt: receiptPath,
        requireSignature: true,
        force: true,
      }),
      /Windows release signing is not verified/,
    );
  } finally {
    rmSync(repositoryRoot, { recursive: true, force: true });
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
