import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { isDevelopmentVersion, versionParityReport } from '../scripts/check-version-parity.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('every shipped product surface consumes one release version', () => {
  assert.deepEqual(versionParityReport(root).issues, []);
});

test('stable identity passes stable validation while development identity is rejected', () => {
  const report = versionParityReport(root, { stable: true });
  assert.equal(report.status, 'pass');
  assert.deepEqual(report.issues, []);
  assert.equal(isDevelopmentVersion('0.1.0-dev.1'), true);
  assert.equal(isDevelopmentVersion('0.1.0'), false);
});

function writeFixture(path, content) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
}

function lockFixture() {
  const fixture = mkdtempSync(join(tmpdir(), 'legion-version-parity-'));
  const version = '0.2.8';
  const json = JSON.stringify({ version });
  writeFixture(join(fixture, 'release/version.json'), JSON.stringify({ schemaVersion: 1, kind: 'legion-release-version', version }));
  for (const path of ['package.json', '.claude-plugin/plugin.json', '.codex-plugin/plugin.json', 'engine/assets/legion-plugin/plugin.json', 'src/registry/plugin-surface.json']) writeFixture(join(fixture, path), json);
  writeFixture(join(fixture, 'engine/Cargo.toml'), `[workspace]\n[workspace.package]\nversion = "${version}"\n`);
  writeFixture(join(fixture, 'engine/bins/legion/Cargo.toml'), `[package]\nname = "legion"\nversion.workspace = true\n`);
  writeFixture(join(fixture, 'engine/bins/legion/src/cli.rs'), 'env!("CARGO_PKG_VERSION")');
  writeFixture(join(fixture, 'src/lib/version.mjs'), '"../../release/version.json"');
  writeFixture(join(fixture, 'engine/Cargo.lock'), `version = 4\n\n[[package]]\nname = "legion"\nversion = "${version}"\n`);
  return fixture;
}

test('lock parity rejects sourced or missing workspace package blocks', () => {
  const fixture = lockFixture();
  try {
    writeFileSync(join(fixture, 'engine/Cargo.lock'), 'version = 4\n\n[[package]]\nname = "legion"\nversion = "0.2.8"\nsource = "registry+https://example.invalid"\n');
    assert.match(versionParityReport(fixture).issues.find((issue) => issue.path === 'engine/Cargo.lock')?.reason ?? '', /missing, malformed, or sourced externally/);
    writeFileSync(join(fixture, 'engine/Cargo.lock'), 'version = 4\n\n[[package]]\nname = "unrelated"\nversion = "0.2.8"\n');
    assert.match(versionParityReport(fixture).issues.find((issue) => issue.path === 'engine/Cargo.lock')?.reason ?? '', /missing, malformed, or sourced externally/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
