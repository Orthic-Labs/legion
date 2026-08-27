#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const readJson = (root, path) => JSON.parse(readFileSync(join(root, path), 'utf8'));

function cargoManifests(root, cursor = join(root, 'engine'), output = []) {
  for (const entry of readdirSync(cursor)) {
    if (entry === 'target') continue;
    const path = join(cursor, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) cargoManifests(root, path, output);
    else if (entry === 'Cargo.toml') output.push(path);
  }
  return output;
}

export function versionParityReport(root = ROOT, { stable = false } = {}) {
  const release = readJson(root, 'release/version.json');
  const expected = release.version;
  const issues = [];
  if (release.schemaVersion !== 1 || release.kind !== 'legion-release-version' || typeof expected !== 'string') {
    issues.push({ path: 'release/version.json', reason: 'invalid canonical release version record' });
  }
  if (stable && /-dev\./.test(expected)) {
    issues.push({ path: 'release/version.json', reason: `stable release cannot use development version ${expected}` });
  }
  for (const path of ['package.json', '.claude-plugin/plugin.json', '.codex-plugin/plugin.json', 'engine/assets/legion-plugin/plugin.json', 'src/registry/plugin-surface.json']) {
    const observed = readJson(root, path).version;
    if (observed !== expected) issues.push({ path, reason: `version ${observed ?? '<missing>'} differs from ${expected}` });
  }
  const workspace = readFileSync(join(root, 'engine', 'Cargo.toml'), 'utf8');
  const workspaceVersion = /^version\s*=\s*"([^"]+)"$/m.exec(workspace)?.[1];
  if (workspaceVersion !== expected) {
    issues.push({ path: 'engine/Cargo.toml', reason: `workspace version ${workspaceVersion ?? '<missing>'} differs from ${expected}` });
  }
  for (const path of cargoManifests(root)) {
    if (path === join(root, 'engine', 'Cargo.toml')) continue;
    const source = readFileSync(path, 'utf8');
    if (!/^version\.workspace\s*=\s*true$/m.test(source)) {
      issues.push({ path: relative(root, path).replaceAll('\\', '/'), reason: 'crate version does not inherit workspace release version' });
    }
  }
  const lock = readFileSync(join(root, 'engine/Cargo.lock'), 'utf8');
  for (const section of lock.split('[[package]]').slice(1)) {
    const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(section)?.[1];
    if (name !== 'legion' && !name?.startsWith('legion-')) continue;
    const observed = /^\s*version\s*=\s*"([^"]+)"/m.exec(section)?.[1];
    if (observed !== expected) issues.push({ path: 'engine/Cargo.lock', reason: `${name} lock version ${observed ?? '<missing>'} differs from ${expected}` });
  }
  const library = readFileSync(join(root, 'src/lib/version.mjs'), 'utf8');
  if (!library.includes("../../release/version.json")) {
    issues.push({ path: 'src/lib/version.mjs', reason: 'library version does not consume canonical release version record' });
  }
  const cli = readFileSync(join(root, 'engine/bins/legion/src/cli.rs'), 'utf8');
  if (!cli.includes('env!("CARGO_PKG_VERSION")')) {
    issues.push({ path: 'engine/bins/legion/src/cli.rs', reason: 'CLI version does not consume Cargo package version' });
  }
  return { schemaVersion: 1, kind: 'legion-version-parity-report', version: expected, stable, status: issues.length ? 'fail' : 'pass', issues };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const report = versionParityReport(ROOT, { stable: process.argv.includes('--stable') });
  if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else if (report.status === 'pass') process.stdout.write(`version parity: PASS (${report.version})\n`);
  else for (const issue of report.issues) process.stderr.write(`${issue.path}: ${issue.reason}\n`);
  process.exitCode = report.status === 'pass' ? 0 : 1;
}
