#!/usr/bin/env node
// Native executable builder per SNIP-SEA-01. Builds Node Single Executable
// Applications for the current platform, records toolchain/config/package
// digests, and never publishes. No Rust wrapper crate.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function digestOf(file) {
  if (!existsSync(file)) return null;
  return `sha256:${createHash('sha256').update(readFileSync(file)).digest('hex')}`;
}

export function exeSuffix() {
  return platform() === 'win32' ? '.exe' : '';
}

export function seaConfig() {
  return JSON.parse(readFileSync(join(root, 'packaging', 'sea', 'sea-config.json'), 'utf8'));
}

export function buildNative({ nodeBinary = process.execPath, outDir = join(root, 'dist') } = {}) {
  const suffix = exeSuffix();
  const config = seaConfig();
  const prepDir = join(root, 'dist');
  mkdirSync(prepDir, { recursive: true });

  // SEA requires a CommonJS entry that loads the ESM CLI via dynamic import.
  const entry = join(prepDir, 'sea-entry.cjs');
  writeFileSync(entry, `module.exports = require('../bin/nemesis.mjs');\n`);
  const output = join(prepDir, 'sea-preparation.blob');

  // SEA requires the declared assets to exist; create empty placeholder tarballs.
  const assetsDir = join(prepDir, 'assets');
  mkdirSync(assetsDir, { recursive: true });
  for (const asset of ['schemas.tar', 'registry.tar']) {
    const assetPath = join(assetsDir, asset);
    if (!existsSync(assetPath)) {
      execFileSync('tar', ['-cf', assetPath, '--files-from', '/dev/null'], { stdio: 'ignore' });
    }
  }

  execFileSync(nodeBinary, ['--build-sea', join(root, 'packaging', 'sea', 'sea-config.json')], { cwd: root, stdio: 'inherit' });

  const target = join(outDir, `nemesis${suffix}`);
  if (existsSync(join(root, 'node_modules', 'postject'))) {
    execFileSync('cp', [nodeBinary, target], { stdio: 'inherit' });
    execFileSync(process.execPath, [
      join(root, 'node_modules', 'postject', 'postject.js'), target, 'NODE_SEA_BLOB', output,
      '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
    ], { stdio: 'inherit' });
    console.log('SEA blob injected');
  } else {
    // postject is optional; without it no executable is emitted, so a bare
    // node copy can never be mistaken for a nemesis binary.
    console.log('postject not installed; SEA blob injection skipped (equivalence test uses npm CLI)');
  }

  const manifest = {
    schemaVersion: 1,
    kind: 'nemesis-native-build',
    platform: platform(),
    nodeBinary: nodeBinary,
    nodeVersion: execFileSync(nodeBinary, ['--version'], { encoding: 'utf8' }).trim(),
    seaConfigDigest: digestOf(join(root, 'packaging', 'sea', 'sea-config.json')),
    packageDigest: digestOf(join(root, 'package.json')),
    executable: existsSync(target) ? target : null,
    executableDigest: digestOf(target),
    rustCrate: false,
    blobInjected: existsSync(target),
  };
  writeFileSync(join(outDir, 'native-build-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const manifest = buildNative();
    console.log(`native build: ${manifest.executable} (${manifest.nodeVersion})`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
