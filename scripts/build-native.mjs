#!/usr/bin/env node
// Native executable builder per SNIP-SEA-01. Builds Node Single Executable
// Applications for the current platform, records toolchain/config/package
// digests, and never publishes. No Rust wrapper crate.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { arch, platform } from 'node:os';
import { nativeBuildManifest } from '../lib/distribution/native-manifest.mjs';
import { fileDigest } from '../lib/distribution/release-manifest.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function digestOf(file) { return fileDigest(file); }

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

  // SEA starts a CJS file. Dynamic import preserves the canonical ESM CLI.
  const entry = join(prepDir, 'sea-entry.cjs');
  writeFileSync(entry, `void import('../bin/nemesis.mjs');\n`);
  const output = join(prepDir, 'sea-preparation.blob');

  // SEA assets must contain real shipped material; empty placeholders are a
  // release-integrity failure, not an optional optimization.
  const assetsDir = join(prepDir, 'assets');
  mkdirSync(assetsDir, { recursive: true });
  for (const [asset, source] of [['schemas.tar', 'schemas'], ['registry.tar', 'registry']]) {
    const assetPath = join(assetsDir, asset);
    rmSync(assetPath, { force: true });
    execFileSync('tar', ['-cf', assetPath, '-C', root, source], { stdio: 'inherit' });
    if (!existsSync(assetPath) || readFileSync(assetPath).length === 0) throw new Error(`SEA asset archive is empty: ${asset}`);
  }

  execFileSync(nodeBinary, ['--build-sea', join(root, 'packaging', 'sea', 'sea-config.json')], { cwd: root, stdio: 'inherit' });

  const target = join(outDir, `nemesis${suffix}`);
  if (existsSync(join(root, 'node_modules', 'postject', 'postject.js'))) {
    execFileSync('cp', [nodeBinary, target], { stdio: 'inherit' });
    execFileSync(process.execPath, [
      join(root, 'node_modules', 'postject', 'postject.js'), target, 'NODE_SEA_BLOB', output,
      '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
    ], { stdio: 'inherit' });
    console.log('SEA blob injected');
  } else throw new Error('native build BLOCKED: postject injection tool is absent');

  if (!existsSync(target)) throw new Error('native build failed: injected executable is absent');
  const manifest = nativeBuildManifest({
    platform: platform(), architecture: arch(), nodeBinary,
    nodeVersion: execFileSync(nodeBinary, ['--version'], { encoding: 'utf8' }).trim(),
    seaConfigDigest: digestOf(join(root, 'packaging', 'sea', 'sea-config.json')),
    packageDigest: digestOf(join(root, 'package.json')),
    assets: ['schemas.tar', 'registry.tar'].map((name) => ({ path: `assets/${name}`, digest: digestOf(join(assetsDir, name)) })),
    executable: target,
  });
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
