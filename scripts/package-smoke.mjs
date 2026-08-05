#!/usr/bin/env node
// Package smoke: pack the tarball, install into clean temporary projects, and
// exercise local bin, npx-style, and global-prefix execution. Also asserts the
// package contents against MANIFEST.package.json — any unexpected path fails.

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const repoRoot = resolve(import.meta.dirname, '..');
const require = createRequire(import.meta.url);

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function makeTempProject(mode) {
  const dir = mkdtempSync(join(tmpdir(), `nemesis-pack-${mode}-`));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `fixture-${mode}`, version: '1.0.0', private: true }));
  return dir;
}

function assertPackageContents(tarballPath) {
  const manifest = JSON.parse(readFileSync(join(repoRoot, 'MANIFEST.package.json'), 'utf8'));
  const list = run('tar', ['-tzf', tarballPath], repoRoot).split('\n').filter(Boolean);
  const contents = list.map((line) => line.replace(/^package\//, ''));
  const unexpected = contents.filter((path) => {
    if (!path) return false;
    if (path === 'package/' || path === 'package') return false;
    // allowlistedTopLevel entries carry their own trailing slash (e.g. 'bin/'),
    // so a plain startsWith match is correct.
    if (manifest.allowlistedTopLevel.some((top) => path === top || path.startsWith(top))) return false;
    return true;
  });
  if (unexpected.length) {
    throw new Error(`package contains unexpected paths: ${unexpected.join(', ')}`);
  }
  for (const forbidden of manifest.forbiddenContents) {
    const hit = contents.find((path) => path.toLowerCase().includes(forbidden.toLowerCase()));
    if (hit) throw new Error(`package contains forbidden content: ${hit}`);
  }
  return contents;
}

export async function packageSmoke() {
  const packOut = run('npm', ['pack', '--json', '--ignore-scripts'], repoRoot);
  // npm pack --json emits the JSON array on stdout (possibly with lifecycle
  // text before it); the top-level array starts at the first '['.
  const jsonStart = packOut.indexOf('[');
  if (jsonStart < 0) throw new Error(`npm pack produced no JSON: ${packOut.slice(0, 200)}`);
  const pack = JSON.parse(packOut.slice(jsonStart));
  const tarball = join(repoRoot, pack[0].filename);
  if (!existsSync(tarball)) throw new Error(`tarball missing: ${tarball}`);
  try {
    const contents = assertPackageContents(tarball);
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
    if (pkg.version !== pack[0].version) throw new Error('package version mismatch');
    for (const mode of ['local', 'npx', 'prefix']) {
      const fixture = makeTempProject(mode);
      try {
        if (mode === 'prefix') {
          const prefix = makeTempProject('prefix-target');
          run('npm', ['install', '--ignore-scripts', '--prefix', prefix, tarball], fixture);
          run(join(prefix, 'node_modules', '.bin', 'nemesis'), ['--version'], fixture);
          rmSync(prefix, { recursive: true, force: true });
        } else {
          run('npm', ['install', '--ignore-scripts', tarball], fixture);
          if (mode === 'local') {
            const version = run(join(fixture, 'node_modules', '.bin', 'nemesis'), ['--version'], fixture).trim();
            if (version !== pkg.version) throw new Error(`local version mismatch: ${version}`);
          } else {
            const npxOut = run('npx', ['--no-install', 'nemesis', '--version'], fixture).trim();
            if (npxOut !== pkg.version) throw new Error(`npx version mismatch: ${npxOut}`);
          }
        }
        console.log(`OK ${mode} install smoke`);
      } finally {
        rmSync(fixture, { recursive: true, force: true });
      }
    }
    return { tarball, contents: contents.length, version: pkg.version };
  } finally {
    rmSync(tarball, { force: true });
  }
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  packageSmoke()
    .then((result) => {
      console.log(`package smoke passed: ${result.tarball.split('/').pop()} (${result.contents} files, v${result.version})`);
    })
    .catch((error) => {
      console.error(error.message);
      process.exit(1);
    });
}
