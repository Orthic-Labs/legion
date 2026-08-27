#!/usr/bin/env node
// Validate static relative ESM imports against npm's own dry-run package file list.
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkPublicationSurface } from './check-publication-surface.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const JAVASCRIPT_FILE = /\.[cm]?js$/i;
const STATIC_ESM_SPECIFIER = /^\s*(?:import\s+(?:[^"']+?\s+from\s+)?|export\s+[^"']*?\s+from\s+)(["'])(\.{1,2}\/[^"']+)\1/gm;
const DYNAMIC_ESM_SPECIFIER = /^\s*(?!\/[/\*]|\*)[^\n]*?\bimport\s*\(\s*(["'])(\.{1,2}\/[^"']+)\1\s*\)/gm;

function normalizePath(path) {
  return String(path).replaceAll('\\', '/').replace(/^\.\//, '');
}

export function packedFilesFromNpmPackPayload(payload) {
  const pack = Array.isArray(payload) ? payload[0] : payload;
  if (!Array.isArray(pack?.files)) throw new TypeError('npm pack --dry-run --json returned no file list');
  return [...new Set(pack.files.map(({ path }) => normalizePath(path)).filter(Boolean))].sort();
}

export function npmPackDryRun(root = ROOT, { spawn = spawnSync } = {}) {
  const command = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const result = spawn(command, ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    shell: process.platform === 'win32',
  });
  if (result.error || result.status !== 0) {
    const detail = String(result.error?.message ?? result.stderr ?? result.stdout ?? 'unknown npm pack failure').trim();
    throw new Error(`npm pack --dry-run failed: ${detail}`);
  }
  return packedFilesFromNpmPackPayload(JSON.parse(result.stdout));
}

export function relativeEsmSpecifiers(source) {
  return [...source.matchAll(STATIC_ESM_SPECIFIER), ...source.matchAll(DYNAMIC_ESM_SPECIFIER)]
    .map((match) => match[2]);
}

export function resolvePackedRelativeImport(from, specifier) {
  const pathname = specifier.split(/[?#]/, 1)[0];
  const resolved = posix.normalize(posix.join(posix.dirname(normalizePath(from)), pathname));
  return resolved === '..' || resolved.startsWith('../') ? null : normalizePath(resolved);
}

export function findMissingPackedRelativeImports({ packedFiles, sources }) {
  const packed = new Set(packedFiles.map(normalizePath));
  const missing = [];
  for (const [from, source] of Object.entries(sources)) {
    for (const specifier of relativeEsmSpecifiers(source)) {
      const target = resolvePackedRelativeImport(from, specifier);
      if (!target || !packed.has(target)) missing.push({ from: normalizePath(from), specifier, target });
    }
  }
  return missing;
}

function packedJavaScriptSources(root, packedFiles) {
  const sources = {};
  for (const path of packedFiles) {
    if (!JAVASCRIPT_FILE.test(path)) continue;
    const absolute = resolve(root, path);
    if (!existsSync(absolute)) throw new Error(`npm pack listed source absent from workspace: ${path}`);
    sources[path] = readFileSync(absolute, 'utf8');
  }
  return sources;
}

export function checkPackedImportClosure(root = ROOT, options = {}) {
  const surface = checkPublicationSurface(root);
  if (surface.status !== 'pass') {
    return { status: 'error', exitCode: 1, message: `packed import closure skipped: ${surface.message}` };
  }
  try {
    const packedFiles = options.packedFiles ?? npmPackDryRun(root, options);
    const sources = options.sources ?? packedJavaScriptSources(root, packedFiles);
    const missing = findMissingPackedRelativeImports({ packedFiles, sources });
    return missing.length === 0
      ? { status: 'pass', exitCode: 0, message: `packed import closure passes (${Object.keys(sources).length} JavaScript files)` }
      : { status: 'error', exitCode: 1, message: `packed import closure failed: ${missing.map(({ from, specifier, target }) => `${from} imports ${specifier} -> ${target ?? 'outside packed root'}`).join('; ')}`, missing };
  } catch (error) {
    return { status: 'error', exitCode: 1, message: `packed import closure failed: ${error.message}` };
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const result = checkPackedImportClosure();
  const output = result.exitCode === 0 ? process.stdout : process.stderr;
  output.write(`${result.message}\n`);
  process.exitCode = result.exitCode;
}
