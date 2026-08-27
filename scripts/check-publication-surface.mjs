#!/usr/bin/env node
// package.json#files & MANIFEST.package.json are one ordered public-surface contract.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function readJson(root, path) {
  return JSON.parse(readFileSync(resolve(root, path), 'utf8'));
}

function declaration(root) {
  const pkg = readJson(root, 'package.json');
  const manifest = readJson(root, 'MANIFEST.package.json');
  return {
    packageFiles: pkg.files,
    manifestFiles: manifest.allowlistedTopLevel,
  };
}

export function publicationSurfaceDeclaration(root = ROOT) {
  return declaration(root);
}

export function validatePublicationSurface({ packageFiles, manifestFiles }, root = ROOT) {
  const errors = [];
  if (!Array.isArray(packageFiles)) errors.push('package.json#files must be an array');
  if (!Array.isArray(manifestFiles)) errors.push('MANIFEST.package.json#allowlistedTopLevel must be an array');
  if (errors.length > 0) return errors;

  for (const [label, entries] of [['package.json#files', packageFiles], ['MANIFEST.package.json#allowlistedTopLevel', manifestFiles]]) {
    const seen = new Set();
    for (const entry of entries) {
      if (typeof entry !== 'string' || entry.length === 0) {
        errors.push(`${label} contains an invalid path`);
        continue;
      }
      if (seen.has(entry)) errors.push(`${label} contains duplicate path ${entry}`);
      seen.add(entry);
      if (!existsSync(resolve(root, entry))) errors.push(`${label} names absent path ${entry}`);
    }
  }

  if (JSON.stringify(packageFiles) !== JSON.stringify(manifestFiles)) {
    errors.push('package.json#files & MANIFEST.package.json#allowlistedTopLevel must be exactly equal in order & content');
  }
  return errors;
}

export function checkPublicationSurface(root = ROOT) {
  try {
    const errors = validatePublicationSurface(declaration(root), root);
    return errors.length === 0
      ? { status: 'pass', exitCode: 0, message: 'publication surface contract passes' }
      : { status: 'error', exitCode: 1, message: `publication surface contract failed: ${errors.join('; ')}`, errors };
  } catch (error) {
    return { status: 'error', exitCode: 1, message: `publication surface contract failed: ${error.message}`, errors: [error.message] };
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const result = checkPublicationSurface();
  const output = result.exitCode === 0 ? process.stdout : process.stderr;
  output.write(`${result.message}\n`);
  process.exitCode = result.exitCode;
}
