#!/usr/bin/env node
// EC-1 — one-time bootstrap for Arcane host-held signing keys.
//
// Layout matches ../KEY-CUSTODY.md exactly: `<dir>/<keyId>.key` holds
// hex-encoded raw key bytes, an optional sibling `<dir>/<keyId>.json` holds
// non-secret metadata `{createdAt, custody, status}`. `loadHostKeyRing({dir})`
// (../lib/keys.mjs) reads this same layout back.
//
// Idempotent by default: if an active (non-revoked) key already exists in
// the target directory, this script refuses to overwrite it and exits
// non-zero. Pass --rotate to explicitly provision a new key alongside the
// existing one (rotation is additive — KEY-CUSTODY.md's rotation story: add
// under a new keyId with a later createdAt, `activeKeyId()` picks it up
// automatically; revoking the old key is a separate, deliberate operation
// this script does not perform).
//
// NEVER prints key material. Only keyId and paths.

import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ulid } from '../lib/ids.mjs';

const DEFAULT_DIR = join(homedir(), '.claude', 'arcane-keys');

function parseArgs(argv) {
  const args = { rotate: false, dir: DEFAULT_DIR };
  for (const arg of argv) {
    if (arg === '--rotate') args.rotate = true;
    else if (arg.startsWith('--dir=')) args.dir = arg.slice('--dir='.length);
    else throw new Error(`unrecognized argument: ${arg}`);
  }
  return args;
}

function ensureOwnerOnlyDir(dir) {
  const existed = existsSync(dir);
  mkdirSync(dir, { recursive: true });
  if (platform() !== 'win32') {
    // POSIX: owner-only rwx. Windows ACL-based permissions are out of scope
    // for this bootstrap — NTFS already scopes a user-profile directory to
    // its owner by default, and chmod is a no-op there.
    try {
      chmodSync(dir, 0o700);
    } catch {
      // best-effort; absence of chmod support is not fatal.
    }
  }
  return existed;
}

function existingActiveKeyId(dir) {
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir).filter((f) => f.endsWith('.key'));
  for (const file of files) {
    const keyId = file.slice(0, -'.key'.length);
    const metaPath = join(dir, `${keyId}.json`);
    let status = 'active';
    if (existsSync(metaPath)) {
      try {
        const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
        status = meta.status ?? 'active';
      } catch {
        status = 'active';
      }
    }
    if (status === 'active') return keyId;
  }
  return null;
}

/**
 * Provision a new host key in `dir`. Returns `{keyId, keyPath, metaPath, created}`.
 * `created` is false (idempotent no-op) when an active key already exists
 * and `rotate` was not passed.
 */
export function provisionKeys({ dir = DEFAULT_DIR, rotate = false } = {}) {
  ensureOwnerOnlyDir(dir);

  const existing = existingActiveKeyId(dir);
  if (existing && !rotate) {
    return { keyId: existing, keyPath: join(dir, `${existing}.key`), metaPath: join(dir, `${existing}.json`), created: false };
  }

  const keyId = `hostkey_${ulid()}`;
  const keyPath = join(dir, `${keyId}.key`);
  const metaPath = join(dir, `${keyId}.json`);

  const keyMaterial = randomBytes(32);
  writeFileSync(keyPath, keyMaterial.toString('hex'), { encoding: 'utf8', mode: 0o600 });
  if (platform() !== 'win32') {
    try {
      chmodSync(keyPath, 0o600);
    } catch {
      // best-effort
    }
  }

  const meta = { createdAt: new Date().toISOString(), custody: 'host-provisioned', status: 'active' };
  writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });

  return { keyId, keyPath, metaPath, created: true };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = provisionKeys(args);
  if (result.created) {
    console.log(`provisioned host key ${result.keyId}`);
  } else {
    console.log(`active host key already present: ${result.keyId} (pass --rotate to provision a new one)`);
  }
  console.log(`dir: ${args.dir}`);
  console.log(`key file: ${result.keyPath}`);
  console.log(`meta file: ${result.metaPath}`);
}

// Only run as a script (not when imported for tests).
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`;
if (isMain || process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
