// Host-held key custody (S03 §4.2: "key/capability material outside ordinary
// model-controlled payloads").
//
// A KeyRing never lets key material escape through anything but `.get()`:
// `.list()` (and therefore any log line or error `detail` built from it) is
// metadata-only. Resolution of a missing, unknown, or revoked key always
// fails closed with ARC_AUTH_KEY_UNAVAILABLE — there is no silent fallback to
// an invented or default key anywhere in this module.
//
// See ../KEY-CUSTODY.md for the full custody/rotation/threat-model story.

import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ArcaneError } from './errors.mjs';

export class KeyRing {
  #keys = new Map();

  /**
   * @param {string} keyId
   * @param {Buffer} keyMaterial raw key bytes — never logged, never returned
   *   by list().
   * @param {object} [meta] `{createdAt, custody, status}`. `custody` should
   *   describe *where* the material came from (file path class, not the
   *   material itself); `status` is `'active'` or `'revoked'`.
   */
  add(keyId, keyMaterial, meta = {}) {
    if (typeof keyId !== 'string' || keyId.length === 0) {
      throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', 'keyId must be a non-empty string', {});
    }
    if (!Buffer.isBuffer(keyMaterial) || keyMaterial.length === 0) {
      throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', 'keyMaterial must be a non-empty Buffer', { keyId });
    }
    this.#keys.set(keyId, {
      key: keyMaterial,
      createdAt: meta.createdAt || new Date().toISOString(),
      custody: meta.custody || 'unspecified',
      status: meta.status || 'active',
      revokedAt: null,
      revokedReason: null,
    });
  }

  /**
   * @returns {{keyId: string, key: Buffer, custody: string, status: string}}
   * @throws {ArcaneError} ARC_AUTH_KEY_UNAVAILABLE (failClosed) if `keyId` is
   *   unknown or revoked.
   */
  get(keyId) {
    let rec = this.#keys.get(keyId);
    // Authority-proof keys are deterministic HMAC derivations of their root
    // key, so any ring holding the root can re-derive them. Without this a
    // record signed by a derived key verifies only inside the process that
    // issued it — a fresh ring reading the same record fails closed even
    // though the material is reproducible. Derivation must match
    // authority-invocation-proof.mjs #credentials exactly.
    if (!rec) {
      const derived = /^(.+):authority-proof:([^:]+):([^:]+)$/.exec(keyId);
      const root = derived && this.#keys.get(derived[1]);
      if (root && root.status !== 'revoked') {
        const macDomain = `arcane-authority-proof:v1:${derived[2]}:${derived[3]}`;
        const material = createHmac('sha256', root.key).update(`arcane-key-derivation:v1\0${macDomain}`, 'utf8').digest();
        this.add(keyId, material, { custody: `derived:${derived[1]}:${macDomain}` });
        rec = this.#keys.get(keyId);
      }
    }
    if (!rec || rec.status === 'revoked') {
      throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `key unavailable: ${keyId}`, { keyId });
    }
    return { keyId, key: rec.key, custody: rec.custody, status: rec.status };
  }

  has(keyId) {
    return this.#keys.has(keyId);
  }

  revoke(keyId, reason = 'revoked') {
    const rec = this.#keys.get(keyId);
    if (!rec) {
      throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `cannot revoke unknown key: ${keyId}`, { keyId });
    }
    rec.status = 'revoked';
    rec.revokedAt = new Date().toISOString();
    rec.revokedReason = reason;
  }

  /** Newest non-revoked key. @throws {ArcaneError} ARC_AUTH_KEY_UNAVAILABLE if none. */
  activeKeyId() {
    let best = null;
    for (const [keyId, rec] of this.#keys) {
      if (rec.status === 'revoked') continue;
      if (!best || rec.createdAt > best.createdAt) best = { keyId, createdAt: rec.createdAt };
    }
    if (!best) throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', 'no active key available', {});
    return best.keyId;
  }

  /** Metadata only — NEVER key material. */
  list() {
    return [...this.#keys.entries()].map(([keyId, rec]) => ({
      keyId,
      createdAt: rec.createdAt,
      custody: rec.custody,
      status: rec.status,
      revokedAt: rec.revokedAt,
      revokedReason: rec.revokedReason,
    }));
  }
}

/**
 * Read host-held key files from `dir`. Layout: `<keyId>.key` holds hex-encoded
 * key bytes; an optional sibling `<keyId>.json` holds `{createdAt, custody,
 * status}`. Absence of the directory or of any `.key` file is
 * ARC_AUTH_KEY_UNAVAILABLE — never a fabricated key.
 */
function loadDirectoryInto(ring, dir) {
  if (!dir || !existsSync(dir)) {
    throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `host key directory not found: ${dir}`, { dir });
  }
  const files = readdirSync(dir).filter((f) => f.endsWith('.key'));
  if (files.length === 0) {
    throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `no host key material found in ${dir}`, { dir });
  }
  for (const file of files) {
    const keyId = file.slice(0, -'.key'.length);
    const hex = readFileSync(join(dir, file), 'utf8').trim();
    let keyMaterial;
    try {
      keyMaterial = Buffer.from(hex, 'hex');
    } catch {
      keyMaterial = Buffer.alloc(0);
    }
    if (keyMaterial.length === 0) {
      throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `key material unreadable for ${keyId}`, { keyId });
    }
    let meta = { custody: `host-file:${file}` };
    const metaPath = join(dir, `${keyId}.json`);
    if (existsSync(metaPath)) {
      meta = { ...meta, ...JSON.parse(readFileSync(metaPath, 'utf8')) };
    }
    if (ring.has(keyId)) {
      const existing = ring.get(keyId);
      if (!existing.key.equals(keyMaterial)) {
        throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', `conflicting host key id across verification directories: ${keyId}`, { keyId });
      }
      continue;
    }
    ring.add(keyId, keyMaterial, meta);
  }
}

export function loadHostKeyRing({ dir }) {
  const ring = new KeyRing();
  loadDirectoryInto(ring, dir);
  return ring;
}

// One Mac host verification ring is projected at this path by workspace setup.
// Host adapters may keep per-harness signing paths, but authenticated CLI
// readers must verify every legitimate historical host key from one custody
// location rather than whichever harness happened to sign the latest event.
export const DEFAULT_CANONICAL_HOST_KEY_DIR = join(homedir(), '.codex', 'arcane-keys');

export function loadCanonicalHostKeyRing({ dir = DEFAULT_CANONICAL_HOST_KEY_DIR } = {}) {
  return loadHostKeyRing({ dir });
}

export function loadVerificationKeyRing({ dirs }) {
  if (!Array.isArray(dirs) || dirs.length === 0) {
    throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE', 'verification requires at least one host key directory', {});
  }
  const ring = new KeyRing();
  for (const dir of [...new Set(dirs)]) loadDirectoryInto(ring, dir);
  return ring;
}

/**
 * Fixtures only. Generates random 32-byte HMAC keys — never reads or writes a
 * real credential. `seedIds` order determines recency (later ids are newer),
 * so the last id in the array is `activeKeyId()` by default.
 */
export function generateTestKeyRing(seedIds = ['k1']) {
  const ring = new KeyRing();
  const base = Date.now();
  seedIds.forEach((id, i) => {
    ring.add(id, randomBytes(32), {
      createdAt: new Date(base + i).toISOString(),
      custody: 'test-fixture:generateTestKeyRing',
      status: 'active',
    });
  });
  return ring;
}
