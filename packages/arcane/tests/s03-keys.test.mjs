// S03 — lib/keys.mjs
//
// KeyRing is the host-held key custody primitive every other S03 module signs
// or verifies against. Mandatory coverage here: key material never leaks
// through list(); missing/revoked/unknown key resolution fails closed with
// ARC_AUTH_KEY_UNAVAILABLE; loadHostKeyRing fails closed when no host key
// material is present (never falls back to inventing a key).

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { KeyRing, loadHostKeyRing, generateTestKeyRing } from '../lib/keys.mjs';
import { ArcaneError } from '../lib/errors.mjs';

test('KeyRing.add + get round-trips key material', () => {
  const ring = new KeyRing();
  const material = Buffer.from('0'.repeat(64), 'hex');
  ring.add('k1', material, { custody: 'test' });
  const got = ring.get('k1');
  assert.equal(got.keyId, 'k1');
  assert.ok(Buffer.isBuffer(got.key));
  assert.ok(got.key.equals(material));
  assert.equal(got.custody, 'test');
  assert.equal(got.status, 'active');
});

test('KeyRing.list() never exposes key material', () => {
  const ring = new KeyRing();
  ring.add('k1', Buffer.from('a'.repeat(64), 'hex'), { custody: 'test' });
  const listed = ring.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].keyId, 'k1');
  assert.ok(!('key' in listed[0]), 'list() entries must not carry a key property');
  const serialized = JSON.stringify(listed);
  assert.ok(!serialized.includes('a'.repeat(64)), 'key material must not appear in serialized list() output');
});

test('KeyRing.has() reflects presence without throwing', () => {
  const ring = new KeyRing();
  assert.equal(ring.has('missing'), false);
  ring.add('k1', Buffer.from('b'.repeat(64), 'hex'));
  assert.equal(ring.has('k1'), true);
});

test('KeyRing.get() on unknown key throws ARC_AUTH_KEY_UNAVAILABLE, failClosed', () => {
  const ring = new KeyRing();
  assert.throws(() => ring.get('nope'), (err) => {
    assert.ok(err instanceof ArcaneError);
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.equal(err.failClosed, true);
    return true;
  });
});

test('KeyRing.revoke() then get() throws ARC_AUTH_KEY_UNAVAILABLE', () => {
  const ring = new KeyRing();
  ring.add('k1', Buffer.from('c'.repeat(64), 'hex'));
  ring.revoke('k1', 'rotated');
  assert.throws(() => ring.get('k1'), (err) => {
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    return true;
  });
  const listed = ring.list();
  assert.equal(listed[0].status, 'revoked');
});

test('KeyRing.revoke() on unknown key throws ARC_AUTH_KEY_UNAVAILABLE', () => {
  const ring = new KeyRing();
  assert.throws(() => ring.revoke('nope'), (err) => {
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    return true;
  });
});

test('KeyRing.activeKeyId() returns the newest non-revoked key', () => {
  const ring = new KeyRing();
  ring.add('k1', Buffer.from('d'.repeat(64), 'hex'), { createdAt: '2026-01-01T00:00:00.000Z' });
  ring.add('k2', Buffer.from('e'.repeat(64), 'hex'), { createdAt: '2026-06-01T00:00:00.000Z' });
  assert.equal(ring.activeKeyId(), 'k2');
  ring.revoke('k2');
  assert.equal(ring.activeKeyId(), 'k1');
});

test('KeyRing.activeKeyId() throws ARC_AUTH_KEY_UNAVAILABLE when no active key exists', () => {
  const ring = new KeyRing();
  assert.throws(() => ring.activeKeyId(), (err) => {
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    return true;
  });
  ring.add('k1', Buffer.from('f'.repeat(64), 'hex'));
  ring.revoke('k1');
  assert.throws(() => ring.activeKeyId(), (err) => {
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    return true;
  });
});

test('generateTestKeyRing() mints usable, distinct random keys for fixtures', () => {
  const ring = generateTestKeyRing(['k1', 'k2']);
  assert.equal(ring.has('k1'), true);
  assert.equal(ring.has('k2'), true);
  const k1 = ring.get('k1');
  const k2 = ring.get('k2');
  assert.ok(!k1.key.equals(k2.key), 'seeded fixture keys must not collide');
  assert.equal(ring.activeKeyId(), 'k2', 'later seed id should be the newest/active key');
});

test('loadHostKeyRing() fails closed with ARC_AUTH_KEY_UNAVAILABLE when the directory is absent', () => {
  const dir = join(tmpdir(), 'legion-arcane-s03-keys-missing-' + Date.now());
  assert.throws(() => loadHostKeyRing({ dir }), (err) => {
    assert.ok(err instanceof ArcaneError);
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.equal(err.failClosed, true);
    return true;
  });
});

test('loadHostKeyRing() fails closed with ARC_AUTH_KEY_UNAVAILABLE when the directory has no key files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-arcane-s03-keys-empty-'));
  try {
    assert.throws(() => loadHostKeyRing({ dir }), (err) => {
      assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
      return true;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadHostKeyRing() loads host-held key material and metadata from disk', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-arcane-s03-keys-host-'));
  try {
    writeFileSync(join(dir, 'hostkey1.key'), '11'.repeat(32), 'utf8');
    writeFileSync(join(dir, 'hostkey1.json'), JSON.stringify({ custody: 'host-file:hostkey1.key', status: 'active' }), 'utf8');
    const ring = loadHostKeyRing({ dir });
    const got = ring.get('hostkey1');
    assert.ok(Buffer.isBuffer(got.key));
    assert.equal(got.key.length, 32);
    assert.equal(got.custody, 'host-file:hostkey1.key');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadHostKeyRing() never surfaces key material through KeyRing.list()', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-arcane-s03-keys-host2-'));
  try {
    writeFileSync(join(dir, 'hostkey2.key'), '22'.repeat(32), 'utf8');
    const ring = loadHostKeyRing({ dir });
    const serialized = JSON.stringify(ring.list());
    assert.ok(!serialized.includes('22'.repeat(32)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
