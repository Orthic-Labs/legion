import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  CONFIG_SCHEMA_VERSION,
  DEFAULT_CONFIG,
  HOST_OWNED,
  loadRepositoryConfig,
  mergeConfig,
  normalizePath,
  profileConfig,
  validateConfig,
} from '../lib/config/index.mjs';

test('defaults are safe and versioned', () => {
  assert.equal(DEFAULT_CONFIG.schemaVersion, CONFIG_SCHEMA_VERSION);
  assert.equal(DEFAULT_CONFIG.profile, 'standard');
  assert.deepEqual(DEFAULT_CONFIG.policy.failOn, ['critical', 'high']);
});

test('profiles exist for fast, standard, full, release', () => {
  for (const name of ['fast', 'standard', 'full', 'release']) {
    const config = profileConfig(name);
    assert.equal(config.profile, name);
    assert.ok(config.limits.providerTimeoutMs > 0);
  }
  assert.ok(profileConfig('fast').limits.providerTimeoutMs < profileConfig('release').limits.providerTimeoutMs);
});

test('precedence: defaults < user < repository < cli < sealed plan', () => {
  const merged = mergeConfig({
    defaults: profileConfig('standard'),
    user: { limits: { providerTimeoutMs: 60000 } },
    repository: { limits: { providerTimeoutMs: 90000 }, policy: { failOn: ['high'] } },
    cli: { limits: { providerTimeoutMs: 150000 } },
  });
  assert.equal(merged.limits.providerTimeoutMs, 150000, 'cli wins over repository');
  assert.equal(merged.policy.failOn[0], 'high', 'repository policy wins over user');
  assert.equal(merged.profile, 'standard');
});

test('repository config cannot set host-owned keys', () => {
  assert.throws(() => mergeConfig({
    defaults: profileConfig('standard'),
    repository: { networkGuard: { active: false } },
  }), /host-owned key/);
  assert.throws(() => mergeConfig({
    defaults: profileConfig('standard'),
    repository: { planSigningKey: 'attacker-key' },
  }), /host-owned key/);
  assert.throws(() => mergeConfig({
    defaults: profileConfig('standard'),
    repository: { mutation: true },
  }), /host-owned key/);
});

test('unknown keys are rejected', () => {
  assert.throws(() => validateConfig({ schemaVersion: 1, profile: 'standard', bogusKey: 1 }), /unknown key/);
});

test('unknown profile is rejected', () => {
  assert.throws(() => validateConfig({ schemaVersion: 1, profile: 'turbo' }), /profile/);
});

test('future schema versions are rejected', () => {
  assert.throws(() => validateConfig({ ...DEFAULT_CONFIG, schemaVersion: 2 }), /schemaVersion/);
});

test('host-owned key set covers the frozen controls', () => {
  for (const key of ['networkGuard', 'planSigningKey', 'modelCredentials', 'mutation', 'externalToolAllowlist', 'releaseSigning']) {
    assert.ok(HOST_OWNED.has(key), `host-owned key ${key}`);
  }
});

test('loadRepositoryConfig reads nemesis.config.json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-config-'));
  try {
    writeFileSync(join(dir, 'nemesis.config.json'), JSON.stringify({ schemaVersion: 1, profile: 'fast' }));
    const config = loadRepositoryConfig(dir);
    assert.equal(config.profile, 'fast');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRepositoryConfig returns {} when absent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-config-'));
  try {
    assert.deepEqual(loadRepositoryConfig(dir), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('path normalization resolves absolute canonical paths', () => {
  const cwd = '/tmp';
  assert.equal(normalizePath('a/b', cwd), resolve(cwd, 'a/b'));
  assert.equal(normalizePath('/abs/path', cwd), resolve('/abs/path'));
  assert.equal(normalizePath('', cwd), resolve(cwd));
});
