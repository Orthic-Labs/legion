import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildPolicyInjection } from '../host/policy-inject.mjs';

test('brief and minimize are injected when no policy.toml is present (falls back to brief-policy.md)', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-policy-inject-'));
  try {
    const injection = buildPolicyInjection({ workspace });
    assert.ok(injection);
    assert.match(injection.additionalContext, /Brief is default/);
    assert.match(injection.additionalContext, /MINIMIZE/);
    assert.equal(injection.systemMessage, 'MINIMIZE:ON');
    // no double-injection: exactly one MINIMIZE block
    assert.equal(injection.additionalContext.match(/# MINIMIZE/g)?.length, 1);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('policy.toml brief.content wins over brief-policy.md when both are readable', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-policy-inject-toml-'));
  try {
    mkdirSync(join(workspace, 'tools', 'lib'), { recursive: true });
    writeFileSync(join(workspace, 'tools', 'lib', 'policy.toml'), '[brief]\ncontent = """\nCUSTOM BRIEF TEXT FROM TOML\n"""\n');
    const injection = buildPolicyInjection({ workspace });
    assert.match(injection.additionalContext, /CUSTOM BRIEF TEXT FROM TOML/);
    assert.doesNotMatch(injection.additionalContext, /Brief is default/);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('policy.toml present but brief.content key missing falls back to brief-policy.md', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-policy-inject-notoml-key-'));
  try {
    mkdirSync(join(workspace, 'tools', 'lib'), { recursive: true });
    writeFileSync(join(workspace, 'tools', 'lib', 'policy.toml'), '[other]\nkey = "value"\n');
    const injection = buildPolicyInjection({ workspace });
    assert.match(injection.additionalContext, /Brief is default/);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('ccx directive is present only when ANTHROPIC_BASE_URL targets the local gateway on port 8801', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-policy-inject-ccx-'));
  const prior = process.env.ANTHROPIC_BASE_URL;
  try {
    delete process.env.ANTHROPIC_BASE_URL;
    assert.doesNotMatch(buildPolicyInjection({ workspace }).additionalContext, /ccx-mode/);

    process.env.ANTHROPIC_BASE_URL = 'https://api.anthropic.com';
    assert.doesNotMatch(buildPolicyInjection({ workspace }).additionalContext, /ccx-mode/);

    process.env.ANTHROPIC_BASE_URL = 'http://127.0.0.1:8801';
    assert.match(buildPolicyInjection({ workspace }).additionalContext, /ccx-mode/);

    process.env.ANTHROPIC_BASE_URL = 'http://localhost:8801/v1';
    assert.match(buildPolicyInjection({ workspace }).additionalContext, /ccx-mode/);
  } finally {
    if (prior === undefined) delete process.env.ANTHROPIC_BASE_URL; else process.env.ANTHROPIC_BASE_URL = prior;
    rmSync(workspace, { recursive: true, force: true });
  }
});
