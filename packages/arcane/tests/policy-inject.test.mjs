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

// The two operator kill switches the Python hooks carried. Dropping them in the
// port would have removed the only way to silence an injector without editing
// the harness config.
test('BRIEF_MODE_OFF=1 silences the Brief injection but not Minimize', () => {
  const prior = process.env.BRIEF_MODE_OFF;
  try {
    process.env.BRIEF_MODE_OFF = '1';
    const out = buildPolicyInjection({ workspace: process.cwd() });
    assert.doesNotMatch(out.additionalContext, /Brief is default/);
    assert.equal(out.systemMessage, 'MINIMIZE:ON');
  } finally {
    if (prior === undefined) delete process.env.BRIEF_MODE_OFF; else process.env.BRIEF_MODE_OFF = prior;
  }
});

test('CCX_GATEWAY_MODE_OFF=1 silences the gateway directive even on the gateway', () => {
  const priorOff = process.env.CCX_GATEWAY_MODE_OFF;
  const priorUrl = process.env.ANTHROPIC_BASE_URL;
  try {
    process.env.CCX_GATEWAY_MODE_OFF = '1';
    process.env.ANTHROPIC_BASE_URL = 'http://127.0.0.1:8801';
    assert.doesNotMatch(buildPolicyInjection({ workspace: process.cwd() }).additionalContext, /ccx-mode/);
  } finally {
    if (priorOff === undefined) delete process.env.CCX_GATEWAY_MODE_OFF; else process.env.CCX_GATEWAY_MODE_OFF = priorOff;
    if (priorUrl === undefined) delete process.env.ANTHROPIC_BASE_URL; else process.env.ANTHROPIC_BASE_URL = priorUrl;
  }
});
