// The installed policy pack shipped `effect_rules: []` with
// `unclassified_effect: "deny"`. The guard then denied every classified effect
// — VCS_PUSH, VCS_COMMIT, FILE_WRITE — with no rule that could ever satisfy
// it, and the denial read as a deliberate boundary rather than a blank pack.
// It stayed invisible while hooks were unregistered; the moment they worked,
// nothing could push.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const source = JSON.parse(
  readFileSync(join(root, 'src/lib/guard/compat/policy/arcane-policy-v1.json'), 'utf8'),
);
// Strip comments: the assembler explains the defect it fixes by quoting the
// empty rule set, and that prose must not read as the defect itself.
const assembler = readFileSync(join(root, 'scripts/assemble-native-release.mjs'), 'utf8')
  .split(/\r?\n/)
  .filter((line) => !line.trim().startsWith('//'))
  .join('\n');

test('the assembler derives the installed rules instead of hard-coding none', () => {
  assert.match(assembler, /effect_rules: effectRules/, 'installed pack must carry derived rules');
  assert.doesNotMatch(assembler, /effect_rules: \[\]/, 'an empty rule set denies everything');
  assert.match(assembler, /arcane-policy-v1\.json/, 'rules must come from the compat policy');
});

test('every effect class the guard can raise has a rule', () => {
  // Mirrors the enum in engine/crates/legion-policy-model/src/effect.rs; a
  // class the guard classifies but the pack never names is denied by fallback.
  const CLASSES = [
    'FILE_WRITE', 'FILE_DELETE', 'FILE_MOVE', 'COMMAND_EXEC', 'NETWORK_EGRESS',
    'PROCESS_SPAWN', 'CREDENTIAL_ACCESS', 'DEPENDENCY_INSTALL', 'VCS_COMMIT',
    'VCS_PUSH', 'PUBLISH', 'EXTERNAL_SIDE_EFFECT',
  ];
  const covered = new Set(source.effectRules.map((rule) => rule.effectClass));
  assert.deepEqual(CLASSES.filter((c) => !covered.has(c)), [], 'effect classes with no policy rule');
});

test('outward-facing effects still require approval', () => {
  for (const effectClass of ['VCS_PUSH', 'PUBLISH', 'EXTERNAL_SIDE_EFFECT', 'DEPENDENCY_INSTALL']) {
    const rule = source.effectRules.find((r) => r.effectClass === effectClass);
    assert.ok(rule, `${effectClass} has no rule`);
    assert.equal(rule.approvalRequired, true, `${effectClass} must require approval`);
  }
  const credential = source.effectRules.find((r) => r.effectClass === 'CREDENTIAL_ACCESS');
  assert.equal(credential.rule, 'deny', 'credential access stays denied');
});
