import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { applyDenialCircuit, DenialCircuit } from '../lib/denial-circuit.mjs';
import { decision } from '../lib/errors.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-denial-circuit-'));
  return { root, circuit: new DenialCircuit({ root, keyRing: generateTestKeyRing(['k1']), keyId: 'k1', clock: () => '2026-08-12T00:00:00.000Z' }) };
}

const context = Object.freeze({ sessionId: 'session-1', runId: 'run-1', taskId: 'T-4', eventType: 'Stop', target: 'completion' });
const denied = (code = 'ARC_CLAIM_PREREQUISITE_UNMET', detail = {}) => decision({ allowed: false, code, message: 'denied', detail });

test('EC-603 T-4: same authenticated conversational fingerprint opens termination exactly on second denial', () => {
  const { root, circuit } = fixture();
  try {
    const first = applyDenialCircuit(denied(), circuit, context);
    const second = applyDenialCircuit(denied(), circuit, context);
    assert.equal(first.allowed, false); assert.equal(first.detail.termination, undefined);
    assert.equal(second.allowed, false); assert.equal(second.detail.termination, 'terminate');
    assert.match(second.detail.retrySignature, /^sha256:/);
    const scope = { runId: 'run-1', sessionId: 'session-1', taskId: 'T-4' };
    const name = createHash('sha256').update(JSON.stringify(scope), 'utf8').digest('hex');
    assert.equal(readFileSync(join(root, `${name}.json`), 'utf8').includes('authentication'), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('EC-603 T-4: changed fingerprint resets authenticated count', () => {
  const { root, circuit } = fixture();
  try {
    applyDenialCircuit(denied(), circuit, context);
    const changed = applyDenialCircuit(denied('ARC_EVIDENCE_INSUFFICIENT', { missingClasses: ['high-risk-assurance'] }), circuit, context);
    const secondChanged = applyDenialCircuit(denied('ARC_EVIDENCE_INSUFFICIENT', { missingClasses: ['high-risk-assurance'] }), circuit, context);
    assert.equal(changed.detail.termination, undefined);
    assert.equal(secondChanged.detail.termination, 'terminate');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('EC-603 T-4: effect & security denials persist retry receipts but never release denied effect', () => {
  const { root, circuit } = fixture();
  try {
    for (const eventType of ['PreToolUse', 'PostToolUse']) {
      const first = applyDenialCircuit(denied('ARC_PATH_FORBIDDEN'), circuit, { ...context, eventType, target: 'src/a.mjs' });
      const second = applyDenialCircuit(denied('ARC_PATH_FORBIDDEN'), circuit, { ...context, eventType, target: 'src/a.mjs' });
      assert.equal(first.allowed, false); assert.equal(second.allowed, false); assert.equal(second.detail.termination, undefined);
    }
    const one = applyDenialCircuit(denied('ARC_AUTH_FORGED'), circuit, context);
    const two = applyDenialCircuit(denied('ARC_AUTH_FORGED'), circuit, context);
    assert.equal(one.allowed, false); assert.equal(two.allowed, false); assert.equal(two.detail.termination, undefined);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('EC-603 T-4: tampered persisted circuit state fails closed', () => {
  const { root, circuit } = fixture();
  try {
    applyDenialCircuit(denied(), circuit, context);
    const actual = readdirSync(root).find((name) => name.endsWith('.json'));
    writeFileSync(join(root, actual), '{"forged":true}', 'utf8');
    assert.throws(() => applyDenialCircuit(denied(), circuit, context), /denial circuit receipt authentication failed/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
