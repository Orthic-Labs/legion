import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { generateTestKeyRing } from '../lib/keys.mjs';
import { loadPolicy, PolicyEngine } from '../lib/policy.mjs';
import { UserApprovalAuthority } from '../lib/user-approval.mjs';

const now = Date.parse('2026-08-11T12:00:00.000Z');
const binding = { sessionId: 'session-1', runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-503', contractVersion: 6, contractDigest: `sha256:${'a'.repeat(64)}`, effectClass: 'FILE_DELETE', target: 'x.txt' };
const userTurnJsonl = (text) => `${JSON.stringify({ type: 'user', message: { content: text } })}\n`;
const policy = new PolicyEngine(loadPolicy());
function subject(text = 'Delete x.txt now.', clock = () => now) { const path = join(mkdtempSync(join(tmpdir(), 'arcane-approval-')), 't.jsonl'); writeFileSync(path, userTurnJsonl(text)); return { authority: new UserApprovalAuthority({ keyRing: generateTestKeyRing(), policy, clock }), path }; }

test('host transcript path issues & consumes a target-bound delete approval once', () => {
  const { authority, path } = subject(); const record = authority.deriveRecord({ ...binding, transcriptPath: path });
  assert.ok(record); assert.equal(record.sessionId, undefined); assert.equal(record.userTurn, undefined);
  assert.equal(authority.consume(record, { ...binding, transcriptPath: path }).allowed, true);
  assert.equal(authority.consume(record, { ...binding, transcriptPath: path }).code, 'ARC_REPLAY_NONCE_SEEN');
});

test('policy supplies every approval-required class and refuses nonmembers', () => {
  const required = policy.approvalRequiredEffectClasses();
  assert.equal(Object.isFrozen(required), true);
  assert.deepEqual(required, ['FILE_DELETE', 'CREDENTIAL_ACCESS', 'DEPENDENCY_INSTALL', 'VCS_COMMIT', 'VCS_PUSH', 'PUBLISH', 'EXTERNAL_SIDE_EFFECT']);
  for (const effectClass of required) {
    const { authority, path } = subject();
    const expected = { ...binding, effectClass, transcriptPath: path };
    const record = authority.deriveRecord(expected);
    assert.ok(record, effectClass);
    assert.equal(authority.consume(record, expected).allowed, true, effectClass);
  }
  const { authority, path } = subject();
  assert.equal(authority.deriveRecord({ ...binding, effectClass: 'FILE_WRITE', transcriptPath: path }), null);
});

test('plan, revoke, question, unreadable transcript, forged & mismatched approvals deny', () => {
  for (const text of ['Plan deletion.', 'Do not delete x.txt.', 'Should I delete x.txt?', 'hello']) {
    const { authority, path } = subject(text); assert.equal(authority.deriveRecord({ ...binding, transcriptPath: path }), null, text);
  }
  const { authority, path } = subject(); const record = authority.deriveRecord({ ...binding, transcriptPath: path });
  assert.equal(authority.consume({ ...record, mac: '0'.repeat(64) }, { ...binding, transcriptPath: path }).code, 'ARC_AUTH_FORGED');
  assert.equal(authority.consume(record, { ...binding, target: 'y.txt', transcriptPath: path }).code, 'ARC_BINDING_MISMATCH');
  writeFileSync(path, userTurnJsonl('Do not continue.'));
  assert.equal(authority.consume(record, { ...binding, transcriptPath: path }).code, 'ARC_APPROVAL_REQUIRED');
});

test('expired, wrong-contract, wrong-session & no-policy approvals deny', () => {
  let clock = now;
  const { authority, path } = subject(undefined, () => clock);
  const record = authority.deriveRecord({ ...binding, transcriptPath: path });
  clock = now + 901_000;
  assert.equal(authority.consume(record, { ...binding, transcriptPath: path }).code, 'ARC_APPROVAL_REQUIRED');

  const fresh = subject();
  const freshRecord = fresh.authority.deriveRecord({ ...binding, transcriptPath: fresh.path });
  assert.equal(fresh.authority.consume(freshRecord, { ...binding, contractDigest: `sha256:${'b'.repeat(64)}`, transcriptPath: fresh.path }).code, 'ARC_BINDING_MISMATCH');
  assert.equal(fresh.authority.consume(freshRecord, { ...binding, sessionId: 'session-2', transcriptPath: fresh.path }).code, 'ARC_BINDING_MISMATCH');
  const unavailable = new UserApprovalAuthority({ keyRing: generateTestKeyRing(), clock: () => now });
  assert.equal(unavailable.deriveRecord({ ...binding, transcriptPath: fresh.path }), null);
});
