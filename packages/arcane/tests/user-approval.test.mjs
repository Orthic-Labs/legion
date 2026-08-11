import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { generateTestKeyRing } from '../lib/keys.mjs';
import { UserApprovalAuthority } from '../lib/user-approval.mjs';

const now = Date.parse('2026-08-11T12:00:00.000Z');
const binding = { sessionId: 'session-1', runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-503', contractVersion: 6, contractDigest: `sha256:${'a'.repeat(64)}`, effectClass: 'FILE_DELETE', target: 'x.txt' };
const userTurnJsonl = (text) => `${JSON.stringify({ type: 'user', message: { content: text } })}\n`;
function subject(text = 'Delete x.txt now.') { const path = join(mkdtempSync(join(tmpdir(), 'arcane-approval-')), 't.jsonl'); writeFileSync(path, userTurnJsonl(text)); return { authority: new UserApprovalAuthority({ keyRing: generateTestKeyRing(), clock: () => now }), path }; }

test('host transcript path issues & consumes a target-bound delete approval once', () => {
  const { authority, path } = subject(); const record = authority.deriveRecord({ ...binding, transcriptPath: path });
  assert.ok(record); assert.equal(record.sessionId, undefined); assert.equal(record.userTurn, undefined);
  assert.equal(authority.consume(record, binding).allowed, true);
  assert.equal(authority.consume(record, binding).code, 'ARC_REPLAY_NONCE_SEEN');
});

test('plan, revoke, question, unreadable transcript, forged & mismatched approvals deny', () => {
  for (const text of ['Plan deletion.', 'Do not delete x.txt.', 'Should I delete x.txt?', 'hello']) {
    const { authority, path } = subject(text); assert.equal(authority.deriveRecord({ ...binding, transcriptPath: path }), null, text);
  }
  const { authority, path } = subject(); const record = authority.deriveRecord({ ...binding, transcriptPath: path });
  assert.equal(authority.consume({ ...record, mac: '0'.repeat(64) }, binding).code, 'ARC_AUTH_FORGED');
  assert.equal(authority.consume(record, { ...binding, target: 'y.txt' }).code, 'ARC_BINDING_MISMATCH');
});
