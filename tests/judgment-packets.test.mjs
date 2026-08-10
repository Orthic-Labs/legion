import assert from 'node:assert/strict';
import test from 'node:test';
import { buildJudgmentPacket } from '../lib/core/judgment-packets.mjs';

test('judgment packet carries immutable sealed lens', () => {
  const packet = buildJudgmentPacket({ subject: { id: 'F-1' }, reviewerRole: 'oracle', lens: { id: 'audit', digest: 'sha256:abc', content: 'locked' } });
  assert.deepEqual(packet.lens, { id: 'audit', digest: 'sha256:abc', content: 'locked' });
  assert.ok(Object.isFrozen(packet.lens));
});
