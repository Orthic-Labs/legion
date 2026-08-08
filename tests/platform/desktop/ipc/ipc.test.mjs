import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateDesktopIpc, executeDesktopIpc } from '../../../../providers/runtime/desktop/ipc/index.mjs';

test('B4-018 scopes IPC by actor/capability & fails unknown callers safely', () => {
  const result = evaluateDesktopIpc({
    commands: [{ id: 'files.read', actors: ['editor'], capabilities: ['filesystem'] }],
    attempts: [{ id: 'ok', command: 'files.read', actor: 'editor', capabilities: ['filesystem'] }, { id: 'bad', command: 'missing', actor: 'guest', capabilities: [] }],
    helpers: [{ id: 'sidecar', digest: `sha256:${'a'.repeat(64)}`, stopped: true, inheritedHandles: [] }],
  });
  assert.deepEqual(result.receipts.map(({ status }) => status), ['pass', 'blocked']);
  assert.equal(result.receipts[1].reason, 'unknown-command');
  assert.equal(result.status, 'unproven');
});

test('B4-018 reports helper lifecycle & identity gaps', () => {
  const result = evaluateDesktopIpc({ helpers: [{ id: 'leak', stopped: false }] });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('helper-identity-unproven:leak'));
  assert.ok(result.coverageGaps.includes('helper-outlived-parent:leak'));
});

test('B4-018 requires adversarial denominator & executes cases through host', async () => {
  assert.notEqual(evaluateDesktopIpc({ commands: [], attempts: [], helpers: [] }).status, 'pass');
  const commands = [{ id: 'files.read', actors: ['editor'], capabilities: ['filesystem'], schema: 'read-v1', arguments: { path: 'string' }, privilege: 'user', identity: 'signed-command' }];
  const host = { exercise: async ({ caseId }) => ({ id: caseId, command: 'files.read', actor: caseId === 'wrong-caller' ? 'guest' : 'editor', capabilities: ['filesystem'], observedDenied: caseId !== 'allowed', terminal: true }), receipt: async () => ({ source: 'native-host', terminal: true }) };
  const result = await executeDesktopIpc({ host, commands, helpers: [{ id: 'h', digest: `sha256:${'a'.repeat(64)}`, stopped: true, inheritedHandles: [], workingDirectory: 'C:/temp', environmentBound: true }], boundaries: { navigation: true, remoteContent: true, externalUrl: true, shell: true, process: true, filesystem: true }, inventory: { sockets: [], plugins: [], sidecars: [] } });
  assert.equal(result.status, 'pass');
});
