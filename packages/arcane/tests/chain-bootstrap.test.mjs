// The two defects that made the contract chain unrunnable from the day it was
// written. Both were found the first time anyone tried to seal a contract and
// execute against it, and each one alone was fatal: no seal could be minted,
// and no file could be written under a seal that did exist.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

import { AuthorityBindingStore } from '../lib/authority-binding-store.mjs';
import { workspaceRelative } from '../lib/preeffect-gate.mjs';

const roots = [];
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });

function store() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-bootstrap-'));
  roots.push(root);
  return new AuthorityBindingStore({ root: join(root, 'authority-bindings') });
}

// --- Defect 1: a Sage agent could not find its own binding ------------------
// Only agentIdDigest is persisted and the lookup path hashes the raw id, so
// nothing could supply `contract seal --agent`. findLatest resolves by session
// instead, which is derivable from what the caller already has.

test('findLatest resolves the session Sage binding without the raw agent id', () => {
  const bindings = store();
  bindings.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'agent-alpha', agentType: 'sage', eventId: 'e1' });
  const found = bindings.findLatest({ adapter: 'claude-code', sessionId: 's1', authority: 'sage' });
  assert.equal(found?.authority, 'sage');
  // The raw id is never returned — only the digest the store actually holds.
  assert.ok(found.agentIdDigest.startsWith('sha256:'));
  assert.equal(found.agentId, undefined);
});

test('findLatest returns the most recent binding when a session has several', () => {
  const bindings = store();
  let n = 0;
  const clocked = new AuthorityBindingStore({ root: bindings.root, clock: () => `2026-08-11T00:00:0${n++}.000Z` });
  clocked.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'old', agentType: 'sage', eventId: 'e1' });
  clocked.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'new', agentType: 'sage', eventId: 'e2' });
  const found = clocked.findLatest({ adapter: 'claude-code', sessionId: 's1', authority: 'sage' });
  assert.equal(found.observedAt, '2026-08-11T00:00:01.000Z');
});

test('findLatest never crosses a session, an adapter, or an authority', () => {
  const bindings = store();
  bindings.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'a', agentType: 'sage', eventId: 'e1' });
  assert.equal(bindings.findLatest({ adapter: 'claude-code', sessionId: 'other', authority: 'sage' }), null);
  assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 's1', authority: 'sage' }), null);
  // An Alchemist must never be resolvable as the sealer.
  bindings.observe({ adapter: 'claude-code', sessionId: 's2', agentId: 'b', agentType: 'alchemist', eventId: 'e2' });
  assert.equal(bindings.findLatest({ adapter: 'claude-code', sessionId: 's2', authority: 'sage' }), null);
});

test('a pre-resolved record still cannot be borrowed across sessions', () => {
  const bindings = store();
  bindings.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'a', agentType: 'sage', eventId: 'e1' });
  const record = bindings.findLatest({ adapter: 'claude-code', sessionId: 's1', authority: 'sage' });
  assert.throws(
    () => bindings.assertForTurn({ adapter: 'claude-code', sessionId: 'different', turnId: 't', keyId: 'k', record, authorityLedger: { assertForTurn: () => ({}) } }),
    /binding identity conflict/,
  );
});

test('caller-claimed authority is still refused when a record is passed in', () => {
  const bindings = store();
  bindings.observe({ adapter: 'claude-code', sessionId: 's1', agentId: 'a', agentType: 'sage', eventId: 'e1' });
  const record = bindings.findLatest({ adapter: 'claude-code', sessionId: 's1', authority: 'sage' });
  assert.throws(
    () => bindings.assertForTurn({ adapter: 'claude-code', sessionId: 's1', turnId: 't', keyId: 'k', record, authority: 'sage', authorityLedger: {} }),
    /caller authority forbidden/,
  );
});

// --- Defect 2: every owned path looked unowned ------------------------------
// Contracts carry workspace-relative paths; Write/Edit report absolute ones.
// ARC_PATH_NOT_OWNED therefore denied every FILE_WRITE under every seal.

test('an absolute host path is matched against a relative scope entry', () => {
  assert.equal(
    workspaceRelative('D:/Claude/tools/skills/legion/hooks/stop-shape.mjs', 'D:/Claude'),
    'tools/skills/legion/hooks/stop-shape.mjs',
  );
});

test('backslashes and drive-letter casing do not defeat the match', () => {
  assert.equal(workspaceRelative('D:\\Claude\\tools\\a.mjs', 'd:/claude'), 'tools/a.mjs');
});

test('a path outside the workspace is left absolute, so it still fails own[]', () => {
  const outside = workspaceRelative('C:/Windows/System32/drivers/etc/hosts', 'D:/Claude');
  assert.equal(outside, 'C:/Windows/System32/drivers/etc/hosts');
});

test('a sibling directory sharing the workspace prefix is not treated as inside it', () => {
  // 'D:/Claude-backup' must not relativize against 'D:/Claude'.
  assert.equal(workspaceRelative('D:/Claude-backup/secret.txt', 'D:/Claude'), 'D:/Claude-backup/secret.txt');
});

test('an already-relative path passes through unchanged', () => {
  assert.equal(workspaceRelative('tools/a.mjs', 'D:/Claude'), 'tools/a.mjs');
});

test('with no workspace known, the path is left alone rather than guessed at', () => {
  assert.equal(workspaceRelative('D:/Claude/tools/a.mjs', null), 'D:/Claude/tools/a.mjs');
});

test('traversal survives relativization and is still rejected downstream', () => {
  // workspaceRelative preserves the '..' segment; pathMatches is what refuses it.
  assert.ok(workspaceRelative('D:/Claude/tools/../../etc/passwd', 'D:/Claude').includes('..'));
});

// The declared caps in host-runtime-output-v1 were documentation until the
// shared validator learned maxLength: every over-long string validated clean.
test('maxLength is enforced, so the schema caps are a gate and not a comment', async () => {
  const { RuntimeSchemaSet } = await import('../lib/runtime-schema.mjs');
  const schema = new RuntimeSchemaSet();
  const output = (context) => ({
    hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: context },
    code: null,
    publicReason: 'Allowed',
    enforcementHealth: 'strong',
    retrySignature: null,
    termination: 'continue',
    certification: 'not_claimed',
    missingClasses: [],
    responsibleProducer: null,
    remediationRoutes: [],
    missingEvidence: [],
  });
  assert.deepEqual(schema.validate('arcane-host-runtime-output-v1', output('x'.repeat(4000))), []);
  // The schema is a oneOf, so an over-long string surfaces as "no branch
  // matched" rather than a max-length issue. What matters is that it now fails
  // at all — before the validator learned maxLength, 4001 chars validated clean.
  assert.notDeepEqual(schema.validate('arcane-host-runtime-output-v1', output('x'.repeat(4001))), []);
});
