// EC-5 item 7 — THE acceptance test for the whole contract.
//
// Drives the real Claude Code adapter (handleClaudeCodeHookEvent /
// normalizeClaudeCodeEvent) through a full session lifecycle with NO manual
// stamping of any host event or session binding — every hostEvent field this
// test cares about (runId, sourceRevision, priorCorrelation.requestId,
// contractId/taskId) is produced by the real pipeline items 1, 2, 4, and 5
// built, exactly as a live hook subprocess would produce it:
//
//   1. SessionStart with no prior binding -> SessionBindingStore mints an
//      ambient runId (items 1+2).
//   2. PreToolUse then PostToolUse Write on a path inside an ISOLATED
//      PolicyEngine fixture's signoff-level lockedDomain (NOT the real
//      bundle — its highRisk domains would drag in Covenant, which is out of
//      scope here) -> PreEffectCorrelationStore mints/hands off requestId,
//      hook-adapter-core computes sourceRevision from a real git repo, and
//      HostIngestor accepts the post-effect as an AMBIENT receipt (real
//      runId, null contractId/taskId — amendment A-ER-1, item 5).
//   3. Stop -> refused: the run has an effect receipt but zero evidence
//      receipts, so completion-gate's signoff prerequisites are unmet.
//   4. `legion run open --contract EC-5 --task T-1` is SIMULATED exactly as
//      the item 3 CLI command implements it (`putBinding` with the run's own
//      runId) — the only "manual" step in this file, and it is manual
//      because it stands in for a separate process (the CLI) the test
//      cannot literally shell out to without leaving the unit-test tier. A
//      proper verification/evidence receipt is minted for the same runId
//      (mirrors the identical pattern already established in
//      s09-completion-gate.test.mjs and claude-code-adapter.test.mjs's own
//      "Stop passes" test — there is no Oracle/evidence-producer pipeline in
//      scope to drive this any more "realistically" than that).
//   5. Stop -> passes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  handleClaudeCodeHookEvent,
  evaluateClaudeCodeStop,
  claudeCodeStopHookOutput,
} from '../src/lib/guard/compat/host/claude-code-adapter.mjs';
import { SessionBindingStore } from '../src/lib/host/arcane/session-binding.mjs';
import { PreEffectCorrelationStore } from '../src/lib/guard/compat/effects/preeffect-correlation.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';
import { ReceiptStore } from '../src/lib/guard/compat/audit/receipt-store.mjs';
import { ReplayGuard } from '../src/lib/guard/compat/effects/replay.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../src/lib/guard/compat/policy/policy.mjs';
import { EC5_DIGEST } from './fixtures/arcane-package/runtime-binding-contract.mjs';

const LOCKED_PATH = 'docs/legal/terms.md';
const SESSION_ID = 'e2e-session-1';
const TOOL_USE_ID = 'e2e-tool-use-1';
const CONTRACT_VERSION = 1;

function tempDir(prefix) {
  const root = mkdtempSync(path.join(tmpdir(), prefix));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** A real, throwaway git repo as the session's workspace — sourceRevision
 * (item 5) must be computed honestly from it, not stubbed. */
function gitWorkspace() {
  const { root, cleanup } = tempDir('arcane-e2e-workspace-');
  const git = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  git(['init', '-q']);
  git(['config', 'user.email', 'test@example.com']);
  git(['config', 'user.name', 'test']);
  writeFileSync(path.join(root, 'README.md'), 'e2e fixture\n');
  git(['add', 'README.md']);
  git(['commit', '-q', '-m', 'init']);
  const headRevision = git(['rev-parse', 'HEAD']).trim();
  return { root, headRevision, cleanup };
}

/** Isolated PolicyEngine fixture: the real bundle's claimLevels/effectRules
 * (so 'signoff' behaves exactly as production defines it), but with
 * lockedDomains swapped for ONE synthetic entry — never the real bundle's
 * lockedDomains, whose highRisk matches would drag Covenant into this test. */
function e2ePolicy() {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const bundle = {
    ...loaded.bundle,
    lockedDomains: [{ pattern: 'docs/legal/**', claimLevel: 'signoff', note: 'EC-5 item 7 E2E fixture' }],
  };
  return new PolicyEngine({ ...loaded, bundle });
}

test('EC-5 item 7 (acceptance): SessionStart mints ambient -> PostToolUse Write mints an ambient receipt -> Stop refused -> run open + verification receipt -> Stop passes', () => {
  const workspace = gitWorkspace();
  const receiptDir = tempDir('arcane-e2e-receipts-');
  const bindingDir = tempDir('arcane-e2e-bindings-');
  const correlationDir = tempDir('arcane-e2e-correlation-');

  const keyRing = generateTestKeyRing(['k1']);
  const receiptStore = new ReceiptStore({ root: receiptDir.root });
  const replayGuard = new ReplayGuard({});
  const policy = e2ePolicy();
  const sessionBinding = new SessionBindingStore({ root: bindingDir.root });
  const preEffectCorrelation = new PreEffectCorrelationStore({ root: correlationDir.root });

  const deps = { keyRing, receiptStore, replayGuard, policy, sessionBinding, preEffectCorrelation };

  try {
    // ── 1. SessionStart mints ambient ────────────────────────────────────
    const sessionStart = handleClaudeCodeHookEvent(
      { hook_event_name: 'SessionStart', session_id: SESSION_ID, cwd: workspace.root },
      deps,
    );
    assert.equal(sessionStart.accepted, true, JSON.stringify(sessionStart.decision));
    const runId = sessionStart.hostEvent.runId;
    assert.match(runId, /^run_[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(sessionStart.hostEvent.contractId, null);
    assert.equal(sessionStart.hostEvent.taskId, null);
    assert.deepEqual(sessionBinding.getBinding(SESSION_ID), { runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null });

    // ── 2. PreToolUse then PostToolUse Write on the locked path ──────────
    const preToolUse = handleClaudeCodeHookEvent(
      {
        hook_event_name: 'PreToolUse', session_id: SESSION_ID, cwd: workspace.root,
        tool_name: 'Write', tool_input: { file_path: LOCKED_PATH }, tool_use_id: TOOL_USE_ID,
      },
      deps,
    );
    assert.equal(preToolUse.accepted, true, JSON.stringify(preToolUse.decision));
    assert.equal(preToolUse.hostEvent.runId, runId, 'pre-effect reads the ambient binding session-start minted');

    const postToolUse = handleClaudeCodeHookEvent(
      {
        hook_event_name: 'PostToolUse', session_id: SESSION_ID, cwd: workspace.root,
        tool_name: 'Write', tool_input: { file_path: LOCKED_PATH }, tool_response: { ok: true }, tool_use_id: TOOL_USE_ID,
      },
      deps,
    );
    assert.equal(postToolUse.accepted, true, JSON.stringify(postToolUse.decision));
    assert.ok(postToolUse.receipt, 'amendment A-ER-1: real runId + null contractId/taskId ingests as an ambient receipt, not refused');
    assert.equal(postToolUse.receipt.runId, runId);
    assert.equal(postToolUse.receipt.contractId, null, 'ambient tier — no contract bound yet');
    assert.equal(postToolUse.receipt.taskId, null, 'ambient tier — no task bound yet');
    assert.equal(postToolUse.receipt.sourceRevision, workspace.headRevision, 'sourceRevision computed honestly from the real git workspace, item 5');
    assert.match(postToolUse.hostEvent.priorCorrelation.requestId, /^req_[0-9A-HJKMNP-TV-Z]{26}$/, 'PreEffectCorrelationStore round-tripped a real requestId, item 5');

    // ── 3. Stop is refused — an effect receipt exists, but zero evidence ──
    const stopPayload = { hook_event_name: 'Stop', session_id: SESSION_ID, cwd: workspace.root };
    const stopOne = handleClaudeCodeHookEvent(stopPayload, deps);
    assert.equal(stopOne.hostEvent.runId, runId, 'Stop reads the same ambient binding — no putBinding upgrade has happened yet');

    const completionOne = evaluateClaudeCodeStop(stopOne.hostEvent, { policy, receiptStore, claimedLevel: 'signoff' });
    assert.equal(completionOne.allowed, false, 'signoff requires evidence this run does not have yet');
    assert.equal(completionOne.detail.lockedDomainMatches.length, 1, 'the locked test path forced signoff prerequisite evaluation');
    assert.equal(completionOne.detail.lockedDomainMatches[0].pattern, 'docs/legal/**');

    const blockOutput = claudeCodeStopHookOutput(completionOne);
    assert.ok(blockOutput, 'Stop is actually blocked, not silently allowed');
    assert.equal(blockOutput.decision, 'block');

    // ── 4. Simulate `legion run open --contract EC-5 --version 1 --task T-1` ─────────
    // Exactly what lib/cli/commands/run.mjs's runOpen() does: putBinding
    // with the SAME runId ensureBinding already minted, never a new one.
    const opened = sessionBinding.putBinding(SESSION_ID, { runId, taskId: 'T-1', contractId: 'EC-5', contractVersion: CONTRACT_VERSION, contractDigest: EC5_DIGEST });
    assert.deepEqual(opened, { runId, taskId: 'T-1', contractId: 'EC-5', contractVersion: CONTRACT_VERSION, contractDigest: EC5_DIGEST });

    // Mint a proper verification receipt for the same runId (same pattern
    // as s09-completion-gate.test.mjs / claude-code-adapter.test.mjs's own
    // "Stop passes" test — no Oracle/evidence-producer pipeline is in scope
    // here to drive this any other way).
    receiptStore.append({
      schemaVersion: 1,
      kind: 'legion-evidence-capability-receipt',
      evidenceId: 'evid_01ARZ3NDEKTSV4RRFFQ69G5FAV',
      runId,
      taskId: 'T-1',
      contractId: 'EC-5',
      producerAuthority: 'oracle',
      capability: 'test-run',
      observation: { exitCode: 0 },
      evidenceClass: 'deterministic',
      authentication: {
        issuerIdentity: keyRing.activeKeyId(), verificationMethod: 'capability-signature', perMessage: true,
        verifiedAt: new Date().toISOString(),
      },
      replayDefense: { nonce: 'n-e2e-1', sequence: 1, freshnessWindowSeconds: 900, freshAt: new Date().toISOString() },
      sourceRevision: workspace.headRevision,
      dependsOn: [],
      stale: false,
      observedAt: new Date().toISOString(),
    });

    // ── 5. Stop passes ─────────────────────────────────────────────────
    const stopTwo = handleClaudeCodeHookEvent(stopPayload, deps);
    assert.equal(stopTwo.hostEvent.runId, runId);
    assert.equal(stopTwo.hostEvent.contractId, 'EC-5', 'the run-open upgrade is now visible on freshly-observed hostEvents too');
    assert.equal(stopTwo.hostEvent.taskId, 'T-1');

    const completionTwo = evaluateClaudeCodeStop(stopTwo.hostEvent, { policy, receiptStore, claimedLevel: 'signoff' });
    assert.equal(completionTwo.allowed, true, completionTwo.message);
    assert.equal(completionTwo.enforcementHealth, 'strong');

    const finalOutput = claudeCodeStopHookOutput(completionTwo);
    assert.equal(finalOutput, null, 'Stop passes through — no block output');
  } finally {
    workspace.cleanup();
    receiptDir.cleanup();
    bindingDir.cleanup();
    correlationDir.cleanup();
  }
});
