// B7-030 — isolated remediation sandboxes, checkpoints, and cleanup.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import {
  SANDBOX_NETWORK_POLICY,
  SANDBOX_PROCESS_POLICY,
  assertPrimaryRepositoryUntouched,
  buildSandboxReceiptSchema,
  createRemediationSandbox,
  requireMutationCapability,
} from '../../lib/remediation/sandbox.mjs';
import {
  cleanupReceipt,
  cleanupSandbox,
} from '../../lib/remediation/cleanup.mjs';
import {
  createCheckpoint,
  restoreCheckpoint,
  restorePlan,
} from '../../lib/remediation/checkpoint.mjs';

const binding = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'abc123',
  dirtyPatchDigest: null,
  cortexGenerationId: 'gen',
  cortexManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

const repo = { root: '/repo', gitCommonDir: '/repo/.git' };

function runner(overrides = {}) {
  const calls = [];
  return {
    calls,
    run: async (spec) => {
      calls.push(spec);
      if (overrides.fail) return { exitCode: 1, stderr: overrides.stderr ?? 'boom' };
      return { exitCode: 0, stdout: '' };
    },
  };
}

function host(mutation = true) {
  return { capabilities: { mutation } };
}

async function sandbox(options = {}) {
  return createRemediationSandbox({
    repo,
    baseRevision: 'abc123',
    runId: 'run-1',
    host: options.host ?? host(),
    processRunner: options.processRunner ?? runner(),
    binding,
    findingRunDigest: 'sha256:findingrun',
    inputOverlayPolicy: options.inputOverlayPolicy,
    createdAt: '2026-08-08T00:00:00Z',
  });
}

test('remediation requires an explicit mutation capability', async () => {
  assert.throws(() => requireMutationCapability(host(false)), /explicit host mutation capability/);
  assert.equal(requireMutationCapability(host(true)), true);
  await assert.rejects(() => sandbox({ host: host(false) }), /explicit host mutation capability/);
});

test('a sandbox is an isolated copy of the bound base revision, outside the primary worktree', async () => {
  const processRunner = runner();
  const result = await sandbox({ processRunner });
  assert.equal(result.receipt.baseRevision, 'abc123');
  assert.equal(result.receipt.baseIdentity.repositoryRevision, binding.repositoryRevision);
  assert.equal(result.path, join('/repo/.git', 'nemesis-sandboxes', 'run-1'));
  assert.notEqual(result.path, repo.root);
  assert.equal(assertPrimaryRepositoryUntouched(result.receipt, repo), true);
  assert.throws(
    () => assertPrimaryRepositoryUntouched({ ...result.receipt, sandboxPath: '/repo/src' }, repo),
    /primary repository/,
  );
  // Base revision mismatch against the run binding is refused up front.
  await assert.rejects(
    () => createRemediationSandbox({ repo, baseRevision: 'deadbeef', runId: 'r', host: host(), processRunner, binding, findingRunDigest: 'sha256:f' }),
    /base revision does not match the bound run/,
  );
});

test('the sandbox receipt records identity, policy, files, cleanup, and the finding run it belongs to', async () => {
  const result = await sandbox();
  const receipt = result.receipt;
  assert.equal(receipt.kind, 'nemesis-remediation-sandbox');
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.findingRunDigest, 'sha256:findingrun');
  assert.deepEqual(receipt.binding, binding);
  assert.equal(receipt.inputOverlayPolicy, 'bound-base-revision-only');
  assert.deepEqual(receipt.processPolicy, SANDBOX_PROCESS_POLICY);
  assert.deepEqual(receipt.networkPolicy, SANDBOX_NETWORK_POLICY);
  assert.equal(receipt.networkPolicy.allowed, false);
  assert.equal(receipt.primaryRepositoryMutated, false);
  assert.ok(Array.isArray(receipt.createdPaths));
  assert.deepEqual(receipt.cleanup.command, ['git', 'worktree', 'remove', '--force', result.path]);
  assert.match(receipt.digest, /^sha256:/);
  // Deterministic: identical inputs produce an identical receipt.
  const again = await sandbox();
  assert.deepEqual(again.receipt, receipt);
  assert.throws(() => cleanupReceipt({ path: '/x' }), /removed/);
});

test('an unbounded input overlay policy is rejected', async () => {
  await assert.rejects(() => sandbox({ inputOverlayPolicy: 'whatever-the-producer-wants' }), /unknown input overlay policy/);
});

test('checkpoints restore and a failed restore is visible, never silently passed', async () => {
  const checkpoint = createCheckpoint({ worktreePath: '/w', baseCommit: 'abc', files: ['b.ts', 'a.ts'] });
  assert.deepEqual(restorePlan(checkpoint).steps.map((step) => step.file), ['a.ts', 'b.ts']);
  const ok = await restoreCheckpoint({ checkpoint, processRunner: runner() });
  assert.equal(ok.restored, true);
  assert.equal(ok.error, null);
  const bad = await restoreCheckpoint({ checkpoint, processRunner: runner({ fail: true, stderr: 'locked' }) });
  assert.equal(bad.restored, false);
  assert.equal(bad.error, 'locked');
  assert.match(bad.recoveryCommand, /git -C \/w checkout/);
});

test('failed cleanup leaves exact recovery data and is never reported as removed', async () => {
  const result = await sandbox();
  const failed = await cleanupSandbox({ sandbox: result.receipt, processRunner: runner({ fail: true, stderr: 'in-use' }) });
  assert.equal(failed.removed, false);
  assert.equal(failed.error, 'in-use');
  assert.deepEqual(failed.residualPaths, [result.receipt.sandboxPath]);
  assert.deepEqual(failed.recoveryCommand, ['git', 'worktree', 'remove', '--force', result.receipt.sandboxPath]);
  assert.equal(failed.kind, 'nemesis-remediation-cleanup');
  const cleaned = await cleanupSandbox({ sandbox: result.receipt, processRunner: runner() });
  assert.equal(cleaned.removed, true);
  assert.deepEqual(cleaned.residualPaths, []);
  assert.equal(cleaned.recoveryCommand, null);
});

test('the committed sandbox receipt schema matches its generator', () => {
  const committed = JSON.parse(readFileSync(new URL('../../schemas/remediation/sandbox-receipt-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(committed, buildSandboxReceiptSchema());
  assert.ok(committed.required.includes('binding'));
  assert.ok(committed.required.includes('findingRunDigest'));
  assert.equal(committed.properties.primaryRepositoryMutated.const, false);
});
