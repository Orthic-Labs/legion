// Isolated remediation sandbox (B7-030).
//
// Every remediation run — proposal, preview, verification — happens in a copy
// of the bound base revision, never in the user's primary repository. The
// sandbox receipt records exactly what was created and how to recover it, and
// is bound to the finding run so a proposal cannot be verified against a
// different audit than the one that produced it.

import { createHash } from 'node:crypto';
import { join, normalize, resolve, sep } from 'node:path';

export const SANDBOX_SCHEMA_VERSION = 1;

// Bounded overlay policies. A producer never chooses its own.
export const INPUT_OVERLAY_POLICIES = Object.freeze([
  'bound-base-revision-only',
  'bound-base-revision-plus-dirty-overlay',
]);

export const SANDBOX_PROCESS_POLICY = Object.freeze({
  execution: 'allowlist-only',
  allowedExecutables: Object.freeze(['git']),
  inheritEnvironment: false,
  cwdConfinedToSandbox: true,
});

export const SANDBOX_NETWORK_POLICY = Object.freeze({
  allowed: false,
  reason: 'remediation is offline; no fetch, publish, or upload is permitted',
});

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`sandbox\0${JSON.stringify(value)}`).digest('hex')}`;
}

export function requireMutationCapability(host) {
  if (host?.capabilities?.mutation !== true) {
    throw new Error('remediation sandbox requires explicit host mutation capability');
  }
  return true;
}

function withinPrimaryWorktree(candidate, repoRoot) {
  const root = resolve(repoRoot);
  const path = resolve(candidate);
  if (path === root) return true;
  if (!path.startsWith(root + sep)) return false;
  // The git common directory lives under the root but is not the working tree.
  return !normalize(path).includes(`${sep}.git${sep}`);
}

/**
 * Fails loudly if a sandbox would (or did) land inside the user's working tree.
 */
export function assertPrimaryRepositoryUntouched(receipt, repo) {
  if (receipt?.primaryRepositoryMutated !== false) {
    throw new Error('sandbox receipt does not attest that the primary repository is unmutated');
  }
  if (withinPrimaryWorktree(receipt.sandboxPath, repo.root)) {
    throw new Error(`sandbox path ${receipt.sandboxPath} is inside the primary repository working tree`);
  }
  for (const path of receipt.createdPaths ?? []) {
    if (withinPrimaryWorktree(path, repo.root)) {
      throw new Error(`sandbox created ${path} inside the primary repository working tree`);
    }
  }
  return true;
}

export function sandboxReceipt({
  runId,
  sandboxPath,
  baseRevision,
  baseIdentity,
  inputOverlayPolicy,
  createdPaths,
  cleanup,
  binding,
  findingRunDigest,
  createdAt = null,
}) {
  const receipt = {
    schemaVersion: SANDBOX_SCHEMA_VERSION,
    kind: 'legion-remediation-sandbox',
    runId,
    sandboxPath,
    baseRevision,
    baseIdentity,
    inputOverlayPolicy,
    processPolicy: SANDBOX_PROCESS_POLICY,
    networkPolicy: SANDBOX_NETWORK_POLICY,
    createdPaths: [...(createdPaths ?? [])].sort(),
    cleanup,
    primaryRepositoryMutated: false,
    createdAt,
    binding,
    findingRunDigest,
  };
  receipt.digest = digestOf(receipt);
  return receipt;
}

/**
 * Create one isolated sandbox per remediation run.
 */
export async function createRemediationSandbox({
  repo,
  baseRevision,
  runId,
  host,
  processRunner,
  binding,
  findingRunDigest,
  inputOverlayPolicy = 'bound-base-revision-only',
  createdAt = null,
}) {
  requireMutationCapability(host);
  if (!INPUT_OVERLAY_POLICIES.includes(inputOverlayPolicy)) {
    throw new Error(`unknown input overlay policy: ${String(inputOverlayPolicy)}`);
  }
  if (!binding?.repositoryRevision) throw new Error('sandbox requires the run binding');
  if (baseRevision !== binding.repositoryRevision) {
    throw new Error('sandbox base revision does not match the bound run revision');
  }
  if (typeof findingRunDigest !== 'string' || !findingRunDigest.startsWith('sha256:')) {
    throw new Error('sandbox must be bound to a finding run digest');
  }
  if (inputOverlayPolicy === 'bound-base-revision-only' && binding.dirtyPatchDigest !== null) {
    throw new Error('bound-base-revision-only sandbox cannot be created from a dirty run');
  }

  const path = join(repo.gitCommonDir, 'legion-sandboxes', runId);
  if (withinPrimaryWorktree(path, repo.root)) {
    throw new Error(`refusing to create a sandbox inside the primary repository working tree: ${path}`);
  }

  const result = await processRunner.run({
    executable: 'git',
    args: ['worktree', 'add', '--detach', path, baseRevision],
    cwd: repo.root,
  });
  if (result?.exitCode !== 0) {
    throw new Error(`sandbox creation failed: ${result?.stderr ?? result?.error?.message ?? 'unknown'}`);
  }

  const cleanup = {
    command: ['git', 'worktree', 'remove', '--force', path],
    cwd: repo.root,
    description: 'Remove the remediation sandbox worktree.',
  };

  const receipt = sandboxReceipt({
    runId,
    sandboxPath: path,
    baseRevision,
    baseIdentity: {
      repositoryRevision: binding.repositoryRevision,
      dirtyPatchDigest: binding.dirtyPatchDigest,
      planDigest: binding.planDigest,
    },
    inputOverlayPolicy,
    createdPaths: [path],
    cleanup,
    binding,
    findingRunDigest,
    createdAt,
  });
  assertPrimaryRepositoryUntouched(receipt, repo);
  return { path, receipt };
}

export function buildSandboxReceiptSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/remediation/sandbox-receipt-v1.json',
    title: 'RemediationSandboxReceiptV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'runId', 'sandboxPath', 'baseRevision', 'baseIdentity',
      'inputOverlayPolicy', 'processPolicy', 'networkPolicy', 'createdPaths', 'cleanup',
      'primaryRepositoryMutated', 'binding', 'findingRunDigest', 'digest',
    ],
    properties: {
      schemaVersion: { const: SANDBOX_SCHEMA_VERSION },
      kind: { const: 'legion-remediation-sandbox' },
      runId: { type: 'string', minLength: 1 },
      sandboxPath: { type: 'string', minLength: 1 },
      baseRevision: { type: 'string', minLength: 1 },
      baseIdentity: {
        type: 'object',
        required: ['repositoryRevision', 'dirtyPatchDigest', 'planDigest'],
        properties: {
          repositoryRevision: { type: 'string', minLength: 1 },
          dirtyPatchDigest: { type: ['string', 'null'] },
          planDigest: { type: 'string', pattern: '^sha256:' },
        },
        additionalProperties: false,
      },
      inputOverlayPolicy: { enum: [...INPUT_OVERLAY_POLICIES] },
      processPolicy: { type: 'object' },
      networkPolicy: {
        type: 'object',
        required: ['allowed', 'reason'],
        properties: { allowed: { const: false }, reason: { type: 'string' } },
        additionalProperties: false,
      },
      createdPaths: { type: 'array', items: { type: 'string' } },
      cleanup: {
        type: 'object',
        required: ['command', 'cwd', 'description'],
        properties: {
          command: { type: 'array', items: { type: 'string' }, minItems: 1 },
          cwd: { type: 'string' },
          description: { type: 'string' },
        },
        additionalProperties: false,
      },
      // Proposal and verification never touch the audited repository.
      primaryRepositoryMutated: { const: false },
      createdAt: { type: ['string', 'null'] },
      binding: { type: 'object' },
      findingRunDigest: { type: 'string', pattern: '^sha256:' },
      digest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}
