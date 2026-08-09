import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { executePlannedProvider, resolveRepositoryModule } from '../lib/providers/provider-executor.mjs';
import { runExternal, blocked, pickEnvironment } from '../lib/providers/executor/external-process.mjs';
import { requireProjectExecutionSandbox, ProviderBlockedError } from '../lib/host/sandbox-policy.mjs';
import { fixedHost } from '../lib/host/fixed-host.mjs';
import { SPAWN_STATUS } from '../lib/core/execution-receipt.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('external process runner blocks non-allowlisted executables', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['node']) });
  const receipt = await runExternal({ provider: 'x', executable: 'rm', args: ['-rf', '/'], cwd: root }, host);
  assert.equal(receipt.spawnStatus, 'blocked');
  assert.equal(receipt.providerResult.status, 'blocked');
  assert.match(receipt.providerResult.coverageGaps[0].reason, /not-allowlisted/);
});

test('shell execution is forbidden', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set([process.execPath]) });
  await assert.rejects(
    () => runExternal({ provider: 'x', executable: process.execPath, shell: true, cwd: root }, host),
    /shell execution is forbidden/,
  );
});

test('external process runs with sanitized environment', async () => {
  const host = fixedHost({
    env: { ...process.env, SECRET: 'leak' },
    allowedExecutables: new Set([process.execPath]),
  });
  const receipt = await runExternal({
    provider: 'probe', executable: process.execPath,
    args: ['-e', 'process.exit(process.env.SECRET ? 1 : 0)'],
    cwd: root, environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt.spawnStatus, 'completed');
  // The child must not see the SECRET key (sanitized environment); it exits 0
  // only when SECRET is absent.
  assert.equal(receipt.exitCode, 0);
});

test('timeout aborts the child and reports timeout', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set([process.execPath]) });
  const receipt = await runExternal({
    provider: 'slow', executable: process.execPath, args: ['-e', 'setTimeout(()=>{}, 60000)'],
    cwd: root, timeoutMs: 200, environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt.spawnStatus, 'timeout');
  assert.equal(receipt.timedOut, true);
});

test('output cap terminates the child', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set([process.execPath]) });
  const receipt = await runExternal({
    provider: 'noisy', executable: process.execPath, args: ['-e', 'while(true) console.log("x".repeat(1000))'],
    cwd: root, maxOutputBytes: 4096, environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt.stdoutArtifact.bytes, 4096);
  assert.equal(receipt.timedOut, false);
  assert.equal(receipt.spawnStatus, 'output-limit');
  assert.equal(receipt.providerResult.status, 'partial');
  assert.equal(receipt.providerResult.complete, false);
  assert.equal(receipt.providerResult.coverageGaps[0].kind, 'execution-output-limit');
  assert.ok(SPAWN_STATUS.includes(receipt.spawnStatus));
  const schema = JSON.parse(readFileSync(new URL('../schemas/execution-receipt-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(schema.properties.spawnStatus.enum, SPAWN_STATUS);
});

test('project-executing provider requires a network-sandbox receipt', () => {
  const provider = { id: 'runtime.app', hostCapabilities: ['project-execution'] };
  const host = fixedHost();
  assert.throws(() => requireProjectExecutionSandbox(provider, host), ProviderBlockedError);
  assert.throws(() => requireProjectExecutionSandbox(provider, host), /network-sandbox-receipt-missing/);
  const sandboxed = fixedHost({ capabilities: { networkSandbox: { active: true, receipt: { id: 'r1' } } } });
  assert.doesNotThrow(() => requireProjectExecutionSandbox(provider, sandboxed));
});

test('non-project providers do not require a sandbox', () => {
  const provider = { id: 'security.credentials', hostCapabilities: [] };
  assert.doesNotThrow(() => requireProjectExecutionSandbox(provider, fixedHost()));
});

test('reasoning-contract providers remain unproven when reviewer is unavailable', async () => {
  const host = fixedHost();
  const result = await executePlannedProvider({
    provider: { id: 'security.adjudication', runner: { kind: 'reasoning-contract', contract: 'x' } },
    root: '/tmp', plan: {}, projection: {}, artifacts: new Map(), host,
  });
  assert.equal(result.status, 'unproven');
  assert.equal(result.complete, false);
  assert.deepEqual(result.coverageGaps,[{kind:'reasoning-reviewer-unavailable'}]);
});

test('imported-artifact provider requires its artifact', async () => {
  const host = fixedHost();
  const missing = await executePlannedProvider({
    provider: { id: 'codeql', runner: { kind: 'imported-artifact', artifact: 'codeql.sarif' } },
    root: '/tmp', plan: {}, projection: {}, artifacts: new Map(), host,
  });
  assert.equal(missing.status, 'missing');
  const present = await executePlannedProvider({
    provider: { id: 'codeql', runner: { kind: 'imported-artifact', artifact: 'codeql.sarif' } },
    root: '/tmp', plan: {}, projection: {}, artifacts: new Map([['codeql.sarif', { path: 'x' }]]), host,
  });
  assert.equal(present.status, 'pass');
});

test('resolveRepositoryModule rejects absolute external paths', () => {
  assert.throws(() => resolveRepositoryModule('/etc/evil.mjs'), /repository-relative/);
  assert.throws(() => resolveRepositoryModule('C:\\evil.mjs'), /repository-relative/);
  assert.match(resolveRepositoryModule('providers/security-suite.mjs'), /providers[\\/]security-suite\.mjs$/);
});

test('pickEnvironment only carries allowlisted keys', () => {
  const env = { PATH: '/a', HOME: '/b', SECRET: 'x' };
  assert.deepEqual(pickEnvironment(env, ['PATH', 'HOME']), { PATH: '/a', HOME: '/b' });
});

test('blocked helper produces a canonical blocked receipt', () => {
  const receipt = blocked({ provider: 'x', executable: 'tool', args: [], cwd: '/tmp' }, 'reason');
  assert.equal(receipt.spawnStatus, 'blocked');
  assert.equal(receipt.kind, 'legion-execution-result');
});
