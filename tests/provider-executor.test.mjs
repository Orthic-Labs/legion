import assert from 'node:assert/strict';
import test from 'node:test';
import { executePlannedProvider, resolveRepositoryModule } from '../lib/providers/provider-executor.mjs';
import { runExternal, blocked, pickEnvironment } from '../lib/providers/external-process.mjs';
import { requireProjectExecutionSandbox, ProviderBlockedError } from '../lib/host/sandbox-policy.mjs';
import { fixedHost } from '../lib/host/fixed-host.mjs';

test('external process runner blocks non-allowlisted executables', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['node']) });
  const receipt = await runExternal({ provider: 'x', executable: 'rm', args: ['-rf', '/'], cwd: '/tmp' }, host);
  assert.equal(receipt.spawnStatus, 'blocked');
  assert.equal(receipt.providerResult.status, 'blocked');
  assert.match(receipt.providerResult.coverageGaps[0].reason, /not-allowlisted/);
});

test('shell execution is forbidden', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['sh']) });
  await assert.rejects(
    () => runExternal({ provider: 'x', executable: 'sh', shell: true, cwd: '/tmp' }, host),
    /shell execution is forbidden/,
  );
});

test('external process runs with sanitized environment', async () => {
  const host = fixedHost({
    env: { ...process.env, SECRET: 'leak' },
    allowedExecutables: new Set(['node']),
  });
  const receipt = await runExternal({
    provider: 'probe', executable: 'node',
    args: ['-e', 'process.exit(process.env.SECRET ? 1 : 0)'],
    cwd: '/tmp', environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt.spawnStatus, 'completed');
  // The child must not see the SECRET key (sanitized environment); it exits 0
  // only when SECRET is absent.
  assert.equal(receipt.exitCode, 0);
});

test('timeout aborts the child and reports timeout', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['node']) });
  const receipt = await runExternal({
    provider: 'slow', executable: 'node', args: ['-e', 'setTimeout(()=>{}, 60000)'],
    cwd: '/tmp', timeoutMs: 200, environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt.spawnStatus, 'timeout');
  assert.equal(receipt.timedOut, true);
});

test('output cap terminates the child', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['node']) });
  const receipt = await runExternal({
    provider: 'noisy', executable: 'node', args: ['-e', 'while(true) console.log("x".repeat(1000))'],
    cwd: '/tmp', maxOutputBytes: 4096, environmentKeys: ['PATH', 'HOME'],
  }, host);
  assert.equal(receipt._outputLimitHit, true);
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

test('reasoning-contract providers are never invoked by the executor', async () => {
  const host = fixedHost();
  const result = await executePlannedProvider({
    provider: { id: 'security.adjudication', runner: { kind: 'reasoning-contract', contract: 'x' } },
    root: '/tmp', plan: {}, projection: {}, artifacts: new Map(), host,
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.complete, true);
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
  assert.ok(resolveRepositoryModule('providers/security-suite.mjs').endsWith('providers/security-suite.mjs'));
});

test('pickEnvironment only carries allowlisted keys', () => {
  const env = { PATH: '/a', HOME: '/b', SECRET: 'x' };
  assert.deepEqual(pickEnvironment(env, ['PATH', 'HOME']), { PATH: '/a', HOME: '/b' });
});

test('blocked helper produces a canonical blocked receipt', () => {
  const receipt = blocked({ provider: 'x', executable: 'tool', args: [], cwd: '/tmp' }, 'reason');
  assert.equal(receipt.spawnStatus, 'blocked');
  assert.equal(receipt.kind, 'nemesis-execution-result');
});
