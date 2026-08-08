import assert from 'node:assert/strict';
import test from 'node:test';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizePath } from '../lib/config/index.mjs';
import { runDoctor } from '../lib/cli/commands/doctor.mjs';
import { runExternal } from '../lib/providers/executor/external-process.mjs';
import { fixedHost } from '../lib/host/fixed-host.mjs';
import { validateProviderResult } from '../scripts/normalize-provider-result.mjs';
import { finalizeAudit } from '../audit-finalize.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('Windows drive paths are normalized once', () => {
  assert.equal(normalizePath('D:\\D:\\work\\nemesis', 'D:\\work'), 'D:\\work\\nemesis');
  assert.equal(normalizePath('d:\\D:\\work\\nemesis', 'D:\\work'), 'd:\\work\\nemesis');
  assert.equal(normalizePath('D:\\d:\\work\\nemesis', 'D:\\work'), 'D:\\work\\nemesis');
  assert.equal(normalizePath('d:/D:\\work/nemesis', 'D:\\work'), 'd:\\work\\nemesis');
  assert.equal(normalizePath('/tmp/d:/D:/work', '/repo'), resolve('/repo', '/tmp/d:/D:/work'));
});

test('doctor obtains toolchains from injected host capability', async () => {
  let output = '';
  const toolchains = { state: 'ready', tools: [{ name: 'node', executable: 'node', version: '26.5.1' }] };
  await runDoctor(['.'], {
    stdout: { write(value) { output += value; } }, stderr: { write() {} }, env: {}, cwd: root,
    host: { toolchain: { discover() { return toolchains; } } },
  });
  assert.deepEqual(JSON.parse(output).hostCapabilities.toolchains, toolchains);
});

test('external process receipt has a schema-valid provider result', async () => {
  const host = fixedHost({ env: process.env, allowedExecutables: new Set(['node']) });
  const receipt = await runExternal({ provider: 'windows.probe', executable: 'node', args: ['-e', ''], cwd: root }, host);
  assert.equal(validateProviderResult(receipt.providerResult), true);
});

test('audit rerun commands preserve adversarial paths as non-shell argv data', () => {
  const workspace = 'D:\\work\\$(touch owned) `echo owned` "quoted" space';
  const facts = {
    workspace, out_dir: `${workspace}\\.audit\\run`, incomplete: false,
    plan: { binding: { repositoryRevision: 'abc' }, coverageGaps: [] }, cortex: { state: 'ready' },
    checks: [{ status: 'ran', verdict: 'pass' }], network_policy: { mode: 'deny' },
    plan_binding_verification: { valid: true },
    provider_reconciliation: { missingChecks: [], unplannedChecks: [], denominatorMismatches: [], unresolvedCoverage: [], missingRuntimeProviders: [], providerResults: [] },
  };
  const report = finalizeAudit({ facts, candidates: { candidates: [] }, adjudication: { complete: true, verdicts: [] } });
  assert.equal(report.schemaVersion, 4);
  assert.deepEqual(report.rerun.audit, {
    executable: process.execPath,
    args: [join(root, 'audit-run.mjs'), workspace],
  });
  assert.deepEqual(report.rerun.verify, {
    executable: process.execPath,
    args: [join(root, 'audit-verify.mjs'), '--facts', join(`${workspace}\\.audit\\run`, 'facts.json')],
  });
  assert.equal(typeof report.rerun.audit, 'object');
});
