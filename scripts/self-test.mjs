#!/usr/bin/env node
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const AUDIT_ROOT = dirname(HERE);
const TEST_ROOT = join(AUDIT_ROOT, 'tests');
const tests = readdirSync(TEST_ROOT).filter((name) => name.endsWith('.test.mjs')).sort().map((name) => join(TEST_ROOT, name));
if (!tests.length) { console.error('No audit tests found.'); process.exit(2); }

const testEnv = {
  ...process.env,
  AUDIT_PLAN_SIGNING_KEY: process.env.AUDIT_PLAN_SIGNING_KEY ?? 'audit-self-test-signing-key-not-for-production',
  AUDIT_OFFLINE: '1',
  npm_config_offline: 'true',
  CARGO_NET_OFFLINE: 'true',
  PIP_NO_INDEX: '1',
};

const syntaxTargets = [
  'tools/audit/audit-run.mjs', 'tools/audit/audit-complete.mjs', 'tools/audit/audit-finalize.mjs', 'tools/audit/audit-plan.mjs',
  'tools/audit/audit-verify.mjs', 'tools/audit/security-pipeline.mjs',
  'src/adapters/cortex-projection.mjs', 'src/adapters/ecosystem-manifests.mjs', 'src/adapters/security-adjudication.mjs',
  'src/providers/native-family-runner.mjs', 'src/providers/framework-suite.mjs', 'src/providers/security-suite.mjs',
  'src/providers/data-suite.mjs', 'src/providers/infrastructure-suite.mjs', 'src/providers/generic-source-suite.mjs',
  'src/providers/accessibility-suite.mjs', 'src/providers/visual-core.mjs',
  'src/registry/provider-registry.mjs', 'src/registry/provider-registry-complete.mjs',
  'scripts/generate-manifest.mjs', 'scripts/report-to-sarif.mjs',
].map((path) => join(AUDIT_ROOT, path));

for (const target of syntaxTargets) {
  const check = spawnSync(process.execPath, ['--check', target], { stdio: 'inherit', windowsHide: true, env: testEnv });
  if (check.status !== 0) process.exit(check.status ?? 1);
}
const manifest = spawnSync(process.execPath, [join(HERE, 'generate-manifest.mjs'), '--check'], { cwd: AUDIT_ROOT, stdio: 'inherit', windowsHide: true, env: testEnv });
if (manifest.status !== 0) process.exit(manifest.status ?? 1);
const result = spawnSync(process.execPath, ['--test', ...tests], { cwd: AUDIT_ROOT, stdio: 'inherit', windowsHide: true, env: testEnv });
process.exit(result.status ?? 1);
