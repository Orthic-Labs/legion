import assert from 'node:assert/strict';
import test from 'node:test';

import { EXIT } from '../lib/errors.mjs';
import { runCli } from '../lib/cli/run.mjs';

function stream() { return { value: '', write(chunk) { this.value += chunk; } }; }

test('budget inspect is registered & rejects an incomplete read-only request', async () => {
  const stdout = stream(), stderr = stream();
  const result = await runCli(['budget', 'inspect'], { stdout, stderr, env: {}, cwd: process.cwd() });
  assert.equal(result.exitCode, EXIT.USAGE);
  assert.match(stderr.value, /budget inspect requires --contract/);
});

test('budget is listed in CLI help', async () => {
  const stdout = stream(), stderr = stream();
  const result = await runCli(['--help'], { stdout, stderr, env: {}, cwd: process.cwd() });
  assert.equal(result.exitCode, EXIT.PASS);
  assert.match(stdout.value, /budget/);
});
