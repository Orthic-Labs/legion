import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runInit } from '../src/lib/cli/commands/init.mjs';

test('init defaults to a no-write preview', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-init-characterization-'));
  let output = '';
  try {
    const result = runInit([], { stdout: { write(value) { output += value; } }, stderr: { write() {} }, cwd: root });
    assert.equal(result.exitCode, 0);
    assert.equal(JSON.parse(output).dryRun, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
