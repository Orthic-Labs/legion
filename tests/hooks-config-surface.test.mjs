import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const hooksRoot = join(root, 'hooks');

test('hooks publication contains configuration only', () => {
  assert.deepEqual(readdirSync(hooksRoot).sort(), ['hooks.json']);
  const config = JSON.parse(readFileSync(join(hooksRoot, 'hooks.json'), 'utf8'));
  for (const entries of Object.values(config.hooks)) {
    for (const entry of entries) {
      for (const hook of entry.hooks) assert.equal(hook.command, 'legion-hook');
    }
  }
});
