import assert from 'node:assert/strict';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const emptyOrAbsent = (path) => !existsSync(path) || readdirSync(path).every((name) => {
  const child = join(path, name);
  return statSync(child).isDirectory() ? emptyOrAbsent(child) : false;
});

test('published package contains canonical skill trees without legacy parity payloads', () => {
  assert.equal(existsSync(join(ROOT, 'SKILL.md')), false);
  assert.equal(emptyOrAbsent(join(ROOT, 'audit-fix')), true);
  assert.equal(emptyOrAbsent(join(ROOT, 'audit-visual')), true);
  for (const name of ['audit-fix', 'audit-visual', 'alchemist', 'architect', 'coder', 'covenant', 'debugger', 'dispatch', 'handoff', 'qa', 'tasklist']) {
    assert.equal(emptyOrAbsent(join(ROOT, 'skills', name, 'legacy-source')), true, name);
  }
  assert.equal(existsSync(join(ROOT, 'skills', 'audit-fix', 'SKILL.md')), true);
  assert.equal(existsSync(join(ROOT, 'skills', 'audit-visual', 'SKILL.md')), true);
});
