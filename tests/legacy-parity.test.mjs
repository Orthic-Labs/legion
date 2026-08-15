import assert from 'node:assert/strict';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = fileURLToPath(new URL('./..', import.meta.url));
const emptyOrAbsent = (path) => !existsSync(path) || readdirSync(path).every((name) => {
  const child = join(path, name);
  return statSync(child).isDirectory() ? emptyOrAbsent(child) : false;
});

test('legacy skill roots are hard-cut and canonical roots remain present', () => {
  for (const path of [
    'audit-fix/SKILL.md', 'audit-visual/SKILL.md', 'skills/audit-fix/legacy-source',
    'skills/audit-visual/legacy-source', 'skills/alchemist/legacy-source',
    'skills/architect/legacy-source', 'skills/coder/legacy-source',
    'skills/covenant/legacy-source', 'skills/debugger/legacy-source',
    'skills/dispatch/legacy-source', 'skills/handoff/legacy-source',
    'skills/qa/legacy-source', 'skills/tasklist/legacy-source',
  ]) assert.equal(emptyOrAbsent(join(ROOT, path)), true, path);
  for (const path of ['skills/audit-fix/SKILL.md', 'skills/audit-visual/SKILL.md']) {
    assert.equal(existsSync(join(ROOT, path)), true, path);
  }
});
