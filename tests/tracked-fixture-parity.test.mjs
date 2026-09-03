// Four times today a test or manifest referenced a file the repository could
// not carry, and each time the same check passed locally because the file was
// on disk: bench/ ignored the coverage corpora, *.receipt.json swallowed
// shipped example fixtures, audit receipts were digested into a skill
// manifest, and a bare evidence/ rule caught corpus fixtures. A green local
// run proves nothing about a fresh checkout, so assert the two agree.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
// Trees whose contents are consumed by tests or digested into manifests, so
// every file in them must exist in a fresh clone.
const MUST_BE_TRACKED = ['bench/corpora', 'bench/fixtures', 'bench/rule-output', 'bench/detectors'];

const tracked = new Set(
  execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
    .split('\n')
    .filter(Boolean),
);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === '__pycache__' || name.startsWith('.')) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(relative(root, path).split(sep).join('/'));
  }
  return out;
}

test('every consumed fixture is carried by the repository', () => {
  const untracked = [];
  for (const tree of MUST_BE_TRACKED) {
    const absolute = join(root, tree);
    try { statSync(absolute); } catch { continue; }
    for (const file of walk(absolute)) if (!tracked.has(file)) untracked.push(file);
  }
  assert.deepEqual(untracked.sort(), [], 'fixtures on disk that a fresh clone would not have');
});
