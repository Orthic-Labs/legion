#!/usr/bin/env node
// Runs every Python test suite the workspace owns. Public repository: local scope is
// reads, static checks, and interpreted-language tests only — no cargo, no compile.
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PY = process.platform === 'win32' ? 'py' : 'python3';
const PY_ARGS = process.platform === 'win32' ? ['-3.11'] : [];

function run(args, cwd = ROOT) {
  const result = spawnSync(PY, [...PY_ARGS, ...args], { stdio: 'inherit', cwd });
  if (result.error && result.error.code === 'ENOENT') {
    console.error('WARNING: no Python interpreter found; skipping Python test suites (pnpm test:python)');
    process.exit(0);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

// 1. Alchemist unittest suite.
run(['-m', 'unittest', 'discover', '-s', 'skills/alchemist/tests', '-v']);

// 2. Dispatch validator smoke script.
run(['src/lib/dispatch-validator/test_validate_dispatch.py']);

// 2a. Shipped skill bundles — exercise the packaged copy under skills/, not just the
//     src/lib development copy, so a bundle-only defect (dead vendored authority path,
//     stale fixture) cannot regress silently the way it did before these were wired in.
run(['skills/dispatch/scripts/test_validate_dispatch.py']);
run(['skills/tasklist/scripts/test_validate_tasklist.py']);
run(['skills/tasklist/tests/tasklist-entrypoint.test.py']);

// 3. Research-core entrypoint parity (pytest-style fixtures).
run(['-m', 'pytest', 'src/lib/research-core/test_entrypoint_parity.py', '-v']);

// 4. Research-core recovered evidence/router/meter/shard/stopping suite —
//    standalone scripts with `if __name__ == '__main__'`, one process each so a
//    failure names its own file instead of hiding behind unittest discovery.
const researchTestsDir = path.join(ROOT, 'src', 'lib', 'research-core', 'tests');
const researchTests = readdirSync(researchTestsDir)
  .filter((name) => name.startsWith('test_') && name.endsWith('.py'))
  .sort();
for (const name of researchTests) {
  run([path.join('src', 'lib', 'research-core', 'tests', name)]);
}

console.log(`OK: python suites passed (alchemist, dispatch-validator, entrypoint-parity, ${researchTests.length} research-core tests)`);
