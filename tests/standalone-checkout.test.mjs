import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createRequire } from 'node:module';

const root = fileURLToPath(new URL('..', import.meta.url));

test('public checkout contains no parent-workspace path dependency', () => {
  const conformance = readFileSync(join(root, 'tests', 'run-audit-conformance-tests.mjs'), 'utf8');
  // The conformance suite must resolve everything from the checkout root.
  assert.ok(!conformance.includes('WORKSPACE_ROOT'), 'conformance must not reference a parent workspace root');
  assert.ok(!conformance.includes('../../../../'), 'conformance must not climb above the checkout');
});

test('no workflow runs automatically on push or pull request', () => {
  // This repository deliberately ships no CI. The remaining workflows are manual
  // (workflow_dispatch) or tag-gated release guards; none may fire on ordinary pushes.
  const dir = join(root, '.github', 'workflows');
  for (const name of readdirSync(dir)) {
    const workflow = readFileSync(join(dir, name), 'utf8');
    const triggers = workflow.slice(workflow.indexOf('on:'), workflow.indexOf('permissions:'));
    assert.ok(!/\bpull_request\b/.test(triggers), `${name} must not run on pull requests`);
    assert.ok(!/push:\s*\n\s*branches:/.test(triggers), `${name} must not run on branch pushes`);
  }
});

test('publication guard exists and blocks public channels without a grant', () => {
  const check = join(root, 'scripts', 'check-publication-policy.mjs');
  // Internal channel always allowed.
  const internal = execFileSync(process.execPath, [check, '--channel', 'internal-pack'], { cwd: root, encoding: 'utf8' });
  assert.match(internal, /internal channel allowed/);
  // npm carries an explicit grant in release/publication-policy.json.
  const npm = execFileSync(process.execPath, [check, '--channel', 'npm'], { cwd: root, encoding: 'utf8' });
  assert.match(npm, /publication channel allowed: npm/);
  // A channel with no grant must still be refused — that is the guard's contract.
  try {
    execFileSync(process.execPath, [check, '--channel', 'homebrew'], { cwd: root, encoding: 'utf8' });
    assert.fail('ungranted channel must be blocked');
  } catch (error) {
    assert.equal(error.status, 5, 'publication guard must exit 5 (integrity) for an ungranted channel');
  }
});

test('license and third-party notices are present', () => {
  const license = readFileSync(join(root, 'LICENSE'), 'utf8');
  assert.ok(license.includes('Orthic Labs Source Use License'), 'LICENSE identifies the Orthic Labs source-use license');
  const notices = readFileSync(join(root, 'docs/THIRD_PARTY_NOTICES.md'), 'utf8');
  assert.ok(notices.length > 0, 'third-party notices placeholder exists');
});

test('fresh standalone checkout runs self-test and schema check without parent files', () => {
  // Simulate a clean checkout: run the two self-contained validation commands
  // from the repository root with an isolated HOME so no parent-workspace state
  // can leak in.
  const tempHome = mkdtempSync(join(tmpdir(), 'legion-standalone-'));
  try {
    const schemaCheck = execFileSync(process.execPath, ['scripts/generate-schemas.mjs', '--check'], {
      cwd: root, encoding: 'utf8', env: { ...process.env, HOME: tempHome },
    });
    assert.match(schemaCheck, /schemas are in sync/);
    const selfTest = execFileSync(process.execPath, ['scripts/self-test.mjs'], {
      cwd: root, encoding: 'utf8', env: { ...process.env, HOME: tempHome },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    // The self-test script verifies the manifest matches the runtime check set;
    // a self-contained checkout must report that match (or an OK) without
    // needing parent-workspace files.
    assert.match(selfTest, /match|OK|pass/i);
  } finally {
    rmSync(tempHome, { recursive: true, force: true });
  }
});

test('Windows portability tests pass from a copied standalone checkout', () => {
  const temp = mkdtempSync(join(tmpdir(), 'legion-portable-copy-'));
  const checkout = join(temp, 'legion-copy');
  try {
    cpSync(root, checkout, {
      recursive: true,
      filter(source) {
        const path = relative(root, source).replaceAll('\\', '/');
        return !path.startsWith('.git')
          && !path.startsWith('node_modules')
          && !path.startsWith('qualification/evidence')
          && path !== 'docs/architecture.md'
          && path !== 'pnpm-lock.yaml';
      },
    });
    const require = createRequire(import.meta.url);
    const hookRuntime = require.resolve('@rightkit/hooks');
    cpSync(dirname(dirname(hookRuntime)), join(checkout, 'node_modules', '@rightkit', 'hooks'), { recursive: true });
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const output = execFileSync(process.execPath, ['--test', 'tests/windows-portability.test.mjs'], {
      cwd: checkout,
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.match(output, /pass 4/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
