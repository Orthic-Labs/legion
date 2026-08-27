import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));

test('public checkout contains no parent-workspace path dependency', () => {
  const conformance = readFileSync(join(root, 'tests', 'run-audit-conformance-tests.mjs'), 'utf8');
  // The conformance suite must resolve everything from the checkout root.
  assert.ok(!conformance.includes('WORKSPACE_ROOT'), 'conformance must not reference a parent workspace root');
  assert.ok(!conformance.includes('../../../../'), 'conformance must not climb above the checkout');
});

test('ordinary pull requests & main pushes run mandatory repository checks', () => {
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  const triggers = workflow.slice(workflow.indexOf('on:'), workflow.indexOf('permissions:'));
  assert.match(triggers, /\bpull_request\b/);
  assert.match(triggers, /push:\s*\n\s*branches:\s*\[main\]/);
  assert.match(workflow, /pnpm legion:check/);
  assert.match(workflow, /pnpm test/);
  assert.match(workflow, /working-directory: engine\s+run: cargo test --locked/);
  assert.doesNotMatch(workflow, /uses:\s+[^\s]+@v\d+/i, 'GitHub Actions must use immutable revisions');
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
