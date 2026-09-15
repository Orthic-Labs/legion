import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { nodeNestedRoutes, routeMismatches, rustNestedRoutes } from './native-cli/inventory.mjs';

// Run a copy of the checker against a miniature owned tree. Never remove real
// runtime sources to test the post-deletion gate.
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'legion-native-surface-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const path of ['scripts', 'tests', 'release']) mkdirSync(join(root, path));
  writeFileSync(join(root, 'scripts/check-native-cli-surface.mjs'), readFileSync(new URL('./check-native-cli-surface.mjs', import.meta.url)));
  writeFileSync(join(root, 'package.json'), '{}');
  writeFileSync(join(root, 'release/distribution-contract.json'), JSON.stringify({ nodePackage: { access: 'private-development-tooling' } }));
  for (const name of ['cli', 'doctor', 'bind']) writeFileSync(join(root, `tests/${name}.test.mjs`), "import '../scripts/native-cli/test-helper.mjs';\n");
  return {
    root,
    run(phase = 'enforce') {
      return spawnSync(process.execPath, [join(root, 'scripts/check-native-cli-surface.mjs'), `--phase=${phase}`], { cwd: root, encoding: 'utf8', timeout: 10_000 });
    },
    add(relative, contents = '') {
      const path = join(root, relative);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, contents);
    },
  };
}

test('enforce succeeds when runtime entrypoints and command directory are absent', (t) => {
  const tree = fixture(t);
  const result = tree.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).ok, true);
});

test('record reports real runtime gaps without granting enforcement success', (t) => {
  const tree = fixture(t);
  tree.add('src/bin/legion.mjs', '// retained reference implementation\n');
  tree.add('src/lib/cli/commands/state.mjs', '// retained command\n');
  const record = tree.run('record');
  assert.equal(record.status, 0, record.stderr);
  const summary = JSON.parse(record.stdout);
  assert.equal(summary.ok, false);
  assert.equal(summary.issues.length, 2);
  const enforce = tree.run();
  assert.equal(enforce.status, 1, enforce.stderr);
  assert.deepEqual(JSON.parse(enforce.stdout).issues, summary.issues);
});

test('native helper requirement is enforced for every named product test', (t) => {
  const tree = fixture(t);
  tree.add('tests/bind.test.mjs', '// no invocation helper\n');
  const result = tree.run();
  assert.equal(result.status, 1, result.stderr);
  assert.ok(JSON.parse(result.stdout).issues.some((issue) => issue.includes('tests/bind.test.mjs')));
});

test('development scripts are permitted but npm Legion entrypoints are rejected', (t) => {
  const tree = fixture(t);
  tree.add('scripts/build.mjs', '// permitted build tooling\n');
  assert.equal(tree.run().status, 0);
  tree.add('package.json', JSON.stringify({ bin: { legion: './src/bin/legion.mjs' } }));
  const result = tree.run();
  assert.equal(result.status, 1, result.stderr);
  assert.ok(JSON.parse(result.stdout).issues.includes('package.json must not register npm bin legion'));
});

test('enforce recursively rejects a nested Node CLI runtime module', (t) => {
  const tree = fixture(t);
  tree.add('src/lib/cli/commands/governance/deep/retained.mjs', '// nested semantic route\n');
  const result = tree.run();
  assert.equal(result.status, 1, result.stderr);
  assert.ok(JSON.parse(result.stdout).issues.includes('forbidden Node Legion runtime file: src/lib/cli/commands/governance/deep/retained.mjs'));
});

test('nested Node/Rust route parity fails closed when Rust omits a route', () => {
  const node = nodeNestedRoutes({ run: "const [sub,...rest]=argv; if (sub === 'open') return; if (sub === 'launch') return;" }, [{ command: 'run', source: './commands/run.mjs' }]);
  const rust = rustNestedRoutes('enum RunCommand {\n    Open(RunOpenArgs)\n}', {}, node);
  assert.deepEqual(routeMismatches(node, rust), ['run.launch']);
});
