import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { discoverBookTests } from '../scripts/qualify-book.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SELF = 'tests/book-source-completion.test.mjs';

const BOOK_TESTS = Object.freeze({
  1: Object.freeze({
    'B1-001': ['tests/package-install.test.mjs'],
    'B1-002': ['tests/schema-generation.test.mjs'],
    'B1-003': ['tests/cli.test.mjs'],
    'B1-004': ['tests/core-foundations.test.mjs'],
    'B1-005': ['tests/artifact-store.test.mjs'],
    'B1-006': ['tests/core-foundations.test.mjs'],
    'B1-007': ['tests/config.test.mjs'],
    'B1-008': ['tests/config.test.mjs'],
    'B1-009': ['tests/provider-contracts.test.mjs'],
    'B1-010': ['tests/provider-sdk.test.mjs'],
    'B1-011': ['tests/provider-dag.test.mjs'],
    'B1-012': ['tests/provider-executor.test.mjs'],
    'B1-013': ['tests/cortex-adapter.test.mjs'],
    'B1-014': ['tests/core-api.test.mjs'],
    'B1-015': ['tests/core-foundations.test.mjs'],
    'B1-016': ['tests/execution-semantics.test.mjs'],
    'B1-017': ['tests/provider-denominator-signature.test.mjs'],
    'B1-018': ['tests/audit-finalize.test.mjs'],
    'B1-019': ['tests/audit-finalize.test.mjs'],
    'B1-020': ['tests/audit-verify.test.mjs'],
    'B1-021': ['tests/cli.test.mjs'],
    'B1-022': ['tests/schema-generation.test.mjs'],
    'B1-023': ['tests/standalone-checkout.test.mjs'],
    'B1-024': ['tests/standalone-checkout.test.mjs'],
    'B1-025': ['tests/visual-core.test.mjs'],
    'B1-026': ['tests/generic-source-suite.test.mjs'],
    'B1-027': ['tests/book-qualification.test.mjs'],
    'B1-028': ['tests/book-qualification.test.mjs'],
  }),
  2: Object.freeze(Object.fromEntries(
    Array.from({ length: 30 }, (_, index) => [
      `B2-${String(index + 1).padStart(3, '0')}`,
      [SELF],
    ]),
  )),
  3: Object.freeze({
    'B3-001': ['tests/provider-contracts.test.mjs'],
    'B3-002': ['tests/provider-executor.test.mjs'],
    'B3-003': ['tests/providers/ast-grep/structural.test.mjs'],
    'B3-004': ['tests/providers/opengrep/sast.test.mjs'],
    'B3-005': ['tests/provider-executor.test.mjs'],
    'B3-006': ['tests/providers/supply-chain/supply-chain.test.mjs'],
    'B3-007': ['tests/providers/supply-chain/supply-chain.test.mjs'],
    'B3-008': ['tests/providers/supply-chain/supply-chain.test.mjs'],
    'B3-009': ['tests/providers/supply-chain/supply-chain.test.mjs'],
    'B3-010': ['tests/reachability.test.mjs'],
    'B3-011': ['tests/coverage-registry.test.mjs'],
    'B3-012': ['tests/providers/javascript/javascript.test.mjs'],
    'B3-013': ['tests/providers/python/python.test.mjs'],
    'B3-014': ['tests/providers/rust/rust.test.mjs'],
    'B3-015': ['tests/providers/go/go.test.mjs'],
    'B3-016': ['tests/providers/jvm/jvm.test.mjs'],
    'B3-017': ['tests/providers/dotnet/dotnet.test.mjs'],
    'B3-018': ['tests/providers/c-family/c-family.test.mjs'],
    'B3-019': ['tests/providers/php-ruby/php-ruby.test.mjs'],
    'B3-020': ['tests/providers/mobile/mobile.test.mjs'],
    'B3-021': ['tests/coverage-long-tail.test.mjs'],
    'B3-022': ['tests/framework-suite.test.mjs'],
    'B3-023': ['tests/framework-suite.test.mjs'],
    'B3-024': ['tests/generic-source-suite.test.mjs'],
    'B3-025': ['tests/provider-architecture.test.mjs'],
    'B3-026': ['tests/provider-architecture.test.mjs'],
    'B3-027': ['tests/generic-source-suite.test.mjs'],
    'B3-028': ['tests/generic-source-suite.test.mjs'],
    'B3-029': ['tests/audit-finalize.test.mjs'],
    'B3-030': ['tests/coverage-registry.test.mjs'],
  }),
});

test('canonical qualifier includes source-completion contracts for Book 1', async () => {
  const tests = await discoverBookTests(1, ROOT);
  assert.ok(tests.some((path) => path.endsWith('book-source-completion.test.mjs')));
});

test('external process implementation has one canonical executor authority', async () => {
  const canonical = resolve(ROOT, 'lib/providers/executor/external-process.mjs');
  const legacy = resolve(ROOT, 'lib/providers/external-process.mjs');
  assert.ok(existsSync(canonical), 'canonical executor path is missing');
  const legacyText = readFileSync(legacy, 'utf8');
  assert.match(legacyText, /^export \{ blocked, pickEnvironment, runExternal \} from '.\/executor\/external-process\.mjs';\s*$/);
  const canonicalExports = await import(pathToFileURL(canonical));
  const legacyExports = await import(pathToFileURL(legacy));
  assert.equal(legacyExports.runExternal, canonicalExports.runExternal);
});

function walk(path) {
  if (!existsSync(path)) return [];
  if (statSync(path).isFile()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .flatMap((entry) => walk(resolve(path, entry.name)));
}

async function assertSourceLoads(task, implementationPath) {
  const absolute = resolve(ROOT, implementationPath);
  assert.ok(existsSync(absolute), `${task}: missing implementation ${implementationPath}`);
  const files = walk(absolute);
  assert.ok(files.length > 0, `${task}: empty implementation ${implementationPath}`);
  for (const file of files) {
    assert.ok(statSync(file).size > 0, `${task}: empty source file ${implementationPath}`);
    if (extname(file) === '.json') JSON.parse(readFileSync(file, 'utf8'));
    const executableOnly = implementationPath.startsWith('bin/')
      || implementationPath.startsWith('scripts/')
      || implementationPath.startsWith('bench/');
    if (extname(file) === '.mjs' && !executableOnly) {
      const exports = await import(pathToFileURL(file));
      assert.ok(Object.keys(exports).length > 0, `${task}: ${implementationPath} exposes no contract`);
    }
  }
}

for (const [bookText, taskTests] of Object.entries(BOOK_TESTS)) {
  const book = Number(bookText);
  const receipt = JSON.parse(readFileSync(resolve(ROOT, `qualification/book-${book}.json`), 'utf8'));
  test(`Book ${book} uses qualification v2 source accounting`, () => {
    assert.equal(receipt.schemaVersion, 2);
    assert.equal(receipt.decision, 'SOURCE_IMPLEMENTED');
    assert.deepEqual(receipt.sourceAccounting, {
      implemented: receipt.expectedTaskCount,
      mapped: 0,
      sourceBlocked: 0,
    });
  });

  for (const task of receipt.tasks) {
    test(`${task.id} has executable source plus task-level test evidence`, async () => {
      assert.equal(task.status, 'implemented', `${task.id}: source is still ${task.status}`);
      const focusedTest=task.evidence?.test;
      assert.ok(focusedTest?.path&&focusedTest?.assertion,`${task.id}: no task-owned behavioral assertion is mapped`);
      const tests = [SELF, focusedTest.path];
      for (const testPath of tests) {
        const absolute = resolve(ROOT, testPath);
        assert.ok(existsSync(absolute), `${task.id}: missing test ${testPath}`);
        assert.ok(statSync(absolute).size > 0, `${task.id}: empty test ${testPath}`);
      }
      assert.ok(readFileSync(resolve(ROOT,focusedTest.path),'utf8').includes(focusedTest.assertion),`${task.id}: focused assertion is absent`);
      const implementations = (task.evidence?.implementation ?? []).map(({path})=>path);
      assert.ok(implementations.length > 0, `${task.id}: no implementation evidence`);
      for (const path of implementations) await assertSourceLoads(task.id, path);
    });
  }
}
