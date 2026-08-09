#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BOOK_TEST_ROOTS = Object.freeze({
  1: ['tests'],
  2: ['tests'],
  3: ['tests'],
  4: ['tests'],
  5: ['tests'],
  6: ['tests'],
});

const BOOK_TEST_PREFIXES = Object.freeze({
  1: [
    'artifact-', 'audit-finalize.', 'audit-verify.', 'cli.', 'config.', 'core-', 'cortex-adapter.',
    'execution-semantics.', 'package-install.', 'provider-', 'schema-',
    'standalone-checkout.', 'book-source-completion.', 'core/', 'skills/', 'distribution/package/', 'qualification/book-1-',
  ],
  2: ['core-foundations.', 'book-source-completion.', 'platform/', 'inventory/', 'controls/', 'qualification/book-2-'],
  3: [
    'coverage-', 'framework-suite.',
    'generic-source-suite.', 'native-family-runner.', 'provider-', 'providers/',
    'reachability.', 'book-source-completion.', 'coverage/', 'qualification/book-3-',
  ],
  4: ['book-source-completion.', 'platform/'],
  5: ['book-source-completion.', 'content-', 'design-', 'visual-'],
  6: ['book-source-completion.', 'report-', 'browser-', 'distribution-'],
});

async function files(root) {
  if (!existsSync(root)) return [];
  const entries = await readdir(root, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) return files(path);
    return entry.isFile() && entry.name.endsWith('.test.mjs') ? [path] : [];
  }));
  return nested.flat();
}

export async function discoverBookTests(book, root = ROOT) {
  if (!BOOK_TEST_ROOTS[book]) throw new Error(`unsupported book: ${book}`);
  const candidates = (await Promise.all(BOOK_TEST_ROOTS[book].map((path) => files(join(root, path))))).flat();
  const prefixes = BOOK_TEST_PREFIXES[book];
  return [...new Set(candidates.filter((path) => {
    const testPath = relative(join(root, 'tests'), path).replaceAll('\\', '/');
    return prefixes.some((prefix) => testPath.startsWith(prefix));
  }))]
    .sort((left, right) => left.localeCompare(right));
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function semanticTestResults(output) { return String(output).split(/\r?\n/).flatMap((line) => { const value=line.trim(); const tap=/^(not ok|ok) \d+ - (.+?)(?: #.*)?$/.exec(value); if(tap)return[{name:tap[2].replace(/ \(.*\)$/,''),status:tap[1]==='ok'?'pass':'fail'}]; const spec=/^([✔✖])\s+(.+?)\s+\([^)]*\)$/.exec(value); return spec?[{name:spec[2],status:spec[1]==='✔'?'pass':'fail'}]:[]; }).sort((a, b) => a.name.localeCompare(b.name)); }
export function qualificationDigest(result) { const semantic = { status: result.status, tests: (result.tests ?? []).map(({ name, status }) => ({ name, status })).sort((a, b) => a.name.localeCompare(b.name)) }; return digest(JSON.stringify(semantic)); }

export async function qualifyBook(book, { root = ROOT, execute = true } = {}) {
  const tests = await discoverBookTests(book, root);
  const command = [process.execPath, '--test', ...tests];
  const result = execute ? spawnSync(command[0], command.slice(1), { cwd: root, encoding: 'utf8' }) : { status: null, stdout: '', stderr: '' };
  const receipt = {
    schemaVersion: 1,
    kind: 'legion-book-gate-receipt',
    book,
    tests: tests.map((path) => relative(root, path).replaceAll('\\', '/')),
    command: command.map((part) => part === process.execPath ? 'node' : part),
    status: execute ? (result.status === 0 ? 'pass' : 'fail') : 'planned',
    outputDigest: execute ? qualificationDigest({ status: result.status === 0 ? 'pass' : 'fail', tests: semanticTestResults(`${result.stdout}\n${result.stderr}`) }) : null,
  };
  if (execute) {
    const path = join(root, 'qualification', `book-${book}-artifacts`, 'gate-result.json');
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`);
  }
  return receipt;
}

async function main() {
  const index = process.argv.indexOf('--book');
  const book = index === -1 ? NaN : Number(process.argv[index + 1]);
  if (!Number.isInteger(book) || !BOOK_TEST_ROOTS[book]) throw new Error('usage: qualify-book.mjs --book 1|2|3|4|5|6');
  const receipt = await qualifyBook(book);
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
  process.exitCode = receipt.status === 'pass' ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
