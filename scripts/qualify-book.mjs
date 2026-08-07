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
  2: ['tests', 'tests/platform'],
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
  const prefixes = book === 1
    ? ['core-', 'artifact-', 'config.', 'provider-', 'schema-', 'cli.']
    : ['core-foundations.', 'platform/'];
  return [...new Set(candidates.filter((path) => prefixes.some((prefix) => relative(join(root, 'tests'), path).startsWith(prefix))))]
    .sort((left, right) => left.localeCompare(right));
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export async function qualifyBook(book, { root = ROOT, execute = true } = {}) {
  const tests = await discoverBookTests(book, root);
  const command = [process.execPath, '--test', ...tests];
  const result = execute ? spawnSync(command[0], command.slice(1), { cwd: root, encoding: 'utf8' }) : { status: null, stdout: '', stderr: '' };
  const receipt = {
    schemaVersion: 1,
    kind: 'nemesis-book-gate-receipt',
    book,
    tests: tests.map((path) => relative(root, path).replaceAll('\\', '/')),
    command: command.map((part) => part === process.execPath ? 'node' : part),
    status: execute ? (result.status === 0 ? 'pass' : 'fail') : 'planned',
    outputDigest: execute ? digest(`${result.stdout}\n${result.stderr}`) : null,
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
  if (!Number.isInteger(book) || !BOOK_TEST_ROOTS[book]) throw new Error('usage: qualify-book.mjs --book 1|2');
  const receipt = await qualifyBook(book);
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
  process.exitCode = receipt.status === 'pass' ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
