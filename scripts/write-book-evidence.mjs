import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {currentSourceRevision}from '../lib/qualification/source-revision.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const book = Number(process.argv[process.argv.indexOf('--book') + 1]);
if (!Number.isInteger(book) || book < 1 || book > 3) throw new Error('usage: write-book-evidence.mjs --book 1|2|3');
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const describe = (path) => {
  const bytes = readFileSync(resolve(root, path));
  return { path, digest: sha256(bytes), bytes: bytes.byteLength };
};
const receiptPath = `qualification/book-${book}.json`;
const gatePath = `qualification/book-${book}-artifacts/gate-result.json`;
const receipt = JSON.parse(readFileSync(resolve(root, receiptPath), 'utf8'));
const gate = JSON.parse(readFileSync(resolve(root, gatePath), 'utf8'));
const rawLogs = receipt.checks.map(({ log }) => describe(log));
const qualificationLogs = [
  `qualification/evidence/source-completion/S2-book-${book}.qualification.red.log`,
  `qualification/evidence/source-completion/S2-book-${book}.qualification.green.log`,
  `qualification/evidence/source-completion/S2-book-${book}.gate.corrected.log`
].flatMap((path) => { try { return [describe(path)]; } catch { return []; } });

const evidence = {
  schemaVersion: 3,
  kind: 'nemesis-source-completion-book-evidence',
  routeStep: 'R_INCREMENTAL_BOOK_GATES/S2',
  book,
  sourceRevision: currentSourceRevision(root),
  sourceAccounting: receipt.sourceAccounting,
  decision: gate.status === 'pass' && receipt.decision === 'SOURCE_IMPLEMENTED' ? 'PASS' : 'BLOCKED',
  commands: receipt.checks.map(({ command, status, counts, log }) => ({ command, status, counts, log })),
  qualification: { command: `node scripts/qualify-book.mjs --book ${book}`, status: gate.status, outputDigest: gate.outputDigest, receipt: gatePath },
  taskMap: receipt.tasks.map(({ id, dependsOn, evidence: taskEvidence }) => ({
    task: id,
    dependsOn,
    test: { path: taskEvidence.test.path, assertion: taskEvidence.test.assertion },
    implementation: taskEvidence.implementation.map(({ path, symbol }) => ({ path, symbol })),
    red: taskEvidence.proof.red.path,
    green: taskEvidence.proof.green.path
  })),
  artifacts: [describe(receiptPath), describe(gatePath), describe('schemas/qualification/book-qualification-v2.schema.json'), describe('scripts/qualify-book.mjs'), describe('lib/qualification/book-receipt.mjs'), ...rawLogs, ...qualificationLogs],
  externalBlockers: receipt.blockers
};
writeFileSync(resolve(root, `qualification/evidence/source-completion/S2-book-${book}.json`), `${JSON.stringify(evidence, null, 2)}\n`);
