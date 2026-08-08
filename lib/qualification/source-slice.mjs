import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const BLOB_OID = /^[0-9a-f]{40}$/;
const MISSING_REASONS = new Set(['source-path-missing', 'source-path-not-found']);

function gitBlobOid(file, repositoryRoot) {
  return execFileSync('git', ['hash-object', file], {
    cwd: repositoryRoot, encoding: 'utf8', windowsHide: true,
  }).trim();
}

function sourceRecordBlockers(record, index, repositoryRoot) {
  const path = typeof record?.path === 'string' ? record.path.trim() : '';
  const blockers = [];
  const add = (reason, details = {}) => blockers.push({ index, path: path || null, reason, ...details });
  if (!record || typeof record !== 'object' || Array.isArray(record)) add('source-record-invalid');
  if (record?.status !== 'mapped') add('source-status-not-mapped', { status: record?.status ?? null });
  if (!path) add('source-path-missing');
  let file = null;
  if (path) {
    if (isAbsolute(path)) {
      add('source-path-not-relative');
    } else {
      file = resolve(repositoryRoot, path);
      const contained = relative(repositoryRoot, file);
      if (contained.startsWith(`..${sep}`) || isAbsolute(contained)) {
        add('source-path-outside-root');
        file = null;
      } else if (!existsSync(file)) {
        add('source-path-not-found');
        file = null;
      } else if (!lstatSync(file).isFile()) {
        add('source-path-not-regular-file');
        file = null;
      } else {
        const realFile = realpathSync(file);
        const realContained = relative(repositoryRoot, realFile);
        if (realContained.startsWith(`..${sep}`) || isAbsolute(realContained)) {
          add('source-path-outside-root');
          file = null;
        } else {
          file = realFile;
        }
      }
    }
  }
  if (!BLOB_OID.test(record?.currentBlob ?? '')) {
    add('current-blob-oid-invalid');
  } else if (file) {
    const actualBlob = gitBlobOid(file, repositoryRoot);
    if (record.currentBlob !== actualBlob) add('current-blob-oid-mismatch', { actualBlob });
  }
  return blockers;
}

export function sourceSliceQualification({ book, expectedTaskCount, tasks = [], checks = [], blockers = [], sourceRecords = [], root = process.cwd() } = {}) {
  if (!Number.isInteger(expectedTaskCount) || expectedTaskCount < 1) throw new Error('expectedTaskCount must be a positive integer');
  if (tasks.length !== expectedTaskCount) throw new Error(`book ${book} task accounting mismatch: expected ${expectedTaskCount}, received ${tasks.length}`);
  const taskIds = new Set();
  for (const task of tasks) {
    if (!task?.id || taskIds.has(task.id)) throw new Error(`book ${book} task id missing or duplicated`);
    if (!['implemented', 'mapped', 'blocked'].includes(task.status)) throw new Error(`book ${book} invalid task status: ${task.status}`);
    taskIds.add(task.id);
  }
  const records = Array.isArray(sourceRecords) ? sourceRecords : [sourceRecords];
  const repositoryRoot = records.length ? realpathSync(resolve(root)) : null;
  const sourceBlockers = records.flatMap((record, index) => sourceRecordBlockers(record, index, repositoryRoot));
  const blockedIndexes = new Set(sourceBlockers.map((blocker) => blocker.index));
  const missingIndexes = new Set(sourceBlockers.filter((blocker) => MISSING_REASONS.has(blocker.reason)).map((blocker) => blocker.index));
  const sourceCompletion = records.length ? {
    total: records.length,
    mapped: records.length - blockedIndexes.size,
    blocked: blockedIndexes.size,
    missing: missingIndexes.size,
  } : null;
  const sourceBlocked = sourceBlockers.length > 0;
  const decision = tasks.some((task) => task.status === 'blocked') || sourceBlocked ? 'BLOCKED' : 'SOURCE_COMPLETE';
  return { schemaVersion: 1, kind: 'nemesis-book-qualification', book, expectedTaskCount, decision,
    claimLevel: 'source', tasks, checks, blockers, externalGates: blockers.map((blocker) => blocker.id), receiptType: 'source-slice',
    ...(sourceCompletion ? { sourceCompletion } : {}), ...(sourceBlockers.length ? { sourceBlockers } : {}) };
}
