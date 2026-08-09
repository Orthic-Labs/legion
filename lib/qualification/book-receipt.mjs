import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateSchema } from './schema-validator.mjs';
import { currentSourceRevision } from './source-revision.mjs';

const TASK_STATES = new Set(['implemented', 'mapped', 'source-blocked']);
const V1_DECISIONS = new Set(['QUALIFIED', 'SOURCE_COMPLETE', 'BLOCKED']);
const schemaV2 = JSON.parse(readFileSync(new URL('../../schemas/qualification/book-qualification-v2.schema.json', import.meta.url), 'utf8'));
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function validateFileRecord(record, { root, taskId, kind, needle }) {
  const issues = [];
  const path = resolve(root, record?.path ?? '');
  if (!record?.path || !existsSync(path)) return [`${taskId}:${kind}:absent:${record?.path ?? ''}`];
  const bytes = readFileSync(path);
  if (record.bytes !== bytes.byteLength) issues.push(`${taskId}:${kind}:bytes-mismatch`);
  if (record.digest !== digest(bytes)) issues.push(`${taskId}:${kind}:digest-mismatch`);
  if (needle && !bytes.toString('utf8').includes(needle)) issues.push(`${taskId}:${kind}:${kind === 'test' ? 'assertion' : 'symbol'}-absent`);
  return issues;
}
function summary(bytes){const text=bytes.toString('utf8');const pick=(name)=>Number(new RegExp(`(?:ℹ|#) ${name} (\\d+)`).exec(text)?.[1]??NaN);return{total:pick('tests'),pass:pick('pass'),fail:pick('fail')};}
function assertionStatus(text, assertion){for(const line of String(text).split(/\r?\n/)){if(!line.includes(assertion))continue;const value=line.trim();if(value.startsWith('✔ ')||/^ok \d+ - /.test(value))return'pass';if(value.startsWith('✖ ')||/^not ok \d+ - /.test(value))return'fail';}return null;}

function validateV1(receipt, root) {
  const issues = [];
  if (!V1_DECISIONS.has(receipt?.decision)) issues.push('invalid-decision');
  for (const task of receipt?.tasks ?? []) {
    if ((!Array.isArray(task.evidence) || task.evidence.length === 0) && !task.mapping?.trim()) issues.push(`${task.id}:missing-evidence`);
    for (const path of task.evidence ?? []) if (!existsSync(resolve(root, path))) issues.push(`${task.id}:absent:${path}`);
  }
  return issues;
}

export function validateBookReceipt(receipt, { root = process.cwd(), sourceRevision } = {}) {
  const issues = [];
  const version = receipt?.schemaVersion;
  if (![1, 2].includes(version) || receipt?.kind !== 'legion-book-qualification') issues.push('invalid-contract');
  if (!Number.isInteger(receipt?.book) || receipt.book < 1 || receipt.book > 8) issues.push('invalid-book');
  if (version === 1) issues.push(...validateV1(receipt, root));
  if (version === 2) issues.push(...validateSchema(schemaV2, receipt));

  const tasks = receipt?.tasks ?? [];
  const expected = Array.from({ length: receipt?.expectedTaskCount ?? 0 }, (_, index) => `B${receipt.book}-${String(index + 1).padStart(3, '0')}`);
  const ids = tasks.map((task) => task.id);
  if (new Set(ids).size !== ids.length) issues.push('duplicate-task');
  if (JSON.stringify(ids) !== JSON.stringify(expected)) issues.push('task-denominator-mismatch');

  for (const [index, task] of tasks.entries()) {
    if (!TASK_STATES.has(task.status) && version === 2) issues.push(`${task.id}:invalid-status`);
    if (version !== 2) continue;
    const seenDependencies = new Set();
    for (const dependency of task.dependsOn ?? []) {
      if (seenDependencies.has(dependency)) issues.push(`${task.id}:duplicate-dependency:${dependency}`);
      seenDependencies.add(dependency);
      const dependencyIndex = ids.indexOf(dependency);
      const dependencyBook=Number(/^B(\d+)-/.exec(dependency)?.[1]);
      if (dependencyIndex === -1 && dependencyBook >= receipt.book) issues.push(`${task.id}:unknown-dependency:${dependency}`);
      else if (dependencyIndex >= index) issues.push(`${task.id}:forward-dependency:${dependency}`);
    }
    const evidence = task.evidence;
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) continue;
    issues.push(...validateFileRecord(evidence.test, { root, taskId: task.id, kind: 'test', needle: evidence.test?.assertion }));
    for (const implementation of evidence.implementation ?? []) {
      issues.push(...validateFileRecord(implementation, { root, taskId: task.id, kind: 'implementation', needle: implementation.symbol }));
    }
    for (const color of ['red', 'green']) {
      if (evidence.proof?.[color]) {const proof=evidence.proof[color];issues.push(...validateFileRecord(proof, { root, taskId: task.id, kind: `${color}-proof` }));if(existsSync(resolve(root,proof.path??''))){const observed=summary(readFileSync(resolve(root,proof.path)));if(JSON.stringify(observed)!==JSON.stringify(proof.counts))issues.push(`${task.id}:${color}-proof:tap-counts-mismatch`);const text=readFileSync(resolve(root,proof.path),'utf8');const status=assertionStatus(text,evidence.test?.assertion);if(!status)issues.push(`${task.id}:${color}-proof:task-assertion-absent`);else if(status!==(color==='red'?'fail':'pass'))issues.push(`${task.id}:${color}-proof:task-assertion-${color==='red'?'not-failed':'not-passed'}`);}}
    }
  }

  const counts = {
    implemented: tasks.filter((task) => task.status === 'implemented').length,
    mapped: tasks.filter((task) => task.status === 'mapped').length,
    sourceBlocked: tasks.filter((task) => task.status === 'source-blocked').length,
  };
  if (version === 2) {
    const observedSourceRevision=currentSourceRevision(root);
    if (receipt.sourceRevision !== observedSourceRevision) issues.push('source-revision-mismatch');
    if (JSON.stringify(receipt.sourceAccounting) !== JSON.stringify(counts)) issues.push('source-accounting-mismatch');
    if (receipt.decision === 'SOURCE_IMPLEMENTED' && (counts.mapped !== 0 || counts.sourceBlocked !== 0)) issues.push('source-implemented-with-source-gaps');
    for (const check of receipt.checks ?? []) {issues.push(...validateFileRecord({ path: check.log, digest: check.digest, bytes: check.bytes }, { root, taskId: check.id, kind: 'check-log' }));if(existsSync(resolve(root,check.log??''))&&JSON.stringify(summary(readFileSync(resolve(root,check.log))))!==JSON.stringify(check.counts))issues.push(`${check.id}:tap-counts-mismatch`);}
  }
  return { valid: issues.length === 0, issues: [...new Set(issues)], taskCount: tasks.length, sourceAccounting: counts };
}

export function loadBookReceipt(path, options) {
  return validateBookReceipt(JSON.parse(readFileSync(path, 'utf8')), options);
}
