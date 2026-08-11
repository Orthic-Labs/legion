import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { readJson, verifyReceipt } from './minimize.mjs';

const COMMIT = /\bgit\s+commit\b/i;
const NO_VERIFY = /\bgit\s+commit\b[^\n;&|]*\s--no-verify\b/i;
const GENERATED_LOCK = /(?:^|[\\/])generated-lock\.json$/i;

export function extractDisciplineShellCommand(payload) {
  const command = payload?.command ?? payload?.tool_input?.command;
  return typeof command === 'string' ? command : '';
}

export function generatedLockTargets(payload) {
  const input = payload?.tool_input ?? payload ?? {};
  const targets = [input.file_path, input.path].filter((value) => typeof value === 'string');
  const patch = typeof input.patch === 'string' ? input.patch : (typeof input.input === 'string' ? input.input : '');
  for (const line of patch.split('\n')) {
    const match = line.match(/^\*\*\* (?:Update|Add|Delete) File: (.+)$/);
    if (match) targets.push(match[1].trim());
  }
  return targets.filter((target) => GENERATED_LOCK.test(target));
}

export function preEffectDiscipline(payload, { workspace }) {
  const command = extractDisciplineShellCommand(payload);
  if (NO_VERIFY.test(command)) return { code: 'ARC_EFFECT_CLASS_UNAUTHORIZED', message: 'git commit --no-verify is blocked' };
  const locks = generatedLockTargets(payload);
  if (locks.length > 0) return { code: 'ARC_EFFECT_CLASS_UNAUTHORIZED', message: `generated-lock is write-protected: ${locks[0]}` };
  if (!COMMIT.test(command)) return null;
  const receiptPath = join(workspace, '.audit', 'minimize', 'commit-receipt.json');
  const policyPath = join(workspace, 'tools', 'skills', 'legion', 'packages', 'arcane', 'policy', 'minimize-policy.md');
  const validatorPath = join(workspace, 'tools', 'skills', 'legion', 'packages', 'arcane', 'lib', 'minimize.mjs');
  try {
    if (!existsSync(receiptPath)) throw new Error('commit receipt is missing');
    verifyReceipt(readJson(receiptPath), { policyPath, validatorPath });
    return null;
  } catch (error) {
    return { code: 'ARC_EFFECT_CLASS_UNAUTHORIZED', message: error.message };
  }
}

export function auditSuccessfulCommit(payload, hostEvent, { workspace }) {
  const command = extractDisciplineShellCommand(payload);
  if (!COMMIT.test(command) || hostEvent?.eventType !== 'post-effect' || hostEvent?.result?.outcome !== 'success') return;
  const record = { event: 'git-commit', sessionId: hostEvent.sessionId ?? null, runId: hostEvent.runId ?? null, sourceRevision: hostEvent.sourceRevision ?? null, command: command.slice(0, 500) };
  const audit = join(workspace, '.audit', 'arcane');
  mkdirSync(audit, { recursive: true });
  appendFileSync(join(audit, 'commit-identity.jsonl'), `${JSON.stringify(record)}\n`, { encoding: 'utf8' });
}
