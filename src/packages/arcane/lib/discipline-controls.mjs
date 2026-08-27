import { appendFileSync, existsSync, mkdirSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';

import { readJson, repositoryRoot, stagedChanges, verifyReceipt } from './minimize.mjs';

const COMMIT = /\bgit(?:\s+-C\s+(?:"[^"]+"|'[^']+'|[^\s;&|]+))?\s+commit\b/i;
const NO_VERIFY = /\bgit(?:\s+-C\s+(?:"[^"]+"|'[^']+'|[^\s;&|]+))?\s+commit\b[^\n;&|]*\s--no-verify\b/i;
const GENERATED_LOCK = /(?:^|[\\/])generated-lock\.json$/i;

function unquote(value) {
  const text = String(value ?? '').trim();
  return (/^(["']).*\1$/.test(text)) ? text.slice(1, -1) : text;
}

export function commitRepository(payload, workspace) {
  const input = payload?.tool_input ?? payload ?? {};
  const command = extractDisciplineShellCommand(payload);
  const base = resolve(workspace, input.workdir ?? input.cwd ?? payload?.cwd ?? '.');
  const gitC = command.match(/\bgit\s+-C\s+("[^"]+"|'[^']+'|[^\s;&|]+)/i);
  return gitC ? resolve(base, unquote(gitC[1])) : base;
}

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

function recordCommitAdvisory(workspace, message) {
  try {
    const audit = join(workspace, '.audit', 'arcane');
    mkdirSync(audit, { recursive: true });
    appendFileSync(join(audit, 'commit-discipline-advisories.jsonl'), `${JSON.stringify({ kind: 'arcane-commit-discipline-advisory', message, observedAt: new Date().toISOString() })}\n`, { encoding: 'utf8' });
  } catch { /* an advisory must never become a commit blocker */ }
}

const canonical = (target) => { try { return realpathSync(target); } catch { return target; } };

function containsPath(root, target) {
  const framed = relative(root, target);
  return framed === '' || (!framed.startsWith('..') && !isAbsolute(framed));
}

export function commitReceiptRequirement({ workspace, repository = workspace, policy, contracted = false }) {
  if (contracted) return { required: true, reason: 'contracted-work', paths: [] };
  if (!policy || policy.failClosed || typeof policy.lockedDomainsFor !== 'function') {
    return { required: false, reason: 'policy-unavailable', paths: [], advisory: 'commit tier could not be classified; ambient commit allowed with advisory' };
  }
  let paths;
  try {
    const requestedRepository = canonical(repository);
    const reportedRoot = canonical(repositoryRoot(repository));
    // Git process state can leak a foreign worktree into rev-parse on hosted
    // Windows runners. Never frame paths from a root that does not contain the
    // repository the caller asked us to inspect.
    const root = containsPath(reportedRoot, requestedRepository) ? reportedRoot : requestedRepository;
    const repositoryPaths = stagedChanges(process.env, repository)
      .flatMap(({ source, path }) => source ? [source, path] : [path]);
    // `repositoryRoot` is canonical (git resolves symlinks) while `workspace`
    // is whatever the caller passed. Relativizing one against the other turns
    // an in-workspace file into a `../..` escape and drops it out of
    // locked-domain matching, so both sides must be canonical.
    const base = canonical(workspace);
    const repositoryPrefix = relative(base, root).replaceAll('\\', '/');
    paths = [...new Set(repositoryPaths.map((path) => [repositoryPrefix, path.replaceAll('\\', '/')].filter(Boolean).join('/')))];
  } catch (error) {
    return { required: false, reason: 'staged-paths-unavailable', paths: [], advisory: `staged paths could not be classified: ${error.message}` };
  }
  const locked = policy.lockedDomainsFor(paths);
  return locked.length > 0
    ? { required: true, reason: 'locked-domain', paths, locked }
    : { required: false, reason: 'ambient', paths };
}

export function preEffectDiscipline(payload, { workspace, policy = null, contracted = false, checkCommit = true }) {
  const command = extractDisciplineShellCommand(payload);
  if (NO_VERIFY.test(command)) return { code: 'ARC_EFFECT_CLASS_UNAUTHORIZED', message: 'git commit --no-verify is blocked' };
  const locks = generatedLockTargets(payload);
  if (locks.length > 0) return { code: 'ARC_EFFECT_CLASS_UNAUTHORIZED', message: `generated-lock is write-protected: ${locks[0]}` };
  if (!COMMIT.test(command) || !checkCommit) return null;
  const requirement = commitReceiptRequirement({ workspace, repository: commitRepository(payload, workspace), policy, contracted });
  if (!requirement.required) {
    if (requirement.advisory) recordCommitAdvisory(workspace, requirement.advisory);
    return null;
  }
  const receiptPath = join(workspace, '.audit', 'minimize', 'commit-receipt.json');
  const policyPath = join(workspace, 'tools', 'skills', 'legion', 'packages', 'arcane', 'policy', 'minimize-policy.md');
  const validatorPath = join(workspace, 'tools', 'skills', 'legion', 'packages', 'arcane', 'lib', 'minimize.mjs');
  try {
    if (!existsSync(receiptPath)) throw new Error('commit receipt is missing');
    verifyReceipt(readJson(receiptPath), { policyPath, validatorPath });
    return null;
  } catch (error) {
    return { code: 'ARC_CLAIM_PREREQUISITE_UNMET', message: error.message };
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
