import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { pathMatches } from './preeffect-gate.mjs';

function command(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1 << 28 });
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Converts a host path to its canonical repository-relative representation.
 * Paths that resolve outside `cwd` are deliberately unmatchable.
 */
export function repositoryRelative(target, cwd) {
  const value = String(target).replaceAll('\\', '/');
  if (value.split('/').includes('..') && !value.startsWith('/')) return null;
  const root = realpathSync(cwd);
  const resolved = resolve(root, value);
  const local = relative(root, resolved).replaceAll('\\', '/');
  if (local === '' || local === '..' || local.startsWith('../') || local.split('/').includes('..')) return null;
  return local;
}

function scopedUntracked(cwd, scope) {
  return command(cwd, ['ls-files', '--others', '--exclude-standard'])
    .split('\n')
    .filter((file) => file && scope.some((pattern) => pathMatches(pattern, file)))
    .sort()
    .map((file) => `${file}\0${sha256(readFileSync(resolve(cwd, file)))}`)
    .join('\n');
}

function repositoryState(cwd, scope = []) {
  const root = realpathSync(command(cwd, ['rev-parse', '--show-toplevel']).trim());
  const tree = command(root, ['rev-parse', 'HEAD^{tree}']).trim();
  const diff = command(root, ['diff', '--binary', 'HEAD']);
  // Git's parent diff records a gitlink's committed revision but not every
  // working-tree change beneath it. Porcelain with submodules enabled binds
  // nested dirty/untracked state as well.
  const status = command(root, ['status', '--porcelain=v1', '--untracked-files=no', '--ignore-submodules=none']);
  return { cwd: root.replaceAll('\\', '/'), state: `git:${tree}:${sha256(`${diff}\n${status}\n${scopedUntracked(root, scope)}`)}` };
}

/** Backwards-compatible one-repository completion identity. */
export function completionIntegratedState(cwd, scope = []) {
  try {
    return repositoryState(cwd, scope).state;
  } catch { return null; }
}

/**
 * Aggregate identity for every delivery repository. Order cannot alter it.
 * Entries are `{ cwd, scope }`; duplicate repositories are rejected as an
 * ambiguous delivery declaration.
 */
export function completionIntegratedStateForRepositories(repositories = []) {
  try {
    const states = repositories.map(({ cwd, scope = [] }) => repositoryState(cwd, scope)).sort((a, b) => a.cwd.localeCompare(b.cwd));
    if (states.some((entry, index) => index && entry.cwd === states[index - 1].cwd)) return null;
    return `git-repositories:${sha256(states.map((entry) => `${entry.cwd}\0${entry.state}`).join('\n'))}`;
  } catch { return null; }
}

export function latestScopedMaterialChange(receiptStore, runId, scope = [], cwd = process.cwd()) {
  return receiptStore.list({ runId }).filter((record) => {
    if (record?.kind !== 'legion-effect-receipt' || !Number.isFinite(Date.parse(record.observedAt))) return false;
    const target = repositoryRelative(record?.observed?.target ?? '', cwd);
    return target !== null && scope.some((pattern) => pathMatches(pattern, target));
  }).map((record) => record.observedAt).sort().at(-1) ?? null;
}
