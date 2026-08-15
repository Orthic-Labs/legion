import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { pathMatches } from './preeffect-gate.mjs';

function command(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalAdoptionProjection(value) {
  if (Array.isArray(value)) return value.map(canonicalAdoptionProjection);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalAdoptionProjection(value[key])]));
}

function adoptionLedgerProjection(ledger) {
  return canonicalAdoptionProjection({
    schema: ledger.schema,
    ledger_version: ledger.ledger_version,
    acceptance_fingerprint: ledger.acceptance_fingerprint,
    frozen_at: ledger.frozen_at,
    stages: (ledger.stages ?? []).map((stage) => ({
      stage_id: stage.stage_id,
      owner: stage.owner,
      required_items: (stage.required_items ?? []).map((item) => ({
        acceptance_id: item.acceptance_id,
        outcome: item.outcome,
        producer: item.producer,
        observable_surface: item.observable_surface,
        verification_method: item.verification_method,
      })),
    })),
    consumption_dependencies: ledger.consumption_dependencies ?? [],
  });
}

function substantiveS11Projection(evidence) {
  const projected = structuredClone(evidence);
  if (projected.verification) delete projected.verification.oracle_admission;
  if (projected.contract_lifecycle) delete projected.contract_lifecycle.current_admission;
  if (projected.integrated_state) delete projected.integrated_state.adoption_state;
  return canonicalAdoptionProjection(projected);
}

function indexGitlink(repository, path) {
  const row = command(repository, ['ls-files', '--stage', '--', path]).trim();
  const match = /^160000 ([0-9a-f]{40}) 0\t/.exec(row);
  if (!match) throw new TypeError(`staged gitlink unavailable: ${path}`);
  return match[1];
}

/**
 * Carrier-stable formal-adoption identity. It binds substantive source &
 * acceptance definitions while deliberately excluding only fields Arcane
 * derives during admission. Unrelated root worktree/index entries cannot
 * alter this projection.
 */
export function adoptionIntegratedState({ parentRepository, legionRepository, ledgerPath, skillArchitecturePath, s11EvidencePath, legionMount = 'legion' }) {
  try {
    const parent = realpathSync(parentRepository);
    const legion = realpathSync(legionRepository);
    const projection = canonicalAdoptionProjection({
      kind: 'adoption-state-v1',
      legionCommit: command(legion, ['rev-parse', 'HEAD']).trim(),
      parentGitlink: indexGitlink(parent, legionMount),
      ledger: adoptionLedgerProjection(JSON.parse(readFileSync(ledgerPath, 'utf8'))),
      skillArchitecture: `sha256:${sha256(readFileSync(skillArchitecturePath))}`,
      s11Evidence: substantiveS11Projection(JSON.parse(readFileSync(s11EvidencePath, 'utf8'))),
    });
    return `adoption-state-v1:${sha256(JSON.stringify(projection))}`;
  } catch { return null; }
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
