import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';

function refuse(code, message) { const error = new Error(message); error.code = code; throw error; }
function git(cwd, args, env) {
  try { return execFileSync('git', args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { refuse('ARC_DELIVERY_GIT_INVALID', `Git delivery check failed: ${args.join(' ')}`); }
}
function succeeds(cwd, args) { try { execFileSync('git', args, { cwd, stdio: 'ignore' }); return true; } catch { return false; } }
function snapshot(root, head) {
  const index = join(tmpdir(), `arcane-delivery-${randomBytes(12).toString('hex')}.index`);
  try {
    const env = { ...process.env, GIT_INDEX_FILE: index };
    git(root, ['read-tree', head], env); git(root, ['add', '-A'], env);
    // Guard state is not task output. Resetting only its reserved path edits
    // temporary index, never caller index or worktree.
    git(root, ['reset', '--', '.audit/arcane'], env);
    return git(root, ['write-tree'], env);
  }
  finally { try { unlinkSync(index); } catch {} }
}
function common(root) { return resolve(root, git(root, ['rev-parse', '--git-common-dir'])); }
function primary(root, commonDir) {
  const blocks = git(root, ['worktree', 'list', '--porcelain']).split('\n\n').filter(Boolean);
  for (const block of blocks) {
    const fields = Object.fromEntries(block.split('\n').map((line) => { const i = line.indexOf(' '); return [line.slice(0, i), line.slice(i + 1)]; }));
    if (!fields.worktree) continue;
    try {
      const canonicalRoot = resolve(git(resolve(fields.worktree), ['rev-parse', '--show-toplevel']));
      if (common(canonicalRoot) !== commonDir) continue;
      const ref = git(canonicalRoot, ['symbolic-ref', '-q', 'HEAD']);
      if (!fields.branch?.startsWith('refs/heads/') || ref !== fields.branch) refuse('ARC_DELIVERY_CANONICAL_REF_INVALID', 'primary worktree must use one matching local branch');
      return { root: canonicalRoot, ref };
    } catch (error) {
      if (error.code === 'ARC_DELIVERY_CANONICAL_REF_INVALID') throw error;
      refuse('ARC_DELIVERY_CANONICAL_REF_INVALID', 'primary worktree identity is unavailable');
    }
  }
  refuse('ARC_DELIVERY_CANONICAL_REF_INVALID', 'primary worktree is unavailable');
}
function parent(root) {
  for (let cursor = dirname(root); cursor !== dirname(cursor); cursor = dirname(cursor)) {
    if (!succeeds(cursor, ['rev-parse', '--is-inside-work-tree'])) continue;
    const parentRoot = resolve(git(cursor, ['rev-parse', '--show-toplevel']));
    if (parentRoot === root) continue;
    const path = relative(parentRoot, root).replaceAll('\\', '/'); const ref = primary(parentRoot, common(parentRoot)).ref;
    const entry = git(parentRoot, ['ls-tree', ref, '--', path]).split('\n').find((line) => line.startsWith('160000 '));
    if (entry) return { root: parentRoot, path, ref };
  }
  return null;
}
function leasePath(repo) { return join(repo.primaryRoot, '.audit', 'arcane', 'delivery', 'lease.json'); }
function acquisitionPath(repo) { return join(repo.primaryRoot, '.audit', 'arcane', 'delivery', 'acquisitions', `${repo.acquisitionKey}.json`); }
function metadata(repo) { const { leaseToken, acquisitionKey, reused, ...value } = repo; return value; }
function acquisitionKey(owner, commonDir) { return createHash('sha256').update(`${owner.sessionId}\0${owner.runId}\0${owner.taskId}\0${commonDir}`).digest('hex'); }
function sameOwner(record, owner, mode) {
  const actual = mode === 'read-only' ? record?.owner : record;
  return actual?.sessionId === owner?.sessionId && actual?.runId === owner?.runId && actual?.taskId === owner?.taskId;
}

// A first-fix owner may repair local implementation under a canonical owner's
// standing ownership. This is a disposition only; it neither changes leases nor
// rewrites the canonical owner.
export function admitLocalRepair({ firstFixOwner, canonicalOwner, requester, repairScope = [] } = {}) {
  const scope = Array.isArray(repairScope) ? repairScope : [];
  if (!firstFixOwner || !canonicalOwner || !requester) {
    return Object.freeze({ outcome: 'LOCAL_REPAIR_DENIED', code: 'ARC_OWNERSHIP_DISPOSITION_INVALID', canonicalOwner: canonicalOwner ?? null, repairScope: Object.freeze(scope) });
  }
  if (requester !== firstFixOwner && requester !== canonicalOwner) {
    return Object.freeze({ outcome: 'LOCAL_REPAIR_DENIED', code: 'ARC_FIRST_FIX_OWNER_REQUIRED', canonicalOwner, repairScope: Object.freeze(scope) });
  }
  return Object.freeze({ outcome: 'LOCAL_REPAIR_PERMITTED', firstFixOwner, canonicalOwner, requester, repairScope: Object.freeze(scope), canonicalOwnershipRewrite: false });
}
function release(repo, owner, recovery = false) {
  if (repo.mode === 'read-only') { const path = acquisitionPath(repo); if (!existsSync(path)) { if (recovery) return; refuse('ARC_DELIVERY_ACQUISITION_MISSING', 'read-only acquisition is missing'); } const acquisition = JSON.parse(readFileSync(path, 'utf8')); if (!sameOwner(acquisition, owner, repo.mode) || acquisition.token !== repo.leaseToken) refuse('ARC_DELIVERY_OWNER_MISMATCH', 'delivery acquisition owner differs'); unlinkSync(path); return; }
  const path = leasePath(repo);
  if (!existsSync(path)) { if (recovery) return; refuse('ARC_DELIVERY_LEASE_MISSING', 'delivery lease is missing before terminal receipt'); }
  const lease = JSON.parse(readFileSync(path, 'utf8'));
  if (!sameOwner(lease, owner, repo.mode) || lease.token !== repo.leaseToken) refuse('ARC_DELIVERY_OWNER_MISMATCH', 'delivery lease owner differs');
  unlinkSync(path);
}
function inspect(path, mode, owner) {
  const root = resolve(git(path, ['rev-parse', '--show-toplevel'])); const commonDir = common(root); const main = primary(root, commonDir); const head = git(root, ['rev-parse', 'HEAD']);
  if (mode === 'read-only') {
    const key = acquisitionKey(owner, commonDir); const path = join(main.root, '.audit', 'arcane', 'delivery', 'acquisitions', `${key}.json`); mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      try { const old = JSON.parse(readFileSync(path, 'utf8')); if (old.owner?.sessionId === owner.sessionId && old.owner?.runId === owner.runId && old.owner?.taskId === owner.taskId && old.metadata?.root === root && old.metadata?.commonDir === commonDir && old.metadata?.primaryRoot === main.root && old.metadata?.canonicalRef === main.ref) return { ...old.metadata, leaseToken: old.token, acquisitionKey: key, reused: true }; } catch {}
      refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'read-only acquisition owner differs');
    }
    const repo = { root, commonDir, primaryRoot: main.root, canonicalRef: main.ref, head, snapshotTree: snapshot(root, head), mode, parent: parent(main.root), leaseToken: randomBytes(32).toString('hex'), acquisitionKey: key };
    writeFileSync(path, JSON.stringify({ owner, token: repo.leaseToken, metadata: metadata(repo) }), { encoding: 'utf8', flag: 'wx' }); return repo;
  }
  const target = leasePath({ primaryRoot: main.root }); mkdirSync(dirname(target), { recursive: true });
  if (existsSync(target)) {
    try {
      const old = JSON.parse(readFileSync(target, 'utf8'));
      if (old.sessionId === owner.sessionId && old.runId === owner.runId && old.taskId === owner.taskId && old.metadata?.root === root && old.metadata?.commonDir === commonDir && old.metadata?.primaryRoot === main.root && old.metadata?.canonicalRef === main.ref) return { ...old.metadata, leaseToken: old.token, reused: true };
    } catch {}
    refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'another run owns repository integration');
  }
  const repo = { root, commonDir, primaryRoot: main.root, canonicalRef: main.ref, head, snapshotTree: snapshot(root, head), mode, parent: parent(main.root), leaseToken: null };
  const lease = { ...owner, repository: root, token: randomBytes(32).toString('hex'), metadata: metadata(repo) };
  try { writeFileSync(target, JSON.stringify(lease), { encoding: 'utf8', flag: 'wx' }); repo.leaseToken = lease.token; }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    try { const old = JSON.parse(readFileSync(target, 'utf8')); if (old.sessionId === owner.sessionId && old.runId === owner.runId && old.taskId === owner.taskId && old.metadata?.root === root && old.metadata?.commonDir === commonDir && old.metadata?.primaryRoot === main.root && old.metadata?.canonicalRef === main.ref) return { ...old.metadata, leaseToken: old.token, reused: true }; } catch {}
    refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'another run owns repository integration');
  }
  return repo;
}
export function openDelivery({ repositories, readOnly, owner, cwd = process.cwd() }) {
  const out = [], seen = new Set();
  try { for (const path of repositories.length ? repositories : [cwd]) { const repo = inspect(path, readOnly ? 'read-only' : 'write', owner); if (!seen.has(repo.commonDir)) { seen.add(repo.commonDir); out.push(repo); } } return { repositories: out }; }
  catch (error) { for (const repo of out.filter((repo) => !repo.reused)) try { release(repo, owner); } catch {} throw error; }
}
export function validateDeliveryReuse({ delivery, repositories, readOnly, owner, cwd = process.cwd() }) {
  const requested = new Map();
  for (const path of repositories.length ? repositories : [cwd]) {
    const root = resolve(git(path, ['rev-parse', '--show-toplevel']));
    const commonDir = common(root);
    requested.set(commonDir, { root, mode: readOnly ? 'read-only' : 'write' });
  }
  if (requested.size !== delivery.repositories.length) refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'requested repository set differs from active delivery');
  for (const repo of delivery.repositories) {
    const requestedRepo = requested.get(repo.commonDir);
    if (!requestedRepo || requestedRepo.root !== repo.root || requestedRepo.mode !== repo.mode) refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'requested repository set differs from active delivery');
    if (repo.mode === 'write') {
      try { const lease = JSON.parse(readFileSync(leasePath(repo), 'utf8')); if (lease.sessionId !== owner.sessionId || lease.runId !== owner.runId || lease.taskId !== owner.taskId || lease.token !== repo.leaseToken) refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'active delivery lease owner differs'); }
      catch (error) { if (error.code === 'ARC_INTEGRATION_OWNER_CONFLICT') throw error; refuse('ARC_INTEGRATION_OWNER_CONFLICT', 'active delivery lease is unavailable'); }
    }
  }
  return delivery;
}
export function validateDeliveryAuthority(delivery, { recovery = false, owner } = {}) {
  for (const repo of delivery.repositories) {
    const path = repo.mode === 'write' ? leasePath(repo) : acquisitionPath(repo);
    let authority;
    try { authority = JSON.parse(readFileSync(path, 'utf8')); } catch { if (recovery && !existsSync(path)) continue; refuse('ARC_DELIVERY_ACQUISITION_MISSING', 'delivery acquisition record is unavailable'); }
    if (!sameOwner(authority, owner, repo.mode)) refuse('ARC_DELIVERY_OWNER_MISMATCH', 'delivery authority owner differs');
    if (authority.token !== repo.leaseToken || JSON.stringify(authority.metadata) !== JSON.stringify(metadata(repo))) refuse('ARC_DELIVERY_METADATA_MISMATCH', 'routing binding differs from delivery acquisition authority');
  }
  return delivery;
}
export function authoritiesAbsent(delivery) { return delivery.repositories.every((repo) => !existsSync(repo.mode === 'write' ? leasePath(repo) : acquisitionPath(repo))); }
const archiveIo = Object.freeze({
  exists: existsSync,
  read: readFileSync,
  write: writeFileSync,
  rename: renameSync,
  hash: (bytes) => createHash('sha256').update(bytes).digest('hex'),
});
function archive(repo, closeTree, io = archiveIo) {
  const bytes = execFileSync('git', ['diff', '--binary', '--full-index', repo.snapshotTree, closeTree], { cwd: repo.root }); const digest = createHash('sha256').update(bytes).digest('hex'); const dir = join(repo.primaryRoot, '.audit', 'arcane', 'delivery', 'patches', 'sha256'); const path = join(dir, `${digest}.patch`); mkdirSync(dir, { recursive: true });
  if (io.exists(path)) { if (io.hash(io.read(path)) !== digest) refuse('ARC_DELIVERY_PATCH_HASH_INVALID', 'archive patch hash differs'); }
  else { const temp = `${path}.${randomBytes(8).toString('hex')}`; io.write(temp, bytes); io.rename(temp, path); }
  return { digest, path };
}
export function prepareClose(delivery, disposition, { owner, io = archiveIo } = {}) {
  validateDeliveryAuthority(delivery, { owner });
  return delivery.repositories.map((repo) => {
    const root = resolve(git(repo.root, ['rev-parse', '--show-toplevel'])); if (root !== repo.root || common(root) !== repo.commonDir) refuse('ARC_DELIVERY_IDENTITY_CHANGED', 'repository identity changed');
    const head = git(root, ['rev-parse', 'HEAD']), closeTree = snapshot(root, head), changed = closeTree !== repo.snapshotTree;
    if (repo.mode === 'read-only' && changed) refuse('ARC_DELIVERY_READ_ONLY_MUTATED', 'read-only repository changed');
    let state = 'clean', reachable = false, parentPinned = null, patch = null;
    if (!changed) {
      state = 'clean';
    } else if (disposition === 'complete') {
      if (closeTree !== git(root, ['rev-parse', 'HEAD^{tree}']) || !succeeds(root, ['merge-base', '--is-ancestor', head, repo.canonicalRef])) refuse('ARC_DELIVERY_NOT_REACHABLE', 'HEAD is not reachable from canonical ref');
      reachable = true; state = 'integrated';
      if (repo.parent) { if (git(repo.parent.root, ['rev-parse', `${repo.parent.ref}:${repo.parent.path}`]) !== head) refuse('ARC_DELIVERY_PARENT_NOT_PINNED', 'parent canonical ref does not pin child'); parentPinned = true; }
    } else { state = 'archived'; patch = archive(repo, closeTree, io); }
    return { repository: root, commonDir: repo.commonDir, baselineTree: repo.snapshotTree, closeTree, canonicalRef: repo.canonicalRef, commit: head, reachable, parentPinned, disposition, state, patch, leaseToken: repo.leaseToken ?? null };
  });
}
export function finalizeClose(delivery, { recovery = false, owner } = {}) {
  validateDeliveryAuthority(delivery, { recovery, owner });
  for (const repo of delivery.repositories) {
    if (repo.mode === 'read-only') continue;
    const path = leasePath(repo);
    if (!existsSync(path)) { if (recovery) continue; refuse('ARC_DELIVERY_LEASE_MISSING', 'delivery lease is missing'); }
    const lease = JSON.parse(readFileSync(path, 'utf8'));
    if (!sameOwner(lease, owner, repo.mode) || lease.token !== repo.leaseToken) refuse('ARC_DELIVERY_OWNER_MISMATCH', 'delivery lease owner differs');
  }
  for (const repo of delivery.repositories) release(repo, owner, recovery);
}
