// Resolve `git rev-parse HEAD` for a workspace without spawning git on the hot
// path. `resolveSourceRevision` ran `spawnSync('git', ...)` on every hook event
// that lacked a sourceRevision — measured at ~66ms per event, a large share of
// a single hook invocation's cost. HEAD only moves on commit/checkout, and git
// resolves it from files under the git directory, so the common cases are pure
// fs reads.
//
// Correctness is preserved by construction: this returns exactly the SHA git
// would, or delegates to the caller's subprocess fallback for any layout it does
// not recognize. It never guesses. A wrong-but-plausible revision in the ledger
// would be worse than the honest null the fallback already yields, so anything
// ambiguous returns `undefined` to mean "not resolved — use the fallback",
// distinct from `null` which the fallback owns.
import { readFileSync, existsSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve, dirname } from 'node:path';

const SHA = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/; // sha1 or sha256 object ids

// `.git` is a directory in a normal checkout, or a `gitdir: <path>` pointer file
// in a worktree or submodule. Resolve to the actual git directory.
function gitDir(workspace) {
  const dotGit = join(workspace, '.git');
  if (!existsSync(dotGit)) return undefined;
  const st = statSync(dotGit);
  if (st.isDirectory()) return dotGit;
  if (st.isFile()) {
    const text = readFileSync(dotGit, 'utf8').trim();
    const m = /^gitdir:\s*(.+)$/.exec(text);
    if (!m) return undefined;
    const target = m[1].trim();
    return isAbsolute(target) ? target : resolve(workspace, target);
  }
  return undefined;
}

// For a worktree/submodule the refs live in the common dir, not the per-worktree
// git dir. `commondir` names it when present; otherwise refs are local.
function commonDir(gd) {
  const cd = join(gd, 'commondir');
  if (!existsSync(cd)) return gd;
  const rel = readFileSync(cd, 'utf8').trim();
  return isAbsolute(rel) ? rel : resolve(gd, rel);
}

function readPackedRef(commonGitDir, ref) {
  const packed = join(commonGitDir, 'packed-refs');
  if (!existsSync(packed)) return undefined;
  for (const line of readFileSync(packed, 'utf8').split(/\r?\n/)) {
    if (!line || line.startsWith('#') || line.startsWith('^')) continue;
    const sp = line.indexOf(' ');
    if (sp === -1) continue;
    const sha = line.slice(0, sp).trim();
    const name = line.slice(sp + 1).trim();
    if (name === ref && SHA.test(sha)) return sha;
  }
  return undefined;
}

/**
 * The SHA at HEAD via fs only, or `undefined` when the layout is not one this
 * resolver handles (the caller should then use its git-subprocess fallback).
 * Never returns a fabricated value.
 */
export function resolveSourceRevisionFs(workspace) {
  if (typeof workspace !== 'string' || workspace.length === 0) return undefined;
  let gd;
  try { gd = gitDir(workspace); } catch { return undefined; }
  if (!gd) return undefined;
  try {
    const headPath = join(gd, 'HEAD');
    if (!existsSync(headPath)) return undefined;
    const head = readFileSync(headPath, 'utf8').trim();
    // Detached HEAD: the file is the object id itself.
    if (SHA.test(head)) return head;
    const m = /^ref:\s*(.+)$/.exec(head);
    if (!m) return undefined;
    const ref = m[1].trim();
    const common = commonDir(gd);
    // A loose ref file wins over packed-refs, matching git.
    const loose = join(common, ref);
    if (existsSync(loose)) {
      const sha = readFileSync(loose, 'utf8').trim();
      return SHA.test(sha) ? sha : undefined;
    }
    return readPackedRef(common, ref);
  } catch {
    return undefined;
  }
}
