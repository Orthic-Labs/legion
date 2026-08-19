// Project canonical Legion skill packages into a harness's skill location
// WITHOUT ever forking their contents.
//
// Agent Skills / SKILL.md is the common capability interchange format across
// harnesses. A skill is a directory `skills/<id>/` with a `SKILL.md` and its
// assets; the canonical copy under the Legion package is the only source of
// truth. Projection makes that same package visible where a harness discovers
// skills — by symlink where the platform allows it, and by a byte-identical
// copy only as a fallback. Neither path edits, templates, or regenerates skill
// content: the conformance tests assert byte-identity against the canonical
// source, so a projection that rewrote a SKILL.md would fail.
import { existsSync, mkdirSync, readdirSync, statSync, symlinkSync, rmSync, lstatSync, readlinkSync, cpSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// The canonical skill packages: every skills/<id> that ships a SKILL.md. The
// support directories (_shared, manifests) carry no SKILL.md and are not skills.
export function canonicalSkillIds(legionRoot) {
  const dir = join(legionRoot, 'skills');
  return readdirSync(dir)
    .filter((id) => { try { return statSync(join(dir, id)).isDirectory(); } catch { return false; } })
    .filter((id) => existsSync(join(dir, id, 'SKILL.md')))
    .sort();
}

export function canonicalSkillPath(legionRoot, id) {
  return join(legionRoot, 'skills', id);
}

// Is `linkPath` already a link/copy pointing at (or matching) the canonical
// package? Used by verify() and by idempotent install.
function pointsAtCanonical(linkPath, canonicalPath) {
  try {
    const st = lstatSync(linkPath);
    if (st.isSymbolicLink()) {
      const target = resolve(join(linkPath, '..'), readlinkSync(linkPath));
      // Must match the canonical package AND actually resolve — a link whose
      // target has moved is a health failure, not a healthy projection.
      return resolve(target) === resolve(canonicalPath) && existsSync(join(linkPath, 'SKILL.md'));
    }
    if (st.isDirectory()) {
      // Copy fallback: compare the SKILL.md bytes. A match means the projected
      // copy is the canonical content, not a fork.
      const a = readFileSync(join(linkPath, 'SKILL.md'));
      const b = readFileSync(join(canonicalPath, 'SKILL.md'));
      return a.equals(b);
    }
  } catch { /* missing or unreadable */ }
  return false;
}

/**
 * Project every canonical skill package into `targetDir`. Prefers a relative
 * symlink so the projection tracks the source with zero duplication; falls back
 * to a verbatim copy only when symlinks are unavailable (recorded per skill).
 *
 * @returns {{ targetDir, linked: string[], copied: string[], mode: 'symlink'|'copy'|'mixed' }}
 */
export function projectSkills(legionRoot, targetDir, { copyFallback = true } = {}) {
  mkdirSync(targetDir, { recursive: true });
  const ids = canonicalSkillIds(legionRoot);
  const linked = [];
  const copied = [];
  for (const id of ids) {
    const canonical = canonicalSkillPath(legionRoot, id);
    const dest = join(targetDir, id);
    if (pointsAtCanonical(dest, canonical)) { linked.push(id); continue; }
    if (existsSync(dest) || (() => { try { return Boolean(lstatSync(dest)); } catch { return false; } })()) {
      rmSync(dest, { recursive: true, force: true });
    }
    try {
      // Absolute target: a projection is pinned to a specific canonical Legion
      // checkout, and an absolute link resolves correctly even when an ancestor
      // of targetDir is itself a symlink (a relative link would walk up through
      // the symlink and dangle). If Legion moves, re-run install.
      symlinkSync(resolve(canonical), dest, 'dir');
      linked.push(id);
    } catch (err) {
      if (!copyFallback) throw err;
      // Verbatim copy — byte-identical, never a transform.
      cpSync(canonical, dest, { recursive: true });
      copied.push(id);
    }
  }
  const mode = copied.length === 0 ? 'symlink' : linked.length === 0 ? 'copy' : 'mixed';
  return { targetDir, linked, copied, mode };
}

/**
 * Verify a skills projection: every canonical skill is present at `targetDir`
 * and its projected form is the canonical content (symlink to it, or a
 * byte-identical copy). Returns the divergences, empty when healthy.
 */
export function verifySkillProjection(legionRoot, targetDir) {
  const ids = canonicalSkillIds(legionRoot);
  const missing = [];
  const forked = [];
  for (const id of ids) {
    const canonical = canonicalSkillPath(legionRoot, id);
    const dest = join(targetDir, id);
    let present = false;
    try { present = Boolean(lstatSync(dest)); } catch { present = false; }
    if (!present) { missing.push(id); continue; }
    if (!pointsAtCanonical(dest, canonical)) forked.push(id);
  }
  // Extra entries under targetDir that are not canonical skills are reported so
  // an uninstall/refresh can be precise, but they are not a health failure.
  let extra = [];
  try {
    extra = readdirSync(targetDir).filter((name) => !ids.includes(name));
  } catch { /* target absent */ }
  return { present: ids.length - missing.length, total: ids.length, missing, forked, extra };
}

/** Remove only the canonical-skill projections this installer created. */
export function unprojectSkills(legionRoot, targetDir) {
  const ids = canonicalSkillIds(legionRoot);
  const removed = [];
  for (const id of ids) {
    const dest = join(targetDir, id);
    try { if (lstatSync(dest)) { rmSync(dest, { recursive: true, force: true }); removed.push(id); } } catch { /* absent */ }
  }
  return { removed };
}
