// Project canonical Legion skill packages into a harness's skill location
// WITHOUT ever forking their contents, and without ever destroying something
// Legion does not own.
//
// Agent Skills / SKILL.md is the common capability interchange format across
// harnesses. A skill is a directory `skills/<id>/` with a `SKILL.md` and its
// assets; the canonical copy under the Legion package is the only source of
// truth. Projection makes that same package visible where a harness discovers
// skills — by symlink where the platform allows it, and by a byte-identical
// copy only as a fallback. Neither path edits, templates, or regenerates skill
// content: the conformance tests assert byte-identity against the canonical
// source, so a projection that rewrote a SKILL.md would fail.
//
// MEMBERSHIP is not decided here. Which capabilities are discoverable is a
// canonical Legion decision, already made and recorded in the generated host
// projection (src/registry/host-projection.json). This module CONSUMES that
// set. Enumerating `skills/*/SKILL.md` off the filesystem would independently
// redefine membership and would project internal-only surfaces.
import { existsSync, mkdirSync, readdirSync, symlinkSync, rmSync, lstatSync, readlinkSync, cpSync, readFileSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';

/** A projection refused because the destination holds something Legion does not own. */
export class SkillProjectionConflict extends Error {
  constructor(conflicts) {
    super(`skill projection refused: ${conflicts.length} destination(s) are not Legion projections: ${conflicts.map((c) => c.id).join(', ')}`);
    this.name = 'SkillProjectionConflict';
    this.code = 'HARNESS_CONFLICT';
    this.conflicts = conflicts;
  }
}

function hostProjectionPath(legionRoot) {
  return join(legionRoot, 'src', 'registry', 'host-projection.json');
}

// Public domain skills and explicit slash entrypoints are both user-invokable
// surfaces. Roles, host capabilities, and every other non-public capability
// remain internal to Legion and never enter a harness's flat skills directory.
function isProjectableCapability(capability) {
  return (capability.kind === 'domain-capability' && capability.discoverability === 'public')
    || (capability.kind === 'entrypoint' && capability.discoverability === 'explicit');
}

/**
 * The canonical user-invokable capability set, in catalog order, read from the
 * generated host projection. Public domain skills and explicit slash
 * entrypoints are included; internal-only surfaces are excluded.
 */
export function canonicalSkillIds(legionRoot) {
  const path = hostProjectionPath(legionRoot);
  if (!existsSync(path)) {
    throw new Error(`host projection missing at ${path}; run: node scripts/generate-host-projection.mjs`);
  }
  const projection = JSON.parse(readFileSync(path, 'utf8'));
  const ids = (projection.capabilities ?? [])
    .filter(isProjectableCapability)
    .map((c) => c.id)
    .sort();
  // A capability the projection declares but whose package is absent is a
  // packaging failure, not something to silently skip.
  const absent = ids.filter((id) => !existsSync(join(legionRoot, 'skills', id, 'SKILL.md')));
  if (absent.length) throw new Error(`host projection declares capabilities with no packaged skill: ${absent.join(', ')}`);
  return ids;
}

/**
 * Capabilities the canonical projection marks internal / non-discoverable.
 * Exposed so conformance tests can assert they never reach a harness's skill
 * discovery surface.
 */
export function internalCapabilityIds(legionRoot) {
  const path = hostProjectionPath(legionRoot);
  const projection = JSON.parse(readFileSync(path, 'utf8'));
  return (projection.capabilities ?? [])
    .filter((c) => !isProjectableCapability(c))
    .map((c) => c.id)
    .sort();
}

export function canonicalSkillPath(legionRoot, id) {
  return join(legionRoot, 'skills', id);
}

/** Every file in a package, as repo-relative POSIX paths, sorted. */
function packageFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(relative(dir, full).split(sep).join('/'));
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Is a copied package the canonical package in full? The no-fork invariant
 * covers the WHOLE skill package — its assets and references, not only
 * SKILL.md. A copy that matches SKILL.md but has a stale or edited reference
 * file is a fork, and must be reported as one.
 */
export function packageMatches(copyPath, canonicalPath) {
  let a;
  let b;
  try {
    a = packageFiles(canonicalPath);
    b = packageFiles(copyPath);
  } catch { return false; }
  if (a.length !== b.length || a.some((f, i) => f !== b[i])) return false;
  for (const file of a) {
    try {
      if (!readFileSync(join(canonicalPath, file)).equals(readFileSync(join(copyPath, file)))) return false;
    } catch { return false; }
  }
  return true;
}

/**
 * Classify what currently sits at a projection destination.
 *   'absent'  nothing there
 *   'legion'  a symlink to the canonical package, or a byte-identical full copy
 *   'foreign' something else — user-owned, or a fork; never destroyed silently
 */
export function classifyDestination(destPath, canonicalPath) {
  let st;
  try { st = lstatSync(destPath); } catch { return 'absent'; }
  if (st.isSymbolicLink()) {
    try {
      const target = resolve(join(destPath, '..'), readlinkSync(destPath));
      // Must match the canonical package AND actually resolve — a link whose
      // target has moved is a health failure, not a healthy projection.
      if (resolve(target) === resolve(canonicalPath)) {
        return existsSync(join(destPath, 'SKILL.md')) ? 'legion' : 'foreign';
      }
    } catch { /* unreadable link */ }
    return 'foreign';
  }
  if (st.isDirectory()) return packageMatches(destPath, canonicalPath) ? 'legion' : 'foreign';
  return 'foreign';
}

/**
 * Project every canonical skill package into `targetDir`. Prefers an absolute
 * symlink so the projection tracks the source with zero duplication; falls back
 * to a verbatim copy only when symlinks are unavailable (recorded per skill).
 *
 * Collision-safe: destinations are classified BEFORE anything is written. If any
 * destination holds a non-Legion item, nothing is written at all and a typed
 * SkillProjectionConflict is raised (or returned, with `onConflict: 'report'`).
 *
 * @returns {{ targetDir, linked: string[], copied: string[], conflicts: object[], mode }}
 */
export function projectSkills(legionRoot, targetDir, { copyFallback = true, onConflict = 'throw' } = {}) {
  const ids = canonicalSkillIds(legionRoot);

  // Phase 1 — classify every destination, write nothing.
  const plan = ids.map((id) => {
    const canonical = canonicalSkillPath(legionRoot, id);
    const dest = join(targetDir, id);
    return { id, canonical, dest, state: classifyDestination(dest, canonical) };
  });
  const conflicts = plan.filter((p) => p.state === 'foreign')
    .map((p) => ({ id: p.id, path: p.dest, reason: 'destination exists and is not a Legion projection' }));
  if (conflicts.length) {
    if (onConflict === 'throw') throw new SkillProjectionConflict(conflicts);
    return { targetDir, linked: [], copied: [], conflicts, mode: 'blocked' };
  }

  // Phase 2 — write. Only 'absent' destinations are touched; 'legion' ones are
  // already correct and are left exactly as they are (idempotent).
  mkdirSync(targetDir, { recursive: true });
  const linked = [];
  const copied = [];
  for (const { id, canonical, dest, state } of plan) {
    if (state === 'legion') { linked.push(id); continue; }
    try {
      // Absolute target: a projection is pinned to a specific canonical Legion
      // checkout, and an absolute link resolves correctly even when an ancestor
      // of targetDir is itself a symlink (a relative link would walk up through
      // the symlink and dangle). If Legion moves, re-run install.
      symlinkSync(resolve(canonical), dest, 'dir');
      linked.push(id);
    } catch (err) {
      if (!copyFallback) throw err;
      // Verbatim copy — byte-identical, never a transform. Verified in full.
      cpSync(canonical, dest, { recursive: true });
      if (!packageMatches(dest, canonical)) {
        rmSync(dest, { recursive: true, force: true });
        throw new Error(`copy fallback produced a non-identical package for skill ${id}`);
      }
      copied.push(id);
    }
  }
  const mode = copied.length === 0 ? 'symlink' : linked.length === 0 ? 'copy' : 'mixed';
  return { targetDir, linked, copied, conflicts: [], mode };
}

/**
 * Verify a skills projection: every canonical skill is present at `targetDir`
 * and its projected form is the canonical content in full (symlink to it, or a
 * byte-identical package copy). Returns the divergences, empty when healthy.
 */
export function verifySkillProjection(legionRoot, targetDir) {
  const ids = canonicalSkillIds(legionRoot);
  const missing = [];
  const forked = [];
  for (const id of ids) {
    const state = classifyDestination(join(targetDir, id), canonicalSkillPath(legionRoot, id));
    if (state === 'absent') missing.push(id);
    else if (state === 'foreign') forked.push(id);
  }
  // Extra entries under targetDir that are not canonical skills are reported so
  // an uninstall/refresh can be precise, but they are not a health failure —
  // they may be the user's own skills sharing the directory.
  let extra = [];
  try {
    extra = readdirSync(targetDir).filter((name) => !ids.includes(name));
  } catch { /* target absent */ }
  return { present: ids.length - missing.length, total: ids.length, missing, forked, extra };
}

/**
 * Remove only the projections Legion actually owns. A destination that is not a
 * recognisable Legion projection is KEPT and reported — uninstall never deletes
 * a user's skill directory merely because it shares a Legion skill name.
 */
export function unprojectSkills(legionRoot, targetDir) {
  const ids = canonicalSkillIds(legionRoot);
  const removed = [];
  const kept = [];
  for (const id of ids) {
    const dest = join(targetDir, id);
    const state = classifyDestination(dest, canonicalSkillPath(legionRoot, id));
    if (state === 'absent') continue;
    if (state === 'foreign') { kept.push({ id, path: dest, reason: 'not a Legion projection' }); continue; }
    rmSync(dest, { recursive: true, force: true });
    removed.push(id);
  }
  // Remove the projection directory only when Legion emptied it.
  try { if (readdirSync(targetDir).length === 0) rmSync(targetDir, { recursive: true, force: true }); } catch { /* absent */ }
  return { removed, kept };
}
