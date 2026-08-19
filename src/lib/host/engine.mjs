// The descriptor-driven adapter engine.
//
// Every harness is a DATA descriptor (see adapters/*.mjs): detection rules and a
// per-surface mechanism. The five adapter operations — detect, capabilities,
// install, verify, uninstall — are implemented ONCE here and parameterized by
// that descriptor. Adding a harness is a new descriptor, never new engine code
// or forked skills; that property is what the conformance tests lock in.
//
// The engine never decides WHAT Legion contains. It reads the canonical skill
// packages and the generated host projection and places them where a harness
// looks. Semantics live in skills/*/SKILL.md and src/roster/*; the engine only
// moves and registers them.
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { projectSkills, verifySkillProjection, unprojectSkills, canonicalSkillIds } from './skill-projection.mjs';
import { capabilityCatalogBlock } from '../host-projection.mjs';
import { upsertMarkerBlock, stripMarkerBlock } from '../cli/commands/bind/common.mjs';
import { SURFACES, enforcementFidelity } from './surfaces.mjs';

const abs = (root, p) => (isAbsolute(p) ? p : join(root, p));

// The command a harness uses to launch the Legion MCP server. node + absolute
// path works regardless of whether the `legion` CLI is on PATH, so it is the
// portable default across harnesses.
export function mcpServerCommand(legionRoot) {
  return { command: process.execPath, args: [join(legionRoot, 'src', 'integrations', 'mcp', 'server.mjs')] };
}

// ---- detection -----------------------------------------------------------
// A descriptor's detect is a small rule object: { anyOf: [path,...] } present in
// the target repo, and/or { env: [VAR,...] } present in the environment.
export function detect(descriptor, root, env = process.env) {
  const rule = descriptor.detect ?? {};
  const anyPath = (rule.anyOf ?? []).some((p) => existsSync(abs(root, p)));
  const anyEnv = (rule.env ?? []).some((v) => Boolean(env[v]));
  return anyPath || anyEnv;
}

// ---- capabilities --------------------------------------------------------
// The declared support table: one entry per surface with its fidelity, the
// mechanism kind, and the concrete location. Pure — no disk writes.
export function capabilities(descriptor, { legionRoot } = {}) {
  const surfaces = {};
  for (const surface of SURFACES) {
    const m = descriptor.surfaces?.[surface] ?? { fidelity: 'unsupported', mechanism: { kind: 'none' } };
    const fidelity = surface === 'hooks' && m.mechanism ? (m.fidelity ?? enforcementFidelity(m.mechanism)) : (m.fidelity ?? 'unsupported');
    surfaces[surface] = { fidelity, mechanism: m.mechanism ?? { kind: 'none' }, note: m.note ?? null };
  }
  return { id: descriptor.id, displayName: descriptor.displayName ?? descriptor.id, installOwner: descriptor.installOwner ?? 'adapter', surfaces };
}

// ---- surface mechanism handlers -----------------------------------------
// Each returns { wrote:[], note } for install, or a verify fragment. They are the
// only place that touches the filesystem, and none of them transform skill
// content: skills are projected as packages by skill-projection.mjs.

function installInstructions(mech, { root, legionRoot }) {
  if (mech.kind === 'agents-md' || mech.kind === 'native-file') {
    const path = abs(root, mech.path);
    // Baseline context + the compact capability catalog. This is a POINTER to
    // the skills, never a copy of their content — native skill discovery does
    // the real work; AGENTS.md is only the fallback baseline (per requirement).
    const block = [
      '# Legion',
      '',
      'Legion authority routing is active. Use it for repository or system-state changes.',
      'Domain expertise is provided as Agent Skills discovered natively by this harness;',
      'the catalog below is a pointer, not a substitute for that discovery.',
      '',
      capabilityCatalogBlock(),
    ].join('\n').trim();
    mkdirSync(join(path, '..'), { recursive: true });
    const existing = existsSync(path) ? readFileSync(path, 'utf8') : '';
    writeFileSync(path, upsertMarkerBlock(existing, block));
    return { wrote: [mech.path] };
  }
  return { wrote: [] };
}

function installSkills(mech, { root, legionRoot }) {
  if (mech.kind === 'skills-dir') {
    // Prefer the common .agents/skills surface; a harness that reads a native
    // location declares it as `path` instead. Same projection either way.
    const target = abs(root, mech.path);
    const result = projectSkills(legionRoot, target, { copyFallback: mech.copyFallback !== false });
    return { wrote: [mech.path], skills: result };
  }
  // kind 'plugin' | 'none': the packaged plugin already ships skills, or the
  // harness has no skill discovery. Nothing for the adapter to place.
  return { wrote: [] };
}

function installAgents(mech, { root, legionRoot }) {
  if (mech.kind === 'dir') {
    const target = abs(root, mech.path);
    mkdirSync(target, { recursive: true });
    // Agents are projected from the package's agents/ directory verbatim — same
    // no-fork rule as skills. We symlink the whole dir's files.
    const src = join(legionRoot, 'agents');
    const wrote = [];
    if (existsSync(src)) {
      for (const f of readdirSync(src).filter((f) => f.endsWith('.md')).sort()) {
        const content = readFileSync(join(src, f));
        writeFileSync(join(target, f), content);
        wrote.push(join(mech.path, f));
      }
    }
    return { wrote };
  }
  return { wrote: [] };
}

function installMcp(mech, { root, legionRoot }) {
  const server = mcpServerCommand(legionRoot);
  if (mech.kind === 'json') {
    const path = abs(root, mech.path);
    let doc = {};
    if (existsSync(path)) { try { doc = JSON.parse(readFileSync(path, 'utf8')); } catch { doc = {}; } }
    const key = mech.key ?? 'mcpServers';
    doc[key] = { ...(doc[key] ?? {}), legion: server };
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
    return { wrote: [mech.path] };
  }
  if (mech.kind === 'toml') {
    const path = abs(root, mech.path);
    const table = mech.table ?? 'mcp_servers';
    const argsToml = server.args.map((a) => JSON.stringify(a)).join(', ');
    const block = `\n[${table}.legion]\ncommand = ${JSON.stringify(server.command)}\nargs = [${argsToml}]\n`;
    mkdirSync(join(path, '..'), { recursive: true });
    const existing = existsSync(path) ? readFileSync(path, 'utf8') : '';
    // Idempotent: replace an existing legion table, else append.
    const re = new RegExp(`\\n\\[${table.replace(/\./g, '\\.')}\\.legion\\][\\s\\S]*?(?=\\n\\[|$)`, 'g');
    const next = re.test(existing) ? existing.replace(re, block.replace(/\n$/, '')) : existing + block;
    writeFileSync(path, next);
    return { wrote: [mech.path] };
  }
  return { wrote: [] };
}

function installHooks(mech, { root, legionRoot }) {
  // Effect enforcement transport is host-specific. Only a blocking-hook mechanism
  // can actually gate an effect; anything else is declared but installs nothing
  // here (the packaged plugin owns Claude's hooks natively).
  if (mech.kind === 'blocking-hook' && mech.path && mech.write) {
    // A descriptor that owns a writable hook config supplies its own writer.
    return mech.write({ root, legionRoot, abs: (p) => abs(root, p) });
  }
  return { wrote: [] };
}

const INSTALLERS = { instructions: installInstructions, skills: installSkills, agents: installAgents, mcp: installMcp, hooks: installHooks };

// ---- install / verify / uninstall ---------------------------------------
export function install(descriptor, { root, legionRoot, surfaces = SURFACES } = {}) {
  const caps = capabilities(descriptor, { legionRoot });
  if (caps.installOwner !== 'adapter') {
    return { id: descriptor.id, installOwner: caps.installOwner, wrote: [], skipped: 'installation owned externally (e.g. packaged plugin); use its own installer', surfaces: {} };
  }
  const applied = {};
  const wrote = [];
  for (const surface of surfaces) {
    const m = descriptor.surfaces?.[surface];
    if (!m || (m.fidelity ?? 'unsupported') === 'unsupported') continue;
    const result = INSTALLERS[surface](m.mechanism ?? { kind: 'none' }, { root, legionRoot });
    applied[surface] = result;
    wrote.push(...(result.wrote ?? []));
  }
  return { id: descriptor.id, installOwner: 'adapter', wrote, surfaces: applied };
}

export function verify(descriptor, { root, legionRoot } = {}) {
  const caps = capabilities(descriptor, { legionRoot });
  const problems = [];
  const surfaces = {};
  for (const surface of SURFACES) {
    const m = descriptor.surfaces?.[surface];
    const fidelity = caps.surfaces[surface].fidelity;
    if (!m || fidelity === 'unsupported') { surfaces[surface] = { fidelity, ok: true }; continue; }
    const mech = m.mechanism ?? { kind: 'none' };
    if (surface === 'skills' && mech.kind === 'skills-dir') {
      const v = verifySkillProjection(legionRoot, abs(root, mech.path));
      const ok = v.missing.length === 0 && v.forked.length === 0;
      if (!ok) problems.push({ surface, missing: v.missing, forked: v.forked });
      surfaces[surface] = { fidelity, ok, ...v };
    } else if (['instructions', 'mcp', 'agents'].includes(surface) && mech.path) {
      const ok = caps.installOwner !== 'adapter' || existsSync(abs(root, mech.path));
      if (!ok) problems.push({ surface, missing: mech.path });
      surfaces[surface] = { fidelity, ok, path: mech.path };
    } else {
      surfaces[surface] = { fidelity, ok: true, note: mech.kind === 'plugin' ? 'owned by packaged plugin' : undefined };
    }
  }
  return { id: descriptor.id, installOwner: caps.installOwner, ok: problems.length === 0, problems, surfaces };
}

export function uninstall(descriptor, { root, legionRoot } = {}) {
  const removed = [];
  for (const surface of SURFACES) {
    const m = descriptor.surfaces?.[surface];
    if (!m) continue;
    const mech = m.mechanism ?? {};
    if (surface === 'skills' && mech.kind === 'skills-dir') {
      const r = unprojectSkills(legionRoot, abs(root, mech.path));
      removed.push(...r.removed.map((id) => join(mech.path, id)));
    } else if (['instructions'].includes(surface) && mech.path && existsSync(abs(root, mech.path))) {
      const path = abs(root, mech.path);
      const stripped = stripMarkerBlock(readFileSync(path, 'utf8'));
      writeFileSync(path, stripped);
      removed.push(mech.path);
    } else if (['mcp', 'agents'].includes(surface) && mech.path) {
      // Leave third-party config in place; only note it. A precise uninstall of
      // shared config files is intentionally conservative.
    }
  }
  return { id: descriptor.id, removed };
}
