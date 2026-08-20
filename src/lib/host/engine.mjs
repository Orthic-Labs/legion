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
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { projectSkills, verifySkillProjection, unprojectSkills } from './skill-projection.mjs';
import { capabilityCatalogBlock } from '../host-projection.mjs';
import { upsertMarkerBlock, stripMarkerBlock } from '../cli/commands/bind/common.mjs';
import { SURFACES, enforcementFidelity } from './surfaces.mjs';

const abs = (root, p) => (isAbsolute(p) ? p : join(root, p));

/** A config surface Legion refused to touch because it does not own what is there. */
export class HarnessConflict extends Error {
  constructor(surface, path, reason) {
    super(`${surface}: refused to write ${path}: ${reason}`);
    this.name = 'HarnessConflict';
    this.code = 'HARNESS_CONFLICT';
    this.surface = surface;
    this.path = path;
    this.reason = reason;
  }
}

// Read an existing config file, FAILING CLOSED. A parse failure is a real
// condition — a user's hand-edited file, or a half-written one — and replacing
// it with `{}` and rewriting would destroy their configuration. Legion refuses
// instead, and says which file to fix.
function readJsonOrRefuse(path, surface) {
  if (!existsSync(path)) return {};
  const text = readFileSync(path, 'utf8');
  if (text.trim() === '') return {};
  try { return JSON.parse(text); }
  catch (err) { throw new HarnessConflict(surface, path, `existing JSON does not parse (${err.message}); fix or move it, Legion will not overwrite it`); }
}

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

function installInstructions(mech, { root, legionRoot, skillsLocation }) {
  if (mech.kind === 'agents-md' || mech.kind === 'native-file') {
    const path = abs(root, mech.path);
    // Baseline context + the compact capability catalog. This is a POINTER to
    // the skills, never a copy of their content — native skill discovery does
    // the real work; AGENTS.md is only the fallback baseline (per requirement).
    const block = [
      '# Legion',
      '',
      'Legion authority routing is active. Use it for repository or system-state changes.',
      `Domain expertise ships as Agent Skills packages under \`${skillsLocation ?? '.agents/skills'}\`;`,
      'read the matching SKILL.md before using a capability. The catalog below is a',
      'pointer to those packages, not a copy of their method.',
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
      const files = readdirSync(src).filter((f) => f.endsWith('.md')).sort();
      // Collision check first: a same-named file that is NOT the canonical
      // content is the user's, and is never overwritten.
      for (const f of files) {
        const dest = join(target, f);
        if (existsSync(dest) && !readFileSync(dest).equals(readFileSync(join(src, f)))) {
          throw new HarnessConflict('agents', dest, 'an existing file with this name is not a Legion projection');
        }
      }
      for (const f of files) {
        writeFileSync(join(target, f), readFileSync(join(src, f)));
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
    const doc = readJsonOrRefuse(path, 'mcp');
    const key = mech.key ?? 'mcpServers';
    doc[key] = { ...(doc[key] ?? {}), legion: server };
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
    return { wrote: [mech.path] };
  }
  if (mech.kind === 'toml') {
    const path = abs(root, mech.path);
    const table = mech.table ?? 'mcp_servers';
    assertPlausibleToml(path, 'mcp');
    const argsToml = server.args.map((a) => JSON.stringify(a)).join(', ');
    const block = `\n[${table}.legion]\ncommand = ${JSON.stringify(server.command)}\nargs = [${argsToml}]\n`;
    mkdirSync(join(path, '..'), { recursive: true });
    const existing = existsSync(path) ? readFileSync(path, 'utf8') : '';
    // Idempotent & self-healing: retain exactly one Legion table even when a
    // prior installer collision left duplicate keys that make Codex reject the
    // entire project configuration.
    let found = false;
    const collapsed = existing.replace(legionTomlBlockRe(table), () => {
      if (found) return '';
      found = true;
      return block.replace(/\n$/, '');
    });
    const next = found ? collapsed : existing + block;
    writeFileSync(path, next);
    return { wrote: [mech.path] };
  }
  return { wrote: [] };
}

// Legion does not ship a TOML parser, so it cannot prove an existing config is
// valid. It CAN refuse to append to a file that is clearly not TOML: every
// significant line of a TOML document is a table header or a key/value pair.
// Appending a table to a malformed file produces a config the harness silently
// drops, so Legion fails closed and names the file instead of rewriting it.
function assertPlausibleToml(path, surface) {
  if (!existsSync(path)) return;
  const MULTI = ['"'.repeat(3), "'".repeat(3)];
  let inMultiline = false;
  for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (inMultiline) { if (MULTI.some((m) => line.includes(m))) inMultiline = false; continue; }
    if (line === '' || line.startsWith('#')) continue;
    if (/^(?:\[[^\]]+\]|\[\[[^\]]+\]\])$/.test(line)) continue;
    if (/^(?:"(?:\\.|[^"\\])*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=/.test(line)) {
      if (MULTI.some((m) => line.trimEnd().endsWith(m))) inMultiline = true;
      continue;
    }
    // Continuation line of a multi-line array or inline table value.
    if (/^[\]}]/.test(line) || /[,[{]$/.test(line)) continue;
    throw new HarnessConflict(surface, path, `existing TOML does not parse as TOML near: ${line.slice(0, 60)}`);
  }
}

// The regex bounding one `[<table>.legion]` block: from its header to the next
// table header or end of file. Install and uninstall use the SAME builder so
// they can never disagree about what Legion owns. A fresh object per call —
// the /g flag makes lastIndex stateful.
function legionTomlBlockRe(table) {
  return new RegExp(`\\n?\\[${table.replace(/\./g, '\\.')}\\.legion\\][\\s\\S]*?(?=\\n\\[|$)`, 'g');
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
  // Where this harness actually finds the skill packages, so the instructions
  // block can point at a real location instead of asserting a native discovery
  // the harness may not have.
  const skillsMech = descriptor.surfaces?.skills?.mechanism;
  const skillsLocation = skillsMech?.kind === 'skills-dir' ? skillsMech.path : null;
  for (const surface of surfaces) {
    const m = descriptor.surfaces?.[surface];
    if (!m || (m.fidelity ?? 'unsupported') === 'unsupported') continue;
    const result = INSTALLERS[surface](m.mechanism ?? { kind: 'none' }, { root, legionRoot, skillsLocation });
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

// Uninstall removes ONLY what Legion owns, and proves ownership before removing
// it. Ownership is inferable without a receipt file: a skill projection is a
// symlink to canonical or a byte-identical package; an agent file is a
// byte-identical copy of the packaged agent; an MCP entry is the `legion` key /
// `[<table>.legion]` block; an instructions block is marker-delimited. Anything
// else is the user's, is preserved, and is reported under `kept`.
export function uninstall(descriptor, { root, legionRoot } = {}) {
  const removed = [];
  const kept = [];
  for (const surface of SURFACES) {
    const m = descriptor.surfaces?.[surface];
    if (!m) continue;
    const mech = m.mechanism ?? {};
    if (surface === 'skills' && mech.kind === 'skills-dir') {
      const r = unprojectSkills(legionRoot, abs(root, mech.path));
      removed.push(...r.removed.map((id) => join(mech.path, id)));
      kept.push(...r.kept.map((k) => ({ surface, path: join(mech.path, k.id), reason: k.reason })));
    } else if (surface === 'instructions' && mech.path && existsSync(abs(root, mech.path))) {
      // Strip only the marker block; the rest of the user's AGENTS.md prose is
      // rewritten byte-for-byte as it was.
      const path = abs(root, mech.path);
      const before = readFileSync(path, 'utf8');
      const stripped = stripMarkerBlock(before);
      if (stripped !== before) { writeFileSync(path, stripped); removed.push(mech.path); }
    } else if (surface === 'agents' && mech.kind === 'dir' && mech.path) {
      const target = abs(root, mech.path);
      const src = join(legionRoot, 'agents');
      if (existsSync(target) && existsSync(src)) {
        for (const f of readdirSync(src).filter((f) => f.endsWith('.md')).sort()) {
          const dest = join(target, f);
          if (!existsSync(dest)) continue;
          if (readFileSync(dest).equals(readFileSync(join(src, f)))) { rmSync(dest); removed.push(join(mech.path, f)); }
          else kept.push({ surface, path: join(mech.path, f), reason: 'not a Legion projection' });
        }
      }
    } else if (surface === 'mcp' && mech.path && existsSync(abs(root, mech.path))) {
      const path = abs(root, mech.path);
      if (mech.kind === 'json') {
        // Surgical: drop the `legion` server, keep every other server and every
        // unrelated top-level key exactly as they were.
        const doc = readJsonOrRefuse(path, 'mcp');
        const key = mech.key ?? 'mcpServers';
        if (doc[key] && Object.hasOwn(doc[key], 'legion')) {
          delete doc[key].legion;
          if (Object.keys(doc[key]).length === 0) delete doc[key];
          writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
          removed.push(`${mech.path}#${key}.legion`);
        }
      } else if (mech.kind === 'toml') {
        assertPlausibleToml(path, 'mcp');
        const table = mech.table ?? 'mcp_servers';
        const before = readFileSync(path, 'utf8');
        const after = before.replace(legionTomlBlockRe(table), '');
        if (after !== before) {
          // Legion created the file only if nothing else remains in it.
          if (after.trim() === '') rmSync(path);
          else writeFileSync(path, after.replace(/^\n+/, ''));
          removed.push(`${mech.path}#${table}.legion`);
        }
      }
    }
  }
  return { id: descriptor.id, removed, kept };
}
