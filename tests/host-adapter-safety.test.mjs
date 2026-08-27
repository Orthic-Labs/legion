// Host/runtime safety invariants for the harness adapter seam.
//
// The conformance suite (host-adapter-conformance.test.mjs) proves the seam
// delivers the SAME canonical Legion to every harness. This suite proves the
// seam is safe on a machine that already has other things on it: it must not
// project what Legion marks internal, must not destroy a user's skill directory
// or configuration, must fail closed on config it cannot parse, must remove only
// what it installed, must not detect three harnesses from one generic file, and
// must not describe surfaces its installer does not actually create.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync, realpathSync, writeFileSync, mkdirSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as reg from '../src/lib/host/registry.mjs';
import {
  canonicalSkillIds, internalCapabilityIds, canonicalSkillPath, projectSkills, unprojectSkills, packageMatches, SkillProjectionConflict,
} from '../src/lib/host/skill-projection.mjs';

const LEGION = reg.LEGION_ROOT;
const CANON = canonicalSkillIds(LEGION);
const PROJECTING = reg.ADAPTER_IDS.filter((id) => reg.capabilities(id).surfaces.skills.mechanism?.kind === 'skills-dir');

const withRepo = (fn) => {
  const root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), 'legion-harness-safety-')));
  try { return fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
};

// ---- 1. internal capabilities never leak into projected discovery ---------

test('the projected set is exactly the canonical user-invokable skill set', () => {
  const onDisk = readdirSync(join(LEGION, 'skills'), { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(LEGION, 'skills', e.name, 'SKILL.md')))
    .map((e) => e.name).sort();
  const internal = internalCapabilityIds(LEGION);
  assert.deepEqual([...CANON, ...internal].sort(), onDisk, 'canonical projection must classify every packaged skill');
  assert.ok(CANON.includes('dispatch'), 'Dispatch workflow must be projected for semantic discovery');
  for (const id of internal) assert.ok(!CANON.includes(id), `${id}: internal capability must not be in the projected set`);
});

test('explicit slash entrypoints remain invokable while internal capabilities stay hidden', () => {
  const internal = internalCapabilityIds(LEGION);
  const entrypoints = ['alchemist', 'coder', 'commit', 'covenant'];
  for (const entrypoint of entrypoints) assert.ok(CANON.includes(entrypoint), `${entrypoint}: explicit slash entrypoint must be projected`);
  for (const id of PROJECTING) {
    withRepo((root) => {
      reg.install(id, { root });
      const dir = reg.capabilities(id).surfaces.skills.mechanism.path;
      const projected = readdirSync(join(root, dir));
      for (const capability of internal) {
        assert.ok(!projected.includes(capability), `${id}: internal capability ${capability} must not be projected as peer expertise`);
      }
    });
  }
});

// ---- 2. collision-safe install -------------------------------------------

test('install refuses to overwrite a user-owned directory that shares a Legion skill name', () => {
  withRepo((root) => {
    const dir = join(root, '.agents', 'skills', CANON[0]);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'SKILL.md'), '# my own skill, not Legion\n');
    assert.throws(() => reg.install('codex', { root }), (err) => err.code === 'HARNESS_CONFLICT');
    // And nothing was written: the refusal is atomic, not partial.
    assert.equal(readFileSync(join(dir, 'SKILL.md'), 'utf8'), '# my own skill, not Legion\n');
    assert.deepEqual(readdirSync(join(root, '.agents', 'skills')), [CANON[0]]);
  });
});

test('install refuses a forked package even when SKILL.md matches byte-for-byte', () => {
  withRepo((root) => {
    const canonical = canonicalSkillPath(LEGION, CANON[0]);
    const dir = join(root, '.agents', 'skills', CANON[0]);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'SKILL.md'), readFileSync(join(canonical, 'SKILL.md')));
    writeFileSync(join(dir, 'EXTRA.md'), 'a file Legion never shipped\n');
    assert.throws(() => projectSkills(LEGION, join(root, '.agents', 'skills')), SkillProjectionConflict);
  });
});

test('install is idempotent and a second run reports no conflict', () => {
  withRepo((root) => {
    reg.install('codex', { root });
    const first = readdirSync(join(root, '.agents', 'skills')).sort();
    reg.install('codex', { root });
    assert.deepEqual(readdirSync(join(root, '.agents', 'skills')).sort(), first);
    assert.ok(reg.verify('codex', { root }).ok);
  });
});

test('a user skill sharing the directory but not a Legion name is left untouched', () => {
  withRepo((root) => {
    const mine = join(root, '.agents', 'skills', 'my-private-skill');
    mkdirSync(mine, { recursive: true });
    writeFileSync(join(mine, 'SKILL.md'), '# mine\n');
    reg.install('codex', { root });
    assert.equal(readFileSync(join(mine, 'SKILL.md'), 'utf8'), '# mine\n');
    const v = reg.verify('codex', { root });
    assert.ok(v.ok, 'a foreign neighbour is not a health failure');
    assert.deepEqual(v.surfaces.skills.extra, ['my-private-skill']);
  });
});

// ---- 3. copy fallback is verified across the WHOLE package ----------------

test('the no-fork invariant covers the whole package, not only SKILL.md', () => {
  withRepo((root) => {
    const target = join(root, '.agents', 'skills');
    // Force the copy path by disabling symlinks for this projection.
    const copied = projectSkills(LEGION, target, { copyFallback: true });
    assert.ok(copied.conflicts.length === 0);
    // Whatever mode was used, the full package must match canonical.
    for (const id of CANON) {
      const dest = join(target, id);
      if (lstatSync(dest).isSymbolicLink()) continue;
      assert.ok(packageMatches(dest, canonicalSkillPath(LEGION, id)), `${id}: full package must match canonical`);
    }
  });
});

test('a copy that diverges anywhere in the package is reported as forked, not healthy', () => {
  withRepo((root) => {
    const id = CANON[0];
    const target = join(root, '.agents', 'skills');
    const canonical = canonicalSkillPath(LEGION, id);
    mkdirSync(join(target, id), { recursive: true });
    // A copy whose SKILL.md is perfect but which carries an extra asset.
    writeFileSync(join(target, id, 'SKILL.md'), readFileSync(join(canonical, 'SKILL.md')));
    writeFileSync(join(target, id, 'reference.md'), 'stale fork\n');
    assert.equal(packageMatches(join(target, id), canonical), false);
  });
});

// ---- 4. malformed config fails closed ------------------------------------

test('malformed MCP JSON is preserved, not replaced with an empty object', () => {
  withRepo((root) => {
    const path = join(root, '.myharness', 'mcp.json');
    mkdirSync(join(root, '.myharness'), { recursive: true });
    const broken = '{ "mcpServers": { "mine": { "command": "node" } ,,, }';
    writeFileSync(path, broken);
    mkdirSync(join(root, '.agents'), { recursive: true });
    writeFileSync(join(root, '.agents', 'legion-harness.json'), JSON.stringify({
      id: 'my-harness',
      surfaces: { mcp: { fidelity: 'strong', mechanism: { kind: 'json', path: '.myharness/mcp.json', key: 'mcpServers' } } },
    }));
    assert.throws(() => reg.install('generic', { root }), (err) => err.code === 'HARNESS_CONFLICT');
    assert.equal(readFileSync(path, 'utf8'), broken, 'the unparseable file must be left exactly as it was');
  });
});

test('malformed MCP TOML is preserved, not appended to', () => {
  withRepo((root) => {
    const path = join(root, '.codex', 'config.toml');
    mkdirSync(join(root, '.codex'), { recursive: true });
    const broken = 'this is not toml at all\n<<<<<<< HEAD\n';
    writeFileSync(path, broken);
    assert.throws(() => reg.install('codex', { root }), (err) => err.code === 'HARNESS_CONFLICT');
    assert.equal(readFileSync(path, 'utf8'), broken);
  });
});

test('Codex MCP install collapses duplicate Legion tables to one valid owner', () => {
  withRepo((root) => {
    const path = join(root, '.codex', 'config.toml');
    mkdirSync(join(root, '.codex'), { recursive: true });
    writeFileSync(path, '[mcp_servers.legion]\ncommand = "node"\nargs = ["old.mjs"]\n\n[mcp_servers.mine]\ncommand = "mine"\n\n[mcp_servers.legion]\ncommand = "node"\nargs = ["duplicate.mjs"]\n');
    reg.install('codex', { root, surfaces: ['mcp'] });
    const after = readFileSync(path, 'utf8');
    assert.equal((after.match(/^\[mcp_servers\.legion\]$/gm) ?? []).length, 1);
    assert.match(after, /\[mcp_servers\.mine\]/);
  });
});

test('Codex MCP install accepts valid quoted TOML keys', () => {
  withRepo((root) => {
    const path = join(root, '.codex', 'config.toml');
    mkdirSync(join(root, '.codex'), { recursive: true });
    writeFileSync(path, '[projects]\n"/Volumes/Example/project" = "trusted"\n');
    reg.install('codex', { root, surfaces: ['mcp'] });
    const after = readFileSync(path, 'utf8');
    assert.match(after, /"\/Volumes\/Example\/project" = "trusted"/);
    assert.equal((after.match(/^\[mcp_servers\.legion\]$/gm) ?? []).length, 1);
  });
});

test('Codex MCP install accepts valid TOML array tables', () => {
  withRepo((root) => {
    const path = join(root, '.codex', 'config.toml');
    mkdirSync(join(root, '.codex'), { recursive: true });
    writeFileSync(path, '[[skills.config]]\npath = "skills/example"\n');
    reg.install('codex', { root, surfaces: ['mcp'] });
    const after = readFileSync(path, 'utf8');
    assert.match(after, /\[\[skills\.config\]\]/);
    assert.equal((after.match(/^\[mcp_servers\.legion\]$/gm) ?? []).length, 1);
  });
});

test('a malformed custom harness descriptor fails closed instead of silently defaulting', () => {
  withRepo((root) => {
    mkdirSync(join(root, '.agents'), { recursive: true });
    writeFileSync(join(root, '.agents', 'legion-harness.json'), '{ not json');
    assert.throws(() => reg.capabilities('generic', { root }), (err) => err.code === 'HARNESS_DESCRIPTOR_INVALID');
  });
});

// ---- 5. precise uninstall ------------------------------------------------

test('uninstall removes Legion projections and keeps everything else', () => {
  withRepo((root) => {
    writeFileSync(join(root, 'AGENTS.md'), '# My project\n\nMy own prose that must survive.\n');
    reg.install('codex', { root });
    const mine = join(root, '.agents', 'skills', 'my-private-skill');
    mkdirSync(mine, { recursive: true });
    writeFileSync(join(mine, 'SKILL.md'), '# mine\n');

    const result = reg.uninstall('codex', { root });
    assert.ok(result.removed.length > 0);
    for (const id of CANON) assert.ok(!existsSync(join(root, '.agents', 'skills', id)), `${id}: removed`);
    assert.equal(readFileSync(join(mine, 'SKILL.md'), 'utf8'), '# mine\n', 'a foreign skill survives uninstall');
    // The user's own AGENTS.md prose survives; only the marker block is gone.
    const agents = readFileSync(join(root, 'AGENTS.md'), 'utf8');
    assert.match(agents, /My own prose that must survive\./);
    assert.doesNotMatch(agents, /Legion authority routing/);
  });
});

test('uninstall never deletes a user directory that merely shares a Legion skill name', () => {
  withRepo((root) => {
    const dir = join(root, '.agents', 'skills', CANON[0]);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'SKILL.md'), '# not Legion\n');
    const result = unprojectSkills(LEGION, join(root, '.agents', 'skills'));
    assert.deepEqual(result.removed, []);
    assert.equal(result.kept.length, 1);
    assert.equal(readFileSync(join(dir, 'SKILL.md'), 'utf8'), '# not Legion\n');
  });
});

test('MCP uninstall is surgical: other servers and unrelated config survive', () => {
  withRepo((root) => {
    const path = join(root, '.codex', 'config.toml');
    mkdirSync(join(root, '.codex'), { recursive: true });
    writeFileSync(path, 'model = "o3"\n\n[mcp_servers.mine]\ncommand = "node"\nargs = ["mine.mjs"]\n');
    reg.install('codex', { root });
    assert.match(readFileSync(path, 'utf8'), /\[mcp_servers\.legion\]/);
    reg.uninstall('codex', { root });
    const after = readFileSync(path, 'utf8');
    assert.doesNotMatch(after, /\[mcp_servers\.legion\]/, 'the legion table is gone');
    assert.match(after, /\[mcp_servers\.mine\]/, "the user's server survives");
    assert.match(after, /model = "o3"/, 'unrelated config survives');
  });
});

test('JSON MCP uninstall drops only the legion key', () => {
  withRepo((root) => {
    const path = join(root, '.myharness', 'mcp.json');
    mkdirSync(join(root, '.myharness'), { recursive: true });
    writeFileSync(path, JSON.stringify({ theme: 'dark', mcpServers: { mine: { command: 'node' } } }, null, 2));
    mkdirSync(join(root, '.agents'), { recursive: true });
    writeFileSync(join(root, '.agents', 'legion-harness.json'), JSON.stringify({
      id: 'my-harness',
      surfaces: { mcp: { fidelity: 'strong', mechanism: { kind: 'json', path: '.myharness/mcp.json', key: 'mcpServers' } } },
    }));
    reg.install('generic', { root });
    assert.ok(JSON.parse(readFileSync(path, 'utf8')).mcpServers.legion);
    reg.uninstall('generic', { root });
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(doc.mcpServers.legion, undefined);
    assert.ok(doc.mcpServers.mine, "the user's server survives");
    assert.equal(doc.theme, 'dark', 'unrelated keys survive');
  });
});

// ---- 6. detection is non-ambiguous ---------------------------------------

test('a bare AGENTS.md does not detect three harnesses at once', () => {
  withRepo((root) => {
    writeFileSync(join(root, 'AGENTS.md'), '# Anything\n');
    const detected = reg.detectHarnesses(root, {});
    assert.deepEqual(detected, [], 'a cross-harness convention file is not evidence of any specific harness');
  });
});

test('.vscode alone does not detect Cline', () => {
  withRepo((root) => {
    mkdirSync(join(root, '.vscode'), { recursive: true });
    writeFileSync(join(root, '.vscode', 'settings.json'), '{}');
    assert.deepEqual(reg.detectHarnesses(root, {}), []);
  });
});

test('each harness is detected by its own specific evidence', () => {
  const evidence = {
    codex: () => ['.codex'],
    cline: () => ['.clinerules'],
    'command-code': () => ['.commandcode'],
    pi: () => ['.pi'],
    'claude-code': () => ['.claude'],
  };
  for (const [id, dirs] of Object.entries(evidence)) {
    withRepo((root) => {
      for (const d of dirs()) mkdirSync(join(root, d), { recursive: true });
      const detected = reg.detectHarnesses(root, {});
      assert.deepEqual(detected, [id], `${id}: its own evidence must detect exactly it`);
    });
  }
});

test('two genuinely coexisting harnesses are both reported, from their own evidence', () => {
  withRepo((root) => {
    mkdirSync(join(root, '.codex'), { recursive: true });
    mkdirSync(join(root, '.clinerules'), { recursive: true });
    assert.deepEqual(reg.detectHarnesses(root, {}).sort(), ['cline', 'codex']);
  });
});

// ---- 7. declared fidelity matches what the installer actually creates -----

test('every declared non-plugin mechanism path is actually created by install', () => {
  for (const id of reg.ADAPTER_IDS) {
    const caps = reg.capabilities(id);
    if (caps.installOwner !== 'adapter') continue;
    withRepo((root) => {
      reg.install(id, { root });
      for (const [surface, s] of Object.entries(caps.surfaces)) {
        if (s.fidelity === 'unsupported' || !s.mechanism?.path) continue;
        assert.ok(existsSync(join(root, s.mechanism.path)),
          `${id}.${surface}: declares ${s.mechanism.path} but install did not create it`);
      }
    });
  }
});

test('no surface is declared supported without an installer that can place it', () => {
  const INSTALLABLE = new Set(['agents-md', 'native-file', 'skills-dir', 'json', 'toml', 'blocking-hook', 'plugin']);
  for (const caps of reg.fidelityMatrix()) {
    for (const [surface, s] of Object.entries(caps.surfaces)) {
      if (s.fidelity === 'unsupported') continue;
      assert.ok(INSTALLABLE.has(s.mechanism.kind),
        `${caps.id}.${surface}: fidelity ${s.fidelity} with mechanism ${s.mechanism.kind}, which no installer implements`);
    }
  }
});

test('only one installer is active for any harness surface: legacy bind writers never auto-select', async () => {
  // Two installers competing for one surface is the failure this pass removed.
  // bind's Claude Code, Codex and AGENTS.md writers are retired or quarantined:
  // none of them may auto-detect, so `legion bind --write` with no explicit
  // --harness can never race the adapter seam.
  const quarantined = ['claude-code', 'codex', 'agents-md'];
  for (const name of quarantined) {
    const mod = await import(`../src/lib/cli/commands/bind/${name}.mjs`);
    await withRepo(async (root) => {
      mkdirSync(join(root, '.codex'), { recursive: true });
      mkdirSync(join(root, '.claude'), { recursive: true });
      writeFileSync(join(root, 'AGENTS.md'), '# anything\n');
      assert.equal(mod.detect(root), false, `bind/${name} must never auto-select`);
    });
  }
});

test('explicit Claude bind remains a read-only retirement receipt', async () => {
  const claude = await import('../src/lib/cli/commands/bind/claude-code.mjs');
  await withRepo(async (root) => {
    mkdirSync(join(root, '.claude'), { recursive: true });
    assert.equal(claude.present(root), true);
    assert.equal(claude.RETIRED, true);
    assert.deepEqual(claude.targets(root), []);
    assert.deepEqual(claude.plan(root), []);
    assert.deepEqual(claude.write(root), { wrote: [], wouldWrite: [] });
    assert.match(claude.RETIREMENT_NOTE, /plugin package/);
  });
});

// ---- 8. real harness discovery smoke test (opt-in, never a CI dependency) --
//
// Proving that files exist on disk is not proof that a harness FINDS them. The
// only locally checkable harness with a read-only discovery command is Codex
// (`codex mcp list`), so that one is exercised for real — but only when the
// binary is present. An absent harness binary must never be a mandatory CI
// dependency, so this test skips rather than fails.
//
// Cline and Command Code are installed on some developer machines but expose no
// read-only "what did you discover" command: confirming discovery there means
// running a model session (network + spend), which does not belong in a test
// suite. Their surfaces stay covered by the descriptor-fidelity tests above.
import { spawnSync } from 'node:child_process';

const codexAvailable = (() => {
  const probe = spawnSync('codex', ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' });
  return probe.status === 0;
})();

test('codex actually discovers the MCP server the installer registered', { skip: codexAvailable ? false : 'codex binary not installed on this machine' }, () => {
  withRepo((root) => {
    reg.install('codex', { root });
    const out = spawnSync('codex', ['mcp', 'list'], {
      cwd: root, encoding: 'utf8', shell: process.platform === 'win32',
      env: { ...process.env, CODEX_HOME: join(root, '.codex') },
    });
    assert.equal(out.status, 0, `codex mcp list failed: ${out.stderr}`);
    assert.match(out.stdout, /legion/, 'codex must list the legion server Legion registered');
  });
});
