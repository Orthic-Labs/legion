// Cross-harness conformance for the host adapter seam.
//
// These tests lock the invariants that make Legion harness-agnostic rather than
// "Claude works and everyone else gets AGENTS.md": the SAME canonical skill
// catalog reaches every harness, no adapter rewrites skill semantics, discovery
// counts match the canonical projection, declared fidelity is structurally sound,
// and adding a skill needs no per-harness edit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync, realpathSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as reg from '../src/lib/host/registry.mjs';
import { canonicalSkillIds } from '../src/lib/host/skill-projection.mjs';
import { SURFACES, FIDELITY } from '../src/lib/host/surfaces.mjs';

const LEGION = reg.LEGION_ROOT;
const CANON = canonicalSkillIds(LEGION);
// The harnesses whose skills mechanism is a projectable skills-dir (i.e. the
// adapter installs skills). Plugin-owned harnesses (Claude Code) ship skills
// through the package and are covered by the parity verifier instead.
const PROJECTING = reg.ADAPTER_IDS.filter((id) => {
  const s = reg.capabilities(id).surfaces.skills;
  return s.mechanism?.kind === 'skills-dir';
});

const withRepo = (fn) => {
  const root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), 'legion-harness-')));
  try { return fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
};

// 1. The same canonical skill catalog reaches every supported harness.
test('the same canonical skill catalog reaches every skill-projecting harness', () => {
  assert.ok(PROJECTING.length >= 4, `expected several projecting harnesses, got ${PROJECTING.join(',')}`);
  for (const id of PROJECTING) {
    withRepo((root) => {
      reg.install(id, { root });
      const dir = reg.capabilities(id).surfaces.skills.mechanism.path;
      const projected = readdirSync(join(root, dir)).sort();
      assert.deepEqual(projected, CANON, `${id}: projected skills must equal the canonical catalog`);
    });
  }
});

// 2. No adapter rewrites semantic skill content.
test('no adapter rewrites skill content: every projected SKILL.md is byte-identical to canonical', () => {
  for (const id of PROJECTING) {
    withRepo((root) => {
      reg.install(id, { root });
      const dir = reg.capabilities(id).surfaces.skills.mechanism.path;
      for (const skill of CANON) {
        const canonical = readFileSync(join(LEGION, 'skills', skill, 'SKILL.md'));
        const projected = readFileSync(join(root, dir, skill, 'SKILL.md'));
        assert.ok(canonical.equals(projected), `${id}: ${skill}/SKILL.md must be byte-identical to canonical`);
      }
    });
  }
});

// 3. Discovery counts match the canonical projection.
test('discovery counts match the canonical projection for every projecting harness', () => {
  for (const id of PROJECTING) {
    withRepo((root) => {
      reg.install(id, { root });
      const v = reg.verify(id, { root });
      assert.equal(v.surfaces.skills.total, CANON.length, `${id}: total`);
      assert.equal(v.surfaces.skills.present, CANON.length, `${id}: present`);
      assert.equal(v.surfaces.skills.missing.length, 0, `${id}: none missing`);
      assert.equal(v.surfaces.skills.forked.length, 0, `${id}: none forked`);
      assert.ok(v.ok, `${id}: verify overall`);
    });
  }
});

// 4. MCP / agents / hooks match declared fidelity, and enforcement is never
//    overclaimed for a harness without a blocking mechanism.
test('declared fidelity is structurally valid and enforcement is never overclaimed', () => {
  for (const caps of reg.fidelityMatrix()) {
    for (const surface of SURFACES) {
      const s = caps.surfaces[surface];
      assert.ok(FIDELITY.includes(s.fidelity), `${caps.id}.${surface}: valid fidelity`);
      // strong requires a real mechanism (not 'none').
      if (s.fidelity === 'strong') {
        assert.notEqual(s.mechanism.kind, 'none', `${caps.id}.${surface}: strong requires a mechanism`);
      }
      // unsupported must not carry a live install mechanism.
      if (s.fidelity === 'unsupported') {
        assert.ok(['none', undefined].includes(s.mechanism.kind), `${caps.id}.${surface}: unsupported must have no mechanism`);
      }
    }
    // Enforcement is only 'strong' with a blocking-hook transport.
    const hooks = caps.surfaces.hooks;
    if (hooks.fidelity === 'strong') {
      assert.equal(hooks.mechanism.kind, 'blocking-hook', `${caps.id}: strong hooks require a blocking-hook transport`);
    }
  }
});

test('MCP install matches the declared mechanism for each harness that supports it', () => {
  for (const id of reg.ADAPTER_IDS) {
    const mcp = reg.capabilities(id).surfaces.mcp;
    if (mcp.fidelity === 'unsupported' || mcp.mechanism.kind === 'plugin') continue;
    withRepo((root) => {
      reg.install(id, { root });
      const path = join(root, mcp.mechanism.path);
      assert.ok(existsSync(path), `${id}: MCP config ${mcp.mechanism.path} must be written`);
      const text = readFileSync(path, 'utf8');
      assert.match(text, /legion/, `${id}: MCP config must register the legion server`);
    });
  }
});

// 5. Adding a skill requires no harness-specific semantic edit.
test('adding a skill flows to every harness with no adapter change', () => {
  // A synthetic canonical skill added under a temp Legion-like tree would require
  // touching the real package; instead prove the projection is purely catalog-
  // driven: the projected set is exactly canonicalSkillIds with no per-harness
  // allow/deny list anywhere in the descriptors.
  for (const id of reg.ADAPTER_IDS) {
    const desc = reg.capabilities(id);
    const skillsMech = desc.surfaces.skills.mechanism;
    // No descriptor may enumerate individual skills — that would be a per-harness
    // semantic edit point. The mechanism carries only a location.
    assert.ok(!('skills' in skillsMech) && !('include' in skillsMech) && !('exclude' in skillsMech),
      `${id}: skills mechanism must not enumerate individual skills`);
  }
  // And the projecting harnesses all resolve their set from the same function.
  for (const id of PROJECTING) {
    withRepo((root) => {
      reg.install(id, { root });
      const dir = reg.capabilities(id).surfaces.skills.mechanism.path;
      assert.equal(readdirSync(join(root, dir)).length, CANON.length, `${id}: count is catalog-driven`);
    });
  }
});

// Generic/custom-harness adapter: a data-only descriptor drives the same engine.
test('a custom harness is supported by data alone via the generic adapter', () => {
  withRepo((root) => {
    mkdirSync(join(root, '.agents'), { recursive: true });
    writeFileSync(join(root, '.agents', 'legion-harness.json'), JSON.stringify({
      id: 'my-harness', displayName: 'My Harness',
      surfaces: { mcp: { fidelity: 'strong', mechanism: { kind: 'json', path: '.myharness/mcp.json', key: 'mcpServers' } } },
    }));
    const caps = reg.capabilities('generic', { root });
    assert.equal(caps.id, 'my-harness');
    assert.equal(caps.surfaces.mcp.fidelity, 'strong');
    reg.install('generic', { root });
    // Skills still project (default surface) and MCP lands where the data said.
    assert.equal(readdirSync(join(root, '.agents', 'skills')).length, CANON.length);
    assert.ok(existsSync(join(root, '.myharness', 'mcp.json')));
  });
});
