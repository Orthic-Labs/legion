import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { loadSkill } from '../../src/lib/skills/loader.mjs';
import { resolveSkillInvocation, validateCapabilitySelection } from '../../src/lib/skills/resolver.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const aliases = JSON.parse(readFileSync(join(ROOT, 'src', 'config', 'capability-aliases.json'), 'utf8')).aliases;
const PUBLIC_ENTRYPOINTS = [
  'ads', 'alchemist', 'architect', 'audit', 'audit-fix', 'audit-visual', 'brand',
  'brand-identity', 'coder', 'commit', 'covenant', 'debugger', 'designer', 'dispatch',
  'gotchas', 'handoff', 'marketing', 'oracle', 'qa', 'research', 'seo', 'social', 'tasklist',
  'wake', 'writing',
];

test('legacy semantic aliases resolve only to packaged public Legion capabilities', () => {
  assert.equal(aliases['/jfdi'], '/alchemist');
  assert.equal(aliases['/council'], '/covenant');
  assert.equal(aliases['/blueprint'], undefined);

  for (const target of [aliases['/jfdi'], aliases['/council']]) {
    const capability = target.slice(1).split(' ', 1)[0];
    assert.equal(existsSync(join(ROOT, 'skills', capability, 'SKILL.md')), true, target);
  }

  assert.equal(Object.hasOwn(aliases, '/council-review'), false);
  assert.equal(Object.hasOwn(aliases, '/just-do-it'), false);
});

test('Blueprint remains a direct host capability, not a packaged skill', () => {
  const projection = JSON.parse(readFileSync(join(ROOT, 'src', 'registry', 'host-projection.json'), 'utf8'));
  assert.equal(projection.capabilities.some(({ id }) => id === 'blueprint'), false);
  assert.equal(projection.hostCapabilities.some(({ id }) => id === 'blueprint-graph'), true);
});

test('canonical & legacy commands resolve through packaged manifests with negative boundaries', () => {
  for (const id of PUBLIC_ENTRYPOINTS) {
    const resolved = resolveSkillInvocation(`/${id} example`, { root: ROOT });
    if (existsSync(join(ROOT, 'skills', id, 'SKILL.md'))) {
      assert.equal(resolved.status, 'resolved', id);
      assert.equal(resolved.canonical, id, id);
    }
  }
  assert.equal(resolveSkillInvocation('/jfdi execute', { root: ROOT }).canonical, 'alchemist');
  assert.equal(resolveSkillInvocation('/council review', { root: ROOT }).canonical, 'covenant');
  assert.equal(resolveSkillInvocation('/blueprint map', { root: ROOT }).status, 'not-found');
  assert.equal(resolveSkillInvocation('/glass refine header', { root: ROOT }).resolvedInvocation, '/designer glass refine header');
  assert.equal(resolveSkillInvocation('/motion hero', { root: ROOT }).resolvedInvocation, '/designer motion hero');
  assert.equal(resolveSkillInvocation('/hormozi launch', { root: ROOT }).resolvedInvocation, '/marketing offer launch');
  assert.equal(resolveSkillInvocation('/test-author auth', { root: ROOT }).resolvedInvocation, '/audit contract-tests auth');
  assert.equal(resolveSkillInvocation('/council-review', { root: ROOT }).status, 'not-found');
  assert.equal(resolveSkillInvocation('/just-do-it', { root: ROOT }).status, 'not-found');
  assert.equal(resolveSkillInvocation('Please explain why this test fails.', { root: ROOT }).status, 'not-found');
});

test('public entrypoints do not route into deleted workspace skill roots', () => {
  for (const id of PUBLIC_ENTRYPOINTS) {
    const body = readFileSync(join(ROOT, 'skills', id, 'SKILL.md'), 'utf8');
    assert.doesNotMatch(body, /\.\.\/\.\.\/\.\.\/[^\s`]+\/SKILL\.md/, id);
  }
  assert.match(readFileSync(join(ROOT, 'skills', 'commit', 'SKILL.md'), 'utf8'), /references\/manual\.md/);
});

test('public entrypoint registry resolves digest-bound, non-publishable bundles', async () => {
  const index = JSON.parse(readFileSync(join(ROOT, 'src', 'registry', 'skills', 'index.json'), 'utf8'));
  const manifests = new Map(index.bundles.map(({ id, manifest }) => [id, manifest]));
  const loadedManifests = Object.fromEntries(index.bundles.map(({ id, manifest }) => [
    id,
    JSON.parse(readFileSync(join(ROOT, manifest), 'utf8')),
  ]));

  for (const id of PUBLIC_ENTRYPOINTS) {
    const manifestPath = manifests.get(id);
    assert.ok(manifestPath, `${id} registry entry`);
    const manifest = JSON.parse(readFileSync(join(ROOT, manifestPath), 'utf8'));
    assert.equal(manifest.id, id);
    assert.equal(manifest.licenseState, 'licensed');
    assert.ok(manifest.rightsReceipt, 'rights receipt present');
    assert.equal(manifest.profiles.audit.publish, false);
    assert.equal(manifest.profiles.authoring.publish, false);

    for (const file of manifest.files) {
      const path = join(ROOT, 'skills', id, file.path);
      assert.equal(existsSync(path), true, `${id}/${file.path}`);
      const digest = `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
      assert.equal(file.digest, digest, `${id}/${file.path} digest`);
    }
    const loaded = await loadSkill(`legion-skill://${id}/SKILL.md`, {
      packageRoot: ROOT,
      manifests: loadedManifests,
      profile: 'audit',
    });
    assert.equal(loaded.state, 'ready', id);
  }
});

test('all routed eval cases remain after capability migration', () => {
  const evalPaths = [
    'skills/handoff/evals/evals.json',
    'skills/architect/evals/evals.json',
    'skills/debugger/evals/evals.json',
    'skills/tasklist/evals/evals.json',
    'skills/dispatch/evals/evals.json',
    'skills/coder/evals/evals.json',
    'skills/qa/evals/evals.json',
    'skills/alchemist/evals/legacy-jfdi.json',
    'skills/covenant/evals/legacy-council.json',
  ];
  const count = evalPaths.reduce((total, path) => {
    const corpus = JSON.parse(readFileSync(join(ROOT, path), 'utf8'));
    return total + Object.entries(corpus)
      .filter(([key, value]) => !['schema_version', 'skill', 'legacy_skill'].includes(key) && Array.isArray(value))
      .reduce((sum, [, rows]) => sum + rows.length, 0);
  }, 0);
  assert.equal(count, 115);
});

test('deterministic selection validation accepts semantic public capabilities and rejects entrypoints', () => {
  const semantic = validateCapabilitySelection({ ids: ['architect', 'audit', 'dispatch'], source: 'semantic' }, { root: ROOT });
  assert.equal(semantic.status, 'resolved');
  assert.equal(semantic.resolved.length, 3);

  // Explicit-only entrypoints are excluded from automatic semantic selection.
  for (const entrypoint of ['alchemist', 'covenant', 'commit', 'coder']) {
    const rejected = validateCapabilitySelection({ ids: [entrypoint], source: 'semantic' }, { root: ROOT });
    assert.equal(rejected.status, 'invalid', `${entrypoint} must not be semantically selected`);
    assert.equal(rejected.invalid[0].reason, 'not-capability');
  }

  // Explicit source may resolve entrypoints per alias/config.
  const explicit = validateCapabilitySelection({ ids: ['alchemist'], source: 'explicit' }, { root: ROOT });
  assert.equal(explicit.status, 'resolved');
});
