import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { loadSkill } from '../../lib/skills/loader.mjs';
import { resolveSkillInvocation, resolveSkillPrompt } from '../../lib/skills/resolver.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const aliases = JSON.parse(readFileSync(join(ROOT, '_audit', 'capability-aliases.json'), 'utf8')).aliases;
const PUBLIC_ENTRYPOINTS = [
  'alchemist', 'architect', 'audit', 'audit-fix', 'audit-visual', 'brand', 'coder',
  'commit', 'compshop', 'content', 'cortex', 'covenant', 'debugger', 'dispatch',
  'handoff', 'qa', 'tasklist',
];

test('legacy semantic aliases resolve only to packaged public Legion capabilities', () => {
  assert.equal(aliases['/jfdi'], '/alchemist');
  assert.equal(aliases['/council'], '/covenant');

  for (const target of [aliases['/jfdi'], aliases['/council']]) {
    const capability = target.slice(1).split(' ', 1)[0];
    assert.equal(existsSync(join(ROOT, 'skills', capability, 'SKILL.md')), true, target);
  }

  assert.equal(Object.hasOwn(aliases, '/council-review'), false);
  assert.equal(Object.hasOwn(aliases, '/just-do-it'), false);
});

test('canonical & legacy commands resolve through packaged manifests with negative boundaries', () => {
  for (const id of PUBLIC_ENTRYPOINTS) {
    const resolved = resolveSkillInvocation(`/${id} example`, { root: ROOT });
    assert.equal(resolved.status, 'resolved', id);
    assert.equal(resolved.canonical, id, id);
  }
  assert.equal(resolveSkillInvocation('/jfdi execute', { root: ROOT }).canonical, 'alchemist');
  assert.equal(resolveSkillInvocation('/council review', { root: ROOT }).canonical, 'covenant');
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
  const index = JSON.parse(readFileSync(join(ROOT, 'registry', 'skills', 'index.json'), 'utf8'));
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
    assert.equal(manifest.licenseState, 'unresolved');
    assert.equal(manifest.rightsReceipt, null);
    assert.equal(manifest.profiles.audit.publish, false);
    assert.equal(manifest.profiles.authoring.publish, false);

    for (const file of manifest.files) {
      const path = join(ROOT, 'skills', id, file.path);
      assert.equal(existsSync(path), true, `${id}/${file.path}`);
      const digest = `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
      assert.equal(file.outputDigest, digest, `${id}/${file.path} output digest`);
      assert.equal(file.sourceDigest, digest, `${id}/${file.path} source digest`);
    }
    const loaded = await loadSkill(`legion-skill://${id}/SKILL.md`, {
      packageRoot: ROOT,
      manifests: loadedManifests,
      profile: 'audit',
    });
    assert.equal(loaded.state, 'ready', id);
  }
});

test('all 110 retired eval cases are retained under canonical entrypoints', () => {
  const evalPaths = [
    'skills/handoff/../../tests/fixtures/handoff/legacy-evals.json',
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
  assert.equal(count, 110);
});

test('all 110 retired eval cases execute through resolver with declared route boundaries', () => {
  const evalPaths = [
    'tests/fixtures/handoff/legacy-evals.json',
    'skills/architect/evals/evals.json',
    'skills/debugger/evals/evals.json',
    'skills/tasklist/evals/evals.json',
    'skills/dispatch/evals/evals.json',
    'skills/coder/evals/evals.json',
    'skills/qa/evals/evals.json',
    'skills/alchemist/evals/legacy-jfdi.json',
    'skills/covenant/evals/legacy-council.json',
  ];
  const rows = evalPaths.flatMap((path) => Object.entries(JSON.parse(readFileSync(join(ROOT, path), 'utf8')))
    .filter(([key, value]) => !['schema_version', 'skill', 'legacy_skill'].includes(key) && Array.isArray(value))
    .flatMap(([, value]) => value));
  assert.equal(rows.length, 110);
  for (const row of rows) {
    const resolved = resolveSkillPrompt(row.prompt, { root: ROOT });
    assert.notEqual(resolved.status, 'invalid', row.id);
    const assertedExpected = (row.assertions ?? []).find(({ type }) => type === 'expected_skill')?.value;
    const expected = row.expected_skill ?? assertedExpected;
    if (expected !== undefined && expected !== null) assert.equal(resolved.canonical ?? '', expected, row.id);
    for (const forbidden of row.forbidden_skills ?? []) assert.notEqual(resolved.canonical, forbidden, row.id);
    for (const assertion of row.assertions ?? []) {
      if (assertion.type === 'forbidden_skill') assert.notEqual(resolved.canonical, assertion.value, row.id);
    }
  }
});
