import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { resolveSkillInvocation, validateCapabilitySelection } from '../src/lib/skills/resolver.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const corpus = JSON.parse(readFileSync(resolve(ROOT, 'tests/fixtures/routing/semantic-routing-v1.json'), 'utf8'));
const catalog = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/skills/index.json'), 'utf8'));
const bundles = new Map(catalog.bundles.map((bundle) => [bundle.id, bundle]));

const OPERATIONS = new Set(['route', 'analyze', 'diagnose', 'decide', 'produce', 'evaluate', 'execute']);
const EFFECTS = new Set(['source-read', 'artifact-write', 'repository-write', 'process-exec', 'network-request']);
const AUTHORITIES = new Set(['sage', 'alchemist', 'oracle']);
const EXPLICIT_ONLY = new Set(['alchemist', 'covenant', 'dispatch', 'commit', 'coder']);
const LEGACY_NATURAL_ROUTES = new Set([
  'alchemist', 'architect', 'audit', 'commit', 'cortex', 'covenant', 'debugger',
  'dispatch', 'doctor', 'execution-preflight', 'handoff', 'marketing', 'qa', 'tasklist',
]);
const REQUIRED_CONCERNS = new Set([
  'public-discovery', 'zero-capability', 'single-capability', 'multi-capability',
  'capability-composition', 'workflow-capability', 'context-capability', 'explicit-only',
  'authority-independence', 'effect-authority-separation', 'assurance-boundary',
  'domain-not-routing', 'legacy-natural-route', 'minimal-pair-task-routing',
  'minimal-pair-brand', 'minimal-pair-coder', 'minimal-pair-audit-oracle',
  'minimal-pair-designer-visual', 'minimal-pair-architect-polysemy',
]);

test('semantic routing corpus covers M-027 acceptance dimensions and every retired natural route', () => {
  assert.equal(corpus.kind, 'legion-semantic-routing-eval');
  assert.equal(new Set(corpus.cases.map(({ id }) => id)).size, corpus.cases.length, 'case ids are unique');
  const concerns = new Set(corpus.cases.flatMap(({ concerns }) => concerns));
  assert.deepEqual([...REQUIRED_CONCERNS].filter((concern) => !concerns.has(concern)), []);
  const legacyRoutes = new Set(corpus.cases.filter(({ concerns: row }) => row.includes('legacy-natural-route')).map(({ legacyRoute }) => legacyRoute));
  assert.deepEqual([...legacyRoutes].sort(), [...LEGACY_NATURAL_ROUTES].sort());
});

test('corpus selections obey public semantic versus deterministic explicit boundaries', () => {
  for (const row of corpus.cases) {
    for (const field of ['expectedCapabilities', 'expectedEntrypoints', 'operations', 'effects', 'attachedAuthorities', 'forbiddenSelections']) {
      assert.ok(Array.isArray(row[field]), `${row.id}.${field} is an array`);
    }
    assert.ok(row.operations.every((value) => OPERATIONS.has(value)), `${row.id} uses canonical operations`);
    assert.ok(row.effects.every((value) => EFFECTS.has(value)), `${row.id} uses canonical effects`);
    assert.ok(row.attachedAuthorities.every((value) => AUTHORITIES.has(value)), `${row.id} uses canonical authorities`);
    assert.equal(row.attachedAuthorities.includes('covenant'), false, `${row.id}: Covenant is never authority`);

    if (row.source === 'semantic') {
      assert.deepEqual(row.expectedEntrypoints, [], `${row.id}: semantic selection contains no entrypoint`);
      const result = validateCapabilitySelection({ ids: row.expectedCapabilities, source: 'semantic' }, { root: ROOT });
      assert.equal(result.status, 'resolved', `${row.id}: ${JSON.stringify(result.invalid)}`);
      for (const id of row.expectedCapabilities) {
        assert.equal(bundles.get(id)?.kind, 'capability', `${row.id}: ${id} is a capability`);
        assert.equal(bundles.get(id)?.discoverability, 'public', `${row.id}: ${id} is public`);
      }
    } else {
      assert.equal(row.source, 'explicit', `${row.id}: declared source`);
      assert.deepEqual(row.expectedCapabilities, [], `${row.id}: explicit route contains no semantic capability`);
      const result = validateCapabilitySelection({ ids: row.expectedEntrypoints, source: 'explicit' }, { root: ROOT });
      assert.equal(result.status, 'resolved', `${row.id}: ${JSON.stringify(result.invalid)}`);
      const invocation = resolveSkillInvocation(row.prompt, { root: ROOT });
      assert.equal(invocation.status, 'resolved', `${row.id}: slash invocation resolves`);
      assert.equal(row.expectedEntrypoints.includes(invocation.canonical), true, `${row.id}: resolved canonical id`);
    }

    for (const id of row.forbiddenSelections) {
      assert.equal(row.expectedCapabilities.includes(id) || row.expectedEntrypoints.includes(id), false, `${row.id}: forbidden ${id} selected`);
    }
  }
});

test('explicit-only entrypoints cannot enter model-side semantic selections', () => {
  const semantic = validateCapabilitySelection({ ids: [...EXPLICIT_ONLY], source: 'semantic' }, { root: ROOT });
  assert.equal(semantic.status, 'invalid');
  assert.deepEqual(new Set(semantic.invalid.map(({ id }) => id)), EXPLICIT_ONLY);
  const explicit = validateCapabilitySelection({ ids: [...EXPLICIT_ONLY], source: 'explicit' }, { root: ROOT });
  assert.equal(explicit.status, 'resolved');
});

test('minimal-pair authority and assurance outcomes remain distinct', () => {
  const byId = new Map(corpus.cases.map((row) => [row.id, row]));
  assert.deepEqual(byId.get('routine-architect-no-sage').attachedAuthorities, []);
  assert.deepEqual(byId.get('unresolved-architect-sage').attachedAuthorities, ['sage']);
  assert.deepEqual(byId.get('routine-debugger-no-sage').attachedAuthorities, []);
  assert.deepEqual(byId.get('unresolved-acceptance-sage').attachedAuthorities, ['sage']);
  assert.deepEqual(byId.get('repository-write-not-alchemist').attachedAuthorities, []);
  assert.deepEqual(byId.get('execute-not-alchemist').attachedAuthorities, []);
  assert.deepEqual(byId.get('assurance-oracle-final').attachedAuthorities, ['oracle']);
  assert.deepEqual(byId.get('assurance-oracle-final').expectedCapabilities, []);
  assert.deepEqual(byId.get('assurance-audit-method').expectedCapabilities, ['audit']);
  assert.deepEqual(byId.get('assurance-designer-qualitative').expectedCapabilities, ['designer']);
  assert.deepEqual(byId.get('assurance-audit-visual-evidence').expectedCapabilities, ['audit-visual']);
});
