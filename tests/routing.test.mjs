import assert from 'node:assert/strict';
import test from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadRoutingGroups, resolveDomain, resolveGroupChild, validateRoutingGroups } from '../src/lib/routing/index.mjs';
import { validateCommercialLenses } from '../src/lib/lenses/routing.mjs';

const ROOT = resolve(import.meta.dirname, '..');

test('grouping domains resolve capabilities from the canonical catalog', () => {
  const results = ['engineering', 'commercial', 'research', 'editorial', 'design'].map((id) => resolveDomain(ROOT, id));
  assert.equal(results[0].status, 'resolved');
  assert.deepEqual(results.slice(1).map(({ status }) => status), ['resolved', 'resolved', 'resolved', 'resolved']);
  assert.ok(results.every(({ capabilities }) => capabilities.length > 0));
  // Groups carry catalog capabilities, never roles, and never routing targetType.
  for (const { capabilities } of results) {
    for (const capability of capabilities) {
      assert.equal(capability.id.startsWith('sage') || capability.id.startsWith('alchemist') || capability.id.startsWith('oracle'), false, 'roles are not grouping children');
      assert.equal(capability.targetType, undefined, 'grouping children carry no routing targetType');
      assert.equal(capability.manifest, `skills/manifests/${capability.id}.json`);
    }
  }
});

test('registry is the single source of grouping children (RTE-001)', () => {
  const registry = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/routing/domains.json'), 'utf8'));
  const graph = loadRoutingGroups(ROOT);
  for (const domain of registry.domains) {
    const actual = graph.domains.find(({ id }) => id === domain.id);
    assert.deepEqual(
      actual.children.map(({ id }) => id),
      (domain.children ?? []).map(({ id }) => id),
      `${domain.id} children come from the registry`,
    );
  }
});

test('grouping projection is capabilities-only; every child resolves to a catalog capability', () => {
  const report = validateRoutingGroups(loadRoutingGroups(ROOT));
  assert.equal(report.ok, true, JSON.stringify(report.findings));
  const graph = loadRoutingGroups(ROOT);
  const index = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/skills/index.json'), 'utf8'));
  for (const domain of graph.domains) {
    for (const child of domain.children ?? []) {
      const record = resolveGroupChild(index, child.id);
      assert.ok(record, `${child.id} is a catalog capability`);
      assert.equal(record.id, child.id);
    }
  }
});

test('validator rejects duplicate groups, non-catalog children, and dangling members', () => {
  const graph = loadRoutingGroups(ROOT);
  const invalid = structuredClone(graph);
  invalid.domains.push(structuredClone(invalid.domains[0]));
  invalid.domains[0].children.push({ id: 'not-a-capability' });
  invalid.domains[0].children.push({ id: 'sage' });
  const report = validateRoutingGroups(invalid);
  assert.equal(report.ok, false);
  assert.ok(report.findings.some(({ code }) => code === 'duplicate-root'));
  assert.equal(report.findings.filter(({ code }) => code === 'dangling-target').length, 2);
});

test('routing compatibility preserves provider/audit lens ids', () => {
  const expected = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/lenses/commercial-routing.json'), 'utf8')).lenses.slice().sort();
  const report = validateCommercialLenses(ROOT);
  assert.equal(report.ok, true, JSON.stringify(report.findings));
  assert.deepEqual(report.lensIds, expected);
});
