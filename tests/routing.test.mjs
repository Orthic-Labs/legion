import assert from 'node:assert/strict';
import test from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadRoutingGraph, resolveDomain, targetExists, validateRoutingGraph } from '../src/lib/routing/index.mjs';
import { validateCommercialLenses } from '../src/lib/lenses/routing.mjs';

const ROOT = resolve(import.meta.dirname, '..');

test('five canonical domains resolve through dispatch or packaged content', () => {
  const results = ['engineering', 'commercial', 'research', 'editorial', 'design'].map((id) => resolveDomain(ROOT, id));
  assert.equal(results[0].status, 'resolved');
  assert.deepEqual(results.slice(1).map(({ status }) => status), ['resolved', 'resolved', 'resolved', 'resolved']);
  assert.deepEqual(results[0].capabilities.map(({ targetType }) => targetType), ['agent-dispatch', 'agent-dispatch', 'agent-dispatch']);
  assert.ok(results.slice(1).every(({ capabilities }) => capabilities.length > 0));
});

test('advisory leaves are reachable, not merely status-resolved (RTE-004)', () => {
  // The prior assertions checked `status` only, so a domain reported `resolved`
  // while every child carried availability 'unavailable' and nothing could be
  // dispatched. Availability must be derived from the leaf actually resolving.
  for (const id of ['commercial', 'research', 'editorial', 'design']) {
    const { status, capabilities } = resolveDomain(ROOT, id);
    assert.equal(status, 'resolved', id);
    assert.ok(capabilities.length > 0, `${id} has children`);
    for (const leaf of capabilities) {
      assert.equal(leaf.availability, 'available', `${id}/${leaf.id} availability`);
      assert.ok(targetExists(ROOT, leaf), `${id}/${leaf.id} targetRef resolves`);
      const manifest = JSON.parse(readFileSync(resolve(ROOT, leaf.targetRef), 'utf8'));
      const entry = resolve(ROOT, 'skills', leaf.id, manifest.entry);
      assert.ok(existsSync(entry), `${id}/${leaf.id} entrypoint ${manifest.entry} exists`);
    }
  }
});

test('registry is the single source of advisory children (RTE-001)', () => {
  const registry = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/routing/domains.json'), 'utf8'));
  const graph = loadRoutingGraph(ROOT);
  for (const domain of registry.domains) {
    const actual = graph.domains.find(({ id }) => id === domain.id);
    assert.deepEqual(
      actual.children.map(({ id }) => id),
      (domain.children ?? []).map(({ id }) => id),
      `${domain.id} children come from the registry`,
    );
  }
});

test('routing projection keeps engineering dispatch-only and advisory content-only', () => {
  const report = validateRoutingGraph(loadRoutingGraph(ROOT));
  assert.equal(report.ok, true, JSON.stringify(report.findings));
  const graph = loadRoutingGraph(ROOT);
  for (const domain of graph.domains) {
    const expected = domain.id === 'engineering' ? 'agent-dispatch' : 'content';
    assert.ok((domain.children ?? []).every(({ targetType }) => targetType === expected));
  }
});

test('validator rejects duplicate roots, mixed leaf types, and dangling targets', () => {
  const graph = loadRoutingGraph(ROOT);
  const invalid = structuredClone(graph);
  invalid.domains.push(structuredClone(invalid.domains[0]));
  invalid.domains[0].children[0].targetType = 'content';
  invalid.domains[0].children[1].targetRef = 'roster/missing.md';
  invalid.domains[0].children[2].targetRef = '../AGENTS.md';
  const report = validateRoutingGraph(invalid);
  assert.equal(report.ok, false);
  assert.ok(report.findings.some(({ code }) => code === 'duplicate-root'));
  assert.ok(report.findings.some(({ code }) => code === 'mixed-leaf-type'));
  assert.equal(report.findings.filter(({ code }) => code === 'dangling-target').length, 2);
});

test('routing compatibility preserves provider/audit lens ids', () => {
  const expected = JSON.parse(readFileSync(resolve(ROOT, 'src/registry/lenses/commercial-routing.json'), 'utf8')).lenses.slice().sort();
  const report = validateCommercialLenses(ROOT);
  assert.equal(report.ok, true, JSON.stringify(report.findings));
  assert.deepEqual(report.lensIds, expected);
});
