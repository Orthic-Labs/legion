import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadRoutingGraph, resolveDomain, validateRoutingGraph } from '../lib/routing/index.mjs';
import { validateCommercialLenses } from '../lib/lenses/routing.mjs';

const ROOT = resolve(import.meta.dirname, '..');

test('five canonical domains resolve through dispatch or packaged content', () => {
  const results = ['engineering', 'commercial', 'research', 'editorial', 'design'].map((id) => resolveDomain(ROOT, id));
  assert.equal(results[0].status, 'resolved');
  assert.deepEqual(results.slice(1).map(({ status }) => status), ['resolved', 'resolved', 'resolved', 'resolved']);
  assert.deepEqual(results[0].capabilities.map(({ targetType }) => targetType), ['agent-dispatch', 'agent-dispatch', 'agent-dispatch']);
  assert.ok(results.slice(1).every(({ capabilities }) => capabilities.length > 0));
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
  const expected = JSON.parse(readFileSync(resolve(ROOT, 'registry/lenses/commercial-routing.json'), 'utf8')).lenses.slice().sort();
  const report = validateCommercialLenses(ROOT);
  assert.equal(report.ok, true, JSON.stringify(report.findings));
  assert.deepEqual(report.lensIds, expected);
});
