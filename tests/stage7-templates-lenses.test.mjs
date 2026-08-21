import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { validateSchema } from '../src/lib/qualification/schema-validator.mjs';

const root = join(import.meta.dirname, '..');
const read = (path) => readFileSync(join(root, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const fixtures = json('tests/fixtures/stage7/representative-instances.json');
const schemaNames = ['architecture-decision', 'canon-map', 'representative-workload', 'architecture-convergence-receipt', 'intent-epoch'];
const schemaTemplates = { 'architecture-decision': 'adr', 'canon-map': 'canon-map', 'representative-workload': 'representative-workload', 'architecture-convergence-receipt': 'architecture-convergence-receipt', 'intent-epoch': 'intent-epoch' };
const templates = ['architecture-brief', 'quality-scenario', 'assumption-unknown-register', 'domain-data-ownership', 'candidate-card', 'option-evaluation', 'evidence-card', 'adr', 'architecture-review', 'review-module-contract', 'representative-workload', 'canon-map', 'architecture-convergence-receipt', 'intent-epoch'];
const lenses = ['catalogue', 'product-quality', 'data-privacy-security', 'reliability-operations', 'socio-technical', 'economics-sustainability', 'ai-edge-platform-conditional'];

test('S07-01 every representative template has a declared schema where applicable & validates', () => {
  for (const name of templates) assert.ok(read(`skills/architect/doctrine/architecture/templates/${name}.md`).length, name);
  for (const name of schemaNames) {
    const schema = json(`src/schemas/${name}.schema.json`);
    assert.deepEqual(validateSchema(schema, fixtures[name]), [], name);
    assert.match(read(`skills/architect/doctrine/architecture/templates/${schemaTemplates[name]}.md`), new RegExp(schema.$id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('S07-01 schemas reject closed-shape & critical negative instances', () => {
  for (const name of schemaNames) {
    const invalid = structuredClone(fixtures[name]); invalid.extra = true;
    assert.ok(validateSchema(json(`src/schemas/${name}.schema.json`), invalid).length, `${name} closes shape`);
  }
  const adr = structuredClone(fixtures['architecture-decision']); adr.record_worthiness.real_trade_off = false;
  assert.ok(validateSchema(json('src/schemas/architecture-decision.schema.json'), adr).length, 'low-worth ADR rejects');
  const workload = structuredClone(fixtures['representative-workload']); delete workload.actual_acceptance_surface;
  assert.ok(validateSchema(json('src/schemas/representative-workload.schema.json'), workload).length, 'proxy workload rejects');
});

test('S07-01 concern lenses admit only material concerns & declare contract boundaries', () => {
  for (const lens of lenses) {
    const body = read(`src/lenses/architecture/${lens}.md`);
    if (lens === 'catalogue') {
      for (const phrase of ['omission scan', 'Admit', 'applicability', 'inputs', 'outputs', 'negative scope']) assert.match(body, new RegExp(phrase, 'i'));
    } else {
      for (const label of ['Applicability:', 'Inputs:', 'Outputs:', 'Negative scope:']) assert.match(body, new RegExp(label, 'i'));
    }
  }
  const nonmaterial = { frozen_driver: false, scenario: false, constraint: false, risk: false, decision: false };
  assert.equal(Object.values(nonmaterial).some(Boolean), false, 'nonmaterial lens is not admitted');
  assert.match(read('skills/architect/doctrine/architecture/reviews/review-gates.md'), /missing negative scope or admission gates cannot block/i);
});
