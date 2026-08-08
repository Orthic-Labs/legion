// B7-020 Part 2: safety hazard model. SEPARATE from providers/security/**.
// Proves: every hazard states scope/hazards/assumptions/authorityLimits;
// every hazard's reasoning requirement is human-decision (never any other
// value) because every outcome class this model addresses is
// high-consequence; a hazard is never closable by a model/automated
// verdict, only by a human-decision closure; every hazard is never
// certifiable and never asserts a regulatory claim; every domain produces
// each of the seven required disposition counterparts; no module imports a
// live-probe-capable builtin or calls fetch(); the committed schema is
// byte-identical to the code-owned builder; registry <-> scanner rule-id
// parity holds both ways.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scanSafetyHazards, SAFETY_DOMAINS, SAFETY_RULE_IDS } from '../../providers/safety/scanner.mjs';
import { createHazardCandidate, assertHazard, closeHazard } from '../../providers/safety/hazard-model.mjs';
import { buildHazardModelSchema } from '../../providers/safety/schema-builder.mjs';
import { safetySchemaText } from '../../providers/safety/generate-schema.mjs';
import {
  HAZARD_DISPOSITION,
  OUTCOME_CLASS,
  REASONING_REQUIREMENT,
} from '../../providers/safety/contracts.mjs';

const SAFETY_MODULE_FILES = [
  'providers/safety/contracts.mjs',
  'providers/safety/hazard-model.mjs',
  'providers/safety/scanner.mjs',
  'providers/safety/schema-builder.mjs',
  'providers/safety/generate-schema.mjs',
].map((rel) => [rel, fileURLToPath(new URL(`../../${rel}`, import.meta.url))]);

const registryPath = fileURLToPath(new URL('../../registry/rules/safety/hazards.json', import.meta.url));
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));

// Fixture text per disposition, keyed the same way for every domain trigger:
// only the trigger call differs by domain, the surrounding signal markers
// are the shared, domain-agnostic vocabulary the scanner looks for.
function fixtureFor(triggerCall, disposition) {
  switch (disposition) {
    case 'positive': return `${triggerCall};`;
    case 'mitigated': return `if (interlockEnforced()) { ${triggerCall}; }`;
    case 'blocked': return `if (preconditionFailed()) { return; } ${triggerCall};`;
    case 'unsafe-degraded': return `degradedMode = "unsafe"; ${triggerCall};`;
    case 'missing-interlock': return `interlockBypassed(); ${triggerCall};`;
    case 'human-override': return `humanOverrideGranted(); ${triggerCall};`;
    case 'clean': return '// nothing hazardous here\nconst value = 1;';
    default: throw new Error(`unknown disposition ${disposition}`);
  }
}

// A minimal call matching each domain's own trigger regex (see
// providers/safety/scanner.mjs), reused across every disposition fixture for
// that domain. Kept as an explicit map (rather than derived from the regex)
// so a future trigger-pattern edit fails this test loudly instead of the
// derivation silently producing a non-matching call.
const TRIGGER_CALL_BY_DOMAIN = Object.freeze({
  'physical.direct-actuator-command': 'actuator.start(cmd)',
  'medical.dose-administration': 'administerDose(patient, dose)',
  'financial.irreversible-transfer': 'transferFunds(account, amount)',
  'child-facing.minor-data-collection': 'collectChildData(profile)',
  'operational.production-disruption-command': 'shutdownProductionService(service)',
  'irreversible.destructive-account-action': 'factoryReset(device)',
  'catastrophic-data-loss.bulk-destructive-operation': 'dropDatabase(name)',
});

function triggerCallFor(domain) {
  const call = TRIGGER_CALL_BY_DOMAIN[domain.id];
  if (!call) throw new Error(`no test trigger call registered for safety domain ${domain.id}`);
  assert.match(`${call};`, domain.trigger, `test trigger call for ${domain.id} does not actually match its own scanner trigger pattern`);
  return call;
}

// ---------------------------------------------------------------------------
// Registry <-> scanner rule-id parity (both directions).
// ---------------------------------------------------------------------------

test('registry/rules/safety/hazards.json and the scanner domains are in exact rule-id parity', () => {
  assert.equal(registry.schemaVersion, 1);
  const registryIds = new Set(registry.hazards.map((h) => h.id));
  const scannerIds = new Set(SAFETY_RULE_IDS);
  for (const id of scannerIds) assert.ok(registryIds.has(id), `registry is missing scanner rule ${id}`);
  for (const id of registryIds) assert.ok(scannerIds.has(id), `registry has an orphan rule ${id} not produced by the scanner`);
  assert.equal(registryIds.size, scannerIds.size);
  for (const entry of registry.hazards) {
    assert.equal(entry.reasoningRequirement, 'human-decision');
    assert.equal(entry.certifiable, false);
    assert.equal(entry.regulatoryClaim, null);
    assert.ok(OUTCOME_CLASS.includes(entry.outcomeClass));
  }
});

// ---------------------------------------------------------------------------
// All 7 outcome classes are covered, one domain rule each.
// ---------------------------------------------------------------------------

test('the hazard scanner covers all seven required outcome classes', () => {
  const covered = new Set(SAFETY_DOMAINS.map((d) => d.outcomeClass));
  for (const outcomeClass of OUTCOME_CLASS) assert.ok(covered.has(outcomeClass), `missing outcome class ${outcomeClass}`);
  assert.equal(covered.size, OUTCOME_CLASS.length);
});

// ---------------------------------------------------------------------------
// Every domain produces each of the seven required disposition counterparts
// (positive/mitigated/blocked/unsafe-degraded/missing-interlock/
// human-override), plus 'clean' meaning no hazard fires at all.
// ---------------------------------------------------------------------------

test('every safety domain produces every required disposition counterpart from its own trigger', () => {
  for (const domain of SAFETY_DOMAINS) {
    const call = triggerCallFor(domain);
    for (const disposition of HAZARD_DISPOSITION) {
      const source = fixtureFor(call, disposition);
      const hazards = scanSafetyHazards({ files: ['a.js'], readFile: () => source, denominatorDigest: 'sha256:d' });
      const forDomain = hazards.filter((h) => h.domain === domain.id);
      if (disposition === 'clean') {
        assert.equal(forDomain.length, 0, `${domain.id} must not fire on a clean fixture`);
        continue;
      }
      assert.equal(forDomain.length, 1, `${domain.id} must fire exactly once on its ${disposition} fixture`);
      assert.equal(forDomain[0].disposition, disposition, `${domain.id} classified its ${disposition} fixture as ${forDomain[0].disposition}`);
    }
  }
});

// ---------------------------------------------------------------------------
// THE CRITICAL ONE: every hazard requires human-decision, never any other
// REASONING_REQUIREMENT value, and can only be closed by a human decision.
// ---------------------------------------------------------------------------

test('every emitted hazard requires human-decision reasoning, regardless of outcome class or disposition', () => {
  let total = 0;
  for (const domain of SAFETY_DOMAINS) {
    const call = triggerCallFor(domain);
    const hazards = scanSafetyHazards({ files: ['a.js'], readFile: () => `${call};`, denominatorDigest: 'sha256:d' });
    for (const hazard of hazards.filter((h) => h.domain === domain.id)) {
      total += 1;
      assert.equal(hazard.reasoningRequirement, 'human-decision');
      assert.ok(REASONING_REQUIREMENT.includes(hazard.reasoningRequirement));
      assert.equal(hazard.certifiable, false);
      assert.equal(hazard.regulatoryClaim, null);
      assert.ok(['review-required', 'unproven'].includes(hazard.status));
      assert.notEqual(hazard.status, 'certified');
    }
  }
  assert.equal(total, SAFETY_DOMAINS.length);
});

test('a hazard requiring human-decision cannot be closed by a model or automated verdict, only by a human decision', () => {
  const domain = SAFETY_DOMAINS[0];
  const call = triggerCallFor(domain);
  const [hazard] = scanSafetyHazards({ files: ['a.js'], readFile: () => `${call};`, denominatorDigest: 'sha256:d' })
    .filter((h) => h.domain === domain.id);
  assert.ok(hazard);

  for (const method of ['model-verdict', 'automated-verdict']) {
    assert.throws(
      () => closeHazard({ hazard, method, decidedBy: 'system', decision: 'accepted-risk', rationale: 'attempted non-human closure' }),
      /human-decision/,
      `closure via ${method} must be rejected`,
    );
  }

  const closure = closeHazard({
    hazard, method: 'human-decision', decidedBy: 'reviewer@example.com',
    decision: 'accepted-risk', rationale: 'reviewed by a qualified domain authority',
  });
  assert.equal(closure.kind, 'safety-hazard-closure');
  assert.equal(closure.method, 'human-decision');
  assert.equal(closure.hazardId, hazard.id);
});

test('createHazardCandidate refuses to build a hazard for an outcome class outside the defined vocabulary', () => {
  assert.throws(() => createHazardCandidate({
    domain: 'bogus.domain',
    outcomeClass: 'low-consequence-made-up',
    ruleId: 'bogus.rule',
    claim: 'x',
    severityHint: 'low',
    scope: { static: true, runtime: false, description: 'x' },
    hazards: ['x'],
    assumptions: ['x'],
    authorityLimits: ['x'],
    disposition: 'positive',
    misuseScenarios: ['x'],
    evidenceRefs: ['ev1'],
  }), /outcome class/);
});

// ---------------------------------------------------------------------------
// Structural requirements: non-empty scope/hazards/assumptions/
// authorityLimits/misuseScenarios/evidenceRefs on every hazard; assertHazard
// validates the shape.
// ---------------------------------------------------------------------------

test('every hazard states a non-empty static/runtime scope, hazards, assumptions, authority limits, misuse scenarios, and evidence', () => {
  for (const domain of SAFETY_DOMAINS) {
    const call = triggerCallFor(domain);
    const hazards = scanSafetyHazards({ files: ['a.js'], readFile: () => `${call};`, denominatorDigest: 'sha256:d' })
      .filter((h) => h.domain === domain.id);
    for (const hazard of hazards) {
      assertHazard(hazard);
      assert.equal(typeof hazard.scope.static, 'boolean');
      assert.equal(typeof hazard.scope.runtime, 'boolean');
      assert.ok(hazard.scope.description.length > 0);
      assert.ok(hazard.hazards.length > 0);
      assert.ok(hazard.assumptions.length > 0);
      assert.ok(hazard.authorityLimits.length > 0);
      assert.ok(hazard.misuseScenarios.length > 0);
      assert.ok(hazard.evidenceRefs.length > 0);
    }
  }
});

// ---------------------------------------------------------------------------
// Missing qualified domain evidence yields review-required or unproven,
// never a certification — and no string anywhere asserts compliance with a
// named standard.
// ---------------------------------------------------------------------------

test('no hazard status, claim, hazard, assumption, or authority-limit string ever certifies or asserts regulatory compliance', () => {
  const forbidden = /\bcertif|\bcomplian/i;
  const standards = /\bIEC\s*61508\b|\bISO\s*26262\b|\bFDA\b|\bUL\b/;
  for (const domain of SAFETY_DOMAINS) {
    const call = triggerCallFor(domain);
    const hazards = scanSafetyHazards({ files: ['a.js'], readFile: () => `${call};`, denominatorDigest: 'sha256:d' })
      .filter((h) => h.domain === domain.id);
    for (const hazard of hazards) {
      assert.ok(!forbidden.test(hazard.claim), `${hazard.ruleId} claim uses certification/compliance language`);
      assert.notEqual(hazard.status, 'certified');
      for (const field of [hazard.hazards, hazard.assumptions, hazard.authorityLimits]) {
        for (const str of field) {
          assert.ok(!forbidden.test(str), `${hazard.ruleId}: "${str}" uses certification/compliance language`);
        }
      }
      // Standard names may appear only inside an explicit non-assertion
      // (authorityLimits), never inside the positive claim itself.
      assert.ok(!standards.test(hazard.claim), `${hazard.ruleId} claim names a regulatory standard directly`);
    }
  }
  for (const entry of registry.hazards) {
    assert.ok(!forbidden.test(entry.id), `registry hazard id ${entry.id} uses certification/compliance language`);
  }
});

// ---------------------------------------------------------------------------
// No offensive/live capability.
// ---------------------------------------------------------------------------

const FORBIDDEN_IMPORTS = ['node:http', 'node:https', 'node:net', 'node:dgram', 'node:child_process', 'node:serialport', 'serialport', 'usb'];

test('no safety module imports a live-probe-capable builtin, a serial/USB library, or calls fetch(', () => {
  for (const [name, path] of SAFETY_MODULE_FILES) {
    const source = readFileSync(path, 'utf8');
    for (const forbidden of FORBIDDEN_IMPORTS) {
      assert.ok(!source.includes(`'${forbidden}'`) && !source.includes(`"${forbidden}"`), `${name} must not import ${forbidden}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(source), `${name} must not call fetch(`);
  }
});

// ---------------------------------------------------------------------------
// Generated schema is byte-identical to the committed file.
// ---------------------------------------------------------------------------

test('generated hazard-model schema is byte-identical to the committed schemas/safety/hazard-model-v1.schema.json', () => {
  const committedPath = fileURLToPath(new URL('../../schemas/safety/hazard-model-v1.schema.json', import.meta.url));
  const committedText = readFileSync(committedPath, 'utf8');
  assert.equal(committedText, safetySchemaText(), 'committed schema drifted from the generator; run node providers/safety/generate-schema.mjs');
  assert.deepEqual(JSON.parse(committedText), buildHazardModelSchema());
});

test('the committed schema requires reasoningRequirement to be exactly human-decision and forbids certifiable/regulatoryClaim from being anything but false/null', () => {
  const schema = buildHazardModelSchema();
  assert.deepEqual(schema.properties.reasoningRequirement, { const: 'human-decision' });
  assert.deepEqual(schema.properties.certifiable, { const: false });
  assert.deepEqual(schema.properties.regulatoryClaim, { const: null });
  assert.ok(schema.required.includes('hazards'));
  assert.ok(schema.required.includes('assumptions'));
  assert.ok(schema.required.includes('authorityLimits'));
  assert.ok(schema.required.includes('scope'));
  assert.ok(schema.required.includes('misuseScenarios'));
});

// ---------------------------------------------------------------------------
// Determinism: same input produces deeply-equal output twice, no wall-clock.
// ---------------------------------------------------------------------------

test('scanning is deterministic: same input produces deeply-equal hazards twice, and no hazard carries a timestamp field', () => {
  const domain = SAFETY_DOMAINS[0];
  const call = triggerCallFor(domain);
  const run = () => scanSafetyHazards({ files: ['a.js'], readFile: () => `${call};`, denominatorDigest: 'sha256:d' });
  const first = run();
  const second = run();
  assert.deepEqual(first, second);
  for (const hazard of first) {
    assert.ok(!('timestamp' in hazard));
    assert.ok(!('createdAt' in hazard));
  }
});
