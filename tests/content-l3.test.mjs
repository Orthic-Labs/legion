import test from 'node:test';
import assert from 'node:assert/strict';

import { detectAntiSlop } from '../providers/copy/anti-slop.mjs';
import { analyzeClarity } from '../providers/copy/clarity.mjs';
import { analyzeDocumentation } from '../providers/copy/documentation.mjs';
import { assessChronology } from '../providers/narrative/chronology.mjs';

const binding = { repository: 'sha256:fixture-repository' };

test('B6-013 requires context, preserves technical near misses, and records feature vectors', () => {
  const result = detectAntiSlop([
    {
      id: 'copy:generic',
      text: "In today's fast-paced world, our revolutionary platform delivers the best results.",
      surface: { type: 'paragraph' },
      audience: 'engineering leaders',
      purpose: 'explain product value',
      claimRefs: ['claim:best'],
      evidenceRefs: [],
      binding,
    },
    {
      id: 'copy:technical',
      text: 'Select the best-fit algorithm for this data set.',
      surface: { type: 'documentation' },
      audience: 'data engineers',
      purpose: 'give a precise configuration instruction',
      constraints: { technicalTerms: ['best-fit'] },
      evidenceRefs: ['evidence:algorithm-doc'],
      binding,
    },
    {
      id: 'copy:single-word',
      text: 'Revolutionary',
      surface: { type: 'heading' },
      audience: 'buyers',
      purpose: 'name a report section',
      evidenceRefs: [],
      binding,
    },
  ], {
    claimProofLedger: {
      claims: [{ id: 'claim:best', disposition: 'unproven', evidenceRefs: [] }],
    },
    binding,
  });

  assert.equal(result.provider, 'copy.anti-slop');
  assert.equal(result.status, 'candidates');
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.anti-slop.generic-opener'));
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.anti-slop.unsupported-superlative'));
  assert.equal(result.candidates.some(({ contentItemIds }) => contentItemIds.includes('copy:technical')), false);
  assert.equal(result.candidates.some(({ contentItemIds }) => contentItemIds.includes('copy:single-word')), false);
  for (const candidate of result.candidates) {
    assert.equal(candidate.kind, 'legion-copy-candidate');
    assert.equal(candidate.verdict, 'UNADJUDICATED');
    assert.equal(candidate.detectorKind, 'interpretive');
    assert.ok(candidate.featureVector.context);
    assert.ok(candidate.claim.includes('because'));
    assert.deepEqual(candidate.binding, binding);
  }
});

test('B6-013 emits deterministic findings only for explicit policy bans', () => {
  const result = detectAntiSlop([
    {
      id: 'copy:banned',
      text: 'Guaranteed profit arrives tomorrow.',
      surface: { type: 'paragraph' },
      audience: 'investors',
      purpose: 'state expected outcome',
      evidenceRefs: [],
      binding,
    },
  ], {
    explicitBans: [{ id: 'claims.no-guaranteed-profit', phrase: 'guaranteed profit' }],
    binding,
  });

  assert.deepEqual(result.findings.map(({ ruleId }) => ruleId), ['claims.no-guaranteed-profit']);
  assert.equal(result.findings[0].detectorKind, 'deterministic');
  assert.deepEqual(result.findings[0].contentItemIds, ['copy:banned']);
});

test('B6-014 binds clarity candidates to audience, role, exact spans, and safe suggestions', () => {
  const result = analyzeClarity([
    {
      id: 'copy:clarity',
      text: 'It may perhaps facilitate utilization of the service.',
      surface: { type: 'hint', controlId: 'service-access' },
      audience: 'first-time users',
      purpose: 'explain how to use the service',
      evidenceRefs: ['evidence:hint'],
      binding,
    },
    {
      id: 'copy:technical-clarity',
      text: 'Rotate the nonce before retrying authenticated encryption.',
      surface: { type: 'documentation' },
      audience: 'cryptography engineers',
      purpose: 'preserve nonce uniqueness',
      constraints: { requiredTerms: ['nonce'], explainedTerms: ['nonce'] },
      binding,
    },
  ], { binding });

  assert.equal(result.status, 'candidates');
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.clarity.ambiguous-pronoun'));
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.clarity.repeated-hedge'));
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.clarity.nominalization'));
  assert.equal(result.candidates.some(({ contentItemIds }) => contentItemIds.includes('copy:technical-clarity')), false);
  for (const candidate of result.candidates) {
    assert.equal(candidate.audience, 'first-time users');
    assert.equal(candidate.contentRole, 'hint');
    assert.ok(candidate.span.text);
    assert.ok(Number.isInteger(candidate.span.start));
    assert.ok(candidate.suggestion);
    assert.equal(candidate.suggestionKind, 'meaning-preserving-editorial-option');
  }
});

test('B6-014 makes known control-label contradictions deterministic', () => {
  const result = analyzeClarity([
    {
      id: 'copy:label',
      text: 'Delete draft',
      surface: { type: 'button', controlId: 'publish-draft' },
      audience: 'editors',
      purpose: 'publish a draft',
      binding,
    },
  ], {
    controls: [{ id: 'publish-draft', action: 'publish', outcome: 'draft becomes public' }],
    binding,
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'copy.clarity.control-label-contradiction');
  assert.equal(result.findings[0].detectorKind, 'deterministic');
  assert.equal(result.findings[0].control.action, 'publish');
});

test('B6-021 binds command examples to current contracts and separates factual drift', () => {
  const result = analyzeDocumentation([
    {
      id: 'docs:command-current',
      text: 'Run `legion scan --dry-run` after creating legion.json.',
      kind: 'command-help',
      commandId: 'scan',
      examples: ['legion scan --dry-run'],
      prerequisiteRefs: ['config:legion'],
      audience: 'operators',
      evidenceRefs: ['contract:scan'],
      binding,
    },
    {
      id: 'docs:command-stale',
      text: 'Run `legion scan --legacy`.',
      kind: 'command-help',
      commandId: 'scan',
      examples: ['legion scan --legacy'],
      audience: 'operators',
      binding,
    },
    {
      id: 'docs:release-planned',
      text: 'Legion now ships remote mutation.',
      kind: 'release-note',
      releaseState: 'planned',
      claimsShipped: true,
      audience: 'customers',
      binding,
    },
  ], {
    commandContracts: [{
      id: 'scan',
      command: 'legion scan',
      options: ['--dry-run'],
      prerequisites: ['config:legion'],
      evidenceRefs: ['contract:scan'],
    }],
    binding,
  });

  assert.equal(result.commandBindings[0].status, 'bound');
  assert.deepEqual(result.commandBindings[0].examples, ['legion scan --dry-run']);
  assert.ok(result.findings.some(({ ruleId, contentItemIds }) =>
    ruleId === 'copy.documentation.command-contract-drift' && contentItemIds.includes('docs:command-stale')));
  assert.ok(result.findings.some(({ ruleId, contentItemIds }) =>
    ruleId === 'copy.documentation.planned-as-shipped' && contentItemIds.includes('docs:release-planned')));
  assert.equal(result.candidates.length, 0);
});

test('B6-021 keeps editorial polish separate and never suggests legal notice rewrites', () => {
  const result = analyzeDocumentation([
    {
      id: 'docs:editorial',
      text: 'It should be noted that the command writes the report.',
      kind: 'tutorial',
      audience: 'operators',
      purpose: 'explain command side effects',
      binding,
    },
    {
      id: 'docs:legal',
      text: 'It should be noted that all rights are reserved.',
      kind: 'legal-notice',
      authority: 'legal',
      audience: 'customers',
      binding,
    },
  ], { binding });

  assert.deepEqual(result.candidates.map(({ contentItemIds }) => contentItemIds), [['docs:editorial']]);
  assert.equal(result.candidates[0].category, 'editorial-polish');
  assert.ok(result.coverageGaps.includes('authority-required:docs:legal'));
});

test('B6-025 blocks evidence-backed false sequence and ignores reviewer booleans', () => {
  const model = {
    schemaVersion: 1,
    kind: 'legion-narrative-model',
    units: [
      { id: 'unit:hook', role: 'hook', sourceOrder: 0, coldOpen: true, contentItemIds: ['copy:hook'] },
      { id: 'unit:setup', role: 'setup', sourceOrder: 1, contentItemIds: ['copy:setup'] },
      { id: 'unit:claim', role: 'development', sourceOrder: 2, contentItemIds: ['copy:claim'] },
    ],
    edges: [
      { from: 'unit:setup', to: 'unit:hook', kind: 'explanation', strength: 'observed', evidenceRefs: ['evidence:setup'] },
      { from: 'unit:claim', to: 'unit:setup', kind: 'chronology', strength: 'observed', evidenceRefs: ['evidence:sequence'], reviewerApproved: true },
      { from: 'unit:hook', to: 'unit:claim', kind: 'causality', strength: 'inferred', evidenceRefs: [] },
      { from: 'unit:missing', to: 'unit:claim', kind: 'antecedent', strength: 'observed', evidenceRefs: ['evidence:graph'] },
    ],
    denominatorDigest: 'sha256:model-denominator',
    binding,
  };

  const result = assessChronology(model);
  assert.ok(result.findings.some(({ ruleId }) => ruleId === 'narrative.chronology.false-sequence'));
  assert.ok(result.findings.some(({ ruleId }) => ruleId === 'narrative.chronology.missing-antecedent'));
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'narrative.chronology.unsupported-causality'));
  const forbidden = result.alternateOrders.find(({ edge }) => edge.from === 'unit:claim' && edge.to === 'unit:setup');
  assert.equal(forbidden.classification, 'forbidden');
  assert.deepEqual(forbidden.evidenceRefs, ['evidence:sequence']);
});

test('B6-025 preserves truthful cold opens and keeps uncertain reordering review-required', () => {
  const result = assessChronology({
    schemaVersion: 1,
    kind: 'legion-narrative-model',
    units: [
      { id: 'unit:hook', role: 'hook', sourceOrder: 0, coldOpen: true, contentItemIds: ['copy:hook'] },
      { id: 'unit:setup', role: 'setup', sourceOrder: 1, contentItemIds: ['copy:setup'] },
      { id: 'unit:payoff', role: 'payoff', sourceOrder: 2, contentItemIds: ['copy:payoff'] },
    ],
    edges: [
      { from: 'unit:setup', to: 'unit:hook', kind: 'explanation', strength: 'observed', evidenceRefs: ['evidence:setup'] },
      { from: 'unit:setup', to: 'unit:payoff', kind: 'chronology', strength: 'inferred', evidenceRefs: [] },
    ],
    denominatorDigest: 'sha256:cold-open-denominator',
    binding,
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.candidates.length, 0);
  assert.ok(result.alternateOrders.some(({ classification }) => classification === 'review-required'));
  assert.equal(result.status, 'pass');
});

test('B6-013 every expanded anti-slop candidate has an explanatory claim', () => {
  const result = detectAntiSlop([
    { id: 'copy:repeat-1', text: 'Success innovation growth value.', audience: 'buyers', purpose: 'explain value', surface: { type: 'paragraph' }, binding },
    { id: 'copy:repeat-2', text: 'Success innovation growth value.', audience: 'buyers', purpose: 'explain value', surface: { type: 'paragraph' }, binding },
    { id: 'copy:filler', text: 'At the end of the day, teams ship reports.', audience: 'operators', purpose: 'explain outcome', surface: { type: 'paragraph' }, binding },
  ], { binding });

  assert.ok(result.candidates.length >= 3);
  assert.equal(result.candidates.some(({ claim }) => claim.startsWith('undefined')), false);
});

test('B6-014 does not treat a specific control label as a deterministic vague label', () => {
  const result = analyzeClarity([
    {
      id: 'copy:specific-label',
      text: 'Continue to dashboard',
      surface: { type: 'button', controlId: 'continue-dashboard' },
      audience: 'operators',
      purpose: 'open dashboard',
      binding,
    },
  ], {
    controls: [{ id: 'continue-dashboard', action: 'navigate', outcome: 'dashboard opens' }],
    binding,
  });

  assert.equal(result.findings.some(({ ruleId }) => ruleId === 'copy.clarity.control-label-vague'), false);
});

test('B6-021 requires a command token boundary and protects authority case-insensitively', () => {
  const result = analyzeDocumentation([
    {
      id: 'docs:prefix-collision',
      text: 'Run `legion scanner`.',
      kind: 'command-help',
      examples: ['legion scanner'],
      audience: 'operators',
      binding,
    },
    {
      id: 'docs:legal-case',
      text: 'It should be noted that all rights are reserved.',
      kind: 'notice',
      authority: 'Legal',
      audience: 'customers',
      binding,
    },
  ], {
    commandContracts: [{ id: 'scan', command: 'legion scan', options: [] }],
    binding,
  });

  const command = result.commandBindings.find(({ contentItemId }) => contentItemId === 'docs:prefix-collision');
  assert.equal(command.status, 'unbound');
  assert.equal(result.candidates.some(({ contentItemIds }) => contentItemIds.includes('docs:legal-case')), false);
  assert.ok(result.coverageGaps.includes('authority-required:docs:legal-case'));
});

test('B6-025 blocks duplicate unit identities and evidence-backed false attribution', () => {
  const result = assessChronology({
    schemaVersion: 1,
    kind: 'legion-narrative-model',
    units: [
      { id: 'unit:source-a', role: 'proof', sourceOrder: 0 },
      { id: 'unit:source-a', role: 'proof', sourceOrder: 1 },
      { id: 'unit:claim', role: 'development', sourceOrder: 2 },
    ],
    edges: [{
      from: 'unit:source-a',
      to: 'unit:claim',
      kind: 'attribution',
      expectedSourceId: 'unit:source-a',
      observedSourceId: 'unit:source-b',
      evidenceRefs: ['evidence:attribution'],
    }],
    binding,
  });

  assert.ok(result.findings.some(({ ruleId }) => ruleId === 'narrative.chronology.duplicate-unit-id'));
  assert.ok(result.findings.some(({ ruleId }) => ruleId === 'narrative.chronology.false-attribution'));
});
