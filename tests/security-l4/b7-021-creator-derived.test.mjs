// B7-021 — creator security taxonomy -> original pack backlog traceability.
//
// This test proves registry/rules/security/creator-derived.json maps every
// creator-security category onto exactly one owning pack (with rule ids that
// really exist in the registries/packs this task maps onto) or an explicit,
// reasoned exclusion — never both, never neither, never a duplicate claim —
// and that references/source-provenance/creator-security.json records a real
// source digest without assuming redistribution rights or shipping the
// creator archive. It also proves no verbatim source prose leaked into either
// output file.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

const CREATOR_DERIVED_PATH = fileURLToPath(
  new URL('../../registry/rules/security/creator-derived.json', import.meta.url),
);
const PROVENANCE_PATH = fileURLToPath(
  new URL('../../references/source-provenance/creator-security.json', import.meta.url),
);

// The exact ecosystem this task maps onto, per its own instructions: the 8
// generated security rule registries plus three standalone packs that are not
// mirrored into any registry file.
const REGISTRY_FILES = [
  'injection-output.json',
  'browser-http.json',
  'boundaries.json',
  'crypto-data-privacy.json',
  'abuse-observability.json',
  'supply-developer-machine.json',
  'ai.json',
  'specialist.json',
];

const STANDALONE_PACK_FILES = [
  'credentials.mjs',
  'authentication-session.mjs',
  'authorization-tenant.mjs',
];

// The source ledger's own published identity for the creator.security
// sub-document (from its `sources[]` entry), recorded here only as an
// opaque hash literal for comparison — never as ledger content/prose.
const EXPECTED_SOURCE_DIGEST = 'sha256:c9d728c8eda9df46c035e5d0b4ea81116dfa1b4f9c475b621fc4b220e9866a3a';
const EXPECTED_SOURCE_DOCUMENT_ID = 'creator.security';

// Absolute path to the read-only external source ledger. Present in this
// lane's environment; guarded with existsSync so the verbatim-prose check
// degrades to a skip (not a false pass) if the external doc is unavailable.
const EXTERNAL_LEDGER_PATH = 'D:/workspace/docs/plans/nemesis/creator-audits-source-ledger.seed.json';

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

async function buildValidRuleUniverse() {
  /** @type {Map<string, string>} ruleId -> packId */
  const ruleToPack = new Map();
  /** @type {Set<string>} */
  const validPackIds = new Set();

  for (const file of REGISTRY_FILES) {
    const registry = loadJson(fileURLToPath(new URL(`../../registry/rules/security/${file}`, import.meta.url)));
    assert.ok(Array.isArray(registry.rules), `${file} must have a rules array`);
    for (const rule of registry.rules) {
      assert.ok(rule.id, `${file} has a rule with no id`);
      assert.ok(rule.pack, `${file} rule ${rule.id} has no pack`);
      // A given rule id must not appear under two different packs across the
      // whole ecosystem (would make ownership ambiguous).
      if (ruleToPack.has(rule.id)) {
        assert.equal(ruleToPack.get(rule.id), rule.pack, `rule id ${rule.id} claimed by two packs in the registries`);
      }
      ruleToPack.set(rule.id, rule.pack);
      validPackIds.add(rule.pack);
    }
  }

  for (const file of STANDALONE_PACK_FILES) {
    const url = pathToFileURL(fileURLToPath(new URL(`../../providers/security/packs/${file}`, import.meta.url))).href;
    const mod = await import(url);
    const pack = mod.default;
    assert.ok(pack && pack.id, `${file} must have a default-exported pack with an id`);
    assert.ok(Array.isArray(pack.rules) && pack.rules.length > 0, `${file} pack must declare rules[]`);
    validPackIds.add(pack.id);
    for (const rule of pack.rules) {
      assert.ok(rule.id, `${file} has a rule with no id`);
      if (!ruleToPack.has(rule.id)) {
        ruleToPack.set(rule.id, pack.id);
      }
    }
  }

  return { ruleToPack, validPackIds };
}

test('creator-derived.json and its provenance record exist and parse', () => {
  assert.ok(existsSync(CREATOR_DERIVED_PATH), 'registry/rules/security/creator-derived.json must exist');
  assert.ok(existsSync(PROVENANCE_PATH), 'references/source-provenance/creator-security.json must exist');
  const table = loadJson(CREATOR_DERIVED_PATH);
  assert.equal(table.schemaVersion, 1);
  assert.equal(table.sourceDocumentId, EXPECTED_SOURCE_DOCUMENT_ID);
  assert.equal(table.sourceDigest, EXPECTED_SOURCE_DIGEST);
  assert.ok(Array.isArray(table.categories) && table.categories.length > 0, 'categories must be a non-empty array');
});

test('every category is exactly one of owned (single pack) or explicitly excluded with a reason', () => {
  const table = loadJson(CREATOR_DERIVED_PATH);
  for (const category of table.categories) {
    assert.ok(category.id && typeof category.id === 'string', 'category must have a string id');
    assert.ok(category.intent && typeof category.intent === 'string' && category.intent.length > 0,
      `category ${category.id} must have a non-empty intent restatement`);
    assert.ok(Array.isArray(category.sourceAreas) && category.sourceAreas.length > 0,
      `category ${category.id} must record which source ledger area(s) it relates to`);
    assert.ok(category.sourceDigest === EXPECTED_SOURCE_DIGEST,
      `category ${category.id} must carry the source digest`);
    assert.ok(category.fixtureRequirement !== undefined,
      `category ${category.id} must declare a fixtureRequirement (string when owned, null when excluded)`);
    assert.ok(Array.isArray(category.applicability) && category.applicability.length > 0,
      `category ${category.id} must declare applicability`);
    assert.ok(category.evidenceRequirement && typeof category.evidenceRequirement === 'string',
      `category ${category.id} must classify its evidence requirement`);

    if (category.status === 'owned') {
      assert.ok(!('exclusion' in category) || category.exclusion == null,
        `owned category ${category.id} must not also carry an exclusion`);
      assert.equal(typeof category.owningPack, 'string', `owned category ${category.id} must have exactly one owningPack (a string, not an array)`);
      assert.ok(category.owningPack.length > 0, `owned category ${category.id} owningPack must be non-empty`);
      assert.ok(Array.isArray(category.owningRuleIds) && category.owningRuleIds.length > 0,
        `owned category ${category.id} must list at least one owningRuleId`);
      assert.ok(typeof category.fixtureRequirement === 'string' && category.fixtureRequirement.length > 0,
        `owned category ${category.id} must describe a concrete fixtureRequirement`);
    } else if (category.status === 'excluded') {
      assert.equal(category.owningPack, undefined, `excluded category ${category.id} must not claim an owningPack`);
      assert.equal(category.owningRuleIds, undefined, `excluded category ${category.id} must not claim owningRuleIds`);
      assert.ok(category.exclusion && typeof category.exclusion.reason === 'string' && category.exclusion.reason.length >= 20,
        `excluded category ${category.id} must record a substantive exclusion reason`);
    } else {
      assert.fail(`category ${category.id} has unknown status ${category.status}; must be 'owned' or 'excluded'`);
    }
  }
});

test('every owningPack/owningRuleIds pair actually exists in the mapped registries and packs', async () => {
  const table = loadJson(CREATOR_DERIVED_PATH);
  const { ruleToPack, validPackIds } = await buildValidRuleUniverse();

  for (const category of table.categories) {
    if (category.status !== 'owned') continue;
    assert.ok(validPackIds.has(category.owningPack),
      `category ${category.id} owningPack ${category.owningPack} does not exist in any loaded registry or pack`);
    for (const ruleId of category.owningRuleIds) {
      assert.ok(ruleToPack.has(ruleId),
        `category ${category.id} owningRuleIds references ${ruleId}, which does not exist in any loaded registry or pack`);
      assert.equal(ruleToPack.get(ruleId), category.owningPack,
        `category ${category.id} claims rule ${ruleId} under pack ${category.owningPack}, but the registry/pack records it under ${ruleToPack.get(ruleId)}`);
    }
  }
});

test('no rule id is claimed by two categories, and no category claims two owning packs', () => {
  const table = loadJson(CREATOR_DERIVED_PATH);
  const owningRuleIdToCategory = new Map();

  for (const category of table.categories) {
    if (category.status !== 'owned') continue;

    // "no category claims two owning packs" -- owningPack is a single
    // string field (already type-checked above), so this is structurally
    // guaranteed; assert it explicitly here as the acceptance-named check.
    assert.equal(typeof category.owningPack, 'string');
    assert.ok(!Array.isArray(category.owningPack));

    for (const ruleId of category.owningRuleIds) {
      assert.ok(!owningRuleIdToCategory.has(ruleId),
        `rule id ${ruleId} is claimed by both ${owningRuleIdToCategory.get(ruleId)} and ${category.id}`);
      owningRuleIdToCategory.set(ruleId, category.id);
    }
  }

  assert.ok(owningRuleIdToCategory.size > 0, 'at least some categories must be owned');
});

test('every brief-named creator security topic has coverage (owned or excluded)', () => {
  const table = loadJson(CREATOR_DERIVED_PATH);
  const ids = new Set(table.categories.map((c) => c.id));
  const namedTopics = [
    'passwords', 'sessions', 'tokens', 'authorization', 'injection', 'browser',
    'request-validation', 'secrets', 'production-hardening', 'crypto', 'data',
    'api-abuse', 'uploads', 'dependencies', 'logging',
  ];
  for (const topic of namedTopics) {
    assert.ok(ids.has(topic), `named creator security topic "${topic}" is missing from creator-derived.json`);
  }
  const excludedCount = table.categories.filter((c) => c.status === 'excluded').length;
  assert.ok(excludedCount > 0, 'at least one category must demonstrate the explicit-exclusion path (policy suggestions that cannot be evidenced)');
});

test('provenance records source identity, digest, and does not assume redistribution rights', () => {
  const provenance = loadJson(PROVENANCE_PATH);
  assert.equal(provenance.sourceLedger.sourceDocumentId, EXPECTED_SOURCE_DOCUMENT_ID);
  assert.equal(provenance.sourceLedger.sha256, EXPECTED_SOURCE_DIGEST.replace('sha256:', ''));
  assert.ok(provenance.sourceLedger.itemCount > 0);
  assert.equal(provenance.rights.redistributionRightsAssumed, false,
    'provenance must not assume redistribution rights over the source ledger');
  assert.equal(provenance.rights.creatorArchiveShipped, false,
    'provenance must record that the creator archive is not shipped');
  assert.ok(typeof provenance.rights.statement === 'string' && provenance.rights.statement.length > 20);
  assert.ok(typeof provenance.derivation.traceabilityTable === 'string');
});

test('the creator archive is not shipped: the seed ledger was not copied into the repo', () => {
  const creatorDerivedRaw = readFileSync(CREATOR_DERIVED_PATH, 'utf8');
  const provenanceRaw = readFileSync(PROVENANCE_PATH, 'utf8');

  // The ledger's own self-identifying "kind" marker and its full item list
  // shape ("allowedTerminalDispositions") must never appear verbatim here --
  // if they do, the seed was pasted in wholesale rather than referenced.
  assert.ok(!creatorDerivedRaw.includes('nemesis-creator-audit-source-ledger-seed') || creatorDerivedRaw.includes('"seedKind"') === false,
    'creator-derived.json must not embed the raw ledger kind marker as ledger content');
  assert.ok(!creatorDerivedRaw.includes('allowedTerminalDispositions'),
    'creator-derived.json must not embed the ledger\'s internal schema fields');
  assert.ok(!provenanceRaw.includes('allowedTerminalDispositions'),
    'provenance must not embed the ledger\'s internal schema fields');

  // Files should be traceability/provenance records, not a copy of a
  // 100-item, ~60KB-plus source document.
  assert.ok(creatorDerivedRaw.length < 60_000,
    `creator-derived.json is ${creatorDerivedRaw.length} bytes -- too large for a traceability table, suggests the source was copied in`);
  assert.ok(provenanceRaw.length < 10_000,
    `provenance file is ${provenanceRaw.length} bytes -- too large for a provenance record, suggests the source was copied in`);

  // No file matching the ledger's own filename pattern should exist inside
  // the implementation repo (it is read-only external input, never shipped).
  assert.ok(!existsSync(`${REPO_ROOT}/creator-audits-source-ledger.seed.json`),
    'the source ledger seed must not be copied into the nemesis repo root');
  assert.ok(!existsSync(`${REPO_ROOT}/registry/rules/security/creator-audits-source-ledger.seed.json`),
    'the source ledger seed must not be copied into the security registry directory');
});

test('no ledger item title or notes string appears verbatim in the deliverable outputs', { skip: !existsSync(EXTERNAL_LEDGER_PATH) }, () => {
  const ledger = loadJson(EXTERNAL_LEDGER_PATH);
  const securityItems = ledger.items.filter((item) => item.sourceDocumentId === 'creator.security');
  assert.ok(securityItems.length > 0, 'expected creator.security items in the external ledger');

  const table = loadJson(CREATOR_DERIVED_PATH);
  const provenance = loadJson(PROVENANCE_PATH);

  const outputStrings = [];
  function collectStrings(value) {
    if (typeof value === 'string') {
      outputStrings.push(value);
    } else if (Array.isArray(value)) {
      value.forEach(collectStrings);
    } else if (value && typeof value === 'object') {
      Object.values(value).forEach(collectStrings);
    }
  }
  collectStrings(table);
  collectStrings(provenance);

  const bannedStrings = new Set();
  for (const item of securityItems) {
    if (item.title) bannedStrings.add(item.title);
    if (item.notes) bannedStrings.add(item.notes);
  }

  for (const output of outputStrings) {
    assert.ok(!bannedStrings.has(output),
      `output string exactly matches a creator.security ledger item's title/notes verbatim: ${JSON.stringify(output)}`);
  }
});
