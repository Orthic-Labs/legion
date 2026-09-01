#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const canonDir = join(root, 'docs', 'canon');
const preservationPath = join(canonDir, 'registers', 'preservation-map.md');
const pendingPath = join(root, 'docs', 'pending', 'README.md');
const provenanceDir = join(root, 'docs', 'provenance', 'migrations', '2026-08-29-pending');
const trackerPath = join(provenanceDir, 'PENDING-WORK-2026-08-29.md');
const triagePath = join(provenanceDir, 'arcane-package-triage-v2.md');
const migrationResultPath = join(provenanceDir, 'arcane-package-migration-result.json');

const canons = Object.freeze([
  { owner: 'Legion', file: 'legion.md', boundary: 'PUSHED' },
  { owner: 'Sage', file: 'sage.md', boundary: 'PUSHED' },
  { owner: 'Alchemist', file: 'alchemist.md', boundary: 'PUSHED' },
  { owner: 'Oracle', file: 'oracle.md', boundary: 'PUSHED' },
  { owner: 'Arcane', file: 'arcane.md', boundary: 'PUSHED' },
  { owner: 'Guard', file: 'guard.md', boundary: 'RELEASED' },
  { owner: 'Covenant', file: 'covenant.md', boundary: 'PUSHED' },
  { owner: 'Skills', file: 'skills.md', boundary: 'RELEASED' },
]);

const skillOwners = Object.freeze({
  'SKL-001': 'Skills', 'SKL-002': 'Skills', 'SKL-003': 'Skills',
  'SKL-004': 'Architect', 'SKL-005': 'Debugger', 'SKL-006': 'Audit',
  'SKL-007': 'Audit Fix', 'SKL-008': 'Audit Visual', 'SKL-009': 'QA',
  'SKL-010': 'Research', 'SKL-011': 'Marketing', 'SKL-012': 'Ads',
  'SKL-013': 'SEO', 'SKL-014': 'Social', 'SKL-015': 'Designer',
  'SKL-016': 'Brand Identity', 'SKL-017': 'Writing', 'SKL-018': 'Alchemist',
  'SKL-019': 'Covenant', 'SKL-020': 'Oracle', 'SKL-021': 'Dispatch',
  'SKL-022': 'Tasklist', 'SKL-023': 'Handoff', 'SKL-024': 'Commit',
  'SKL-025': 'Coder', 'SKL-026': 'Wake', 'SKL-027': 'Gotchas', 'SKL-028': 'Brand', 'SKL-029': 'Foundation', 'SKL-030': 'Blueprint',
});

const headers = Object.freeze({
  group: ['ID', 'Parent', 'Owner', 'Scope', 'Derived rollup'],
  capability: ['ID', 'Parent', 'Owner', 'Scope', 'Observable behavior', 'Implementation', 'Verification', 'Qualification', 'Delivery', 'Action', 'Evidence'],
  implementation: ['ID', 'Capability targets', 'Mechanism', 'Source/donor', 'Reuse mode', 'State', 'Production consumer'],
  qualification: ['ID', 'Capability targets', 'Acceptance boundary', 'State', 'Evidence', 'Material revision'],
  decision: ['ID', 'Kind', 'Capability targets', 'Decision', 'Authority/evidence', 'State'],
  preservation: ['Legacy key', 'Legacy location', 'Old ID', 'New kind', 'Target/parent', 'Disposition', 'Ambiguity'],
});

const enums = Object.freeze({
  Scope: new Set(['COMMITTED', 'EXPLORATORY', 'BACKLOG', 'EXCLUDED']),
  Implementation: new Set(['MISSING', 'PARTIAL', 'DELIVERED', 'UNKNOWN']),
  Verification: new Set(['PENDING', 'FOCUSED_PASS', 'FAIL', 'STALE', 'UNKNOWN']),
  Qualification: new Set(['NOT_REQUIRED', 'PENDING', 'PASS', 'FAIL', 'STALE', 'UNKNOWN']),
  Delivery: new Set(['LOCAL', 'COMMITTED', 'PUSHED', 'RELEASED', 'UNKNOWN']),
  decisionKind: new Set(['REFERENCE', 'EXCLUSION', 'BACKLOG']),
  qualificationState: new Set(['NOT_REQUIRED', 'PENDING', 'PASS', 'FAIL', 'STALE', 'UNKNOWN']),
});
const deliveryRank = Object.freeze({ UNKNOWN: -1, LOCAL: 0, COMMITTED: 1, PUSHED: 2, RELEASED: 3 });

const trackerMappings = Object.freeze({
  1: ['IMPLEMENTATION', 'GRD-007', 'Canonical default Guard policy', 'NONE'],
  2: ['QUALIFICATION', 'GRD-001, GRD-008', 'Installed legion-hook redeployment', 'RECEIPT_REQUIRES_RECONCILIATION'],
  3: ['QUALIFICATION', 'GRD-002, GRD-004', 'Guard property coverage', 'RUN_EVIDENCE_REQUIRES_RECONCILIATION'],
  4: ['REFERENCE', 'GRD-007', 'Historical Node policy disposition', 'NONE'],
  5: ['REFERENCE', '—', 'Parent record for 235 triage rows', 'CHILD_ROWS_PRESERVED_BELOW'],
  6: ['IMPLEMENTATION', 'LEG-010, GRD-009', 'Automatic route/outcome telemetry', 'NONE'],
  7: ['QUALIFICATION', 'ARC-001, ARC-002', 'Behavioral routing evaluation', 'LIVE_GRADER_AND_COVERAGE_UNRESOLVED'],
  8: ['IMPLEMENTATION', 'ARC-007', 'SessionStart policy injection', 'NONE'],
  9: ['IMPLEMENTATION', 'ARC-001', 'Groundwork restoration', 'EXTERNAL_WORKSPACE_CONSUMER'],
  10: ['IMPLEMENTATION', 'ARC-007', 'Ending-shape Stop policy', 'NONE'],
  11: ['REFERENCE', 'ARC-001', 'Arcane/Guard doctrine split', 'NONE'],
  12: ['IMPLEMENTATION', 'ARC-005', 'Bounded falsification posture', 'NONE'],
  13: ['IMPLEMENTATION', 'LEG-010, GRD-009', 'Automatic behavioral provenance digests', 'NONE'],
  14: ['IMPLEMENTATION', 'GRD-011', 'MCP effect classification', 'NONE'],
  15: ['IMPLEMENTATION', 'GRD-010', 'SubagentStop observation', 'NONE'],
  16: ['IMPLEMENTATION', 'GRD-012', 'Verification-proportional Stop gate', 'NONE'],
  17: ['REFERENCE', 'LEG-008', 'Least nondeterministic executor doctrine', 'NONE'],
  18: ['IMPLEMENTATION', 'LEG-005', 'ExecutorRequirement schema & validation', 'NONE'],
  19: ['IMPLEMENTATION', 'SKL-009, SKL-018, SKL-024', 'Per-action executor requirements', 'PARTIAL_SKILL_COVERAGE_REQUIRES_RECONCILIATION'],
  20: ['IMPLEMENTATION', 'LEG-008', 'Host-binding receipt', 'NONE'],
  21: ['IMPLEMENTATION', 'LEG-005', 'Rust Plan Option-B staging', 'OPTION_A_REMAINS_BACKLOG'],
  22: ['QUALIFICATION', 'LEG-005', 'Executor-requirement evaluations', 'LIVE_CONSUMER_REQUIRES_RECONCILIATION'],
  23: ['EXCLUSION', 'ORA-001', 'Retired Oracle runtime package', 'NONE'],
  24: ['IMPLEMENTATION', 'SKL-020', 'Oracle entrypoint packaging', 'NONE'],
  25: ['IMPLEMENTATION', 'SAG-003', 'Sage structural read-only projection', 'HOST_PROJECTION_STILL_CONTRADICTS_GUARD_OWNER'],
  26: ['QUALIFICATION', 'LEG-014', 'Clean-environment product qualification', 'RECEIPT_REQUIRES_RECONCILIATION'],
  27: ['IMPLEMENTATION', 'LEG-015', 'PATH binary checks', 'PACKAGE_MANAGER_ALIAS_DECISION_SPLIT_OUT'],
  28: ['QUALIFICATION', 'SKL-003, LEG-014', 'Codex sidecar & MCP status parity', 'RECEIPT_REQUIRES_RECONCILIATION'],
  29: ['QUALIFICATION', 'LEG-014', 'legion-host clippy', 'RUN_EVIDENCE_REQUIRES_RECONCILIATION'],
  30: ['REFERENCE', '—', 'Documentation separation & absorption', 'MULTI_OWNER_DOCUMENTATION_REGISTERED'],
});

const extraPreservation = Object.freeze([
  ['DEFERRED-ARC-RESIDENT', 'ARCANE-COGNITIVE-CONTROL-PLANE-2026-08-29-REV3.md:1432', 'ARC-P3-RESIDENT', 'BACKLOG', 'ARC-002', 'Resident micro-router/model deferred', 'NONE'],
  ['DEFERRED-LEG-SUPERVISION', 'LEGION-MECHANISM-AWARE-WORK-DECOMPOSITION-2026-08-29-REV3.md:984', 'LEG-SUPERVISION', 'BACKLOG', 'LEG-005', 'Fact-derived work state & supervision extension', 'NONE'],
  ['DEFERRED-SKL-COMPILED', 'LEGION-MECHANISM-AWARE-WORK-DECOMPOSITION-2026-08-29-REV3.md:1164', 'SKL-COMPILED', 'BACKLOG', 'SKL-001, SKL-002, SKL-003', 'Repeated skills to compiled capabilities', 'NONE'],
  ['DEFERRED-GRD-NAME', 'PENDING-WORK-2026-08-29.md:7', 'GRD-NAME', 'BACKLOG', '—', 'Final public Guard name', 'OWNER_DECISION_DEFERRED'],
  ['EXCLUSION-PACKAGE-MANAGERS', 'PENDING-WORK-2026-08-29.md:181', 'LEG-PACKAGE-MANAGERS', 'EXCLUSION', 'LEG-015', 'Homebrew/WinGet are optional aliases, not release gates', 'NONE'],
  ['DEFERRED-PLAN-OPTION-A', 'PENDING-WORK-2026-08-29.md:138', 'LEG-MR-OPTION-A', 'BACKLOG', 'LEG-005', 'Move executor requirements onto PlanNode', 'NONE'],
  ['TRACKER-RELEASE-PUBLICATION', 'PENDING-WORK-2026-08-29.md:242', 'LEG-RELEASE-PUBLICATION', 'BACKLOG', 'LEG-015', 'Immutable release publication remains separate', 'ACTIVE_RELEASE_WORK_EXCLUDED_FROM_CAPABILITY_EVIDENCE'],
  ['CANON-ARC-003', 'docs/current/atoms/arcane.md@d47d3a08', 'ARC-003', 'REFERENCE', 'LEG-008', 'Executor-selection behavior reclassified under Legion binding', 'OLD_ID_RETIRED_NOT_RECYCLED'],
  ['CANON-LEG-013', 'docs/current/atoms/legion.md@d47d3a08', 'LEG-013', 'CAPABILITY', 'LEG-013', 'Narrowed to role & hook integration projection', 'SKILL_PROJECTION_RETAINED_BY_SKL-003'],
  ['CANON-ALC-004', 'docs/current/atoms/alchemist.md@d47d3a08', 'ALC-004', 'CAPABILITY', 'ALC-004', 'Narrowed to contract-bound mechanism execution', 'EXECUTOR_BINDING_RETAINED_BY_LEG-008'],
]);

const migrationOwnerTargets = Object.freeze({
  'Arcane cognitive plane': ['ARC-001'],
  'Guard audit': ['GRD-009'],
  'Guard effects': ['GRD-002'],
  'Guard host': ['GRD-001'],
  'Guard policy': ['GRD-007'],
  'Guard rules': ['GRD-003'],
  'Legion contracts': ['LEG-005'],
  'Legion delivery governance': ['LEG-010'],
  'Legion execution governance': ['LEG-005'],
  'Legion host compatibility': ['LEG-014'],
  'Legion host runtime': ['LEG-006'],
  'Legion judgment governance': ['LEG-004'],
  'Legion kernel': ['LEG-003'],
  'Legion verification': ['LEG-010'],
  'Verification suite': [],
  retired: [],
});

function cells(line) { return line.trim().slice(1, -1).split('|').map((cell) => cell.trim()); }
function isSeparator(row) { return row.every((cell) => /^:?-{3,}:?$/.test(cell)); }
function tableAfter(markdown, heading) {
  const start = markdown.indexOf(`${heading}\n`);
  if (start < 0) throw new Error(`missing heading ${heading}`);
  const lines = markdown.slice(start + heading.length).split(/\r?\n/);
  const rows = [];
  let started = false;
  for (const line of lines) {
    if (!started && line.trim().startsWith('|')) started = true;
    if (started && !line.trim().startsWith('|')) break;
    if (started) rows.push(cells(line));
  }
  if (rows.length < 2) throw new Error(`missing table after ${heading}`);
  return rows;
}
function records(markdown, heading, expectedHeader) {
  const table = tableAfter(markdown, heading);
  if (table[0].join('|') !== expectedHeader.join('|')) throw new Error(`${heading} schema mismatch: ${table[0].join(' | ')}`);
  return table.slice(1).filter((row) => !isSeparator(row)).map((row) => {
    if (row.length !== expectedHeader.length) throw new Error(`${heading}: expected ${expectedHeader.length} fields, got ${row.length}`);
    return Object.fromEntries(expectedHeader.map((name, index) => [name, row[index]]));
  });
}
function targets(value) { return !value || value === '—' ? [] : value.split(',').map((target) => target.trim()).filter(Boolean); }
function proofEvidence(value) {
  const match = /^Acceptance: ([A-Z][A-Z0-9-]+); Revision: ([0-9a-f]{40}); Receipt: ([^;]+@[0-9a-f]{8,64}); Freshness: (\d{4}-\d{2}-\d{2})$/.exec(value);
  if (!match) return null;
  const freshness = Date.parse(`${match[4]}T00:00:00Z`);
  if (!Number.isFinite(freshness) || freshness > Date.now()) return null;
  return { acceptance: match[1], revision: match[2], receipt: match[3], freshness: match[4] };
}
function parseCanon(config) {
  const markdown = readFileSync(join(canonDir, config.file), 'utf8');
  const boundary = /Required delivery boundary: `(LOCAL|COMMITTED|PUSHED|RELEASED)`\./.exec(markdown)?.[1];
  if (boundary !== config.boundary) throw new Error(`${config.file}: required delivery boundary must be ${config.boundary}`);
  const groups = records(markdown, '## Group register', headers.group);
  const capabilities = records(markdown, '## Capability ledger', headers.capability);
  const implementations = records(markdown, '## Implementation register', headers.implementation);
  const qualifications = records(markdown, '## Qualification ledger', headers.qualification);
  const decisions = records(markdown, '## Decision register', headers.decision);
  const groupIds = new Set(groups.map((row) => row.ID));
  const idPrefix = capabilities[0]?.ID.slice(0, 3);
  for (const row of groups) {
    if (!/^[A-Z]{3}-G\d{2}$/.test(row.ID)) throw new Error(`${config.file}: invalid group ID ${row.ID}`);
    if (row.Owner !== config.owner) throw new Error(`${config.file}:${row.ID}: group owner must be ${config.owner}`);
    if (!enums.Scope.has(row.Scope)) throw new Error(`${config.file}:${row.ID}: invalid Scope ${row.Scope}`);
    if (row.Parent !== '—' && !groupIds.has(row.Parent)) throw new Error(`${config.file}:${row.ID}: unknown group parent ${row.Parent}`);
  }
  const groupById = new Map(groups.map((row) => [row.ID, row]));
  for (const row of groups) {
    const seen = new Set([row.ID]);
    let parent = row.Parent;
    while (parent !== '—') {
      if (seen.has(parent)) throw new Error(`${config.file}:${row.ID}: cyclic group parentage`);
      seen.add(parent);
      parent = groupById.get(parent).Parent;
    }
  }
  for (const row of capabilities) {
    if (!/^[A-Z]{3}-\d{3}$/.test(row.ID)) throw new Error(`${config.file}: invalid capability ID ${row.ID}`);
    const expectedOwner = config.owner === 'Skills' ? skillOwners[row.ID] : config.owner;
    if (!expectedOwner || row.Owner !== expectedOwner) throw new Error(`${config.file}:${row.ID}: owner ${row.Owner} != ${expectedOwner}`);
    if (!groupIds.has(row.Parent)) throw new Error(`${config.file}:${row.ID}: unknown parent ${row.Parent}`);
    for (const field of ['Scope', 'Implementation', 'Verification', 'Qualification', 'Delivery']) {
      if (!enums[field].has(row[field])) throw new Error(`${config.file}:${row.ID}: invalid ${field} ${row[field]}`);
    }
    if ((row.Verification === 'FOCUSED_PASS' || row.Qualification === 'PASS') && !proofEvidence(row.Evidence)) {
      throw new Error(`${config.file}:${row.ID}: PASS state lacks acceptance/revision/receipt/freshness evidence`);
    }
    if (row.Qualification === 'NOT_REQUIRED') {
      const disposition = qualifications.find((qualification) => targets(qualification['Capability targets']).includes(row.ID) && qualification.State === 'NOT_REQUIRED');
      if (!disposition || !proofEvidence(disposition.Evidence)) throw new Error(`${config.file}:${row.ID}: NOT_REQUIRED lacks recorded revision-bound disposition`);
    }
  }
  for (const row of implementations) {
    if (!new RegExp(`^${idPrefix}-I\\d{3}$`).test(row.ID)) throw new Error(`${config.file}: invalid implementation ID ${row.ID}`);
    if (!enums.Implementation.has(row.State)) throw new Error(`${config.file}:${row.ID}: invalid implementation state ${row.State}`);
  }
  for (const row of qualifications) {
    if (!new RegExp(`^${idPrefix}-Q\\d{3}$`).test(row.ID)) throw new Error(`${config.file}: invalid qualification ID ${row.ID}`);
    if (!enums.qualificationState.has(row.State)) throw new Error(`${config.file}:${row.ID}: invalid qualification state ${row.State}`);
    if (row.State === 'PASS') {
      const evidence = proofEvidence(row.Evidence);
      if (!evidence) throw new Error(`${config.file}:${row.ID}: PASS lacks acceptance/revision/receipt/freshness evidence`);
      if (evidence.revision !== row['Material revision']) throw new Error(`${config.file}:${row.ID}: PASS predates material revision`);
    }
  }
  for (const row of decisions) {
    if (!new RegExp(`^${idPrefix}-D\\d{3}$`).test(row.ID)) throw new Error(`${config.file}: invalid decision ID ${row.ID}`);
    if (!enums.decisionKind.has(row.Kind)) throw new Error(`${config.file}:${row.ID}: invalid decision kind ${row.Kind}`);
  }
  return { ...config, groups, capabilities, implementations, qualifications, decisions };
}
function closed(row, boundary) {
  return row.Scope === 'COMMITTED' && row.Implementation === 'DELIVERED'
    && row.Verification === 'FOCUSED_PASS' && ['PASS', 'NOT_REQUIRED'].includes(row.Qualification)
    && deliveryRank[row.Delivery] >= deliveryRank[boundary] && Boolean(proofEvidence(row.Evidence));
}
function normalizedTokens(value) {
  const stop = new Set(['a', 'an', 'and', 'the', 'to', 'of', 'for', 'with', 'when', 'only', 'one', 'or', 'from', 'into', 'without']);
  return new Set(value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').split(' ').filter((token) => token.length > 2 && !stop.has(token)));
}
function similarity(a, b) {
  const left = normalizedTokens(a), right = normalizedTokens(b);
  const intersection = [...left].filter((token) => right.has(token)).length;
  const union = new Set([...left, ...right]).size;
  return union ? intersection / union : 0;
}
function validateSemanticOwnership(parsed) {
  const capabilities = parsed.flatMap((canon) => canon.capabilities);
  const byId = new Map(capabilities.map((row) => [row.ID, row]));
  if (byId.has('ARC-003')) throw new Error('ARC-003 must remain retired from capability totals');
  if (/(capabilit|authorit|effect)/i.test(byId.get('ARC-001')['Observable behavior'])) throw new Error('ARC-001 crosses Legion/Guard ownership');
  if (/executor/i.test(byId.get('ALC-004')['Observable behavior'])) throw new Error('ALC-004 overlaps LEG-008 executor binding');
  if (/skill/i.test(byId.get('LEG-013')['Observable behavior'])) throw new Error('LEG-013 overlaps SKL-003 skill projection');
  if (!/skill/i.test(byId.get('SKL-003')['Observable behavior'])) throw new Error('SKL-003 must own skill projection');
  if (byId.get('GRD-011').Parent !== 'GRD-G01') throw new Error('GRD-011 must parent to host interception/classification');
  for (let left = 0; left < capabilities.length; left += 1) {
    for (let right = left + 1; right < capabilities.length; right += 1) {
      if (similarity(capabilities[left]['Observable behavior'], capabilities[right]['Observable behavior']) >= 0.86) {
        throw new Error(`semantic duplicate candidates: ${capabilities[left].ID} and ${capabilities[right].ID}`);
      }
    }
  }
}
function validateTargets(parsed) {
  const capabilityIds = new Set(parsed.flatMap((canon) => canon.capabilities).map((row) => row.ID));
  const idsByKind = { group: new Set(), capability: new Set(), implementation: new Set(), qualification: new Set(), decision: new Set() };
  for (const canon of parsed) {
    for (const [kind, rows] of Object.entries({ group: canon.groups, capability: canon.capabilities, implementation: canon.implementations, qualification: canon.qualifications, decision: canon.decisions })) {
      for (const row of rows) {
        if (idsByKind[kind].has(row.ID)) throw new Error(`duplicate ${kind} ID ${row.ID}`);
        idsByKind[kind].add(row.ID);
      }
    }
    for (const row of [...canon.implementations, ...canon.qualifications, ...canon.decisions]) {
      for (const target of targets(row['Capability targets'])) if (!capabilityIds.has(target)) throw new Error(`${canon.file}:${row.ID}: unknown capability target ${target}`);
    }
  }
  return capabilityIds;
}
function lineNumber(text, index) { return text.slice(0, index).split('\n').length; }
function safeCell(value) { return String(value).replace(/\|/g, '/').replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim(); }
function sha256File(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
function preservationRows(capabilityIds) {
  const tracker = readFileSync(trackerPath, 'utf8'), triage = readFileSync(triagePath, 'utf8');
  const migration = JSON.parse(readFileSync(migrationResultPath, 'utf8'));
  const trackerMatches = [...tracker.matchAll(/^(\d+)\. \*\*/gm)];
  if (trackerMatches.length !== 30) throw new Error(`legacy tracker inventory changed: expected 30 rows, found ${trackerMatches.length}`);
  const rows = trackerMatches.map((match) => {
    const number = Number(match[1]), mapping = trackerMappings[number];
    if (!mapping) throw new Error(`missing tracker mapping ${number}`);
    const id = `TRACKER-${String(number).padStart(2, '0')}`;
    return [id, `PENDING-WORK-2026-08-29.md:${lineNumber(tracker, match.index)}`, id, ...mapping];
  });
  const triageMatches = [...triage.matchAll(/^- `(src\/packages\/arcane\/[^`]+)` — (.+)$/gm)];
  if (triageMatches.length !== 235) throw new Error(`legacy triage inventory changed: expected 235 rows, found ${triageMatches.length}`);
  if (migration.schemaVersion !== 1 || migration.inventory?.expected !== 235 || migration.inventory?.observed !== 235
    || migration.inventory?.migrated !== 232 || migration.inventory?.retiredUnconsumed !== 3 || migration.entries?.length !== 235) {
    throw new Error('P0.5 migration result inventory is incomplete');
  }
  const migrationByOldPath = new Map();
  for (const entry of migration.entries) {
    if (migrationByOldPath.has(entry.oldPath)) throw new Error(`duplicate P0.5 migration source ${entry.oldPath}`);
    migrationByOldPath.set(entry.oldPath, entry);
  }
  const triagePaths = new Set(triageMatches.map((match) => match[1]));
  for (const oldPath of migrationByOldPath.keys()) if (!triagePaths.has(oldPath)) throw new Error(`P0.5 result is outside frozen triage inventory: ${oldPath}`);
  triageMatches.forEach((match, index) => {
    const id = `TRIAGE-${String(index + 1).padStart(3, '0')}`;
    const entry = migrationByOldPath.get(match[1]);
    if (!entry) throw new Error(`P0.5 migration result omits ${match[1]}`);
    if (!entry.triageDisposition) throw new Error(`P0.5 result lacks frozen disposition for ${match[1]}`);
    if (!Array.isArray(entry.owners) || !entry.owners.length) throw new Error(`P0.5 result lacks owner for ${match[1]}`);
    const targetSet = new Set();
    for (const owner of entry.owners) {
      if (!(owner in migrationOwnerTargets)) throw new Error(`P0.5 result has unknown owner ${owner} for ${match[1]}`);
      for (const target of migrationOwnerTargets[owner]) targetSet.add(target);
    }
    const retired = entry.resultDisposition === 'retired-unconsumed';
    if (retired) {
      if (entry.newPath !== null || entry.oldConsumers?.length !== 0
        || existsSync(join(root, entry.oldPath)) || !entry.verification?.includes('pre-migration consumer scan empty')
        || !entry.verification?.includes('old path removed')) {
        throw new Error(`P0.5 retirement is not consumer-safe for ${match[1]}`);
      }
    } else if (entry.resultDisposition === 'migrated') {
      if (!entry.newPath || !entry.sha256AfterMove || !entry.verification?.includes('target exists')
        || !entry.verification?.includes('all resolvable imports rewritten') || existsSync(join(root, entry.oldPath))
        || !existsSync(join(root, entry.newPath)) || sha256File(join(root, entry.newPath)) !== entry.sha256AfterMove) {
        throw new Error(`P0.5 migration lacks target/import verification for ${match[1]}`);
      }
      if (!Array.isArray(entry.newConsumers)) throw new Error(`P0.5 migration lacks consumer inventory for ${match[1]}`);
      for (const consumer of entry.newConsumers) if (!existsSync(join(root, consumer))) throw new Error(`P0.5 consumer is missing: ${consumer}`);
      if (!targetSet.size && entry.newPath.endsWith('/authority-binding-race-worker.mjs')) targetSet.add('GRD-004');
      if (!targetSet.size) throw new Error(`P0.5 migration lacks capability target for ${match[1]}`);
    } else {
      throw new Error(`P0.5 result has invalid disposition for ${match[1]}`);
    }
    const kind = retired ? 'EXCLUSION' : entry.newPath.startsWith('tests/') ? 'QUALIFICATION' : 'IMPLEMENTATION';
    const target = targetSet.size ? [...targetSet].join(', ') : '—';
    const result = retired ? 'Retired after zero-consumer scan' : `Migrated to ${entry.newPath}`;
    rows.push([id, `arcane-package-triage-v2.md:${lineNumber(triage, match.index)}`, id, kind, target, result, 'NONE']);
  });
  rows.push(...extraPreservation);
  const ids = new Set();
  for (const row of rows) {
    if (ids.has(row[2])) throw new Error(`duplicate preserved old ID ${row[2]}`);
    ids.add(row[2]);
    if (row[4] !== '—') for (const target of targets(row[4])) if (!capabilityIds.has(target)) throw new Error(`${row[0]}: unresolved preservation target ${target}`);
  }
  return { rows, tracker: trackerMatches.length, triage: triageMatches.length };
}
function preservationMarkdown(inventory) {
  const unclassified = inventory.rows.filter((row) => row[3] === 'UNCLASSIFIED').length;
  return [
    '# Legacy pending preservation map', '',
    '<!-- GENERATED by scripts/check-atomic-canons.mjs --write. Do not hand-edit. -->', '',
    'Frozen source: `d47d3a081d218fff3356c3e982df7f82df4b07b0` plus relocated 2026-08-29 provenance.', '',
    `- Tracker rows: **${inventory.tracker}**`,
    `- Arcane triage rows: **${inventory.triage}**`,
    `- Deferred/exclusion/canon-normalization rows: **${extraPreservation.length}**`,
    `- Preserved union: **${inventory.rows.length}/${inventory.rows.length}**`,
    `- Unclassified: **${unclassified}**`, '', '## Migration map', '',
    `| ${headers.preservation.join(' | ')} |`, '|---|---|---|---|---|---|---|',
    ...inventory.rows.map((row) => `| ${row.map(safeCell).join(' | ')} |`), '',
  ].join('\n');
}
function pendingMarkdown(parsed, inventory) {
  const committed = parsed.flatMap((canon) => canon.capabilities.filter((row) => row.Scope === 'COMMITTED').map((row) => ({ ...row, canon })));
  const open = committed.filter((row) => !closed(row, row.canon.boundary));
  const unclassified = inventory.rows.filter((row) => row[3] === 'UNCLASSIFIED');
  const lines = [
    '# Legion pending capability work', '',
    '<!-- GENERATED by scripts/check-atomic-canons.mjs --write. Do not hand-edit. -->', '',
    `Committed capability atoms: **${committed.length}**`,
    `Closure-proven: **${committed.length - open.length}**`,
    `Open/unproven: **${open.length}**`,
    `Preserved legacy rows: **${inventory.rows.length}**`,
    `Unclassified preserved rows: **${unclassified.length}**`, '',
    'Atomic state lives in `docs/canon/*.md`; preservation state lives in `docs/canon/registers/preservation-map.md`. This file is derived from both.', '',
    '## Canon summary', '',
    '| Subsystem | Boundary | Capabilities | Closed | Open | Groups | Implementations | Qualifications | Decisions |',
    '|---|---|---:|---:|---:|---:|---:|---:|---:|',
  ];
  for (const canon of parsed) {
    const capabilities = canon.capabilities.filter((row) => row.Scope === 'COMMITTED');
    const canonOpen = capabilities.filter((row) => !closed(row, canon.boundary)).length;
    lines.push(`| [${canon.owner}](../canon/${canon.file}) | ${canon.boundary} | ${capabilities.length} | ${capabilities.length - canonOpen} | ${canonOpen} | ${canon.groups.length} | ${canon.implementations.length} | ${canon.qualifications.length} | ${canon.decisions.length} |`);
  }
  lines.push('', '## Open capability atoms', '');
  for (const canon of parsed) {
    const rows = canon.capabilities.filter((row) => row.Scope === 'COMMITTED' && !closed(row, canon.boundary));
    if (!rows.length) continue;
    lines.push(`### ${canon.owner}`, '', '| Atom | Action | Deficit |', '|---|---|---|');
    for (const row of rows) {
      const deficit = `implementation=${row.Implementation}; verification=${row.Verification}; qualification=${row.Qualification}; delivery=${row.Delivery}/${canon.boundary}; evidence=${row.Evidence}`;
      lines.push(`| [${row.ID}](../canon/${canon.file}) | ${row.Action} | ${deficit} |`);
    }
    lines.push('');
  }
  lines.push('## Unclassified preserved work', '');
  if (!unclassified.length) lines.push('None.');
  else {
    lines.push('| Legacy ID | Location | Disposition | Ambiguity |', '|---|---|---|---|');
    for (const row of unclassified) lines.push(`| [${row[2]}](../canon/registers/preservation-map.md) | ${safeCell(row[1])} | ${safeCell(row[5])} | ${safeCell(row[6])} |`);
  }
  lines.push('');
  return lines.join('\n');
}
export const atomicCanonTestHooks = Object.freeze({ proofEvidence, closed, similarity });
export function validateAtomicCanons({ write = false } = {}) {
  const pendingFiles = readdirSync(dirname(pendingPath)).filter((entry) => entry !== 'plans').sort();
  if (pendingFiles.join('|') !== 'README.md') throw new Error(`docs/pending must contain only README.md (plus plans/); found ${pendingFiles.join(', ')}`);
  const parsed = canons.map(parseCanon);
  const capabilityIds = validateTargets(parsed);
  validateSemanticOwnership(parsed);
  const inventory = preservationRows(capabilityIds);
  const expectedPreservation = preservationMarkdown(inventory), expectedPending = pendingMarkdown(parsed, inventory);
  if (write) {
    mkdirSync(dirname(preservationPath), { recursive: true });
    writeFileSync(preservationPath, expectedPreservation, 'utf8');
    writeFileSync(pendingPath, expectedPending, 'utf8');
  } else {
    if (!existsSync(preservationPath) || readFileSync(preservationPath, 'utf8') !== expectedPreservation) throw new Error('preservation map is stale; run node scripts/check-atomic-canons.mjs --write');
    if (readFileSync(pendingPath, 'utf8') !== expectedPending) throw new Error('docs/pending/README.md is stale; run node scripts/check-atomic-canons.mjs --write');
  }
  const committed = parsed.flatMap((canon) => canon.capabilities.filter((row) => row.Scope === 'COMMITTED').map((row) => ({ ...row, canon })));
  const closedRows = committed.filter((row) => closed(row, row.canon.boundary));
  return { canons: parsed.length, atoms: committed.length, closed: closedRows.length, open: committed.length - closedRows.length, preservationRows: inventory.rows.length, trackerRows: inventory.tracker, triageRows: inventory.triage, unclassified: inventory.rows.filter((row) => row[3] === 'UNCLASSIFIED').length };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const result = validateAtomicCanons({ write: process.argv.includes('--write') });
    console.log(`atomic canons PASS: ${result.canons} subsystems, ${result.atoms} atoms, ${result.closed} closed, ${result.open} open, ${result.preservationRows} preserved, ${result.unclassified} unclassified`);
  } catch (error) {
    console.error(`atomic canons FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
