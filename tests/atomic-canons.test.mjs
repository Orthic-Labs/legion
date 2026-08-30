import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { atomicCanonTestHooks, validateAtomicCanons } from '../scripts/check-atomic-canons.mjs';

test('subsystem atomic canons preserve inventory & derive honest closure', () => {
  const result = validateAtomicCanons();
  assert.equal(result.canons, 8);
  assert.equal(result.atoms, 95);
  assert.equal(result.closed, 0);
  assert.equal(result.open, 95);
  assert.equal(result.trackerRows, 30);
  assert.equal(result.triageRows, 235);
  assert.equal(result.preservationRows, 275);
  assert.equal(result.unclassified, 0);
  const migration = JSON.parse(readFileSync(new URL('../docs/provenance/migrations/2026-08-29-pending/arcane-package-migration-result.json', import.meta.url), 'utf8'));
  assert.deepEqual(migration.inventory, { expected: 235, observed: 235, migrated: 232, retiredUnconsumed: 3 });
});

test('known ownership overlaps are resolved without recycling ARC-003', () => {
  const legion = readFileSync(new URL('../docs/canon/legion.md', import.meta.url), 'utf8');
  const alchemist = readFileSync(new URL('../docs/canon/alchemist.md', import.meta.url), 'utf8');
  const arcane = readFileSync(new URL('../docs/canon/arcane.md', import.meta.url), 'utf8');
  const guard = readFileSync(new URL('../docs/canon/guard.md', import.meta.url), 'utf8');
  const skills = readFileSync(new URL('../docs/canon/skills.md', import.meta.url), 'utf8');
  const preservation = readFileSync(new URL('../docs/canon/registers/preservation-map.md', import.meta.url), 'utf8');

  assert.match(legion, /LEG-013[^\n]+role & hook projections/);
  assert.doesNotMatch(legion.match(/LEG-013[^\n]+/)?.[0] ?? '', /skill/i);
  assert.doesNotMatch(alchemist.match(/ALC-004[^\n]+/)?.[0] ?? '', /executor/i);
  assert.doesNotMatch(arcane, /^\| ARC-003 \|/m);
  assert.match(preservation, /CANON-ARC-003[^\n]+ARC-003[^\n]+REFERENCE[^\n]+LEG-008/);
  assert.match(guard, /GRD-011 \| GRD-G01[^\n]+DELIVERED/);
  assert.match(skills, /SKL-I001[^\n]+src\/registry\/skills\/index\.json/);
  assert.match(skills, /SKL-004 \| SKL-G02 \| Architect \|/);
});

test('closure rejects bare paths, stale proof shape & insufficient delivery', () => {
  const exact = 'Acceptance: LEG-AC-001; Revision: 0123456789abcdef0123456789abcdef01234567; Receipt: evidence/legion.json@01234567; Freshness: 2000-01-01';
  assert.equal(atomicCanonTestHooks.proofEvidence('src/file.rs@01234567'), null);
  assert.equal(atomicCanonTestHooks.proofEvidence(exact)?.acceptance, 'LEG-AC-001');

  const row = {
    Scope: 'COMMITTED', Implementation: 'DELIVERED', Verification: 'FOCUSED_PASS',
    Qualification: 'PASS', Delivery: 'COMMITTED', Evidence: exact,
  };
  assert.equal(atomicCanonTestHooks.closed(row, 'PUSHED'), false);
  assert.equal(atomicCanonTestHooks.closed({ ...row, Delivery: 'PUSHED' }, 'PUSHED'), true);
  assert.equal(atomicCanonTestHooks.closed({ ...row, Delivery: 'PUSHED', Verification: 'PENDING' }, 'PUSHED'), false);
});
