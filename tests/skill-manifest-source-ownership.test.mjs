import assert from 'node:assert/strict';
import test from 'node:test';

import { buildSkillCatalog } from '../scripts/generate-skill-catalog.mjs';
import { parseSkillFrontmatter } from '../scripts/lib/skill-frontmatter.mjs';
import { deriveParity } from '../scripts/refresh-local-skill-manifests.mjs';

test('generated manifest parity derives from canonical semantics & package files only', () => {
  const semantic = { description: 'Architect owns routine architecture craft directly.' };
  const parity = deriveParity('architect', semantic, ['SKILL.md', 'references/manual.md', 'evals/evals.json']);
  assert.deepEqual(parity.triggers, ['/architect', semantic.description]);
  assert.equal(parity.triggers.some((value) => /Sage Architect/.test(value)), false);
  assert.deepEqual(parity.outputs, ['references/manual.md']);
  assert.deepEqual(parity.evals, ['evals/evals.json']);
});

test('catalog semantic lists are exact YAML values, never list-marker text', () => {
  const { index } = buildSkillCatalog();
  assert.equal(index.bundles.length, 26);
  for (const bundle of index.bundles) {
    for (const field of ['operations', 'effects', 'hostRequirements']) {
      assert.equal(bundle[field].some((value) => value.startsWith('- ')), false, `${bundle.id}.${field}`);
    }
  }
  const qa = index.bundles.find(({ id }) => id === 'qa');
  assert.deepEqual(qa.operations, ['analyze', 'evaluate', 'execute', 'produce']);
  assert.deepEqual(qa.effects, ['source-read', 'artifact-write', 'process-exec']);
  const coder = index.bundles.find(({ id }) => id === 'coder');
  assert.deepEqual(coder.hostRequirements, ['pi-cli', 'python-runtime']);
});

test('all 26 packaged sources exactly match frozen classifications and repertoires', () => {
  const expected = {
    ads: ['capability', 'domain', 'public', 'commercial', 'analyze,decide,produce', 'source-read,network-request'],
    alchemist: ['entrypoint', null, 'explicit', null, 'execute', 'source-read,repository-write,process-exec'],
    architect: ['capability', 'domain', 'public', 'engineering', 'analyze,decide,produce', 'source-read,artifact-write'],
    audit: ['capability', 'domain', 'public', 'engineering', 'analyze,evaluate,produce', 'source-read,process-exec,artifact-write'],
    'audit-fix': ['capability', 'workflow', 'public', 'engineering', 'analyze,evaluate,execute,produce', 'source-read,repository-write,process-exec'],
    'audit-visual': ['capability', 'domain', 'public', 'engineering', 'analyze,evaluate,produce', 'source-read,artifact-write,process-exec'],
    brand: ['capability', 'context', 'public', null, 'analyze,produce', 'source-read'],
    'brand-identity': ['capability', 'domain', 'public', 'design', 'analyze,decide,produce,evaluate', 'source-read,artifact-write'],
    foundation: ['capability', 'domain', 'public', 'engineering', 'analyze,evaluate,produce', 'source-read,artifact-write'],
    coder: ['entrypoint', null, 'explicit', null, 'analyze', 'source-read,network-request'],
    commit: ['entrypoint', null, 'explicit', null, 'analyze,evaluate,execute', 'source-read,repository-write,process-exec,network-request'],
    covenant: ['entrypoint', null, 'explicit', null, 'analyze,evaluate,produce', 'source-read'],
    debugger: ['capability', 'domain', 'public', 'engineering', 'analyze,diagnose,decide,produce', 'source-read,process-exec'],
    designer: ['capability', 'domain', 'public', 'design', 'analyze,decide,produce,evaluate', 'source-read,artifact-write'],
    dispatch: ['capability', 'workflow', 'public', null, 'route,produce', 'source-read,artifact-write,process-exec'],
    gotchas: ['capability', 'workflow', 'public', null, 'analyze,execute,produce', 'source-read,repository-write'],
    handoff: ['capability', 'workflow', 'public', null, 'analyze,produce', 'source-read,artifact-write,process-exec'],
    marketing: ['capability', 'domain', 'public', 'commercial', 'analyze,decide,produce', 'source-read,network-request'],
    oracle: ['entrypoint', null, 'explicit', null, 'evaluate', 'source-read'],
    qa: ['capability', 'domain', 'public', 'engineering', 'analyze,evaluate,execute,produce', 'source-read,artifact-write,process-exec'],
    research: ['capability', 'domain', 'public', 'research', 'route,analyze,produce', 'source-read,artifact-write,network-request'],
    seo: ['capability', 'domain', 'public', 'commercial', 'analyze,diagnose,produce', 'source-read,artifact-write,process-exec,network-request'],
    social: ['capability', 'domain', 'public', 'commercial', 'analyze,decide,produce', 'source-read,artifact-write,network-request'],
    tasklist: ['capability', 'workflow', 'public', null, 'analyze,produce,execute', 'source-read,artifact-write,process-exec'],
    wake: ['capability', 'workflow', 'public', null, 'analyze,execute,produce', 'source-read,artifact-write'],
    writing: ['capability', 'domain', 'public', 'editorial', 'analyze,produce,evaluate', 'source-read,artifact-write'],
  };
  const { index } = buildSkillCatalog();
  assert.deepEqual(index.bundles.map(({ id }) => id), Object.keys(expected).sort());
  for (const bundle of index.bundles) {
    assert.deepEqual(
      [bundle.kind, bundle.capabilityClass, bundle.discoverability, bundle.domain ?? null, bundle.operations.join(','), bundle.effects.join(',')],
      expected[bundle.id],
      bundle.id,
    );
    assert.ok(Array.isArray(bundle.hostRequirements), `${bundle.id}.hostRequirements`);
  }
});

test('skill frontmatter parser fails malformed semantic YAML instead of certifying drift', () => {
  assert.throws(
    () => parseSkillFrontmatter('---\nname: qa\ndescription: invalid: unquoted\nkind: capability\ncapabilityClass: domain\ndiscoverability: public\noperations:\n  - analyze\neffects:\n  - source-read\n---\n'),
    /unquoted YAML mapping delimiter/,
  );
  assert.throws(
    () => parseSkillFrontmatter('---\nname: qa\ndescription: "valid"\nkind: capability\ncapabilityClass: domain\ndiscoverability: public\noperations:\n  - analyze\neffects:\n  - source_read\nhostRequirements: []\n---\n'),
    /invalid effects value source_read/,
  );
  assert.throws(
    () => parseSkillFrontmatter('---\nname: qa\ndescription: "valid"\nkind: capability\ncapabilityClass: domain\ndiscoverability: public\noperations:\n  - analyze\neffects:\n  - source-read\n---\n'),
    /missing canonical hostRequirements metadata/,
  );
});
