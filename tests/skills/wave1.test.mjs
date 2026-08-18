import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { verifySkillBytes, verifySkillCatalog } from '../../src/lib/skills/verify.mjs';
import { validateCommercialLenses } from '../../src/lib/lenses/routing.mjs';
import { validateInternalRecipes } from '../../src/lib/recipes/validate.mjs';

test('skills verifier rejects all deterministic drift classes', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-wave1-'));
  try {
    mkdirSync(join(root, 'skills/demo'), { recursive: true });
    mkdirSync(join(root, 'source/demo'), { recursive: true });
    const bytes = Buffer.from('canonical\n');
    const digest = verifySkillBytes(bytes, null).digest;
    const manifests = { demo: { id: 'demo', licenseState: 'unresolved', files: [{ path: 'SKILL.md', sourceDigest: digest, outputDigest: digest }] } };
    writeFileSync(join(root, 'source/demo/SKILL.md'), bytes);
    writeFileSync(join(root, 'skills/demo/SKILL.md'), bytes);
    assert.equal(verifySkillCatalog({ packageRoot: root, manifests, sourceRoot: join(root, 'source') }).ok, true);
    writeFileSync(join(root, 'skills/demo/unexpected.md'), 'x');
    assert.ok(verifySkillCatalog({ packageRoot: root, manifests }).findings.some(({ code }) => code === 'unexpected'));
    rmSync(join(root, 'skills/demo/unexpected.md'));
    writeFileSync(join(root, 'skills/demo/SKILL.md'), 'changed');
    assert.ok(verifySkillCatalog({ packageRoot: root, manifests }).findings.some(({ code }) => code === 'digest-drift'));
    writeFileSync(join(root, 'skills/demo/SKILL.md'), bytes);
    writeFileSync(join(root, 'source/demo/SKILL.md'), 'changed source');
    assert.ok(verifySkillCatalog({ packageRoot: root, manifests, sourceRoot: join(root, 'source') }).findings.some(({ code }) => code === 'transform-drift'));
    rmSync(join(root, 'skills/demo/SKILL.md'));
    assert.ok(verifySkillCatalog({ packageRoot: root, manifests }).findings.some(({ code }) => code === 'missing'));
    assert.ok(verifySkillCatalog({ packageRoot: root, manifests, publication: true }).findings.some(({ code }) => code === 'rights-unresolved'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Wave 1 routing descriptors remain typed unavailable', () => {
  const root = process.cwd();
  assert.equal(validateCommercialLenses(root).ok, true);
  assert.equal(validateInternalRecipes(root).ok, true);
});
