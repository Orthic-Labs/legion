import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { importSkillBundle } from '../../scripts/import-skill-bundle.mjs';
import { verifySkillCatalog } from '../../lib/skills/verify.mjs';
import { transformSkillText } from '../../lib/skills/transform.mjs';

test('reviewed import policy sanitizes identity and private references without a second generator', async () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-import-policy-'));
  try {
    const source = join(root, 'source'); mkdirSync(source, { recursive: true });
    writeFileSync(join(source, 'SKILL.md'), 'the operator reads `operator.yaml` at ~/.claude/skills/research/guide.md.  \n\n');
    mkdirSync(join(source, '.venv'), { recursive: true }); writeFileSync(join(source, '.venv', 'generated.py'), 'ignored\n');
    const receipt = await importSkillBundle({ source, bundle: 'research', output: join(root, 'skills/research'), manifestPath: join(root, 'skills/manifests/research.json'), receiptPath: join(root, 'skills/manifests/research.import-receipt.json'), version: '1.0.0' });
    const manifest = JSON.parse(readFileSync(join(root, 'skills/manifests/research.json'), 'utf8'));
    assert.equal(manifest.noFabrication, true); assert.equal(manifest.approvedWordsRequireRevision, false); assert.equal(manifest.rightsReceipt, null);
    assert.equal(receipt.sourceInventoryFileCount, 2); assert.equal(receipt.sourceFileCount, 1); assert.equal(receipt.excludedGeneratedFileCount, 1);
    const output = readFileSync(join(root, 'skills/research/SKILL.md'), 'utf8');
    assert.match(output, /the approving human.*private-history\.yaml.*<external-reference>/); assert.equal(output.endsWith('  \n\n'), false);
    assert.equal(verifySkillCatalog({ packageRoot: root, manifests: { research: manifest } }).findings.filter(({ code }) => code === 'private-reference').length, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('skill transforms do not treat executable source as Markdown', () => {
  const source = "const pattern = /\\]\\(([^)]+)\\)/g;\nwriteResult();\n";
  assert.equal(transformSkillText(source, { bundle: 'designer', path: 'script.mjs', profile: 'audit' }), source);
});
