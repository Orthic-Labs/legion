import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const BUNDLES = ['ads', 'brand-identity', 'designer', 'marketing', 'research', 'seo', 'social', 'writing'];

test('Claude Code & Codex discover every canonical Legion skill pack', () => {
  const claude = JSON.parse(readFileSync(join(ROOT, '.claude-plugin', 'plugin.json'), 'utf8'));
  const codex = JSON.parse(readFileSync(join(ROOT, '.codex-plugin', 'plugin.json'), 'utf8'));
  const packageManifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

  assert.equal(claude.name, 'legion');
  assert.equal(codex.name, 'legion');
  assert.ok(packageManifest.files.includes('skills/'));

  for (const bundle of BUNDLES) {
    const skillPath = join(ROOT, 'skills', bundle, 'SKILL.md');
    assert.equal(existsSync(skillPath), true, `${bundle} entrypoint`);
    assert.match(readFileSync(skillPath, 'utf8'), new RegExp(`^---\\nname: ${bundle}\\n`, 'u'), `${bundle} canonical name`);
  }
});
