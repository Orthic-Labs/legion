import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { validateManifest } from '@rightkit/git/manifest.mjs';
import { renderLanes } from '@rightkit/git/sync.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('right-git owns exact public CI bytes', () => {
  const manifest = JSON.parse(readFileSync(join(root, '.rightgit.json'), 'utf8'));
  assert.deepEqual(validateManifest(manifest), { valid: true, errors: [] });
  const rendered = renderLanes(manifest, root);
  assert.equal(rendered.length, 2);
  for (const lane of rendered) {
    assert.equal(lane.content, readFileSync(join(root, '.github/workflows', lane.filename), 'utf8'));
  }
  assert.deepEqual(readdirSync(join(root, '.github/workflows')).sort(), ['ci.yml', 'release-candidate.yml']);
});

test('action uses local pinned pnpm without global installation', () => {
  const action = readFileSync(join(root, 'action.yml'), 'utf8');
  assert.match(action, /corepack pnpm@11\.24\.0 install/);
  assert.match(action, /--frozen-lockfile --prod/);
  assert.doesNotMatch(action, /install --global|npm install -g/);
  assert.match(action, /tools\/audit\/audit-run\.mjs/);
});

test('native assembly consumes right-release target & provenance contracts', () => {
  const assembler = readFileSync(join(root, 'scripts/assemble-native-release.mjs'), 'utf8');
  const config = readFileSync(join(root, 'right-release.config.mjs'), 'utf8');
  assert.match(assembler, /@rightkit\/release\/cargo-target\.mjs/);
  assert.match(assembler, /resolveTargetRoot\(cargoManifest\)/);
  assert.match(assembler, /cargoTarget \? \[cargoTarget\] : \[\]/);
  assert.match(assembler, /process\.platform === "darwin"\s*\? "macos"/);
  assert.doesNotMatch(assembler, /engine["'],\s*["']target["'],\s*["'](?:debug|release)/);
  assert.match(assembler, /localProvenanceScheme/);
  assert.match(assembler, /signedProvenanceScheme/);
  assert.match(config, /packageHook/);
  assert.match(config, /publishBlocked/);
});
