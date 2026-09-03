import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
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
    const workflow = readFileSync(join(root, '.github/workflows', lane.filename), 'utf8');
    if (lane.filename === 'ci.yml') assert.equal(lane.content, workflow);
    else {
      assert.match(workflow, /^# Managed by right-git/);
      assert.match(workflow, /RIGHT_GIT_RELEASE_PLATFORM: \$\{\{ matrix\.platform \}\}/);
      assert.match(workflow, /RIGHT_GIT_RELEASE_ARCHITECTURE: \$\{\{ matrix\.architecture \}\}/);
      for (const runner of ['windows-2025', 'macos-15']) {
        assert.match(workflow, new RegExp(`os: "${runner}"`));
      }
      assert.doesNotMatch(workflow, /windows-11-arm|macos-15-intel/);
      assert.match(workflow, /installed-qualification:/);
      assert.match(workflow, /publish:/);
      assert.match(workflow, /signed_qualification:/);
      assert.equal((workflow.match(/if: \$\{\{ needs\.admission\.outputs\.signed_qualification == 'true' \}\}/g) ?? []).length, 2);
      assert.match(workflow, /publish:[\s\S]*?if: \$\{\{ needs\.admission\.outputs\.publish == 'true' && needs\.installed-qualification\.result == 'success' && needs\.macos-sign\.result == 'success' && needs\.admission\.outputs\.dry_run != 'true' \}\}/);
      assert.match(workflow, /dry_run: \$\{\{ steps\.admit\.outputs\.dry_run \}\}/);
      assert.match(workflow, /RIGHT_GIT_DRY_RUN: \$\{\{ inputs\.dry_run \}\}/);
    }
  }
  // unsigned-installer.yml builds an installable package with no certificate
  // and no publication path: it is the development loop, not a release lane.
  assert.deepEqual(readdirSync(join(root, '.github/workflows')).sort(), ['ci.yml', 'release-candidate.yml', 'unsigned-installer.yml']);
  const unsigned = readFileSync(join(root, '.github/workflows/unsigned-installer.yml'), 'utf8');
  assert.match(unsigned, /^permissions:\r?\n {2}contents: read\r?$/m, 'the unsigned lane never holds write authority');
  assert.doesNotMatch(unsigned, /secrets\./, 'the unsigned lane never reads a secret');
  assert.doesNotMatch(unsigned, /gh release|git tag|sign-windows|publish:/, 'the unsigned lane cannot publish');
  assert.match(unsigned, /--unsigned/, 'the unsigned lane finalizes without signing');
  // The GitHub Pages wrapper was a second, conflicting control plane: the live
  // route is the RightKit Worker backed by R2, so the product must carry no
  // Pages CNAME and no unpinned latest-download wrapper of its own.
  for (const retired of ['docs/CNAME', 'docs/install.ps1', 'site/install.ps1']) {
    assert.equal(existsSync(join(root, retired)), false, `retired Pages path must stay removed: ${retired}`);
  }
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
