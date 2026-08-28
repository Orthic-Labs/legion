import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
const releaseCi = readFileSync(join(root, '.github/workflows/release-candidate.yml'), 'utf8');
const gate = readFileSync(join(root, 'scripts/ci/right-git-ci.sh'), 'utf8');
const smoke = readFileSync(join(root, 'scripts/ci/native-installed-smoke.mjs'), 'utf8');

test('CI pins toolchains, gates all supported hosts, and smoke-tests installed product', () => {
  for (const os of ['ubuntu-24.04', 'windows-2025', 'macos-15']) assert.match(ci, new RegExp(os));
  assert.match(ci, /node: \["22\.23\.2"\]/);
  assert.match(ci, /node-version: \$\{\{ matrix\.node \}\}/);
  assert.match(ci, /version: 11\.24\.0/);
  assert.match(ci, /toolchain: 1\.98\.0/);
  assert.match(ci, /Managed by right-git/);
  assert.match(ci, /bash \.\/scripts\/ci\/right-git-ci\.sh/);
  assert.match(gate, /pnpm install --frozen-lockfile/);
  assert.match(gate, /pnpm legion:check/);
  assert.match(gate, /pnpm test/);
  assert.match(gate, /cargo test --locked/);
  assert.match(gate, /native:assemble -- --profile debug/);
  assert.match(smoke, /"setup", "preview"/);
  assert.match(smoke, /"setup", "--check"/);
  assert.match(smoke, /"setup", "repair"/);
  assert.match(smoke, /allowIncomplete/);
  assert.match(smoke, /payload\.status === "incomplete"/);
  const actionRefs = [...ci.matchAll(/^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)/gm)].map((match) => match[1]);
  assert.ok(actionRefs.length >= 5);
  for (const ref of actionRefs) assert.match(ref, /^[0-9a-f]{40}$/);
  assert.match(ci, /permissions:\s*\n\s*contents: read/);
});

test('public release CI selects explicit supported targets and release profile', () => {
  assert.match(releaseCi, /include:/);
  assert.match(releaseCi, /platform: "windows"[\s\S]*architecture: "x86_64"/);
  assert.match(releaseCi, /platform: "macos"[\s\S]*architecture: "arm64"/);
  assert.match(releaseCi, /LEGION_RELEASE_PLATFORM: \$\{\{ matrix\.platform \}\}/);
  assert.match(releaseCi, /LEGION_RELEASE_ARCHITECTURE: \$\{\{ matrix\.architecture \}\}/);
  assert.doesNotMatch(releaseCi, /--profile debug/);
});
