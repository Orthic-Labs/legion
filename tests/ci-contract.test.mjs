import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
const releaseCi = readFileSync(join(root, '.github/workflows/release-candidate.yml'), 'utf8');
const gate = readFileSync(join(root, 'scripts/gate.sh'), 'utf8');
const gateImplementation = readFileSync(join(root, 'scripts/ci/right-git-ci.sh'), 'utf8');
const smoke = readFileSync(join(root, 'scripts/ci/native-installed-smoke.mjs'), 'utf8');
const candidate = readFileSync(join(root, 'scripts/ci/prepare-unsigned-candidate.mjs'), 'utf8');

test('push and PR CI stays Windows-only while release candidates build primary installer targets', () => {
  assert.match(ci, /os: \["windows-2025"\]/);
  assert.doesNotMatch(ci, /os: \[[^\]]*(?:ubuntu-24\.04|macos-15)[^\]]*\]/);
  assert.match(ci, /node: \["22\.23\.2"\]/);
  assert.match(ci, /node-version: \$\{\{ matrix\.node \}\}/);
  assert.match(ci, /version: 11\.24\.0/);
  assert.match(ci, /components: rustfmt, clippy/);
  assert.doesNotMatch(ci, /^\s*toolchain:/m);
  assert.match(ci, /fetch-depth: 0/);
  assert.match(ci, /cache-on-failure: true/);
  assert.match(ci, /Managed by right-git/);
  assert.match(ci, /bash \.\/scripts\/gate\.sh/);
  assert.match(gate, /exec bash .*ci\/right-git-ci\.sh/);
  assert.match(gateImplementation, /pnpm install --frozen-lockfile/);
  assert.match(gateImplementation, /pnpm legion:check/);
  assert.match(gateImplementation, /pnpm test/);
  assert.match(gateImplementation, /cargo test --locked/);
  assert.match(gateImplementation, /native:assemble -- --profile debug/);
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
  assert.match(releaseCi, /os: "windows-2025"[\s\S]*platform: "windows"[\s\S]*architecture: "x86_64"/);
  assert.match(releaseCi, /os: "macos-15"[\s\S]*platform: "macos"[\s\S]*architecture: "arm64"/);
  assert.doesNotMatch(releaseCi, /windows-11-arm|macos-15-intel/);
  for (const targetTriple of [
    'x86_64-pc-windows-msvc',
    'aarch64-apple-darwin',
  ]) assert.match(releaseCi, new RegExp(targetTriple));
  assert.match(releaseCi, /RIGHT_GIT_RELEASE_PLATFORM: \$\{\{ matrix\.platform \}\}/);
  assert.match(releaseCi, /RIGHT_GIT_RELEASE_ARCHITECTURE: \$\{\{ matrix\.architecture \}\}/);
  assert.doesNotMatch(releaseCi, /bash \.\/scripts\/gate\.sh/);
  assert.ok(releaseCi.indexOf('pnpm install --frozen-lockfile') < releaseCi.indexOf('Build unsigned release candidate'));
  assert.match(releaseCi, /windows-sign:/);
  assert.match(releaseCi, /macos-sign:/);
  assert.match(releaseCi, /installed-qualification:/);
  assert.match(releaseCi, /publish:/);
  assert.match(releaseCi, /release:finalize-windows/);
  assert.match(releaseCi, /release:finalize-macos/);
  assert.match(releaseCi, /release:qualify-installed/);
  assert.match(releaseCi, /release:publish-qualified/);
  assert.match(releaseCi, /signed_qualification:/);
  assert.equal((releaseCi.match(/if: \$\{\{ startsWith\(github\.ref, 'refs\/tags\/v'\) \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.signed_qualification == true\) \}\}/g) ?? []).length, 2);
  assert.match(releaseCi, /publish:[\s\S]*?if: \$\{\{ startsWith\(github\.ref, 'refs\/tags\/v'\) && needs\.installed-qualification\.result == 'success' && needs\.macos-sign\.result == 'success' \}\}/);
  assert.match(releaseCi, /name: legion-signed-windows-\$\{\{ matrix\.architecture \}\}-22\.23\.2/);
  assert.match(releaseCi, /name: legion-signed-macos-\$\{\{ matrix\.architecture \}\}-22\.23\.2/);
  assert.match(releaseCi, /pnpm run release:finalize-windows/);
  assert.match(releaseCi, /pnpm run release:finalize-macos/);
  assert.match(releaseCi, /secrets\.APPLE_CERTIFICATE_BASE64/);
  assert.doesNotMatch(releaseCi, /pull_request_target/);
  assert.doesNotMatch(releaseCi, /--profile debug/);
  assert.match(candidate, /pnpm npm_execpath is required for cross-platform candidate execution/);
  assert.match(candidate, /process\.execPath/);
  assert.match(candidate, /\["build", "--locked", "--release", "--bins"/);
});
