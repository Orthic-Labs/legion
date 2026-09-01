import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));

test('direct bootstrap is sole public installation channel', () => {
  const channels = JSON.parse(readFileSync(join(root, 'packaging/channels.json'), 'utf8'));
  const contract = JSON.parse(readFileSync(join(root, 'release/distribution-contract.json'), 'utf8'));
  assert.equal(channels.versionSource, 'release/version.json');
  assert.equal(contract.nativeRelease.channel, 'direct-bootstrap');
  assert.equal(channels.channels['direct-bootstrap'].stableUrl, contract.nativeRelease.bootstrapAuthority);
  assert.equal(channels.channels['direct-bootstrap'].payloadAuthority, 'immutable-github-release');
  assert.equal(channels.channels.homebrew, undefined);
  assert.equal(channels.channels.winget, undefined);
  assert.equal(contract.packageManagers, undefined);
});

test('repository carries no placeholder formula or pseudo-WinGet manifest', () => {
  assert.equal(existsSync(join(root, 'packaging/homebrew/formula.md')), false);
  assert.equal(existsSync(join(root, 'packaging/winget/manifest.md')), false);
});
