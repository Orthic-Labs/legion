import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));

test('package-manager channel identity matches frozen distribution contract', () => {
  const channels = JSON.parse(readFileSync(join(root, 'packaging/channels.json'), 'utf8'));
  const contract = JSON.parse(readFileSync(join(root, 'migration/native-rust/m0/distribution-contract.json'), 'utf8'));
  assert.equal(channels.versionSource, 'release/version.json');
  assert.equal(channels.channels.homebrew.tapRepository, contract.macOS.initialChannel);
  assert.equal(channels.channels.homebrew.formula, 'orthic-labs/tap/legion');
  assert.equal(channels.channels.winget.packageIdentifier, contract.windows.packageIdentifier);
  assert.equal(channels.channels.homebrew.status, 'unavailable');
  assert.equal(channels.channels.winget.status, 'unavailable');
});

test('repository carries no placeholder formula or pseudo-WinGet manifest', () => {
  assert.equal(existsSync(join(root, 'packaging/homebrew/formula.md')), false);
  assert.equal(existsSync(join(root, 'packaging/winget/manifest.md')), false);
});
