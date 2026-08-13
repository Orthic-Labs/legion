import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkCanonicalNames } from '../lib/naming/check.mjs';
import { canonicalAuthority, canonicalizeAuthorityRecord } from '../lib/naming/registry.mjs';
import { isLegionOwnedAssuranceBinding, migrateMcpServers, migrateNamingState } from '../lib/naming/migrations.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const owned = { command: 'python3', args: ['-m', 'legion_kernel.adapters.mcp_server'] };

test('canonical authority aliases read old and write canonical', () => {
  assert.equal(canonicalAuthority('seer'), 'oracle');
  assert.equal(canonicalAuthority('oracle'), 'oracle');
  assert.equal(canonicalAuthority('forge'), 'alchemist');
  assert.equal(canonicalAuthority('alchemist'), 'alchemist');
  assert.equal(canonicalAuthority('sorcerer'), 'alchemist');
  assert.equal(canonicalAuthority('sentinel'), 'arcane');
  assert.deepEqual(canonicalizeAuthorityRecord({ authority: 'seer', nested: { producerAuthority: 'forge' } }), { authority: 'oracle', nested: { producerAuthority: 'alchemist' } });
});

test('naming migration is deterministic and idempotent', () => {
  const input = { product: 'nemesis', authority: 'seer' };
  const once = migrateNamingState(input);
  const twice = migrateNamingState(once);
  assert.deepEqual(once, twice);
  assert.equal(once.product, 'legion');
  assert.equal(once.authority, 'oracle');
});

test('MCP migration changes only Legion-owned legacy assurance binding', () => {
  assert.equal(isLegionOwnedAssuranceBinding(owned), true);
  const migrated = migrateMcpServers({ mcp_servers: { seer: owned } });
  assert.equal(migrated.mcp_servers.seer, undefined);
  assert.deepEqual(migrated.mcp_servers.oracle, owned);
  const userOwned = { mcp_servers: { seer: { command: 'my-private-server' } } };
  assert.deepEqual(migrateMcpServers(userOwned), userOwned);
  const conflict = { mcp_servers: { seer: owned, oracle: { command: 'different' } } };
  assert.deepEqual(migrateMcpServers(conflict), conflict);
});

test('repository has no unclassified legacy naming', () => {
  assert.deepEqual(checkCanonicalNames({ root }).unclassified, []);
});
