import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkCanonicalNames } from '../src/lib/naming/check.mjs';
import { canonicalAuthority, canonicalizeAuthorityRecord } from '../src/lib/naming/registry.mjs';
import { inspectMcpNaming, isLegionOwnedAssuranceBinding, migrateMcpServers, migrateNamingState } from '../src/lib/naming/migrations.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const owned = { command: 'python3', args: ['-m', 'legion_kernel.adapters.mcp_server'] };

test('canonical authority aliases read old and write canonical across scalar and array contract fields', () => {
  assert.equal(canonicalAuthority('seer'), 'oracle');
  assert.equal(canonicalAuthority('oracle'), 'oracle');
  assert.equal(canonicalAuthority('forge'), 'alchemist');
  assert.equal(canonicalAuthority('alchemist'), 'alchemist');
  assert.equal(canonicalAuthority('sorcerer'), 'alchemist');
  assert.equal(canonicalAuthority('sentinel'), 'arcane');
  assert.deepEqual(
    canonicalizeAuthorityRecord({ authority: 'seer', callerAuthority: 'forge', authoritiesInvolved: ['seer', 'sentinel'], nested: { producerAuthority: 'sorcerer' } }),
    { authority: 'oracle', callerAuthority: 'alchemist', authoritiesInvolved: ['oracle', 'arcane'], nested: { producerAuthority: 'alchemist' } },
  );
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
  assert.deepEqual(inspectMcpNaming(conflict), { status: 'legacy-present', legacy: [{ id: 'seer', owned: true, conflict: true }] });
  const camel = migrateMcpServers({ mcpServers: { seer: owned } });
  assert.equal(camel.mcpServers.seer, undefined);
  assert.deepEqual(camel.mcpServers.oracle, owned);
  const reordered = migrateMcpServers({ mcp_servers: {
    seer: { command: 'python3', args: ['-m', 'legion_kernel.adapters.mcp_server'], env: { B: '2', A: '1' } },
    oracle: { env: { A: '1', B: '2' }, args: ['-m', 'legion_kernel.adapters.mcp_server'], command: 'python3' },
  } });
  assert.equal(reordered.mcp_servers.seer, undefined);
});

function namingFixture() {
  const fixture = mkdtempSync(join(tmpdir(), 'legion-naming-adversarial-'));
  const files = [
    'src/config/naming-registry.json', 'src/config/naming-legacy-allowlist.json', 'README.md', 'package.json', 'MANIFEST.package.json',
    '.claude-plugin/plugin.json', '.codex-plugin/plugin.json', 'src/lib/roster/index.mjs', 'src/lib/cli/commands/doctor.mjs',
    'src/packages/context/lib/context.mjs', 'src/lib/verification/arcane/architecture-event-store.mjs', 'src/lib/contracts/arcane/authority-binding-store.mjs',
    'src/providers/security/packs/output-handling.mjs',
  ];
  for (const path of files) {
    mkdirSync(dirname(join(fixture, path)), { recursive: true });
    cpSync(join(root, path), join(fixture, path));
  }
  return fixture;
}

test('naming checker rejects unclassified active filenames, NUL source, and legacy package manifest entries', () => {
  const fixture = namingFixture();
  try {
    mkdirSync(join(fixture, 'src', 'lib', 'naming'), { recursive: true });
    writeFileSync(join(fixture, 'src', 'lib', 'naming', 'seer-runtime.mjs'), 'export const active = true;\n');
    writeFileSync(join(fixture, 'active.mjs'), Buffer.from('export const value = "\0seer";\n'));
    writeFileSync(join(fixture, 'neutral-nul.mjs'), Buffer.from('export const value = "\0neutral";\n'));
    const doctorPath = join(fixture, 'src', 'lib', 'cli', 'commands', 'doctor.mjs');
    writeFileSync(doctorPath, `${readFileSync(doctorPath, 'utf8')}\n// seer\n`);
    const manifestPath = join(fixture, 'MANIFEST.package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.allowlistedTopLevel.push('packages/seer/');
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const report = checkCanonicalNames({ root: fixture });
    assert.equal(report.status, 'fail');
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'src/lib/naming/seer-runtime.mjs' && reason === 'unclassified legacy filename'));
    assert.ok(report.unclassified.some(({ path }) => path === 'active.mjs'));
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'neutral-nul.mjs' && reason === 'active source cannot be decoded for naming scan'));
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'src/lib/cli/commands/doctor.mjs' && reason.includes('occurrence count differs')));
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'MANIFEST.package.json' && reason.includes('retains legacy assurance package')));
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});

test('naming checker rejects security-pack prefix and occurrence bypasses', () => {
  const fixture = namingFixture();
  try {
    const allowedPath = join(fixture, 'src', 'providers', 'security', 'packs', 'output-handling.mjs');
    writeFileSync(allowedPath, `${readFileSync(allowedPath, 'utf8')}\nexport const currentAuthority = 'forge';\n`);
    const injectedPath = join(fixture, 'src', 'providers', 'security', 'packs', 'injected.mjs');
    writeFileSync(injectedPath, "export const currentAuthority = 'forge';\n");
    const report = checkCanonicalNames({ root: fixture });
    assert.equal(report.status, 'fail');
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'src/providers/security/packs/output-handling.mjs' && reason.includes('occurrence count differs')));
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'src/providers/security/packs/injected.mjs' && reason === 'unclassified legacy token'));
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});

test('naming checker rejects dead exact-path & unused token exemptions', () => {
  const fixture = namingFixture();
  try {
    const allowlistPath = join(fixture, 'src/config/naming-legacy-allowlist.json');
    const allowlist = JSON.parse(readFileSync(allowlistPath, 'utf8'));
    allowlist.rules.push({ path: 'missing/legacy.md', tokens: ['forge'], class: 'R5', reason: 'dead fixture' });
    allowlist.rules.push({ path: 'README.md', tokens: ['seer'], class: 'R5', reason: 'unused fixture' });
    writeFileSync(allowlistPath, `${JSON.stringify(allowlist, null, 2)}\n`);
    const report = checkCanonicalNames({ root: fixture });
    assert.equal(report.status, 'fail');
    assert.ok(report.unclassified.some(({ path, reason }) => path === 'missing/legacy.md' && reason.includes('matches no files')));
    assert.ok(report.unclassified.some(({ path, token, reason }) => path === 'README.md' && token === 'seer' && reason.includes('unused')));
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});

test('naming checker ignores immutable Foundation evidence artifacts', () => {
  const fixture = namingFixture();
  try {
    const reportPath = join(fixture, 'docs', 'foundation', 'comparison.md');
    mkdirSync(dirname(reportPath), { recursive: true });
    writeFileSync(reportPath, 'Donor evidence may use historical tokens such as sentinel or seer.\n');
    const report = checkCanonicalNames({ root: fixture });
    assert.equal(
      report.unclassified.filter(({ path }) => path.startsWith('docs/foundation/')).length,
      0,
    );
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});

test('repository has no unclassified legacy naming', () => {
  assert.deepEqual(checkCanonicalNames({ root }).unclassified, []);
});
