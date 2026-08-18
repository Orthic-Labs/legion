import { canonicalAuthority, canonicalizeAuthorityRecord, canonicalProduct, loadNamingRegistry } from './registry.mjs';

export const NAMING_SCHEMA_VERSION = 3;

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

export function equivalentMcpBinding(left, right) {
  return JSON.stringify(canonicalValue(left)) === JSON.stringify(canonicalValue(right));
}

export function isLegionOwnedAssuranceBinding(entry) {
  if (!entry || !['python', 'python3'].includes(entry.command) || !Array.isArray(entry.args)) return false;
  const moduleFlag = entry.args.indexOf('-m');
  return moduleFlag >= 0 && entry.args[moduleFlag + 1] === 'legion_kernel.adapters.mcp_server';
}

export function migrateMcpServers(input, registry = loadNamingRegistry()) {
  const output = structuredClone(input ?? {});
  const containerKey = output.mcp_servers && typeof output.mcp_servers === 'object'
    ? 'mcp_servers'
    : output.mcpServers && typeof output.mcpServers === 'object' ? 'mcpServers' : null;
  const servers = containerKey ? output[containerKey] : null;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return output;
  const legacyId = Object.entries(registry.authorities).find(([, value]) => value.displayName === 'Oracle')?.[1]?.aliases?.[0]?.id;
  if (!legacyId || !Object.hasOwn(servers, legacyId)) return output;
  const legacy = servers[legacyId];
  if (!isLegionOwnedAssuranceBinding(legacy)) return output;
  if (!servers.oracle) {
    servers.oracle = structuredClone(legacy);
    delete servers[legacyId];
  } else if (equivalentMcpBinding(servers.oracle, legacy)) {
    delete servers[legacyId];
  }
  return output;
}

export function inspectMcpNaming(input, registry = loadNamingRegistry()) {
  const servers = input?.mcp_servers ?? input?.mcpServers;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return Object.freeze({ status: 'absent', legacy: [] });
  const legacyIds = Object.values(registry.authorities).flatMap(({ aliases = [] }) => aliases.map(({ id }) => id));
  const legacy = legacyIds.filter((id) => Object.hasOwn(servers, id)).map((id) => ({
    id,
    owned: isLegionOwnedAssuranceBinding(servers[id]),
    conflict: Object.hasOwn(servers, canonicalAuthority(id, registry)) && !equivalentMcpBinding(servers[id], servers[canonicalAuthority(id, registry)]),
  }));
  return Object.freeze({ status: legacy.length ? 'legacy-present' : 'canonical', legacy: Object.freeze(legacy) });
}

export const MIGRATIONS = Object.freeze([
  Object.freeze({
    id: 'v001_product_namespace_to_legion',
    apply(state, registry) {
      const next = structuredClone(state);
      if (typeof next.product === 'string') next.product = canonicalProduct(next.product, registry);
      return next;
    },
  }),
  Object.freeze({
    id: 'v002_assurance_alias_to_oracle',
    apply(state, registry) {
      return migrateMcpServers(canonicalizeAuthorityRecord(state, registry), registry);
    },
  }),
  Object.freeze({
    id: 'v003_authority_alias_normalization',
    apply(state, registry) {
      return canonicalizeAuthorityRecord(state, registry);
    },
  }),
]);

export function migrateNamingState(input, registry = loadNamingRegistry()) {
  const source = structuredClone(input ?? {});
  const prior = source.namingMigration ?? { schemaVersion: 0, applied: [] };
  let current = source;
  const applied = new Set(prior.applied ?? []);
  for (const migration of MIGRATIONS) {
    current = migration.apply(current, registry);
    applied.add(migration.id);
  }
  current.namingMigration = { schemaVersion: NAMING_SCHEMA_VERSION, applied: [...applied].sort() };
  return current;
}

export function namingMigrationStatus(input) {
  const migrated = migrateNamingState(input);
  return Object.freeze({
    schemaVersion: NAMING_SCHEMA_VERSION,
    current: input?.namingMigration?.schemaVersion === NAMING_SCHEMA_VERSION,
    applied: migrated.namingMigration.applied,
    canonical: JSON.stringify(migrated) === JSON.stringify(migrateNamingState(migrated)),
  });
}

export function canonicalSerializedAuthority(value) {
  return canonicalAuthority(value);
}
