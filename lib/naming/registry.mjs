import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const REGISTRY_PATH = resolve(ROOT, 'config', 'naming-registry.json');

export function loadNamingRegistry(path = REGISTRY_PATH) {
  const registry = JSON.parse(readFileSync(path, 'utf8'));
  if (registry.schemaVersion !== 1 || registry.product?.id !== 'legion') throw new TypeError('invalid Legion naming registry');
  return Object.freeze(registry);
}

export function authorityAliases(registry = loadNamingRegistry()) {
  return Object.freeze(Object.fromEntries(Object.entries(registry.authorities).flatMap(([canonical, value]) =>
    (value.aliases ?? []).map(({ id }) => [id, canonical]))));
}

export function canonicalAuthority(value, registry = loadNamingRegistry()) {
  const normalized = String(value ?? '').trim().toLowerCase().replaceAll('_', '-');
  return authorityAliases(registry)[normalized] ?? normalized;
}

export function canonicalProduct(value, registry = loadNamingRegistry()) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return registry.product.legacyIds.some(({ id }) => id === normalized) ? registry.product.id : normalized;
}

export function canonicalAuthorityIds(registry = loadNamingRegistry()) {
  return Object.freeze(Object.keys(registry.authorities).sort());
}

export function canonicalizeAuthorityRecord(record, registry = loadNamingRegistry()) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return record;
  const authorityFields = new Set(['authority', 'assignedAuthority', 'producerAuthority', 'requestedBy', 'claimingAuthority', 'actor_role', 'role']);
  return Object.fromEntries(Object.entries(record).map(([key, value]) => {
    if (authorityFields.has(key) && typeof value === 'string') return [key, canonicalAuthority(value, registry)];
    if (Array.isArray(value)) return [key, value.map((item) => canonicalizeAuthorityRecord(item, registry))];
    return [key, canonicalizeAuthorityRecord(value, registry)];
  }));
}
