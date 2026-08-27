// Canonical host-capability registry loading and structural validation.
//
// A capability declaration is a contract: every host requirement, probe, and
// degradation path resolves through this one document. Keep validation here so
// build-time closure checks and runtime probes cannot disagree about registry
// validity.
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const CAPABILITY_ID = /^[a-z][a-z0-9-]*$/;
const COMMAND = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const CLASSES = new Set([
  'PACKAGE_INTERNAL', 'HOST_CAPABILITY', 'PROJECT_OVERLAY', 'HISTORICAL_EVIDENCE',
]);

function invalid(path, detail) {
  throw new Error(`${path}: ${detail}`);
}

function validateCommands(value, path) {
  if (!Array.isArray(value) || value.length === 0) invalid(path, 'commands must be a non-empty array');
  if (new Set(value).size !== value.length) invalid(path, 'commands contains duplicates');
  for (const command of value) {
    if (typeof command !== 'string' || !COMMAND.test(command)) invalid(path, `invalid command ${JSON.stringify(command)}`);
  }
}

function validateProbe(probe, path) {
  if (probe == null) return;
  if (!probe || typeof probe !== 'object' || Array.isArray(probe)) invalid(path, 'probe must be an object');
  if (probe.kind === 'command') {
    if (typeof probe.command !== 'string' || !COMMAND.test(probe.command)) invalid(path, 'command probe requires a valid command');
    return;
  }
  if (probe.kind === 'command-any') {
    validateCommands(probe.commands, path);
    return;
  }
  if (probe.kind === 'env') {
    if (typeof probe.env !== 'string' || !probe.env) invalid(path, 'env probe requires an env name');
    return;
  }
  if (probe.kind === 'path') {
    if (typeof probe.path !== 'string' || !probe.path) invalid(path, 'path probe requires a path');
    return;
  }
  invalid(path, `unknown probe kind ${JSON.stringify(probe.kind)}`);
}

/** Validate and return one registry document. */
export function validateCapabilityRegistry(registry, { path = 'capability registry' } = {}) {
  if (!registry || typeof registry !== 'object' || Array.isArray(registry)) invalid(path, 'registry must be an object');
  if (registry.schemaVersion !== 1 || registry.kind !== 'legion-capability-registry') invalid(path, 'registry has an unsupported schema');
  if (!registry.classes || typeof registry.classes !== 'object' || Array.isArray(registry.classes)) invalid(path, 'registry classes must be an object');
  for (const klass of CLASSES) if (typeof registry.classes[klass] !== 'string' || !registry.classes[klass]) invalid(path, `registry does not document ${klass}`);
  if (!registry.capabilities || typeof registry.capabilities !== 'object' || Array.isArray(registry.capabilities)) invalid(path, 'registry capabilities must be an object');
  for (const [id, entry] of Object.entries(registry.capabilities)) {
    const entryPath = `${path}#capabilities.${id}`;
    if (!CAPABILITY_ID.test(id)) invalid(entryPath, 'invalid capability id');
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) invalid(entryPath, 'capability must be an object');
    for (const field of ['kind', 'summary', 'degradation', 'remedy']) {
      if (typeof entry[field] !== 'string' || !entry[field]) invalid(entryPath, `capability declares no ${field}`);
    }
    validateProbe(entry.probe, entryPath);
    if (entry.commands != null) validateCommands(entry.commands, entryPath);
  }
  return registry;
}

/** Read and validate the package's capability registry. */
export function loadCapabilityRegistry(packageRoot = resolve(import.meta.dirname, '../../..')) {
  const path = resolve(packageRoot, 'src/registry/capabilities.json');
  if (!existsSync(path)) throw new Error(`capability registry is absent: ${path}`);
  return validateCapabilityRegistry(JSON.parse(readFileSync(path, 'utf8')), { path });
}

/** Map executable command aliases to their declared host capability. */
export function commandCapabilityMap(registry) {
  const commands = new Map();
  for (const [id, entry] of Object.entries(registry.capabilities ?? {})) {
    const aliases = new Set(entry.commands ?? []);
    if (entry.probe?.kind === 'command') aliases.add(entry.probe.command);
    if (entry.probe?.kind === 'command-any') for (const command of entry.probe.commands) aliases.add(command);
    for (const command of aliases) {
      const key = command.toLowerCase();
      const prior = commands.get(key);
      if (prior && prior !== id) throw new Error(`capability registry maps command ${command} to both ${prior} and ${id}`);
      commands.set(key, id);
    }
  }
  return commands;
}
