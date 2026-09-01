// Runtime capability probing.
//
// The capability registry declares what this package does NOT ship and how it degrades. That
// declaration is checked at build time by dependency-closure.mjs, but a declaration alone tells a
// running caller nothing: an absent capability still fails opaquely at the point of use.
//
// probeCapability answers "is this host actually able to do the thing?" and, when it cannot, hands
// back the registry's degradation plus an actionable remedy the caller can show the user. A
// capability with no probe is reported unknown rather than assumed present — silence is never
// treated as availability.

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { loadCapabilityRegistry } from './registry.mjs';

export { loadCapabilityRegistry } from './registry.mjs';
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
export const COMMAND_PROBE_TIMEOUT_MS = 3_000;

function onPath(command) {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [command], {
      stdio: 'ignore', timeout: COMMAND_PROBE_TIMEOUT_MS, windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

function detect(probe, env, { commandExists = onPath, pathExists = existsSync } = {}) {
  if (!probe) return null;
  if (probe.kind === 'command') return commandExists(probe.command);
  if (probe.kind === 'command-any') return probe.commands.some((command) => commandExists(command));
  if (probe.kind === 'env') return Boolean(env[probe.env]);
  if (probe.kind === 'path') return pathExists(probe.path);
  return null;
}

export function probeCapability(id, {
  registry = loadCapabilityRegistry(), env = process.env, commandExists = onPath, pathExists = existsSync, identity = null, sign = null,
} = {}) {
  const entry = registry.capabilities?.[id];
  if (!entry) throw new Error(`capability is not declared in the registry: ${id}`);
  const available = detect(entry.probe, env, { commandExists, pathExists });
  const metadata = {
    id,
    kind: entry.kind,
    available,                                    // true | false | null (unknown: no probe declared)
    summary: entry.summary,
    degradation: entry.degradation,
    remedy: entry.remedy ?? null,
    message: available === true ? null : unavailableMessage(id, entry, available),
  };
  const metadataDigest = `sha256:${createHash('sha256').update(JSON.stringify(canonical(metadata))).digest('hex')}`;
  const signature = available === true && identity && typeof sign === 'function' ? sign(metadataDigest, identity) : null;
  const trust = available === false ? 'UNAVAILABLE' : available == null ? 'UNKNOWN' : typeof signature === 'string' && signature ? 'VERIFIED' : 'UNKNOWN';
  const attestation = { schemaVersion: 1, kind: 'legion-capability-attestation', capabilityId: id, metadataDigest, availability: available, trust, identity: trust === 'VERIFIED' ? identity : null, signature: trust === 'VERIFIED' ? signature : null };
  return { ...metadata, attestation };
}

function unavailableMessage(id, entry, available) {
  const state = available === false ? 'is not available on this host' : 'could not be detected on this host';
  const remedy = entry.remedy ? ` To enable it: ${entry.remedy}` : '';
  return `${id} ${state}. ${entry.degradation}${remedy}`;
}

export function probeAll(options = {}) {
  const registry = options.registry ?? loadCapabilityRegistry();
  return Object.keys(registry.capabilities ?? {}).map((id) => probeCapability(id, { ...options, registry }));
}
