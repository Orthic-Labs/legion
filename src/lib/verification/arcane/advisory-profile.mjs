import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateSkillBundle } from '../../skills/contracts.mjs';
import { canonicalJson, digestValue } from '../../contracts/arcane/canonical.mjs';
import { ArcaneError } from '../../contracts/arcane/errors.mjs';

const DEFAULT_MANIFEST_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../skills/manifests');
const ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const fail = (message, detail = {}) => { throw new ArcaneError('ARC_PROFILE_BINDING_MISMATCH', message, detail); };

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freeze(child);
  }
  return value;
}

export function compileAdvisoryProfile({ bundleId, profileId, manifestRoot = DEFAULT_MANIFEST_ROOT } = {}) {
  if (!ID.test(bundleId ?? '') || !ID.test(profileId ?? '')) fail('invalid advisory bundle or profile id');
  const path = resolve(manifestRoot, `${bundleId}.json`);
  if (dirname(path) !== resolve(manifestRoot)) fail('advisory manifest path escapes package root');
  let manifest;
  try { manifest = JSON.parse(readFileSync(path, 'utf8')); } catch { fail('canonical advisory manifest is unavailable', { bundleId }); }
  try { validateSkillBundle(manifest); } catch (error) { fail('canonical advisory manifest is invalid', { bundleId, cause: error.message }); }
  if (manifest.id !== bundleId) fail('canonical advisory manifest id differs', { bundleId, actual: manifest.id });
  const profile = manifest.profiles?.[profileId];
  if (!profile || typeof profile.mutation !== 'boolean' || typeof profile.publish !== 'boolean') fail('canonical advisory profile is invalid', { bundleId, profileId });
  const normalized = {
    schemaVersion: 1,
    kind: 'arcane-advisory-profile-binding',
    bundleId,
    bundleVersion: manifest.version,
    profileId,
    manifestDigest: digestValue(manifest),
    profileDigest: digestValue({ domain: 'arcane.advisory-profile.v1', values: [bundleId, manifest.version, profileId, profile] }),
    mutationAllowed: profile.mutation,
    publishAllowed: profile.publish,
    externalOnly: profile.externalOnly === true,
  };
  return freeze(normalized);
}

export function requireCanonicalAdvisoryProfile(binding, options = {}) {
  if (binding == null) return null;
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) fail('advisory profile binding must be an object');
  const canonical = compileAdvisoryProfile({ bundleId: binding.bundleId, profileId: binding.profileId, ...options });
  if (canonicalJson(binding) !== canonicalJson(canonical)) fail('advisory profile binding differs from canonical package manifest', { bundleId: binding.bundleId, profileId: binding.profileId });
  return canonical;
}

export { DEFAULT_MANIFEST_ROOT };
