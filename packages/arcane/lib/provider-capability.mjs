import { decision } from './errors.mjs';

export function verifyExternalProviderCapability(capability, { providerId = capability?.providerId } = {}) {
  const required = ['providerId', 'machineReadable', 'gateable', 'downloadable', 'trustedRetrieval', 'trajectoryBindable', 'sensitivity', 'retention', 'deletionOwner'];
  const missing = required.filter((key) => capability?.[key] === undefined || capability?.[key] === null || capability?.[key] === '');
  if (missing.length || capability.providerId !== providerId) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'external provider capability is incomplete or substituted', detail: { providerId, missing } });
  if (![capability.machineReadable, capability.gateable, capability.downloadable, capability.trustedRetrieval, capability.trajectoryBindable].every(Boolean)) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'external provider cannot produce closure-grade evidence', detail: { providerId } });
  return decision({ allowed: true, message: 'external provider capability supports closure-grade evidence', detail: { providerId } });
}
