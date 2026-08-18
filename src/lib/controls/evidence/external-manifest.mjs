import { digest } from '../../core/binding.mjs';
import { sameBinding } from '../../core/binding.mjs';
const SHA=/^sha256:[a-f0-9]{64}$/;
export function validateExternalEvidence(manifest, binding, {now} = {}) {
  if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw new TypeError('external evidence requires an injected frozen clock');
  const records = manifest?.records ?? [];
  for (const record of records) {
    const levels=record.claimLevels??[];
    if(new Set(levels).size!==levels.length)throw new Error('duplicate claim level');
    if (!record.producer || !record.scope || !record.environment || !record.binding || !sameBinding(record.binding,binding)) throw new Error('invalid external evidence record');
    if(levels.length&&(!SHA.test(record.artifactDigest??'')||!record.observedAt||!record.expiresAt||!Array.isArray(record.limitations)))throw new Error('external evidence requires artifact digest and freshness');
    if(record.observedAt&&!Number.isFinite(Date.parse(record.observedAt)))throw new Error('external evidence observedAt is invalid');
    if(record.expiresAt&&Date.parse(record.expiresAt)<=Date.parse(record.observedAt))throw new Error('external evidence freshness interval is invalid');
    if(record.expiresAt&&Date.parse(record.expiresAt)<=now.getTime())throw new Error('external evidence expired');
  }
  return { schemaVersion: 1, records, digest: digest(records) };
}
