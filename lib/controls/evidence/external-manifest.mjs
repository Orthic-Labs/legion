import { digest } from '../../core/binding.mjs';
export function validateExternalEvidence(manifest, binding) { const records = manifest?.records ?? []; for (const record of records) if (!record.producer || !record.scope || !record.binding || record.binding !== binding) throw new Error('invalid external evidence record'); return { schemaVersion: 1, records, digest: digest(records) }; }
