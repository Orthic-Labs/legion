import { finalize } from '../../web/shared.mjs';
import { verifyInfrastructureExercise } from '../../web/infrastructure/index.mjs';
export function verifyDnsEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyInfrastructureExercise(input); return finalize('nemesis-external-dns-evidence', { provider: 'runtime.external.dns', family: 'dns', ...receipt }); }
