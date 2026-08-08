import { finalize } from '../../web/shared.mjs';
import { verifyInfrastructureExercise } from '../../web/infrastructure/index.mjs';
export function verifyCloudEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyInfrastructureExercise(input); return finalize('nemesis-external-cloud-evidence', { provider: 'runtime.external.cloud', family: 'cloud', ...receipt }); }
