import { finalize } from '../../web/shared.mjs';
import { verifyOperationsExercise } from '../../web/operations/index.mjs';
export function verifyBackupEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyOperationsExercise(input); return finalize('nemesis-external-backup-evidence', { provider: 'runtime.external.backup', family: 'backup', claimLevel: 'external', suppliedOnly: true, networkAttempted: false, ...receipt }); }
