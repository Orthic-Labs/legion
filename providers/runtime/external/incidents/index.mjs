import { finalize } from '../../web/shared.mjs';
import { verifyOperationsExercise } from '../../web/operations/index.mjs';
export function verifyIncidentEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyOperationsExercise(input); return finalize('legion-external-incident-evidence', { provider: 'runtime.external.incidents', family: 'incidents', claimLevel: 'external', suppliedOnly: true, networkAttempted: false, ...receipt }); }
