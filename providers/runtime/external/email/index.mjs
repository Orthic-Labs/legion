import { finalize } from '../../web/shared.mjs';
import { verifyThirdPartyExercise } from '../../web/third-party/index.mjs';
export function verifyEmailEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyThirdPartyExercise(input); return finalize('nemesis-external-email-evidence', { provider: 'runtime.external.email', family: 'email', networkAttempted: false, ...receipt }); }
