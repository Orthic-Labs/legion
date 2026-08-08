import { finalize } from '../../web/shared.mjs';
import { verifyThirdPartyExercise } from '../../web/third-party/index.mjs';
export function verifyThirdPartyEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyThirdPartyExercise(input); return finalize('nemesis-external-third-party-evidence', { provider: 'runtime.external.third-party', family: 'third-party', networkAttempted: false, ...receipt }); }
