import { finalize } from '../../web/shared.mjs';
import { verifyThirdPartyExercise } from '../../web/third-party/index.mjs';
export function verifyCommerceEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyThirdPartyExercise(input); return finalize('nemesis-external-commerce-evidence', { provider: 'runtime.external.commerce', family: 'commerce', networkAttempted: false, ...receipt }); }
