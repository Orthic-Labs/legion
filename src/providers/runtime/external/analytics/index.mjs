import { finalize } from '../../web/shared.mjs';
import { verifyThirdPartyExercise } from '../../web/third-party/index.mjs';
export function verifyAnalyticsEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyThirdPartyExercise(input); return finalize('legion-external-analytics-evidence', { provider: 'runtime.external.analytics', family: 'analytics', networkAttempted: false, ...receipt }); }
