import { finalize } from '../../web/shared.mjs';
import { verifyThirdPartyExercise } from '../../web/third-party/index.mjs';
export function verifyAnalyticsEvidence(input = {}) { const { digest: _, kind: _kind, schemaVersion: _version, ...receipt } = verifyThirdPartyExercise(input); return finalize('nemesis-external-analytics-evidence', { provider: 'runtime.external.analytics', family: 'analytics', networkAttempted: false, ...receipt }); }
