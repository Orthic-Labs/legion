import { finalize } from '../../web/shared.mjs';
import { verifyApiExercise } from '../../web/api/index.mjs';

export function verifyServiceApi(input = {}) {
  const { digest: _digest, kind: _kind, schemaVersion: _schemaVersion, ...receipt } = verifyApiExercise(input);
  return finalize('nemesis-service-api-provider', { provider: 'runtime.service.api', ...receipt });
}
