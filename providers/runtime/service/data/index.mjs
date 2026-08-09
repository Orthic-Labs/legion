import { finalize } from '../../web/shared.mjs';
import { verifyDataExercise } from '../../web/data/index.mjs';

export async function verifyServiceData(input = {}) {
  const { digest: _digest, kind: _kind, schemaVersion: _schemaVersion, ...receipt } = await verifyDataExercise(input);
  return finalize('legion-service-data-provider', { provider: 'runtime.service.data', claimLevel: 'runtime', ...receipt });
}
