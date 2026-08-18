import { finalize } from '../shared.mjs';
import { executeWebProtocol } from '../protocols/index.mjs';
import { inspectWebBackend } from '../backend/index.mjs';
import { runWebScenario } from '../scenario/index.mjs';
import { verifyServiceApi } from '../../service/api/index.mjs';

export async function runWebControl({ binding = {}, family, input = {} } = {}) {
  if (family === 'protocol') return executeWebProtocol({ binding, ...input });
  if (family === 'backend') return inspectWebBackend({ binding, ...input });
  if (family === 'scenario') return runWebScenario({ binding, ...input });
  if (family === 'api') {
    const { digest: _digest, kind: _kind, schemaVersion: _schemaVersion, provider: delegatedProvider, ...receipt } = verifyServiceApi({ binding, ...input });
    return finalize('legion-web-api-provider', { ...receipt, provider: 'runtime.web', delegatedProvider: delegatedProvider ?? 'runtime.service.api' });
  }
  return finalize('legion-web-control-receipt', { status: 'blocked', terminal: true, binding, family: family ?? null, coverageGaps: ['web-control-family-unsupported'] });
}
