import { SERVICE_RUNTIME_SCENARIOS } from '../../worker/index.mjs';

export async function assessServiceRuntime({ target = {}, adapter = {}, productionControls = [] } = {}) {
  const binding = { targetId: target.id ?? null, artifactDigest: target.artifactDigest ?? null, environment: target.environment ?? null, configurationDigest: target.configurationDigest ?? null,
    deployment: target.deployment ?? null, region: target.region ?? null, datastore: target.datastore ?? null, queue: target.queue ?? null, externalProviders: target.externalProviders ?? [], workload: target.workload ?? null };
  const receipts = [];
  for (const id of SERVICE_RUNTIME_SCENARIOS) {
    let result;
    try { result = typeof adapter.execute === 'function' ? await adapter.execute({ id, binding }) : null; } catch { result = { status: 'error', terminal: true }; }
    const valid = result && ['pass', 'fail', 'partial', 'unproven', 'blocked', 'error'].includes(result.status) && result.terminal === true;
    const restartGap = id === 'worker-restart' && valid && result.status === 'pass' && result.restartable !== true ? ['worker-restartability-unproven'] : [];
    receipts.push({ id, status: restartGap.length ? 'partial' : valid ? result.status : 'unproven', terminal: true, binding, cleanup: result?.cleanup ?? null, evidence: result?.evidence ?? null, coverageGaps: valid ? restartGap : ['runtime-execution-missing'] });
  }
  const externalGaps = productionControls.map((id) => `production-external-evidence-missing:${id}`);
  const failures = receipts.filter((item) => item.status === 'fail' || item.status === 'error');
  const missing = receipts.filter((item) => !['pass', 'fail'].includes(item.status));
  return { schemaVersion: 1, kind: 'nemesis-service-worker-runtime-evidence', status: failures.length ? 'fail' : missing.length || externalGaps.length ? 'partial' : 'pass', terminal: true,
    binding, receipts, claims: { runtime: failures.length ? 'failed' : missing.length ? 'partial' : 'evidenced', source: 'unaffected' },
    coverageGaps: [...externalGaps, ...missing.map((item) => `${item.id}:runtime-execution-missing`)].sort() };
}
