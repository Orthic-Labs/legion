import { createHash } from 'node:crypto';
import { sanitizeProducedArtifact } from '../../../../lib/platform/artifact-sanitize.mjs';
import { denominator, exactBinding, finalize, redact, sameBinding } from '../shared.mjs';

const OPERATION_TYPES = new Set(['query', 'migration', 'queue', 'cache', 'lifecycle', 'restore']);
const RESULT_STATUSES = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const nonemptyObject = (value) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0;
const artifactResult = (artifact, binding, definition, dataset, schemaVersion) => { const produced = sanitizeProducedArtifact(artifact); return { ...produced, valid: produced.valid && artifact?.kind === 'data-result' && artifact.caseId === definition.id && artifact.datasetId === dataset && artifact.schemaVersion === schemaVersion && artifact.engineVersion === definition.engine?.version && sameBinding(binding, artifact.binding ?? {}) }; };

function definitionGaps(definition, binding, dataset, schemaVersion) {
  const gaps = [];
  const id = definition?.id ?? 'missing';
  if (!definition || typeof definition !== 'object' || !OPERATION_TYPES.has(definition.operationType)) return [`data-case-definition-untyped:${id}`];
  if (definition.dataset?.id !== dataset || !SHA256.test(definition.dataset?.digest ?? '')) gaps.push(`data-case-dataset-binding-invalid:${id}`);
  if (definition.schema?.version !== schemaVersion || !SHA256.test(definition.schema?.digest ?? '')) gaps.push(`data-case-schema-binding-invalid:${id}`);
  if (typeof definition.engine?.name !== 'string' || !definition.engine.name || typeof definition.engine?.version !== 'string' || !definition.engine.version || !SHA256.test(definition.engine?.digest ?? '')) gaps.push(`data-case-engine-binding-invalid:${id}`);
  if (typeof definition.isolation?.id !== 'string' || !definition.isolation.id || definition.isolation?.environment !== binding.environment || !sameBinding(binding, definition.isolation?.binding ?? {})) gaps.push(`data-case-isolation-binding-invalid:${id}`);
  if (definition.cleanupBinding?.datasetId !== dataset || definition.cleanupBinding?.schemaVersion !== schemaVersion || definition.cleanupBinding?.environment !== binding.environment || !sameBinding(binding, definition.cleanupBinding?.binding ?? {})) gaps.push(`data-case-cleanup-binding-invalid:${id}`);
  if (definition.operationType === 'query' && !SHA256.test(definition.statementDigest ?? '')) gaps.push(`data-case-query-contract-invalid:${id}`);
  if (definition.operationType === 'migration' && (typeof definition.fromSchemaVersion !== 'string' || typeof definition.toSchemaVersion !== 'string' || !SHA256.test(definition.migrationDigest ?? ''))) gaps.push(`data-case-migration-contract-invalid:${id}`);
  if (definition.operationType === 'queue' && (typeof definition.queueName !== 'string' || !definition.queueName || typeof definition.messageId !== 'string' || !definition.messageId)) gaps.push(`data-case-queue-contract-invalid:${id}`);
  if (definition.operationType === 'cache' && (typeof definition.cacheKey !== 'string' || !definition.cacheKey || !['eventual', 'strong'].includes(definition.consistency))) gaps.push(`data-case-cache-contract-invalid:${id}`);
  if (definition.operationType === 'lifecycle' && !['create', 'delete', 'read', 'update'].includes(definition.phase)) gaps.push(`data-case-lifecycle-contract-invalid:${id}`);
  if (definition.operationType === 'restore' && !SHA256.test(definition.restorePointDigest ?? '')) gaps.push(`data-case-restore-contract-invalid:${id}`);
  return gaps;
}

export async function verifyDataExercise({ binding = {}, dataset, schemaVersion, adapter = {}, cases = [] } = {}) {
  const caseList = Array.isArray(cases) ? cases : [];
  const definitions = caseList.map((item) => typeof item === 'string' ? { id: item } : item ?? {});
  const caseIds = definitions.map((item) => item.id);
  const ids = [...new Set(caseIds)].filter((id) => typeof id === 'string' && id).sort();
  let receipts = [];
  let adapterStatus = 'unproven';
  let exerciseStarted = false;
  const executionGaps = definitions.flatMap((definition) => definitionGaps(definition, binding, dataset, schemaVersion));
  let cleanup = { status: 'unproven', residualDamage: [] };
  if (!Array.isArray(cases)) executionGaps.push('data-cases-invalid');
  if (binding.environment === 'production') executionGaps.push('production-effect-forbidden');
  if (definitions.some((definition) => definition?.destructive === true)) executionGaps.push('destructive-effect-forbidden');
  if (exactBinding(binding).gaps.length || !dataset || !schemaVersion || !definitions.length || ids.length !== definitions.length || executionGaps.length) executionGaps.push('data-preflight-invalid');
  const preflightInvalid = executionGaps.includes('data-preflight-invalid');
  if (preflightInvalid) {
    receipts = ids.map((id) => ({ id, status: 'blocked', terminal: true, reason: 'data-preflight-invalid' }));
    adapterStatus = 'blocked';
    cleanup = { status: 'blocked', reason: 'data-preflight-invalid', residualDamage: [] };
  } else try {
    if (typeof adapter.exercise !== 'function') { executionGaps.push('adapter-exercise-missing'); receipts.push(...ids.map((id) => ({ id, status: 'unproven', terminal: true, reason: 'adapter-missing' }))); }
    else {
      exerciseStarted = true;
      const result = await adapter.exercise({ binding, dataset, schemaVersion, cases: definitions });
      const reportedAdapterStatus = result?.status;
      adapterStatus = RESULT_STATUSES.has(reportedAdapterStatus) ? reportedAdapterStatus : 'error';
      if (!RESULT_STATUSES.has(reportedAdapterStatus)) executionGaps.push(`adapter-status-invalid:${reportedAdapterStatus ?? 'missing'}`);
      if (result?.terminal !== true) { executionGaps.push('adapter-result-nonterminal'); adapterStatus = 'error'; }
      const rows = Array.isArray(result?.cases) ? result.cases : [];
      const grouped = new Map();
      for (const row of rows) { if (!grouped.has(row.id)) grouped.set(row.id, []); grouped.get(row.id).push(row); }
      for (const [id, matches] of grouped) { if (!ids.includes(id)) executionGaps.push(`data-case-unplanned:${id}`); if (matches.length > 1) executionGaps.push(`data-case-duplicate:${id}`); }
      receipts = ids.flatMap((id) => {
        const row = grouped.get(id)?.[0];
        if (!row) return [];
        const definition = definitions.find((item) => item.id === id) ?? {};
        const terminal = row.terminal === true;
        const statusValid = RESULT_STATUSES.has(row.status);
        if (!terminal) executionGaps.push(`data-case-nonterminal:${id}`);
        if (!statusValid) executionGaps.push(`data-case-status-invalid:${id}`);
        if (!sameBinding(binding, row.binding ?? {})) executionGaps.push(`data-case-result-binding-mismatch:${id}`);
        if (row.operationType !== definition.operationType) executionGaps.push(`data-case-operation-mismatch:${id}`);
        if (!nonemptyObject(row.observed)) executionGaps.push(`data-case-observed-invalid:${id}`);
        if (!nonemptyObject(row.durableResult)) executionGaps.push(`data-case-durable-result-invalid:${id}`);
        const rawArtifacts = Array.isArray(row.artifacts) ? row.artifacts : [];
        const artifactResults = rawArtifacts.map((artifact) => artifactResult(artifact, binding, definition, dataset, schemaVersion));
        const artifacts = artifactResults.filter((item) => item.valid).map((item) => item.artifact);
        if (!artifactResults.length || artifactResults.some((item) => !item.valid)) executionGaps.push(`data-case-artifacts-invalid:${id}`);
        if (artifactResults.some((item) => item.sensitive)) executionGaps.push(`data-case-artifact-sensitive:${id}`);
        return [{ id, operationType: definition.operationType ?? null, status: terminal && statusValid ? row.status : 'error', terminal: true, observed: redact(row.observed ?? null), durableResult: redact(row.durableResult ?? null), artifacts }];
      });
    }
  } catch (error) { adapterStatus = 'error'; receipts.push(...ids.map((id) => ({ id, status: 'error', terminal: true, error: redact(error?.message ?? String(error)) })));
  } finally {
    if (exerciseStarted && typeof adapter.cleanup === 'function') {
      try { cleanup = { status: 'pass', ...redact(await adapter.cleanup({ binding, dataset, schemaVersion })) }; }
      catch (error) { cleanup = { status: 'error', error: redact(error?.message ?? String(error)), residualDamage: redact(Array.isArray(error?.residualDamage) ? error.residualDamage : []) }; executionGaps.push('cleanup-error'); }
    }
  }
  const counts = denominator(ids, receipts);
  const gaps = exactBinding(binding).gaps.map((key) => `binding-missing:${key}`);
  gaps.push(...executionGaps);
  if (caseList.length === 0) gaps.push('data-case-denominator-empty');
  if (ids.length !== caseList.length) gaps.push('data-case-denominator-duplicate');
  if (!dataset) gaps.push('dataset-unbound');
  if (!schemaVersion) gaps.push('schema-version-unbound');
  if (cleanup.status !== 'pass') gaps.push('cleanup-unproven');
  if (cleanup.status === 'pass' && (cleanup.datasetId !== dataset || cleanup.schemaVersion !== schemaVersion || cleanup.environment !== binding.environment || !sameBinding(binding, cleanup.binding ?? {}))) gaps.push('cleanup-binding-mismatch');
  if (cleanup.residualDamage?.length) gaps.push('cleanup-residual-damage');
  gaps.push(...counts.missing.map((id) => `data-case-missing:${id}`));
  const statuses = new Set([adapterStatus, cleanup.status, ...receipts.map((item) => item.status)]);
  const status = statuses.has('error') ? 'error' : statuses.has('fail') ? 'fail' : statuses.has('blocked') ? 'blocked' : statuses.has('partial') ? 'partial' : gaps.length || statuses.has('unproven') ? 'unproven' : 'pass';
  return finalize('nemesis-web-data-exercise', { status, terminal: true, binding, dataset, schemaVersion, caseDefinitions: definitions, denominator: counts, receipts, cleanup, coverageGaps: [...new Set(gaps)].sort() });
}
