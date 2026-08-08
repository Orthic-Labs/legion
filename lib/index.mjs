// Canonical public library surface for @orthic-labs/nemesis.
// The CLI, MCP server, hooks, CI actions, and tests import from here; no
// channel may shell out to the top-level scripts to access core behavior.

export { EXIT, NemesisError, exitCodeForReport } from './errors.mjs';
export { NEMESIS_VERSION, NEMESIS_PACKAGE, NEMESIS_REPOSITORY } from './version.mjs';
export {
  RunArtifactStore,
  audit,
  bindRepository,
  buildPlan,
  executePlan,
  finalizeRun,
  inspectProduct,
  reconcileRun,
  verifyRun,
  writeRunManifest,
} from './core/index.mjs';
export { fixedHost } from './host/fixed-host.mjs';
export { createHost } from './host/index.mjs';
export { renderHtmlReport } from './report/html/index.mjs';
export { editorDiagnostics } from './report/editor/index.mjs';
export { verifySkillBytes as verifySkillBundle } from './skills/verify.mjs';

export const PUBLIC_API_VERSION = 1;
export const COMPATIBILITY_SURFACES = Object.freeze({
  'audit-run': Object.freeze({ deprecated: true, since: '0.1.0', replacement: 'audit' }),
  'audit-plan': Object.freeze({ deprecated: true, since: '0.1.0', replacement: 'buildPlan' }),
  'audit-finalize': Object.freeze({ deprecated: true, since: '0.1.0', replacement: 'finalizeRun' }),
  'audit-verify': Object.freeze({ deprecated: true, since: '0.1.0', replacement: 'verifyRun' }),
});

export async function loadReport(path, { fs } = {}) {
  const reader = fs?.readFile ?? (await import('node:fs/promises')).readFile;
  const report = JSON.parse(await reader(path, 'utf8'));
  if (report?.kind !== 'repository-audit-report' && !Array.isArray(report?.findings)) throw new TypeError('invalid Nemesis report');
  return report;
}

// Versioned core contracts. The full deterministic core API (buildPlan,
// executePlan, reconcileRun, finalizeRun, verifyRun) is added by PR06.
export {
  SCHEMA_VERSIONS,
  assertSupportedSchemaVersion,
  buildAuditPlan,
  sealPlan,
  verifyPlanBinding,
  verifyPlanSeal,
  verifyPlanSignature,
  writeAuditPlan,
} from '../audit-plan.mjs';

export {
  PROVIDER_PHASES,
  PROVIDER_ROLES,
  PROVIDER_STATUS,
  assertEnum,
} from '../registry/provider-contracts.mjs';
