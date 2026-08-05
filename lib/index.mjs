// Canonical public library surface for @orthic-labs/nemesis.
// The CLI, MCP server, hooks, CI actions, and tests import from here; no
// channel may shell out to the top-level scripts to access core behavior.

export { EXIT, NemesisError, exitCodeForReport } from './errors.mjs';
export { NEMESIS_VERSION, NEMESIS_PACKAGE, NEMESIS_REPOSITORY } from './version.mjs';

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
  canonicalJson,
  canonicalize,
  loadProviderRegistry,
  registryDigest,
  selectProviders,
  sha256,
} from '../registry/provider-registry.mjs';

export {
  PROVIDER_PHASES,
  PROVIDER_ROLES,
  PROVIDER_STATUS,
  assertEnum,
} from '../registry/provider-contracts.mjs';
