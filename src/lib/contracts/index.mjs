// Versioned contract surface for @orthic-labs/legion/contracts.
export { EXIT, LegionError, exitCodeForReport } from '../errors.mjs';
export { SCHEMA_VERSIONS, assertSupportedSchemaVersion } from '../../../tools/audit/audit-plan.mjs';
export {
  PROVIDER_PHASES,
  PROVIDER_ROLES,
  PROVIDER_STATUS,
  assertEnum,
} from '../../registry/provider-contracts.mjs';
export {
  EVIDENCE_STRENGTH,
  EVIDENCE_RANK,
  FACT_KINDS,
  PATH_PRIORITY,
  PATH_STATUS,
  SECURITY_VERDICTS,
  assertBinding,
  canonicalize,
  digest,
  stableId,
} from '../../providers/security/contracts.mjs';
