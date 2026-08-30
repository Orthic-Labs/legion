import { ArcaneError } from '../../../../contracts/arcane/errors.mjs';

const SCHEMA = 'arcane.migration-cutover-assessment.v1';
const ABSENCE_SURFACES = Object.freeze(['imports', 'routes', 'runtime_registrations', 'configuration_keys', 'dependencies', 'tests', 'documentation', 'emitted_protocol_variants']);
const COEXISTENCE_FIELDS = Object.freeze(['owner', 'reconciliation', 'telemetry', 'expiry', 'rollback', 'trigger']);

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be an object`, { name });
  return value;
}

function nonEmpty(value) { return (typeof value === 'string' && value.length > 0) || (Array.isArray(value) && value.length > 0) || (value && typeof value === 'object' && Object.keys(value).length > 0); }

/** Assess a declared migration from typed scan observations, never text claims. */
export function assessMigrationCutover({ plan, observations }) {
  object(plan, 'plan'); object(observations, 'observations');
  if (!['HARD_CUT', 'BOUNDED_COEXISTENCE'].includes(plan.mode)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'plan.mode must be HARD_CUT or BOUNDED_COEXISTENCE', { mode: plan.mode });
  }
  if (plan.mode === 'HARD_CUT') {
    const configured = plan.hard_cut?.absence_checks;
    object(configured, 'plan.hard_cut.absence_checks');
    const failures = ABSENCE_SURFACES.flatMap((surface) => {
      if (!Array.isArray(configured[surface])) return [{ surface, code: 'ARC_ABSENCE_PROOF_UNDECLARED' }];
      const matches = observations.absence?.[surface];
      if (!Array.isArray(matches)) return [{ surface, code: 'ARC_ABSENCE_PROOF_MISSING' }];
      return matches.length === 0 ? [] : [{ surface, code: 'ARC_ABSENCE_PROOF_FAILED', matches }];
    });
    return Object.freeze({ schema: SCHEMA, mode: plan.mode, ready: failures.length === 0, code: failures.length === 0 ? 'ARC_MIGRATION_CUTOVER_READY' : 'ARC_MIGRATION_ABSENCE_PROOF_FAILED', failures: Object.freeze(failures) });
  }
  const coexistence = object(plan.bounded_coexistence, 'plan.bounded_coexistence');
  const missing = COEXISTENCE_FIELDS.filter((field) => !nonEmpty(coexistence[field]));
  const observationFailures = observations.coexistence?.reconciled === true && observations.coexistence?.telemetryActive === true ? [] : [{ code: 'ARC_COEXISTENCE_OBSERVATION_FAILED' }];
  const failures = [...missing.map((field) => ({ field, code: 'ARC_COEXISTENCE_CONTRACT_MISSING' })), ...observationFailures];
  return Object.freeze({ schema: SCHEMA, mode: plan.mode, ready: failures.length === 0, code: failures.length === 0 ? 'ARC_MIGRATION_CUTOVER_READY' : 'ARC_MIGRATION_READINESS_FAILED', failures: Object.freeze(failures) });
}

export { ABSENCE_SURFACES, COEXISTENCE_FIELDS };
