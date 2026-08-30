import { ArcaneError } from '../../../../contracts/arcane/errors.mjs';

const RECOVERY_SCHEMA = 'arcane.control-recovery.v1';

function requireObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be an object`, { name });
  }
  return value;
}

function requireId(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be a non-empty string`, { name });
  }
  return value;
}

/**
 * Execute one narrowly authorized control-state recovery.  Callers retain
 * persistence ownership: this function returns a replacement or quarantine
 * disposition; it never writes a control store itself.
 */
export function recoverControlState({ controlId, state, authorization, authenticate, repair, verify }) {
  requireId(controlId, 'controlId');
  requireObject(authorization, 'authorization');
  if (authorization.controlId !== controlId || authorization.operation !== 'RECOVER_CONTROL_STATE') {
    return Object.freeze({ schema: RECOVERY_SCHEMA, allowed: false, code: 'ARC_RECOVERY_SCOPE_DENIED', controlId });
  }
  if (typeof authenticate !== 'function' || authenticate(authorization) !== true) {
    return Object.freeze({ schema: RECOVERY_SCHEMA, allowed: false, code: 'ARC_RECOVERY_AUTH_REQUIRED', controlId });
  }
  if (typeof repair !== 'function' || typeof verify !== 'function') {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'recoverControlState requires repair and verify functions', {});
  }

  let recovered;
  try {
    recovered = repair(state, Object.freeze({ controlId, authorization }));
  } catch (error) {
    return Object.freeze({
      schema: RECOVERY_SCHEMA, allowed: false, code: 'ARC_RECOVERY_QUARANTINED', controlId,
      quarantine: Object.freeze({ originalState: state, reasonCode: error?.code ?? 'ARC_RECOVERY_REPAIR_FAILED' }),
    });
  }
  const verification = verify(recovered, Object.freeze({ controlId, authorization }));
  if (verification !== true) {
    return Object.freeze({
      schema: RECOVERY_SCHEMA, allowed: false, code: 'ARC_RECOVERY_VERIFY_FAILED', controlId,
      quarantine: Object.freeze({ originalState: state, recoveredState: recovered, reasonCode: 'ARC_RECOVERY_VERIFY_FAILED' }),
    });
  }
  return Object.freeze({
    schema: RECOVERY_SCHEMA, allowed: true, code: 'ARC_RECOVERY_RESUMED', controlId,
    replacementState: recovered, preservedState: state, verification: 'PASS',
  });
}
