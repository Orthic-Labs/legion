import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';
import { createDecisionEnvelope, publicReason } from '../lib/decision-envelope.mjs';

const schema = new RuntimeSchemaSet();

export { publicReason };

const publicDetail = (envelope) => ({ code: envelope.code, publicReason: envelope.publicReason, enforcementHealth: envelope.enforcementHealth, retrySignature: envelope.retrySignature, termination: envelope.termination, certification: envelope.certification, missingClasses: envelope.missingClasses, responsibleProducer: envelope.responsibleProducer, remediationRoutes: envelope.remediationRoutes, missingEvidence: envelope.missingEvidence });

/**
 * `escalate` renders a PreToolUse refusal as the host's own approval prompt
 * (`permissionDecision: 'ask'`) instead of a flat `deny`.
 *
 * A gate that refuses an effect for want of an approval, while offering no path
 * by which that approval could ever be produced, is not enforcement — it is a
 * dead end; every gate must be earnable. Arcane's target-bound VCS
 * rewrite approval was exactly that: `approvalStore` defaults to null and no
 * host wires one, so every `git push --force` was refused unappealably. Handing
 * the decision to the operator through the host's existing permission prompt
 * keeps the gate deterministic (the effect never proceeds unreviewed) while
 * restoring an earnable path. `deny` remains correct for classes where no
 * approval could make the effect safe (see DESTRUCTIVE_COMMAND).
 */
export function renderHostRuntimeOutput({ eventType, allowed, code = null, detail = {}, enforcementHealth = 'strong', escalate = false }) {
  if (allowed) return null;
  const envelope = createDecisionEnvelope({ allowed, code, detail, enforcementHealth });
  const reason = envelope.publicReason;
  let output;
  if (eventType === 'PreToolUse') {
    output = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: escalate ? 'ask' : 'deny', permissionDecisionReason: reason }, ...publicDetail(envelope) };
  } else if (eventType === 'Stop') {
    output = { decision: 'block', reason, ...publicDetail(envelope) };
  } else {
    output = { hookSpecificOutput: { hookEventName: eventType, additionalContext: `Arcane: ${reason}` }, ...publicDetail(envelope) };
  }
  schema.assert('arcane-host-runtime-output-v1', output);
  return output;
}

export function serializeHostRuntimeOutput(output) {
  if (output === null) return '';
  schema.assert('arcane-host-runtime-output-v1', output);
  return `${JSON.stringify(output)}\n`;
}
