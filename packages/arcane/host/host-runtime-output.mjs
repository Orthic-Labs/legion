import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';
import { createDecisionEnvelope, publicReason } from '../lib/decision-envelope.mjs';

const schema = new RuntimeSchemaSet();

export { publicReason };

const publicDetail = (envelope) => ({ code: envelope.code, publicReason: envelope.publicReason, enforcementHealth: envelope.enforcementHealth, retrySignature: envelope.retrySignature, termination: envelope.termination, certification: envelope.certification, missingClasses: envelope.missingClasses, responsibleProducer: envelope.responsibleProducer, remediationRoutes: envelope.remediationRoutes, missingEvidence: envelope.missingEvidence });

export function renderHostRuntimeOutput({ eventType, allowed, code = null, detail = {}, enforcementHealth = 'strong' }) {
  if (allowed) return null;
  const envelope = createDecisionEnvelope({ allowed, code, detail, enforcementHealth });
  const reason = envelope.publicReason;
  let output;
  if (eventType === 'PreToolUse') {
    output = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason }, ...publicDetail(envelope) };
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
