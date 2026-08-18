// Deterministic evaluators for architecture corpus families.  Inputs are
// structured policy facts; row prose/expectations are never consulted.
import { digestValue } from '../canonical.mjs';

const IDS = Object.freeze([
  'AE-ADR-ADMISSION-001', 'AE-ADR-ADMISSION-002',
  'AE-CANON-DRIFT-001', 'AE-CANON-DRIFT-002',
  'AE-CLARIFICATION-CONVERGENCE-001', 'AE-CLARIFICATION-CONVERGENCE-002',
]);
const freeze = (v) => Object.freeze(v);

/** Decide ADR admission from explicit, typed architecture policy facts. */
export function evaluateAdrAdmission({ reversible = false, boundaryAccepted = false, architectureWorth = false, localAlternatives = 0 } = {}) {
  if (![reversible, boundaryAccepted, architectureWorth].every((v) => typeof v === 'boolean') || !Number.isInteger(localAlternatives) || localAlternatives < 0) {
    return freeze({ status: 'PENDING', missingProducer: 'typed architecture admission facts' });
  }
  const admit = architectureWorth && (!reversible || !boundaryAccepted);
  return freeze({ status: admit ? 'ADMIT' : 'REJECT', artifact: admit ? 'ADR' : 'LOCAL_DECISION_LOG', architectureRoute: admit, alternatives: localAlternatives });
}

/** Compare canonical owners without treating duplicate declarations as valid. */
export function evaluateCanonOwnerDrift({ owners = [] } = {}) {
  if (!Array.isArray(owners) || owners.some((o) => typeof o !== 'string' || !o)) return freeze({ status: 'PENDING', missingProducer: 'canonical owner registry' });
  const unique = [...new Set(owners)];
  return freeze({ status: unique.length === 1 ? 'PASS' : 'FAIL', sourceOwner: unique.length === 1 ? unique[0] : null, ownerCount: unique.length, drift: unique.length > 1 });
}

/** Detect generated/source drift using canonical serialization digests. */
export function evaluateGeneratedSourceDrift({ source, generated } = {}) {
  try {
    const sourceDigest = digestValue(source);
    const generatedDigest = digestValue(generated);
    return freeze({ status: sourceDigest === generatedDigest ? 'PASS' : 'FAIL', sourceDigest, generatedDigest, drift: sourceDigest !== generatedDigest, remediation: sourceDigest === generatedDigest ? null : 'REGENERATE_FROM_SOURCE' });
  } catch {
    return freeze({ status: 'PENDING', missingProducer: 'canonical source and generated artifacts' });
  }
}

/** Stop clarification when next question cannot alter any recorded disposition. */
export function evaluateClarificationConvergence({ impact = {}, dispositionsRecorded = false } = {}) {
  const fields = ['acceptance', 'ranking', 'authority', 'safety', 'increment'];
  if (!impact || typeof impact !== 'object' || fields.some((f) => typeof impact[f] !== 'boolean') || typeof dispositionsRecorded !== 'boolean') return freeze({ status: 'PENDING', missingProducer: 'structured clarification impact assessment' });
  const affects = fields.some((f) => impact[f]);
  return freeze({ status: !affects && dispositionsRecorded ? 'STOP' : 'CONTINUE', stopQuestioning: !affects && dispositionsRecorded, dispositionsRecorded });
}

/** Keep imprecise concern as FOG metadata; no work item is created. */
export function evaluateFogMetadata({ question = '', sharpeningObservation = '', metadata = {} } = {}) {
  if (typeof question !== 'string' || typeof sharpeningObservation !== 'string' || !metadata || typeof metadata !== 'object') return freeze({ status: 'PENDING', missingProducer: 'FOG metadata input' });
  const precise = question.trim().length > 0 && sharpeningObservation.trim().length > 0;
  return freeze({ status: precise ? 'READY' : 'FOG', fogMetadataOnly: !precise, scheduledWork: false, blocker: false });
}

const CASES = Object.freeze({
  'AE-ADR-ADMISSION-001': () => evaluateAdrAdmission({ reversible: true, boundaryAccepted: true, architectureWorth: false, localAlternatives: 1 }),
  'AE-ADR-ADMISSION-002': () => evaluateAdrAdmission({ reversible: true, boundaryAccepted: true, architectureWorth: false, localAlternatives: 2 }),
  'AE-CANON-DRIFT-001': () => evaluateCanonOwnerDrift({ owners: ['architecture-source', 'overlay-generated'] }),
  'AE-CANON-DRIFT-002': () => evaluateGeneratedSourceDrift({ source: { rule: 'source' }, generated: { rule: 'drift' } }),
  'AE-CLARIFICATION-CONVERGENCE-001': () => evaluateClarificationConvergence({ impact: { acceptance: false, ranking: false, authority: false, safety: false, increment: false }, dispositionsRecorded: true }),
  'AE-CLARIFICATION-CONVERGENCE-002': () => evaluateFogMetadata({ question: '', sharpeningObservation: '', metadata: { concern: 'unclear' } }),
});

export const adrCanonClarifyBindings = CASES;
export function adrCanonClarifyRuntimeIds() { return IDS; }
export function executeAdrCanonClarifyCase(id) { return CASES[id]?.() ?? null; }
// Naming aliases follow existing S11 binding modules.
export const adrCanonClarifyBindingIds = adrCanonClarifyRuntimeIds;
export const executeAdrCanonClarifyBinding = executeAdrCanonClarifyCase;

export function validateAdrCanonClarifyObservation(id, value) {
  if (!IDS.includes(id) || !value || typeof value !== 'object' || typeof value.status !== 'string') return false;
  if (id.startsWith('AE-ADR-')) return ['ADMIT', 'REJECT', 'PENDING'].includes(value.status) && (value.status === 'PENDING' || typeof value.architectureRoute === 'boolean');
  if (id === 'AE-CANON-DRIFT-001') return ['PASS', 'FAIL', 'PENDING'].includes(value.status) && (value.status === 'PENDING' || typeof value.drift === 'boolean');
  if (id === 'AE-CANON-DRIFT-002') return ['PASS', 'FAIL', 'PENDING'].includes(value.status) && (value.status === 'PENDING' || typeof value.drift === 'boolean');
  if (id === 'AE-CLARIFICATION-CONVERGENCE-001') return ['STOP', 'CONTINUE', 'PENDING'].includes(value.status) && (value.status === 'PENDING' || typeof value.stopQuestioning === 'boolean');
  return ['FOG', 'READY', 'PENDING'].includes(value.status) && (value.status === 'PENDING' || value.scheduledWork === false);
}
