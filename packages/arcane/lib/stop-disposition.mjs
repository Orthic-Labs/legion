// Termination is independent from certification. Only a verified pending operation may request completion.
export const STOP_DISPOSITIONS = Object.freeze(['completion', 'question', 'pause', 'archive', 'other']);
export function classifyStopDisposition({ authenticatedClaim = false, intent = 'UNKNOWN' } = {}) {
  if (['QUESTION', 'PLAN', 'PAUSE', 'REVOKE', 'SCOPE_NARROW'].includes(intent)) return 'question';
  if (authenticatedClaim === true) return 'completion';
  return 'other';
}
export function stopOutcome(input) { const disposition=classifyStopDisposition(input); return Object.freeze({disposition,termination:{allowed:true},certification:disposition==='completion'?'genuine':'not_claimed'}); }
