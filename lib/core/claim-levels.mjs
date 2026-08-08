export const CLAIM_LEVELS = Object.freeze(['inventory','source','runtime','product','release']);
export function achievedClaimLevel(decisions = {}) { return CLAIM_LEVELS.reduce((level, candidate) => decisions[candidate] === 'pass' ? candidate : level, null); }
