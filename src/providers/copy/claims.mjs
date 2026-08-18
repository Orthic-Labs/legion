import { buildClaimProofLedger } from '../../lib/content/claim-proof-ledger.mjs';
export function assessClaims(input) { const ledger = buildClaimProofLedger(input); return { provider: 'copy.claims', status: ledger.claims.some((claim) => claim.disposition === 'unproven') ? 'unproven' : 'pass', ...ledger }; }
