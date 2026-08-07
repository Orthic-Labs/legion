import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.business-logic', family: 'business-logic', description: 'Workflow invariants, idempotency, and state-transition authority.', rules: [
  { id: 'logic.payment-without-idempotency', pattern: /(?:charge|refund|capture|settle)\s*\([^\n]*(?!idempot)/i, claim: 'A money-moving operation has no visible idempotency binding.', effectKind: 'integrity-impact', effectAction: 'duplicate' },
  { id: 'logic.client-controlled-price', pattern: /(?:price|amount|total)\s*[:=]\s*(?:req|request|body|params)\b/i, claim: 'A client-controlled value may determine a transaction amount.', severityHint: 'high', effectKind: 'integrity-impact' },
] });
