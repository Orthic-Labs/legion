import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.abuse-observability', family: 'abuse-observability', description: 'Abuse resistance, webhook integrity, resilience, and forensics.', rules: [
  { id: 'abuse.login-without-rate-limit', pattern: /(?:login|signin|resetPassword|sendOtp)\s*\([^\n]*(?!rateLimit|throttle)/i, claim: 'An abuse-sensitive identity operation has no visible rate limit.', effectKind: 'availability-impact' },
  { id: 'abuse.webhook-without-signature', pattern: /(?:webhook|callback)\s*\([^\n]*(?!signature|hmac|verify)/i, claim: 'A webhook receiver has no visible authenticity verification.', severityHint: 'high', effectKind: 'integrity-impact' },
  { id: 'observability.swallowed-security-error', pattern: /catch\s*\([^)]*\)\s*\{\s*(?:return\s+(?:null|false|undefined)|\})/i, claim: 'An exception may be swallowed without durable diagnostic evidence.' },
] });
