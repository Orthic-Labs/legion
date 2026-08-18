import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.authentication-session', family: 'authentication-session', description: 'Authentication, recovery, session, and token lifecycle.', rules: [
  { id: 'auth.jwt-without-verification', pattern: /jwt\.(?:decode|Decode)\s*\(|parseJwt\s*\(/, claim: 'A JWT may be decoded without visible signature verification.', severityHint: 'high', effectKind: 'principal-access' },
  { id: 'auth.session-cookie-weak', pattern: /(?:session|auth)[\s\S]{0,180}(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['"]none)/i, claim: 'A session cookie may omit a material browser protection.', effectKind: 'credential-possession' },
  { id: 'auth.reset-token-log', pattern: /(?:console|logger)\.(?:log|info|debug)\([^\n]*(?:resetToken|passwordReset|magicLink)/i, claim: 'A recovery credential may be written to logs.', severityHint: 'high', effectKind: 'credential-possession' },
] });
