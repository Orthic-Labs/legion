import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.insecure-defaults', family: 'insecure-defaults', description: 'Fail-open debug, transport, and authentication defaults.', rules: [
  { id: 'defaults.debug-enabled', pattern: /(?:DEBUG|debug)\s*[:=]\s*(?:true|1)|NODE_ENV\s*!==?\s*['"]production/i, claim: 'Debug behavior may be enabled by a production-reachable default.' },
  { id: 'defaults.tls-verification-disabled', pattern: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE/i, claim: 'TLS verification is explicitly disabled.', severityHint: 'high' },
  { id: 'defaults.authentication-optional', pattern: /auth(?:entication)?\s*[:=]\s*(?:false|optional)|ALLOW_ANONYMOUS\s*[:=]\s*(?:true|1)/i, claim: 'Authentication may default to optional or disabled.', severityHint: 'high' },
] });
