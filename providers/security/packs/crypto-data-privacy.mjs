import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.crypto-data-privacy', family: 'crypto-data-privacy', description: 'Cryptography, identity protocols, data protection, and privacy.', rules: [
  { id: 'crypto.weak-hash-password', pattern: /(?:md5|sha1)\s*\([^\n]*(?:password|secret|token)/i, claim: 'A credential may use an unsuitable fast or weak hash.', severityHint: 'high', effectKind: 'credential-possession' },
  { id: 'crypto.static-iv', pattern: /(?:iv|nonce)\s*[:=]\s*(?:Buffer\.alloc\([^)]*,\s*0\)|['"][0-9a-f]{8,}['"])/i, claim: 'Encryption may reuse a static IV or nonce.', severityHint: 'high', effectKind: 'confidentiality-impact' },
  { id: 'privacy.pii-log', pattern: /(?:console|logger)\.(?:log|info|debug)\([^\n]*(?:email|phone|address|token|password|ssn)/i, claim: 'Sensitive personal or credential data may be written to logs.', effectKind: 'confidentiality-impact' },
] });
