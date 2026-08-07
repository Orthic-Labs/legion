import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.browser-http', family: 'browser-http', description: 'Browser, CORS, cache, proxy, and HTTP protocol controls.', rules: [
  { id: 'http.cors-wildcard-credentials', pattern: /Access-Control-Allow-Origin[^\n]*\*[\s\S]{0,200}Access-Control-Allow-Credentials[^\n]*(?:true|1)/i, claim: 'Credentialed cross-origin access may combine with a wildcard origin.', severityHint: 'high' },
  { id: 'http.trust-forwarded-host', pattern: /(?:x-forwarded-host|x-forwarded-proto|host)\b[^\n]*(?:redirect|callback|absoluteUrl)/i, claim: 'A forwarded host value may influence a security-sensitive URL.' },
  { id: 'http.sensitive-public-cache', pattern: /Cache-Control[^\n]*(?:public|s-maxage)[\s\S]{0,200}(?:authorization|session|user|account)/i, claim: 'Sensitive response content may be publicly cacheable.' },
] });
