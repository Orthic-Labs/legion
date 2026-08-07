import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.request-boundaries', family: 'request-boundaries', description: 'SSRF, file, upload, parser, and serialization boundaries.', rules: [
  { id: 'boundary.ssrf', pattern: /(?:fetch|axios|request|urlopen)\s*\([^\n]*(?:req|request|query|params|body|input)/i, claim: 'Request-controlled data may determine a server-side outbound request.', severityHint: 'high', effectKind: 'network-reachability' },
  { id: 'boundary.path-traversal', pattern: /(?:readFile|writeFile|open|sendFile|extract)\s*\([^\n]*(?:req|request|params|query|filename|path)/i, claim: 'Request-controlled path data may reach a filesystem operation.', severityHint: 'high', effectKind: 'data-access' },
  { id: 'boundary.unsafe-deserialization', pattern: /(?:pickle\.loads|yaml\.load\s*\(|ObjectInputStream|BinaryFormatter|unserialize\s*\()/i, claim: 'An unsafe deserialization primitive is present.', severityHint: 'high', effectKind: 'code-execution' },
  { id: 'boundary.upload-unbounded', pattern: /(?:upload|multipart|formidable|multer)[\s\S]{0,240}(?!limit|maxSize|contentLength)/i, claim: 'An upload surface has no visible size or type boundary.', effectKind: 'availability-impact' },
] });
