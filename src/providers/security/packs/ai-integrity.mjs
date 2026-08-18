import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.ai-integrity', family: 'ai-integrity', description: 'RAG poisoning, model abuse, unsafe tool output, and evaluation integrity.', rules: [
  { id: 'ai.rag-untrusted-ingestion', pattern: /(?:embed|vectorStore|indexDocuments|upsert)\s*\([^\n]*(?:url|upload|user|external|web)/i, claim: 'Untrusted content may enter a retrieval corpus without a provenance or trust filter.', effectKind: 'integrity-impact' },
  { id: 'ai.model-output-policy', pattern: /(?:completion|modelOutput|assistantMessage)[\s\S]{0,120}(?:approve|allow|authorize|isSafe)\s*[:=]/i, claim: 'Model output may directly determine a policy or authorization decision.', severityHint: 'high', effectKind: 'control-bypass' },
] });
