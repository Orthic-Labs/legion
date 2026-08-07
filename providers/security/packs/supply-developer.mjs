import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.supply-developer', family: 'supply-developer', description: 'Supply chain, developer machine, repository automation, and update trust.', rules: [
  { id: 'supply.download-execute-unverified', pattern: /(?:curl|wget)[^\n]*(?:\||&&)\s*(?:sh|bash|python|node)|Invoke-WebRequest[^\n]*\|[^\n]*iex/i, claim: 'Downloaded content may execute without an integrity check.', severityHint: 'high', effectKind: 'code-execution' },
  { id: 'supply.mutable-container-tag', pattern: /(?:image:|FROM)\s+[^\s@]+:(?:latest|main|master)\b/i, claim: 'A build or runtime dependency uses a mutable container tag.' },
  { id: 'developer.global-config-write', pattern: /(?:\.gitconfig|\.npmrc|\.cargo\/config|Library\/LaunchAgents)[^\n]*(?:write|append|>|Set-Content)/i, claim: 'Automation may mutate durable developer-machine configuration.', effectKind: 'persistence' },
] });
