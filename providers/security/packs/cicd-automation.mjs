import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.cicd-automation', family: 'cicd-automation', description: 'Workflow permissions, immutable dependencies, and untrusted-event execution.', rules: [
  { id: 'cicd.action-unpinned', pattern: /uses:\s+[\w.-]+\/[\w.-]+@(?:v\d+|main|master)\b/i, claim: 'A third-party workflow action is not pinned to an immutable commit.', effectKind: 'code-execution', effectAction: 'supply-action' },
  { id: 'cicd.pull-request-target-write', pattern: /pull_request_target[\s\S]{0,1200}permissions:[\s\S]{0,400}(?:write-all|contents:\s*write)/i, claim: 'An untrusted pull-request-target workflow may hold write authority.', severityHint: 'high', effectKind: 'code-execution' },
  { id: 'cicd.verifier-bypass', pattern: /(?:verify|check|audit)[^\n]*\|\|\s*true|continue-on-error:\s*true/i, claim: 'A CI verifier can fail without failing the job.', severityHint: 'high', effectKind: 'control-bypass' },
] });
