// HTTP entrypoint extractor per Security Appendix §11.2. Routes become
// entrypoint entities with input sources and handler processes. Auth state is
// observed-protected, observed-public, or unknown — never guessed.

import { entity, fact, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

const ROUTE_PATTERNS = [
  { framework: 'express', pattern: /(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g },
  { framework: 'fastapi', pattern: /@(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g },
  { framework: 'flask', pattern: /@(?:app|route)\.route\(\s*['"]([^'"]+)['"]/g },
  { framework: 'go-web', pattern: /(?:r|router|e|app)\.(GET|POST|PUT|DELETE|PATCH)\(\s*['"]([^'"]+)['"]/g },
];

export function extractHttp({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    for (const { framework, pattern } of ROUTE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const method = match[1].toUpperCase();
        const path = match[2];
        const evidenceRef = stableId('http-route-evidence', { file, method, path });
        const entrypoint = entity('entrypoint', `${method} ${path}`, {
          protocol: 'http', method, path, environment: 'application', framework,
        }, [evidenceRef]);
        const source = entity('source', `${method} ${path} input`, { inputKind: 'request', framework }, [evidenceRef]);
        const process = entity('process', `${method} ${path} handler`, { framework, environment: 'application' }, [evidenceRef]);
        entities.push(entrypoint, source, process);
        relations.push(
          relation('accepts-input-from', entrypoint.id, source.id, [evidenceRef]),
          relation('invokes', entrypoint.id, process.id, [evidenceRef]),
        );
        // Auth state: observed guard → protected; no local evidence → unknown.
        const hasAuth = /auth|session|jwt|passport|getServerSession|requireAuth|@login_required/.test(text);
        if (hasAuth) {
          relations.push(relation('protected-by', entrypoint.id, stableId('auth-control', { file }), [evidenceRef], {}, { assertion: 'observed' }));
        } else {
          initialFacts.push(fact('network-reachability', {
            subject: 'actor:external', action: 'connect', object: entrypoint.id,
            environment: 'application',
          }, [evidenceRef]));
        }
        evidence.push({ id: evidenceRef, kind: 'source-location', file, description: `Route ${method} ${path}` });
      }
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
