// Data extractor per Security Appendix §11.4: database clients/stores,
// read/write sinks, cache/index/vector stores, sensitive data classes,
// tenant-filter patterns, serialization/file stores.

import { entity, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

const STORE_PATTERNS = [
  { kind: 'data-store', pattern: /(?:db|database|client|pool|engine|session)\./g, name: 'database client' },
  { kind: 'data-store', pattern: /(?:redis|memcached|cache)\./g, name: 'cache client' },
  { kind: 'data-store', pattern: /(?:vector|embedding|index)\./g, name: 'vector store client' },
];

export function extractData({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    for (const { kind, pattern, name } of STORE_PATTERNS) {
      if (!pattern.test(text)) continue;
      pattern.lastIndex = 0;
      const evidenceRef = stableId('data-evidence', { file, kind });
      const store = entity(kind, `${name} ${file}`, { environment: 'application' }, [evidenceRef]);
      entities.push(store);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: name });
    }
    // Sensitive data classes from field names.
    if (/\b(?:password|token|secret|apiKey|ssn|email)\b/i.test(text)) {
      const evidenceRef = stableId('sensitive-evidence', { file });
      const dataClass = entity('data-class', `sensitive data ${file}`, { sensitive: true }, [evidenceRef]);
      entities.push(dataClass);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Sensitive data class' });
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
