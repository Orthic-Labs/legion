// Security surface model builder per Security Appendix §10. A pure
// deterministic provider: reads only frozen provider denominator paths, never
// calls Cortex again, never runs a filesystem walk.

import { bindingFromPlan, digest } from './contracts.mjs';
import { extractCommon } from './model-extractors/common.mjs';
import { extractHttp } from './model-extractors/http.mjs';
import { extractIdentity } from './model-extractors/identity.mjs';
import { extractData } from './model-extractors/data.mjs';
import { extractCicd } from './model-extractors/cicd.mjs';
import { extractCloud } from './model-extractors/cloud.mjs';
import { extractNativeWorkspace } from './model-extractors/native-workspace.mjs';
import { extractAiAgent } from './model-extractors/ai-agent.mjs';

const EXTRACTORS = Object.freeze([
  extractCommon,
  extractHttp,
  extractIdentity,
  extractData,
  extractCicd,
  extractCloud,
  extractNativeWorkspace,
  extractAiAgent,
]);

function dedupe(items) {
  return [...new Map(items.map((item) => [item.id, item])).values()]
    .sort((a, b) => a.id.localeCompare(b.id));
}

function assertReferences(entities, relations) {
  const ids = new Set(entities.map((entity) => entity.id));
  for (const relation of relations) {
    if (!ids.has(relation.from)) throw new Error(`unknown relation.from ${relation.from}`);
    if (!ids.has(relation.to)) throw new Error(`unknown relation.to ${relation.to}`);
  }
}

export function buildSecurityModel({ root, plan, projection, lensRegistry }) {
  const binding = bindingFromPlan(plan);
  const denominator = (plan.providers ?? [])
    .find((provider) => provider.id === 'security.surface-model')
    ?.denominator;
  if (!denominator?.pathDigest) throw new Error('surface model denominator missing');

  const files = denominator.paths ?? projection.files ?? [];
  const parts = EXTRACTORS.map((extractor) => extractor({
    root,
    plan,
    projection,
    files,
    lensRegistry,
  }));

  const entities = dedupe(parts.flatMap((part) => part.entities ?? []));
  const relations = dedupe(parts.flatMap((part) => part.relations ?? []));
  const evidence = dedupe(parts.flatMap((part) => part.evidence ?? []));
  const initialFacts = dedupe(parts.flatMap((part) => part.initialFacts ?? []));
  const coverageGaps = parts.flatMap((part) => part.coverageGaps ?? []);

  assertReferences(entities, relations);

  return {
    schemaVersion: 1,
    kind: 'security-surface-model',
    provider: 'security.surface-model',
    providerVersion: '1',
    binding,
    denominatorDigest: denominator.pathDigest,
    complete: coverageGaps.length === 0,
    entities,
    relations,
    initialFacts,
    evidence,
    coverage: {
      expectedFiles: denominator.pathCount,
      examinedFiles: denominator.paths?.length ?? projection.files?.length ?? 0,
      entityCount: entities.length,
      relationCount: relations.length,
      evidenceCount: evidence.length,
      modelDigest: digest({ entities, relations, initialFacts }),
    },
    coverageGaps,
  };
}
