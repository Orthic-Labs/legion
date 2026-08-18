// AI RAG/memory-poisoning security pack. Untrusted-provenance ingestion into
// a retrieval corpus, retrieval without a tenant-scope filter (cross-tenant
// retrieval), durable memory writes sourced from untrusted actors, and the
// archetypal chain where retrieved/RAG content directly drives a destructive
// tool call (prompt-injection-to-sensitive-action).
//
// Same discipline as the other AI packs: every rule requires a typed
// source+sink combination bound to real model entities where the surface
// model provides them (RAG/memory data-stores from the ai-agent extractor),
// falling back to the repository-artifact entity otherwise. Deterministic,
// pattern-only, UNADJUDICATED-only.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function findDataStore(context, storeKind) {
  return context.model.entities.find((e) => e.kind === 'data-store' && e.attributes?.storeKind === storeKind);
}

function findUntrustedSource(context, file) {
  return context.model.entities.find((e) =>
    e.kind === 'source' && e.attributes?.trust === 'untrusted' && e.attributes?.file === file)
    ?? context.model.entities.find((e) => e.kind === 'source' && e.attributes?.trust === 'untrusted');
}

function findControl(context, sinkId, controlTypes) {
  if (sinkId) {
    for (const rel of context.relationsTo(sinkId)) {
      if (rel.kind !== 'protects' && rel.kind !== 'validates') continue;
      const control = context.entityById.get(rel.from);
      if (control?.kind === 'control' && controlTypes.includes(control.attributes?.controlType)) return control;
    }
  }
  return context.model.entities.find((e) => e.kind === 'control' && controlTypes.includes(e.attributes?.controlType)) ?? null;
}

const RULES = [
  {
    id: 'ai.poisoning.rag-ingestion-untrusted-provenance',
    severityHint: 'high',
    controlTypes: ['provenance-filter', 'content-integrity-check'],
    effectKind: 'integrity-impact', effectAction: 'poison-corpus', effectScope: 'rag-store',
    chainRoles: ['starter', 'enabler'],
    storeKind: 'rag',
    claim: 'Untrusted content may enter a retrieval corpus without a provenance or integrity filter.',
    uncertainty: ['Ingestion alone does not confirm the corpus is later retrieved into a prompt; the retrieval path must be adjudicated.'],
    match(text) {
      return /(?:embed|vectorStore|indexDocuments|upsert)\s*\([^\n]*(?:url|upload|user|external|web|scraped)/i.test(text);
    },
  },
  {
    id: 'ai.poisoning.cross-tenant-retrieval',
    severityHint: 'high',
    controlTypes: ['tenant-scope-check'],
    effectKind: 'confidentiality-impact', effectAction: 'cross-tenant-retrieve', effectScope: 'rag-store',
    chainRoles: ['starter', 'control-bypass'],
    storeKind: 'rag',
    claim: 'A retrieval query reaches the vector/RAG store without a visible tenant or namespace scope.',
    uncertainty: ['A missing local tenant filter does not confirm the store is multi-tenant; the store\'s partitioning must be adjudicated.'],
    match(text) {
      return /\b(?:retriever|vectorStore|index)\.(?:query|search|similaritySearch)\s*\(/i.test(text)
        && !/\btenant(?:Id)?\b|\bnamespace\b/i.test(text);
    },
  },
  {
    id: 'ai.poisoning.durable-memory-untrusted-write',
    severityHint: 'high',
    controlTypes: ['memory-write-validation'],
    effectKind: 'persistence', effectAction: 'poison-memory', effectScope: 'memory-store',
    chainRoles: ['starter', 'enabler'],
    storeKind: 'memory',
    claim: 'Durable agent memory is written from request/external/retrieved content without validation, enabling persistent (multi-turn) poisoning.',
    uncertainty: ['A write alone does not confirm the content is later replayed into a prompt; the read path must be adjudicated.'],
    match(text) {
      return /(?:memory_store|session_memory|agent_memory|conversation_history)\s*\.(?:push|save|append|set)\s*\([^\n]*(?:request|input|user|external|retrieved|document)/i.test(text);
    },
  },
  {
    id: 'ai.poisoning.destructive-action-from-retrieved-content',
    severityHint: 'critical',
    controlTypes: ['human-approval'],
    effectKind: 'integrity-impact', effectAction: 'destructive-tool-call', effectScope: 'tool-capability',
    chainRoles: ['starter', 'pivot', 'impact'],
    storeKind: 'rag',
    claim: 'Retrieved (RAG/search) content flows directly into a destructive tool call without an approval gate — the prompt-injection-to-sensitive-action pattern.',
    uncertainty: ['Textual adjacency is not proof of a data-flow edge from the retrieved value to the call argument; the flow must be adjudicated.'],
    match(text) {
      return /(?:retrieved[-_ ]?content|search_result|document[-_ ]?content)[\s\S]{0,120}\b(?:delete|deleteFile|dropTable|rm\s*\(|deploy|transfer)\w*\s*\(/i.test(text);
    },
  },
];

export default Object.freeze({
  id: 'security.ai-poisoning-rag',
  version: '1.0.0',
  candidateClass: 'ai-poisoning-rag',
  description: 'RAG/memory poisoning, cross-tenant retrieval, and retrieved-content-driven destructive actions.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      const untrustedSource = findUntrustedSource(context, file);

      for (const rule of RULES) {
        if (!rule.match(text)) continue;

        const store = findDataStore(context, rule.storeKind);
        const sinkEntity = store ?? artifact;
        const control = findControl(context, sinkEntity?.id, rule.controlTypes);
        if (control) continue;

        const sourceEntity = untrustedSource ?? artifact;
        const sources = sourceEntity ? [sourceEntity.id] : [];
        const sinks = sinkEntity ? [sinkEntity.id] : [];
        const evidenceRefs = [...new Set([...(sourceEntity?.evidenceRefs ?? []), ...(sinkEntity?.evidenceRefs ?? [])])];

        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-poisoning-rag',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources,
          sinks,
          attackerCapabilities: ['control-untrusted-content'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-content', scope: rule.storeKind, environment: 'agent', tenant: null }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: sinkEntity?.id ?? null, scope: rule.effectScope, environment: 'agent', tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs,
          detectorMetadata: {
            file,
            untrustedOrigin: rule.storeKind === 'memory' ? 'memory-content' : 'retrieved-content',
            sink: rule.storeKind,
            detectionMethod: 'lexical-pattern',
            matchDigest: digest({ ruleId: rule.id, file }),
          },
          uncertainty: rule.uncertainty,
        });
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, {
    rootCause(candidate) {
      return {
        class: `${rule.storeKind}-poisoning`,
        storeKind: rule.storeKind,
        missingControl: rule.controlTypes[0] ?? null,
        semanticFeatures: ['ai-poisoning', rule.storeKind, candidate.detectorMetadata?.sink ?? rule.storeKind],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-alternate-stores`, kind: 'model-derived',
          description: 'Enumerate alternate RAG/memory stores and downstream destructive tools the same untrusted source may also reach.',
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
