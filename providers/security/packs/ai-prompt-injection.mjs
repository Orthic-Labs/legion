// AI prompt-injection security pack per Security Appendix §50.7. Untrusted
// prompts, retrieved (RAG/search) content, durable agent memory, and
// dynamically constructed tool/function schemas entering a model invocation
// without a visible trust label.
//
// Every rule requires a source+sink COMBINATION (an untrusted-origin pattern
// feeding a prompt/schema-construction sink) — a bare mention of "prompt" or
// "llm" alone never produces a candidate. Detection prefers typed model
// entities produced by the ai-agent extractor (untrusted-content sources,
// model-invocation processes, tool-capability schemas) when the surface
// model carries them, and falls back to the repository-artifact entity when
// it does not (e.g. a minimal hand-built model in a unit test). Every rule
// only ever emits an UNADJUDICATED candidate via the sealed candidate-engine;
// it never runs a payload, never calls a model, and never certifies a
// finding.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

// Prefer an untrusted-content source entity scoped to this file (the
// ai-agent extractor's `untrusted agent-context content <file>` entity);
// fall back to any untrusted-content source in the model.
function findUntrustedSource(context, file) {
  return context.model.entities.find((e) =>
    e.kind === 'source' && e.attributes?.trust === 'untrusted' && e.attributes?.file === file)
    ?? context.model.entities.find((e) => e.kind === 'source' && e.attributes?.trust === 'untrusted');
}

function findInvocationProcess(context, file) {
  return context.model.entities.find((e) =>
    e.kind === 'process' && e.attributes?.processKind === 'model-invocation' && e.name === `model invocation ${file}`);
}

function findDataStore(context, storeKind) {
  return context.model.entities.find((e) => e.kind === 'data-store' && e.attributes?.storeKind === storeKind);
}

// Best-effort control lookup: prefer a control bound to the sink via a
// `protects`/`validates` relation (the precise, model-grounded path); fall
// back to any matching control entity present anywhere in the model. Never
// invents a control that is not in the model.
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

// Lexical trust-labeling hint: when present near the untrusted-content
// combination, treated as an explicit (if unverified) trust boundary and the
// candidate is suppressed rather than downgraded, mirroring the pinned
// pre-existing behaviour of this rule.
const TRUST_LABEL_HINT = /trust_label|sanitize|escape|allowlist|provenance|content_filter/i;

const RULES = [
  {
    // Pinned: ruleId, claim text, and the "not tool compromise" uncertainty
    // substring are relied on by a pre-existing test.
    id: 'ai.prompt-injection.indirect-untrusted-content',
    claim: 'Untrusted content is mixed into a model prompt without a visible trust label.',
    severityHint: 'high',
    sourceKind: 'untrusted-content',
    sinkKind: 'prompt',
    controlTypes: ['content-provenance-label', 'prompt-trust-boundary'],
    effectKind: 'control-bypass',
    effectAction: 'influence-model',
    effectScope: 'prompt',
    chainRoles: ['starter'],
    uncertainty: ['Influence alone is not tool compromise; downstream output handling must be adjudicated.'],
    match(text) {
      return /(?:prompt|messages|system_prompt|instructions?)\s*[:=]\s*[^\n]*(?:request|input|issue|body|content|document|description)/i.test(text)
        && !TRUST_LABEL_HINT.test(text);
    },
  },
  {
    id: 'ai.prompt-injection.retrieved-content-untrusted',
    claim: 'Retrieved (RAG/search) content reaches the model prompt or context without a trust boundary marker.',
    severityHint: 'high',
    sourceKind: 'retrieved-content',
    sinkKind: 'retrieval-context',
    controlTypes: ['content-provenance-label', 'retrieval-trust-boundary'],
    effectKind: 'control-bypass',
    effectAction: 'influence-model',
    effectScope: 'retrieval-context',
    chainRoles: ['starter'],
    uncertainty: ['Retrieval alone does not confirm attacker control of the corpus; corpus write access must be adjudicated against ai-poisoning-rag candidates.'],
    match(text) {
      return /(?:retriever|vectorStore|search_result|retrieved[-_ ]?content|rag[-_ ]?context|document[-_ ]?content)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]/i.test(text)
        && !TRUST_LABEL_HINT.test(text);
    },
  },
  {
    id: 'ai.prompt-injection.memory-context-untrusted',
    claim: 'Durable agent memory content is re-injected into a prompt without a trust label.',
    severityHint: 'medium',
    sourceKind: 'memory-content',
    sinkKind: 'memory-context',
    controlTypes: ['content-provenance-label', 'memory-trust-boundary'],
    effectKind: 'control-bypass',
    effectAction: 'influence-model',
    effectScope: 'memory-context',
    chainRoles: ['starter'],
    uncertainty: ['A prior turn writing untrusted content into memory is a distinct precondition adjudicated by ai-poisoning-rag candidates, not this rule.'],
    match(text) {
      return /(?:conversation_history|memory_store|session_memory|agent_memory|long[-_ ]?term memory)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]/i.test(text)
        && !TRUST_LABEL_HINT.test(text);
    },
  },
  {
    id: 'ai.prompt-injection.dynamic-tool-schema-untrusted',
    claim: 'A tool/function schema is constructed at runtime from untrusted content rather than a fixed definition.',
    severityHint: 'high',
    sourceKind: 'untrusted-content',
    sinkKind: 'tool-schema',
    controlTypes: ['tool-schema-allowlist', 'content-provenance-label'],
    effectKind: 'control-bypass',
    effectAction: 'redefine-tool-schema',
    effectScope: 'tool-capability',
    chainRoles: ['starter', 'enabler'],
    uncertainty: ['A dynamically built schema is not automatically attacker-controlled; the content source must be adjudicated.'],
    match(text) {
      return /(?:tools|inputSchema|tool_use)\s*(?:\.push|\[|=)[^\n]*(?:JSON\.parse|retrieved|document|request\.|response\.|externalContent)/i.test(text)
        && !TRUST_LABEL_HINT.test(text);
    },
  },
];

export default Object.freeze({
  id: 'security.ai-prompt-injection',
  version: '1.0.0',
  candidateClass: 'ai-prompt-injection',
  description: 'Untrusted prompts, retrieved content, memory, and dynamic tool schemas influencing model decisions.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      const invocation = findInvocationProcess(context, file);
      const untrustedSource = findUntrustedSource(context, file);
      const ragStore = findDataStore(context, 'rag');
      const memoryStore = findDataStore(context, 'memory');

      for (const rule of RULES) {
        if (!rule.match(text)) continue;

        const sinkEntity = invocation ?? artifact;
        let sourceEntity = untrustedSource ?? artifact;
        if (rule.sourceKind === 'retrieved-content' && ragStore) sourceEntity = ragStore;
        if (rule.sourceKind === 'memory-content' && memoryStore) sourceEntity = memoryStore;

        const control = findControl(context, sinkEntity?.id, rule.controlTypes);
        if (control) continue; // observed, model-grounded control suppresses the candidate entirely.

        const sources = sourceEntity ? [sourceEntity.id] : [];
        const sinks = sinkEntity ? [sinkEntity.id] : [];
        const evidenceRefs = [...new Set([...(sourceEntity?.evidenceRefs ?? []), ...(sinkEntity?.evidenceRefs ?? [])])];

        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-prompt-injection',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources,
          sinks,
          attackerCapabilities: ['control-untrusted-content'],
          preconditions: [{
            kind: 'attacker-position', subject: 'actor:external', action: 'supply-content',
            scope: rule.sinkKind, environment: 'agent', tenant: null,
          }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: sinkEntity?.id ?? null, scope: rule.effectScope, environment: 'agent', tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs,
          detectorMetadata: {
            file,
            untrustedOrigin: rule.sourceKind,
            sink: rule.sinkKind,
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
        class: `${rule.sinkKind}-untrusted-content-injection`,
        sinkKind: rule.sinkKind,
        sourceKind: rule.sourceKind,
        missingControl: rule.controlTypes[0] ?? null,
        semanticFeatures: ['untrusted-content-to-model', rule.sourceKind, rule.sinkKind, candidate.detectorMetadata?.sink ?? rule.sinkKind],
      };
    },
    enumerate(context) {
      const alternateSinks = ['prompt', 'retrieval-context', 'memory-context', 'tool-schema'].filter((s) => s !== rule.sinkKind);
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-alternate-sinks`, kind: 'model-derived',
          description: `Enumerate alternate model-context sinks (${alternateSinks.join(', ')}) that the same untrusted source may also reach.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
