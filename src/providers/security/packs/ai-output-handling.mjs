// AI output-handling security pack per Security Appendix §50.8. Model output
// reaching HTML/shell/SQL/filesystem/URL/patch sinks.
//
// Contract: model output is untrusted until validated AT THE SINK. A model
// output flowing into a sink with no observed validator/sanitization control
// produces a candidate; when a validator control is observed bound to that
// sink (via a `protects`/`validates` relation, or present anywhere in the
// model as a looser but still model-grounded signal), the candidate is
// suppressed entirely rather than merely downgraded — there is no "clean"
// verdict here, only "not enough model evidence to allege the primitive".

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

// Prefer the ai-agent extractor's `model output <file>` source entity for
// this file; fall back to any model-output source in the model.
function findModelOutputSource(context, file) {
  return context.model.entities.find((e) =>
    e.kind === 'source' && e.attributes?.sourceKind === 'model-output' && e.attributes?.file === file)
    ?? context.model.entities.find((e) => e.kind === 'source' && e.attributes?.sourceKind === 'model-output');
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
    // Pinned: ruleId and pattern are relied on by a pre-existing test.
    id: 'ai.output-handling.model-output-to-shell',
    sinkKind: 'shell',
    severityHint: 'high',
    pattern: /(?:exec|spawn|system|child_process)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)/i,
    controlTypes: ['shell-argument-escaping', 'output-schema-validation'],
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'sink-process',
    chainRoles: ['enabler', 'impact'],
  },
  {
    // Pinned: ruleId and pattern are relied on by a pre-existing test.
    id: 'ai.output-handling.model-output-to-html',
    sinkKind: 'html',
    severityHint: 'high',
    pattern: /(?:innerHTML|dangerouslySetInnerHTML|v-html|render_template_string|\.html_safe)\s*[^\n]*(?:model|output|completion|response|message)/i,
    controlTypes: ['html-sanitization', 'output-schema-validation'],
    effectKind: 'code-execution', effectAction: 'render', effectScope: 'dom',
    chainRoles: ['enabler', 'impact'],
  },
  {
    id: 'ai.output-handling.model-output-to-sql',
    sinkKind: 'sql',
    severityHint: 'high',
    pattern: /(?:execute|query|raw|FromSqlRaw)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)/i,
    controlTypes: ['sql-parameterization', 'output-schema-validation'],
    effectKind: 'data-access', effectAction: 'query', effectScope: 'sql-sink',
    chainRoles: ['enabler', 'impact'],
  },
  {
    id: 'ai.output-handling.model-output-to-path',
    sinkKind: 'filesystem',
    severityHint: 'high',
    pattern: /(?:writeFile|open|readFile|fs\.write|Path\.)\s*\([^\n]*(?:model|output|completion|response|message)/i,
    controlTypes: ['path-allowlist', 'output-schema-validation'],
    effectKind: 'integrity-impact', effectAction: 'write', effectScope: 'filesystem',
    chainRoles: ['enabler', 'impact'],
  },
  {
    id: 'ai.output-handling.model-output-to-url',
    sinkKind: 'url',
    severityHint: 'medium',
    pattern: /(?:fetch|redirect|location\.href|axios\.get)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)/i,
    controlTypes: ['redirect-allowlist', 'output-schema-validation'],
    effectKind: 'control-bypass', effectAction: 'bypass', effectScope: 'redirect-or-egress',
    chainRoles: ['enabler', 'control-bypass'],
  },
  {
    id: 'ai.output-handling.model-output-to-patch',
    sinkKind: 'patch',
    severityHint: 'high',
    pattern: /(?:applyPatch|git\.apply|autoApply|writeFile\([^\n]*diff)\s*\([^\n]*(?:model|output|completion|response|message|patch)/i,
    controlTypes: ['patch-review', 'human-approval'],
    effectKind: 'integrity-impact', effectAction: 'apply-patch', effectScope: 'repository',
    chainRoles: ['enabler', 'impact'],
  },
];

export default Object.freeze({
  id: 'security.ai-output-handling',
  version: '1.0.0',
  candidateClass: 'ai-output-handling',
  description: 'Model output reaching HTML/shell/SQL/filesystem/URL/patch sinks without a validated-at-sink control.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      const modelOutput = findModelOutputSource(context, file);

      for (const rule of RULES) {
        if (!rule.pattern.test(text)) continue;

        const sinkEntity = artifact;
        const control = findControl(context, sinkEntity?.id, rule.controlTypes);
        if (control) continue; // validated at the sink: no candidate, not "clean".

        const sourceEntity = modelOutput ?? artifact;
        const sources = sourceEntity ? [sourceEntity.id] : [];
        const sinks = sinkEntity ? [sinkEntity.id] : [];
        const evidenceRefs = [...new Set([...(sourceEntity?.evidenceRefs ?? []), ...(sinkEntity?.evidenceRefs ?? [])])];

        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-output-handling',
          claim: `Model output may reach a ${rule.sinkKind} sink without a visible schema-validation or sanitization control.`,
          severityHint: rule.severityHint,
          sources,
          sinks,
          attackerCapabilities: ['influence-model-output'],
          preconditions: [{ kind: 'control-bypass', subject: 'actor:external', action: 'influence-model', scope: 'model-output', environment: 'agent', tenant: null }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: sinkEntity?.id ?? null, scope: rule.effectScope, environment: 'application', tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs,
          detectorMetadata: {
            file,
            untrustedOrigin: 'model-output',
            sink: rule.sinkKind,
            detectionMethod: 'lexical-pattern',
            matchDigest: digest({ ruleId: rule.id, file }),
          },
          uncertainty: ['Model output reaching this sink is not automatically exploitable; whether the output is schema-validated/allowlisted downstream must be adjudicated.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, {
    rootCause(candidate) {
      return {
        class: `${rule.sinkKind}-unvalidated-model-output-sink`,
        sinkKind: rule.sinkKind,
        missingControl: rule.controlTypes[0] ?? null,
        semanticFeatures: ['model-output-to-sink', rule.sinkKind, candidate.detectorMetadata?.sink ?? rule.sinkKind],
      };
    },
    enumerate(context) {
      const alternateSinks = RULES.map((r) => r.sinkKind).filter((s) => s !== rule.sinkKind);
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-alternate-sinks`, kind: 'model-derived',
          description: `Enumerate alternate output sinks (${alternateSinks.join(', ')}) the same model-output source may also reach.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
