// AI model/provider-abuse security pack. Model/provider data retention
// (PII sent to a third-party model without a retention/opt-out control),
// uncapped cost loops (model invocation inside a loop/retry without a
// budget), and shared provider credentials used without per-tenant scoping.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function findInvocationProcess(context, file) {
  return context.model.entities.find((e) =>
    e.kind === 'process' && e.attributes?.processKind === 'model-invocation' && e.name === `model invocation ${file}`)
    ?? context.model.entities.find((e) => e.kind === 'process' && e.attributes?.processKind === 'model-invocation');
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
    id: 'ai.model-abuse.provider-data-retention-unbounded',
    severityHint: 'high',
    controlTypes: ['data-retention-opt-out', 'zero-retention-agreement'],
    effectKind: 'confidentiality-impact', effectAction: 'retain-third-party', effectScope: 'model-provider',
    chainRoles: ['starter', 'impact'],
    claim: 'A model-provider call includes personal/customer data without a visible data-retention opt-out or zero-retention control.',
    uncertainty: ['A per-account or contractual retention setting outside the repository may already govern this call; that must be adjudicated.'],
    match(text) {
      return /(?:openai|anthropic|\.chat\.completions\.create|messages\.create)\s*\(/i.test(text)
        && /\b(?:email|ssn|creditCard|user\.|customer\.|pii)\b/i.test(text)
        && !/zero_retention|retention\s*:\s*['"]?none|dataResidency|optOutTraining|store\s*:\s*false/i.test(text);
    },
  },
  {
    id: 'ai.model-abuse.uncapped-cost-loop',
    severityHint: 'medium',
    controlTypes: ['side-effect-budget', 'rate-limit'],
    effectKind: 'availability-impact', effectAction: 'exhaust-spend', effectScope: 'model-provider',
    chainRoles: ['starter', 'impact'],
    claim: 'A model invocation sits inside a loop/retry construct without a visible call, step, retry, or spend budget, enabling a cost-abuse amplification loop.',
    uncertainty: ['A missing local budget pattern does not confirm the loop is attacker-reachable or unbounded at runtime; both must be adjudicated.'],
    match(text) {
      return /\b(?:while\s*\(|for\s*\(|retry|\.map\()/i.test(text)
        && /\.create\(|\.complete\(|\.generate\(/i.test(text)
        && !/max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget|maxRetries/i.test(text);
    },
  },
  {
    id: 'ai.model-abuse.shared-provider-credential',
    severityHint: 'medium',
    controlTypes: ['identity-scoping', 'tenant-scope-check'],
    effectKind: 'principal-access', effectAction: 'act-as', effectScope: 'model-provider-credential',
    chainRoles: ['enabler'],
    claim: 'A model-provider credential is referenced as a global/shared/static value without per-tenant or per-user scoping.',
    uncertainty: ['A single global credential is not automatically abusable; whether callers can bind it to attacker-chosen inputs across tenants must be adjudicated.'],
    match(text) {
      return /(?:api_key|apiKey|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[:=]/i.test(text)
        && /\bglobal\b|\bshared\b|\bstatic\b|process\.env\./i.test(text)
        && !/\btenant(?:Id)?\b|\bperUser\b|\bscopedKey\b/i.test(text);
    },
  },
];

export default Object.freeze({
  id: 'security.ai-model-abuse',
  version: '1.0.0',
  candidateClass: 'ai-model-abuse',
  description: 'Model/provider data retention, cost-abuse loops, and shared provider credentials.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      const invocation = findInvocationProcess(context, file);

      for (const rule of RULES) {
        if (!rule.match(text)) continue;

        const sinkEntity = invocation ?? artifact;
        const control = findControl(context, sinkEntity?.id, rule.controlTypes);
        if (control) continue;

        const sources = artifact ? [artifact.id] : [];
        const sinks = sinkEntity ? [sinkEntity.id] : [];
        const evidenceRefs = [...new Set([...(artifact?.evidenceRefs ?? []), ...(sinkEntity?.evidenceRefs ?? [])])];

        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-model-abuse',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources,
          sinks,
          attackerCapabilities: ['influence-model-invocation-volume-or-payload'],
          preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'invoke-model', scope: null, environment: 'agent', tenant: null }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: sinkEntity?.id ?? null, scope: rule.effectScope, environment: 'agent', tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs,
          detectorMetadata: {
            file,
            sink: 'model-provider',
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
        class: `model-abuse-${rule.id.split('.').pop()}`,
        missingControl: rule.controlTypes[0] ?? null,
        semanticFeatures: ['ai-model-abuse', rule.id, candidate.detectorMetadata?.sink ?? 'model-provider'],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-alternate-invocations`, kind: 'model-derived',
          description: 'Enumerate alternate model invocation sites, providers, and credential references the same abuse pattern may also reach.',
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
