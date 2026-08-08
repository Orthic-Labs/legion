// AI excessive-agency security pack per Security Appendix §53. Destructive
// tools without approval; shared high-scope identities; cross-tenant tool
// boundaries; agentic loops without a side-effect budget.

import { digest } from '../contracts.mjs';

const DESTRUCTIVE = new Set([
  'delete', 'publish', 'deploy', 'send', 'transfer', 'approve',
  'merge', 'release', 'sign', 'execute', 'write-secret',
]);

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function findToolCapability(context, file) {
  return context.model.entities.find((e) => e.kind === 'tool-capability' && e.attributes?.file === file)
    ?? context.model.entities.find((e) => e.kind === 'tool-capability');
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
    // Pinned: ruleId, claim shape (`A destructive ${action} tool...`), and
    // detectorMetadata.action are relied on by pre-existing tests.
    id: 'ai.agency.destructive-tool-without-approval',
    severityHint: 'high',
    controlTypes: ['human-approval'],
    effectKind: 'principal-access', effectAction: 'act-as', effectScope: 'service-identity',
    chainRoles: ['enabler', 'privilege-escalation', 'impact'],
    uncertainty: ['A runtime policy outside the repository may require approval.'],
    detect(text) {
      const destructivePattern = new RegExp(`\\b(?:name\\s*:\\s*["'](${[...DESTRUCTIVE].join('|')})["']|\\b(?:${[...DESTRUCTIVE].join('|')})\\w*\\s*(?:\\(|:))`, 'i');
      const destructiveMatch = text.match(destructivePattern)?.[1]
        ?? [...DESTRUCTIVE].find((action) => new RegExp(`\\b${action}\\w*\\s*(?:\\(|:)`, 'i').test(text));
      if (!destructiveMatch) return null;
      if (/approval|reauthenticate|requireConfirm|human_in_the_loop|allowlist/i.test(text)) return null;
      return { action: destructiveMatch };
    },
    claim: (m) => `A destructive ${m.action} tool is available to the agent without a visible approval or reauthentication control.`,
  },
  {
    // Pinned: ruleId and claim text are relied on by a pre-existing test.
    id: 'ai.agency.shared-high-scope-identity',
    severityHint: 'medium',
    controlTypes: ['identity-scoping'],
    effectKind: 'principal-access', effectAction: 'act-as', effectScope: 'shared-identity',
    chainRoles: ['enabler'],
    uncertainty: ['Excessive agency amplifies other candidates; alone it may be a misuse hazard.'],
    detect(text) {
      if (!/\b(?:token|credential|secret|api_key)\b/i.test(text)) return null;
      if (!/\b(?:tool|agent|assistant)\b/i.test(text)) return null;
      if (/scope|least|rotate|readonly/.test(text)) return null;
      return {};
    },
    claim: () => 'A shared high-scope identity is exposed to tool execution without visible scoping.',
  },
  {
    id: 'ai.agency.cross-tenant-tool-boundary',
    severityHint: 'high',
    controlTypes: ['tenant-scope-check'],
    effectKind: 'confidentiality-impact', effectAction: 'cross-tenant-act', effectScope: 'tool-capability',
    chainRoles: ['enabler', 'control-bypass'],
    uncertainty: ['A missing local tenant-scope argument does not confirm cross-tenant reach; the tool implementation must be adjudicated.'],
    detect(text) {
      if (!/\btool\b[\s\S]{0,120}\b(?:run|execute|invoke)\s*\(/i.test(text)) return null;
      if (!/\b(?:delete|write|update|transfer|deploy)\w*\s*\(/i.test(text)) return null;
      if (/\btenant(?:Id)?\b/i.test(text)) return null;
      return {};
    },
    claim: () => 'A tool available to the agent performs a state-changing action without a visible tenant-scope argument.',
  },
  {
    id: 'ai.agency.missing-side-effect-budget',
    severityHint: 'medium',
    controlTypes: ['side-effect-budget'],
    effectKind: 'availability-impact', effectAction: 'exhaust', effectScope: 'tool-invocation-loop',
    chainRoles: ['enabler'],
    uncertainty: ['A missing local budget pattern does not confirm an unbounded loop; a runtime orchestrator budget may exist outside the repository.'],
    detect(text) {
      if (!/\bwhile\s*\(\s*true\s*\)|\bfor\s*\(;;\)|\bagent[_ ]?loop\b/i.test(text)) return null;
      if (!/\btool\b|\.run\(|\.invoke\(/i.test(text)) return null;
      if (/max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget/i.test(text)) return null;
      return {};
    },
    claim: () => 'An agentic tool-invocation loop is present without a visible step, call, spend, or token budget control.',
  },
];

export default Object.freeze({
  id: 'security.ai-excessive-agency',
  version: '1.0.0',
  candidateClass: 'ai-agent-agency',
  description: 'Agent tool authority, identity scope, tenant boundary, approval, and side-effect budget bounds.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      const tool = findToolCapability(context, file);

      for (const rule of RULES) {
        const matched = rule.detect(text);
        if (!matched) continue;

        const sinkEntity = tool ?? artifact;
        const control = findControl(context, sinkEntity?.id, rule.controlTypes);
        if (control) continue;

        const sources = artifact ? [artifact.id] : [];
        const sinks = sinkEntity ? [sinkEntity.id] : [];
        const evidenceRefs = [...new Set([...(artifact?.evidenceRefs ?? []), ...(sinkEntity?.evidenceRefs ?? [])])];

        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-agent-agency',
          claim: rule.claim(matched),
          severityHint: rule.severityHint,
          sources,
          sinks,
          attackerCapabilities: ['influence-model-input-or-retrieval'],
          preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'influence-tool-selection-or-arguments', scope: null, environment: 'agent', tenant: null }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: sinkEntity?.id ?? null, scope: rule.effectScope, environment: 'agent', tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs,
          detectorMetadata: {
            file,
            ...matched,
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
        class: `agency-${rule.id.split('.').pop()}`,
        missingControl: rule.controlTypes[0] ?? null,
        semanticFeatures: ['excessive-agency', rule.id, candidate.detectorMetadata?.action ?? rule.id],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-alternate-tools`, kind: 'model-derived',
          description: 'Enumerate alternate destructive tools, shared identities, tenant boundaries, and loop sites the same agent may also reach.',
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
