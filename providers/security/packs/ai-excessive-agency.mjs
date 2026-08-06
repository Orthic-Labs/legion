// AI excessive-agency security pack per Security Appendix §53. Destructive
// tools without approval; broad shared identity; cross-tenant tool boundary.

const DESTRUCTIVE = new Set([
  'delete', 'publish', 'deploy', 'send', 'transfer', 'approve',
  'merge', 'release', 'sign', 'execute', 'write-secret',
]);

export default Object.freeze({
  id: 'security.ai-excessive-agency',
  version: '1.0.0',
  candidateClass: 'ai-agent-agency',
  description: 'Agent tool authority, identity scope, approval, and side-effect bounds.',
  rules: [
    { id: 'ai.agency.destructive-tool-without-approval' },
    { id: 'ai.agency.shared-high-scope-identity' },
  ],
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      const destructivePattern = new RegExp(`\\b(?:name\\s*:\\s*["'](${[...DESTRUCTIVE].join('|')})["']|\\b(?:${[...DESTRUCTIVE].join('|')})\\w*\\s*(?:\\(|:))`, 'i');
      const destructiveMatch = text.match(destructivePattern)?.[1]
        ?? [...DESTRUCTIVE].find((action) => new RegExp(`\\b${action}\\w*\\s*(?:\\(|:)`, 'i').test(text));
      if (destructiveMatch && !/approval|reauthenticate|requireConfirm|human_in_the_loop|allowlist/i.test(text)) {
        observations.push({
          ruleId: 'ai.agency.destructive-tool-without-approval',
          candidateClass: 'ai-agent-agency',
          claim: `A destructive ${destructiveMatch} tool is available to the agent without a visible approval or reauthentication control.`,
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['influence-model-input-or-retrieval'],
          preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'influence-tool-selection-or-arguments', environment: 'agent' }],
          effects: [{ kind: 'principal-access', subject: 'actor:external', action: 'act-as', scope: 'service-identity', environment: 'agent', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['enabler', 'privilege-escalation', 'impact'],
          evidenceRefs: [],
          detectorMetadata: { file, action: destructiveMatch },
          uncertainty: ['A runtime policy outside the repository may require approval.'],
        });
      }
      if (/\b(?:token|credential|secret|api_key)\b/i.test(text) && /\b(?:tool|agent|assistant)\b/i.test(text) && !/scope|least|rotate|readonly/.test(text)) {
        observations.push({
          ruleId: 'ai.agency.shared-high-scope-identity',
          candidateClass: 'ai-agent-agency',
          claim: 'A shared high-scope identity is exposed to tool execution without visible scoping.',
          severityHint: 'medium',
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['influence-model-input-or-retrieval'],
          preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'influence-tool-selection-or-arguments', environment: 'agent' }],
          effects: [{ kind: 'principal-access', subject: 'actor:external', action: 'act-as', scope: 'shared-identity', environment: 'agent', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['enabler'],
          evidenceRefs: [],
          detectorMetadata: { file },
          uncertainty: ['Excessive agency amplifies other candidates; alone it may be a misuse hazard.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {},
});
