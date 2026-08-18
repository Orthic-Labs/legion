// Developer-machine security pack (B7-018): local executable invocation,
// editor/tool config authority, credential-store access, and agent/skill
// config execution paths.
//
// Lexical (pattern-only) detectors over repository text already present in
// the frozen denominator. Never spawns a process, never reads a real
// filesystem path, never calls a model. Repository content (editor, agent,
// hook, and skill configuration) is never a trusted input: every candidate's
// preconditions name the repository as the untrusted origin, because a
// developer's own tools execute exactly what is committed. Tool/config
// findings always name `detectorMetadata.authority` (whose local authority
// the config runs under) and `detectorMetadata.executionPath` (the concrete
// hop sequence). Rules whose claim is really "this local chain executes"
// are always emitted with `detectorMetadata.requiresSandboxReceipt = true`
// plus a typed blocked/unproven marker in `uncertainty` — this module has
// no way to actually execute repository-local tooling to prove the chain.

import { digest } from '../contracts.mjs';

const EDITOR_AGENT_CONFIG_PATTERN = /(^|\/)(\.vscode|\.idea|\.cursor|\.claude|\.github\/copilot|\.mcp\.json|mcp\.json|CLAUDE\.md|AGENTS\.md|\.husky|\.git\/hooks)(\/|$)/i;
const SKILL_CONFIG_PATTERN = /(^|\/)(SKILL\.md|\.claude\/(agents|skills)\/)/i;
const SANDBOX_BYPASS_PATTERN = /dangerouslySkipPermissions|--no-sandbox|bypassPermissions|trust\s*[:=]\s*(?:false|"?off"?|disabled)/i;

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function hostilePrecondition(file, environment) {
  return {
    kind: 'attacker-position',
    subject: 'actor:repository-content',
    action: 'control-repository-content',
    object: file,
    scope: null,
    environment: environment ?? 'developer-machine',
    tenant: null,
  };
}

function sandboxGate(context) {
  const hasReceipt = Boolean(context.projection?.auditFacts?.sandboxReceipt);
  return {
    note: hasReceipt
      ? 'An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.'
      : 'BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this developer-machine chain actually executes remains unproven pending one.',
  };
}

// Handles both global and non-global patterns correctly: a non-global
// RegExp's `lastIndex` never advances, so driving it through an exec loop
// would never terminate. A non-global pattern therefore contributes at most
// one match per file.
function rawMatches(pattern, text) {
  if (!pattern.global) {
    const match = pattern.exec(text);
    return match ? [match] : [];
  }
  const out = [];
  pattern.lastIndex = 0;
  let match = pattern.exec(text);
  while (match !== null) {
    if (match[0].length === 0) { pattern.lastIndex += 1; match = pattern.exec(text); continue; }
    out.push(match);
    match = pattern.exec(text);
  }
  return out;
}

function regexRule(pattern, { fileGuard } = {}) {
  return function matchesIn(context) {
    const out = [];
    for (const file of context.files) {
      if (fileGuard && !fileGuard.test(file)) continue;
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      for (const match of rawMatches(pattern, text)) {
        out.push({ file, line: lineOf(text, match.index), snippet: match[0] });
      }
    }
    return out;
  };
}

const RULES = [
  {
    id: 'developer-machine.local-executable.command-invocation',
    claim: 'Repository-controlled configuration invokes a local executable/shell command that will run with the invoking developer\'s own authority.',
    severityHint: 'high',
    authority: 'developer-machine-user',
    executionPath: 'repository config → local tool loader → child_process/shell invocation',
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'developer-machine-process',
    chainRoles: ['starter', 'impact'],
    executionChain: true,
    uncertainty: ['A command-invocation pattern in configuration is not automatically executed; whether the surrounding tool actually runs it, and with what input, must be adjudicated.'],
    matchesIn: regexRule(
      /\bexec\s*\(|\bspawn\s*\(|child_process|Bash\s*\(|shell\s*=\s*true/i,
      { fileGuard: EDITOR_AGENT_CONFIG_PATTERN },
    ),
  },
  {
    id: 'developer-machine.editor-config.command-authority',
    claim: 'An editor/agent configuration file defines a task, hook, or command that a developer\'s tool will run automatically under the developer\'s own authority.',
    severityHint: 'medium',
    authority: 'developer-machine-user',
    executionPath: 'editor/agent config load → task/hook definition → invoked by editor authority',
    effectKind: 'code-execution', effectAction: 'define-command', effectScope: 'developer-machine-tooling',
    chainRoles: ['enabler'],
    uncertainty: ['A defined task/command is not automatically dangerous; whether it runs without confirmation and what it targets must be adjudicated.'],
    matchesIn: regexRule(
      /"command"\s*:\s*"[^"\n]+"|"runOptions"|postCreateCommand|"task"\s*:/i,
      { fileGuard: EDITOR_AGENT_CONFIG_PATTERN },
    ),
  },
  {
    id: 'developer-machine.credential-store.access-pattern',
    claim: 'Repository-controlled configuration or code references an OS credential store, keychain, or well-known local secrets path.',
    severityHint: 'high',
    authority: 'developer-machine-user',
    executionPath: 'repository config/code → credential-store client → local secret material',
    effectKind: 'credential-possession', effectAction: 'access-local-credential-store', effectScope: 'developer-machine-credentials',
    chainRoles: ['starter', 'pivot'],
    uncertainty: ['A credential-store reference is not automatically an exfiltration path; whether the retrieved value ever leaves the local process must be adjudicated.'],
    matchesIn: regexRule(
      /\bkeytar\b|security\s+find-generic-password|\.aws\/credentials|\.ssh\/id_(?:rsa|ed25519)|\.netrc\b|\bkeychain\b|credential-store/i,
    ),
  },
  {
    id: 'developer-machine.agent-skill-config.execution-path',
    claim: 'An agent/skill configuration file (MCP server, skill, or agent definition) declares a command or entrypoint that will be executed as part of the agent\'s local tool authority.',
    severityHint: 'high',
    authority: 'developer-machine-agent',
    executionPath: '.mcp.json/SKILL.md/.claude agent config → declared server/tool command → local process',
    effectKind: 'code-execution', effectAction: 'execute-declared-tool-command', effectScope: 'developer-machine-agent-runtime',
    chainRoles: ['starter', 'impact'],
    executionChain: true,
    uncertainty: ['A declared agent/skill command is not automatically hostile; whether it is actually invoked and under what approval gate must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!SKILL_CONFIG_PATTERN.test(file) && !/\.mcp\.json$|mcp\.json$/i.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        if (!/"command"\s*:\s*"[^"\n]+"|"args"\s*:\s*\[|\bIgnore prior instructions\b/i.test(text)) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'developer-machine.sandbox-bypass.permission-override',
    claim: 'Repository-controlled configuration disables a local sandbox or permission gate that would otherwise confirm before executing on the developer machine.',
    severityHint: 'high',
    authority: 'developer-machine-user',
    executionPath: 'repository config → sandbox/permission bypass flag → unconfirmed local execution',
    effectKind: 'control-bypass', effectAction: 'disable-local-sandbox', effectScope: 'developer-machine-tooling',
    chainRoles: ['enabler', 'control-bypass'],
    uncertainty: ['A bypass-shaped flag is not automatically active in the invoking tool\'s effective configuration; scope and precedence must be adjudicated.'],
    matchesIn: regexRule(SANDBOX_BYPASS_PATTERN, { fileGuard: EDITOR_AGENT_CONFIG_PATTERN }),
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `developer-machine-${rule.id}`,
        semanticFeatures: ['repository-controlled-developer-machine-config', rule.id],
      };
    },
    enumerate(context) {
      const matches = rule.matchesIn(context).map((m) => ({
        file: m.file,
        line: m.line,
        semanticFingerprint: digest({ ruleId: rule.id, file: m.file, snippet: m.snippet }),
        disposition: 'CONFIRMED',
      }));
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate alternate developer-machine configuration entrypoints for ${rule.id}.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.developer-machine',
  version: '1.0.0',
  candidateClass: 'developer-machine',
  description: 'Local executable invocation, editor/tool config authority, credential-store access, and agent/skill config execution paths.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const rule of RULES) {
      const matches = rule.matchesIn(context);
      for (const match of matches) {
        const artifact = findArtifact(context, match.file);
        const gate = rule.executionChain ? sandboxGate(context) : null;
        const uncertainty = [...rule.uncertainty];
        if (gate) uncertainty.push(gate.note);

        observations.push({
          ruleId: rule.id,
          candidateClass: 'developer-machine',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['read-repository', 'control-repository-content'],
          preconditions: [hostilePrecondition(match.file, 'developer-machine')],
          effects: [{
            kind: rule.effectKind,
            subject: 'actor:repository-content',
            action: rule.effectAction,
            object: artifact?.id ?? null,
            scope: rule.effectScope,
            environment: 'developer-machine',
            tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: rule.chainRoles,
          evidenceRefs: artifact?.evidenceRefs ?? [],
          detectorMetadata: {
            file: match.file,
            line: match.line,
            authority: rule.authority,
            executionPath: rule.executionPath,
            matchDigest: digest(match.snippet),
            ...(gate ? { requiresSandboxReceipt: true } : {}),
          },
          uncertainty,
        });
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
