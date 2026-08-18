// Automation security pack (B7-018): release identity, updater/installer
// trust, signature verification, and privileged automation.
//
// Lexical (pattern-only) detectors over repository/pipeline text already
// present in the frozen denominator. Never triggers a pipeline, never
// contacts an update server, never calls a model. Repository-controlled
// pipeline/release/updater configuration is never a trusted input: every
// candidate's preconditions name the repository as the untrusted origin,
// because whoever can edit this configuration controls what a privileged
// automation identity will run. Tool/config findings always name
// `detectorMetadata.authority` (whose privileged identity the automation
// runs as) and `detectorMetadata.executionPath` (the concrete hop
// sequence). Rules whose claim is really "this privileged automation
// executes" are always emitted with `detectorMetadata.requiresSandboxReceipt
// = true` plus a typed blocked/unproven marker in `uncertainty` — this
// module has no way to actually trigger or execute repository-local
// automation to prove the chain.

import { digest } from '../contracts.mjs';

const WORKFLOW_FILE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)azure-pipelines\.ya?ml$|(^|\/)\.circleci\/config\.ya?ml$|(^|\/)bitbucket-pipelines\.ya?ml$/i;
const UPDATER_CONFIG = /electron-builder\.(ya?ml|json5?|toml)$|(^|\/)app-update\.ya?ml$/i;
const DEPENDENCY_UPDATE_CONFIG = /(^|\/)renovate\.json5?$|(^|\/)\.github\/renovate\.json5?$|(^|\/)\.github\/dependabot\.ya?ml$/i;
const RELEASE_CONFIG = /(^|\/)\.releaserc(\.[a-zA-Z0-9]+)?$|(^|\/)release\.config\.[cm]?js$|(^|\/)\.goreleaser\.ya?ml$/i;

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function hostilePrecondition(file) {
  return {
    kind: 'attacker-position',
    subject: 'actor:repository-content',
    action: 'control-repository-content',
    object: file,
    scope: null,
    environment: 'ci',
    tenant: null,
  };
}

function sandboxGate(context) {
  const hasReceipt = Boolean(context.projection?.auditFacts?.sandboxReceipt);
  return {
    note: hasReceipt
      ? 'An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.'
      : 'BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this privileged automation chain actually executes remains unproven pending one.',
  };
}

function permissionScopeIsElevated(text) {
  const index = text.search(/\bpermissions\s*:/);
  if (index === -1) return false;
  const window = text.slice(index, index + 400);
  return /write-all/.test(window) || /contents\s*:\s*write/.test(window);
}

function fileGuardPasses(fileGuard, file) {
  if (!fileGuard) return true;
  return typeof fileGuard === 'function' ? fileGuard(file) : fileGuard.test(file);
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
      if (!fileGuardPasses(fileGuard, file)) continue;
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
    id: 'automation.release.unresolved-identity-scope',
    claim: 'A publish/release automation step runs without a resolvable permission scope, so the effective authority of the release identity cannot be established from this file.',
    severityHint: 'medium',
    authority: 'ci-release-identity',
    executionPath: 'release trigger → publish step → identity with unresolved permission scope',
    effectKind: 'capability', effectAction: 'run-with-unresolved-scope', effectScope: 'release-identity',
    chainRoles: ['enabler'],
    uncertainty: ['An unresolved permission scope in this file does not prove excess privilege; the effective scope may be constrained elsewhere (org/repo defaults) and must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!WORKFLOW_FILE.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const hasPublish = /\bnpm publish\b|\bdocker push\b|docker\/build-push-action|\bgoreleaser\b|\bsemantic-release\b|\bgh release create\b/.test(text);
        if (!hasPublish) continue;
        if (/\bpermissions\s*:/.test(text)) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'automation.updater.insecure-transport-or-unverified-signature',
    claim: 'An application auto-updater is configured with an insecure (http://) update endpoint or with signature verification explicitly disabled.',
    severityHint: 'high',
    authority: 'end-user-device-updater',
    executionPath: 'installed application → updater config → downloaded update applied to end-user device',
    effectKind: 'code-execution', effectAction: 'apply-unverified-update', effectScope: 'end-user-device',
    chainRoles: ['starter', 'impact'],
    environment: 'end-user-device',
    uncertainty: ['An insecure-transport or disabled-verification marker is not automatically exploitable; whether the updater actually reaches this configuration path at runtime must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!UPDATER_CONFIG.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const insecureTransport = /(?:update|download|artifact)[\s\S]{0,180}http:\/\//i.test(text);
        const disabledSignature = /verifyUpdateCodeSignature\s*:\s*false/.test(text);
        if (!insecureTransport && !disabledSignature) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'automation.release.signing-disabled-or-unenforced',
    claim: 'Release-signing/verification is explicitly disabled or skipped for a publish step.',
    severityHint: 'high',
    authority: 'ci-release-identity',
    executionPath: 'release step → signing/verification flag explicitly disabled → unsigned published artifact',
    effectKind: 'integrity-impact', effectAction: 'publish-unsigned-artifact', effectScope: 'release-artifact',
    chainRoles: ['control-bypass', 'impact'],
    uncertainty: ['An explicitly disabled signing flag is not automatically exploited; whether consumers actually verify signatures on this artifact type must be adjudicated.'],
    matchesIn: regexRule(
      /\bsign\s*:\s*false\b|\bskipSign\s*:\s*true\b|verifyUpdateCodeSignature\s*:\s*false/,
      { fileGuard: (f) => WORKFLOW_FILE.test(f) || RELEASE_CONFIG.test(f) || UPDATER_CONFIG.test(f) },
    ),
  },
  {
    id: 'automation.privileged-automation.hostile-trigger-with-write',
    claim: 'A workflow triggered by untrusted external content (pull_request_target/workflow_run/issue_comment) holds elevated write permission, letting an external contributor drive privileged automation.',
    severityHint: 'high',
    authority: 'ci-privileged-automation-identity',
    executionPath: 'external-contributor content → hostile trigger → privileged (write) automation step',
    effectKind: 'code-execution', effectAction: 'run-privileged-step-from-untrusted-trigger', effectScope: 'ci-privileged-automation',
    chainRoles: ['starter', 'privilege-escalation', 'impact'],
    executionChain: true,
    uncertainty: ['A hostile-trigger-plus-write-permission shape is not automatically exploited; whether attacker-controlled data actually reaches a privileged step within the job must be adjudicated by independent sandboxed execution.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!WORKFLOW_FILE.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const hostileTrigger = /\bpull_request_target\b/.test(text) || /\bworkflow_run\b/.test(text) || /\bissue_comment\b/.test(text);
        if (!hostileTrigger) continue;
        if (!permissionScopeIsElevated(text)) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'automation.dependency-update.automerge-without-review',
    claim: 'Scheduled dependency-update automation is configured to auto-merge without a visible required-review/required-status-check gate in the same file.',
    severityHint: 'medium',
    authority: 'ci-dependency-update-bot-identity',
    executionPath: 'scheduled dependency update → automerge enabled → merged without human review',
    effectKind: 'control-bypass', effectAction: 'merge-without-review', effectScope: 'repository-main-branch',
    chainRoles: ['enabler', 'control-bypass'],
    uncertainty: ['An automerge flag in this file does not prove branch protection is absent; required reviews/status checks may be enforced by host-side repository settings outside this file and must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!DEPENDENCY_UPDATE_CONFIG.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const automerge = /"automerge"\s*:\s*true/.test(text) || /\bautomerge\s*:\s*true\b/.test(text);
        if (!automerge) continue;
        const reviewGate = /requiredReviews|requireStatusChecks|minimumApprovals/i.test(text);
        if (reviewGate) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `automation-${rule.id}`,
        semanticFeatures: ['repository-controlled-automation-config', rule.id],
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
          description: `Enumerate alternate automation/release configuration entrypoints for ${rule.id}.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.automation',
  version: '1.0.0',
  candidateClass: 'automation',
  description: 'Release identity, updater/installer trust, signature verification, and privileged automation.',
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
          candidateClass: 'automation',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['read-repository', 'control-repository-content'],
          preconditions: [hostilePrecondition(match.file)],
          effects: [{
            kind: rule.effectKind,
            subject: 'actor:repository-content',
            action: rule.effectAction,
            object: artifact?.id ?? null,
            scope: rule.effectScope,
            environment: rule.environment ?? 'ci',
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
