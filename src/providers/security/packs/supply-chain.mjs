// Supply-chain security pack (B7-018): dependency and lockfile integrity,
// package install scripts, plugin trust, committed build output, and
// artifact/cache poisoning.
//
// Every rule is a lexical (pattern-only) detector operating on repository
// text and file paths already present in the frozen denominator. It never
// executes a package script, never resolves a dependency, never calls a
// model, and never certifies a finding — it only ever emits UNADJUDICATED
// candidates via the sealed candidate-engine.
//
// Repository content is never a trusted configuration source: every
// candidate's preconditions include an explicit `attacker-position` fact
// naming the repository itself as the untrusted origin of the evidence,
// because a compromised or malicious contributor controls exactly the
// files this pack reads. Findings that name a tool or configuration always
// carry `detectorMetadata.authority` (whose authority the tool/config runs
// under) and `detectorMetadata.executionPath` (the concrete hop sequence
// from repository content to effect). Rules that would require actually
// running repository-local tooling to prove an execution chain are always
// emitted with `detectorMetadata.requiresSandboxReceipt = true` and a typed
// blocked/unproven marker in `uncertainty` — never a clean claim — because
// this module imports no process/filesystem/network primitive and cannot
// execute anything to prove the chain itself.

import { digest } from '../contracts.mjs';

const PACKAGE_MANIFEST = /(^|\/)package\.json$/;
const LOCKFILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/;
const NPM_CONFIG = /(^|\/)\.npmrc$/;
const WORKFLOW_FILE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)azure-pipelines\.ya?ml$|(^|\/)\.circleci\/config\.ya?ml$/i;
const BUILD_OUTPUT_PATH = /(^|\/)(dist|build|out|\.next|target)\/[^/]+/;

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

// Every candidate must state that the repository content it was derived
// from is an untrusted, potentially attacker-controlled source — never a
// trusted configuration input.
function hostilePrecondition(file, environment) {
  return {
    kind: 'attacker-position',
    subject: 'actor:repository-content',
    action: 'control-repository-content',
    object: file,
    scope: null,
    environment: environment ?? 'any',
    tenant: null,
  };
}

// This module never executes repository-local tooling (no
// node:child_process/fs/http/https/net import exists here), so any rule
// whose claim is really "this chain executes" can only ever be a blocked,
// unproven allegation absent an external sandbox execution receipt already
// present in the audit context.
function sandboxGate(context) {
  const hasReceipt = Boolean(context.projection?.auditFacts?.sandboxReceipt);
  return {
    requiresSandboxReceipt: true,
    note: hasReceipt
      ? 'An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.'
      : 'BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this install-time chain actually executes remains unproven pending one.',
  };
}

function ignoreScriptsConfigured(context) {
  for (const file of context.files) {
    if (!NPM_CONFIG.test(file)) continue;
    const text = context.readFile(file) ?? '';
    if (/\bignore-scripts\s*=\s*true\b/i.test(text)) return true;
  }
  return false;
}

function hasIntegrityCoveredLockfile(context, lockfileFile) {
  const text = context.readFile(lockfileFile) ?? '';
  return /\bintegrity\b/i.test(text) || /\bresolution\b.*sha(256|512)/i.test(text);
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
    id: 'supply-chain.dependency.non-registry-source',
    claim: 'A dependency is resolved from a direct git/URL source rather than the package registry, bypassing registry-level integrity and provenance checks.',
    severityHint: 'medium',
    authority: 'package-manager',
    executionPath: 'dependency resolution → non-registry source → installed package',
    effectKind: 'integrity-impact', effectAction: 'substitute-dependency', effectScope: 'dependency-resolution',
    chainRoles: ['enabler'],
    uncertainty: ['A direct-URL/git dependency is not automatically malicious; whether the source is pinned to an immutable commit and reviewed must be adjudicated.'],
    matchesIn: regexRule(
      /"[\w@/.-]+"\s*:\s*"(?:git\+[^"\n]+|https?:\/\/[^"\n]+|github:[^"\n]+)"/g,
      { fileGuard: PACKAGE_MANIFEST },
    ),
  },
  {
    id: 'supply-chain.lockfile.missing',
    claim: 'A package manifest is present without a corresponding dependency lockfile, so transitive dependency versions are not pinned or hash-verified at install time.',
    severityHint: 'medium',
    authority: 'package-manager',
    executionPath: 'dependency install → unpinned resolution → arbitrary transitive package version',
    effectKind: 'integrity-impact', effectAction: 'unpin-dependency-resolution', effectScope: 'dependency-resolution',
    chainRoles: ['enabler'],
    uncertainty: ['A missing lockfile in this denominator slice does not prove no lockfile exists in the full repository; workspace-root lockfiles must be adjudicated.'],
    matchesIn(context) {
      const manifests = context.files.filter((f) => PACKAGE_MANIFEST.test(f));
      if (manifests.length === 0) return [];
      const hasLockfile = context.files.some((f) => LOCKFILE.test(f));
      if (hasLockfile) return [];
      return manifests.map((file) => ({ file, line: 1, snippet: file }));
    },
  },
  {
    id: 'supply-chain.lockfile.integrity-hash-absent',
    claim: 'A dependency lockfile is present without integrity/hash fields for its resolved packages, so a tampered registry-hosted package would not be detected at install time.',
    severityHint: 'medium',
    authority: 'package-manager',
    executionPath: 'npm/yarn/pnpm install → lockfile resolution → unverified package fetch',
    effectKind: 'integrity-impact', effectAction: 'accept-unverified-package', effectScope: 'dependency-resolution',
    chainRoles: ['enabler'],
    uncertainty: ['Lockfile format variation means an absent literal "integrity" token is a lexical heuristic, not a parsed guarantee; the actual lockfile schema must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!LOCKFILE.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        if (hasIntegrityCoveredLockfile(context, file)) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'supply-chain.package-script.install-time-execution',
    claim: 'A package lifecycle script (preinstall/install/postinstall) downloads and executes remote content during dependency installation.',
    severityHint: 'high',
    authority: 'package-manager',
    executionPath: 'npm install → postinstall → shell',
    effectKind: 'code-execution', effectAction: 'execute', effectScope: 'developer-machine-or-ci-install',
    chainRoles: ['starter', 'impact'],
    executionChain: true,
    uncertainty: ['A remote-fetch-pipe-shell lifecycle script is not automatically compromised; its actual execution and payload can only be proven by independent sandboxed execution.'],
    matchesIn(context) {
      if (ignoreScriptsConfigured(context)) return [];
      const pattern = /"(?:preinstall|install|postinstall)"\s*:\s*"[^"\n]*(?:curl|wget)[^"\n]*\|\s*(?:sh|bash)[^"\n]*"/gi;
      return regexRule(pattern, { fileGuard: PACKAGE_MANIFEST })(context);
    },
  },
  {
    id: 'supply-chain.plugin.unpinned-remote-plugin',
    claim: 'A build/lint plugin or extension is loaded from a remote URL rather than a pinned, registry-resolved package, so its content bypasses lockfile integrity checks.',
    severityHint: 'medium',
    authority: 'build-toolchain',
    executionPath: 'build/lint config → remote plugin URL → loaded into toolchain process',
    effectKind: 'code-execution', effectAction: 'load-plugin', effectScope: 'build-toolchain',
    chainRoles: ['enabler'],
    uncertainty: ['A remote plugin reference is not automatically malicious; whether it is actually loaded and what it can reach must be adjudicated.'],
    matchesIn: regexRule(/"(?:plugins|extends)"\s*:\s*\[?[^\]}\n]*https?:\/\/[^"\n]+/gi),
  },
  {
    id: 'supply-chain.artifact.committed-build-output',
    claim: 'A build output directory is committed to the repository, so consumers may trust a prebuilt artifact that was not produced by the pinned, auditable build from source.',
    severityHint: 'medium',
    authority: 'repository-content',
    executionPath: 'committed build artifact → consumed directly → bypasses build-from-source verification',
    effectKind: 'integrity-impact', effectAction: 'substitute-artifact', effectScope: 'build-output',
    chainRoles: ['enabler'],
    uncertainty: ['A committed build-output path is not automatically malicious; whether it is actually consumed instead of a fresh build must be adjudicated.'],
    matchesIn(context) {
      return context.files.filter((f) => BUILD_OUTPUT_PATH.test(f)).map((file) => ({ file, line: 1, snippet: file }));
    },
  },
  {
    id: 'supply-chain.cache.poisoning-surface',
    claim: 'A CI build/dependency cache key is derived from untrusted pull-request or fork-controlled context, letting an external contributor poison a cache entry consumed by a later, more privileged run.',
    severityHint: 'high',
    authority: 'ci-automation-identity',
    executionPath: 'fork PR → cache key control → poisoned cache entry → consumed by later privileged workflow run',
    effectKind: 'integrity-impact', effectAction: 'poison-cache', effectScope: 'ci-cache',
    chainRoles: ['starter', 'pivot'],
    environment: 'ci',
    uncertainty: ['A PR-derived cache key is not automatically exploitable; whether the poisoned entry is later restored into a privileged job must be adjudicated.'],
    matchesIn: regexRule(
      /cache[\s\S]{0,200}?key[\s\S]{0,80}?(?:github\.head_ref|github\.event\.pull_request|pull_request)/i,
      { fileGuard: WORKFLOW_FILE },
    ),
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `supply-chain-${rule.id}`,
        semanticFeatures: ['repository-controlled-configuration', rule.id],
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
          description: `Enumerate alternate configuration and package entrypoints for ${rule.id}.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.supply-chain',
  version: '1.0.0',
  candidateClass: 'supply-chain',
  description: 'Dependency/lockfile integrity, package install scripts, plugin trust, committed build output, and artifact/cache poisoning.',
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
          candidateClass: 'supply-chain',
          claim: rule.claim,
          severityHint: rule.severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['read-repository', 'control-repository-content'],
          preconditions: [hostilePrecondition(match.file, rule.environment)],
          effects: [{
            kind: rule.effectKind,
            subject: 'actor:repository-content',
            action: rule.effectAction,
            object: artifact?.id ?? null,
            scope: rule.effectScope,
            environment: rule.environment ?? 'any',
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
