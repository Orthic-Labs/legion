// Repository-footprint security pack (B7-018, rewrite of the Security
// Appendix §54.8 placeholder): sensitive files committed and the
// malicious-repository boundary — repository content is modeled as
// hostile evidence, never as trusted configuration, because the person
// who committed a given file is not assumed to be the same party
// consuming this audit's findings.
//
// Every rule is a lexical (pattern-only) detector over repository text and
// file paths already present in the frozen denominator. It never opens a
// real filesystem path, never contacts a network endpoint, never calls a
// model, and never certifies a finding — it only ever emits UNADJUDICATED
// candidates via the sealed candidate-engine. Findings that name an
// auto-loaded tool/config path always carry `detectorMetadata.authority`
// and `detectorMetadata.executionPath`.

import { digest } from '../contracts.mjs';

const AUTO_LOADED_HOOK_PATH = /(^|\/)(\.git\/hooks\/[^/.][^/]*|\.husky\/[^/.][^/]*)$/;
const DEVCONTAINER_PATH = /(^|\/)\.devcontainer\/devcontainer\.json$/i;
const SENSITIVE_FILE_PATH = /(^|\/)(\.env(\.[\w-]+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|credentials\.json|\.aws\/credentials|\.kube\/config)$/i;
const INTERNAL_ENDPOINT_PATTERN = /https?:\/\/(?:[\w-]+\.)*internal\b|https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}|https?:\/\/192\.168\.\d{1,3}\.\d{1,3}|https?:\/\/localhost:\d{2,5}\/(?:admin|debug|actuator|internal)/i;

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

// The repository is never a trusted configuration source: any candidate
// derived from committed content states explicitly that an external party
// may read (and, for auto-loaded paths, may have authored) this file.
function hostilePrecondition(file) {
  return {
    kind: 'attacker-position',
    subject: 'actor:repository-content',
    action: 'control-repository-content',
    object: file,
    scope: null,
    environment: 'any',
    tenant: null,
  };
}

// Handles both global and non-global patterns correctly: a non-global
// RegExp's `lastIndex` never advances, so driving it through an exec loop
// would never terminate. A non-global pattern therefore contributes at most
// one match per file.
function regexMatches(pattern, text) {
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

const RULES = [
  {
    id: 'footprint.sourcemap-included',
    claim: 'A source map with original source content is present in the repository, disclosing unminified source and internal file layout to anyone who can read the built output.',
    severityHint: 'medium',
    authority: 'repository-content',
    executionPath: 'committed source map → readable by any repository/artifact consumer → original source disclosed',
    effectKind: 'confidentiality-impact', effectAction: 'disclose', effectScope: 'source-content',
    chainRoles: ['enabler'],
    uncertainty: ['Source maps may be stripped at release time; whether this file ships in the distributed artifact must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (!/\.map$/.test(file)) continue;
        const text = context.readFile(file) ?? '';
        if (!/sourceMappingURL|"sources"\s*:/.test(text)) continue;
        out.push({ file, line: 1, snippet: file });
      }
      return out;
    },
  },
  {
    id: 'footprint.local-db-committed',
    claim: 'A local database or backup file is committed to the repository.',
    severityHint: 'high',
    authority: 'repository-content',
    executionPath: 'committed database/backup file → readable by any repository consumer → local data disclosed',
    effectKind: 'data-access', effectAction: 'read', effectScope: 'local-data',
    chainRoles: ['starter', 'impact'],
    uncertainty: ['The database may contain no sensitive data; its actual contents must be adjudicated.'],
    matchesIn(context) {
      return context.files
        .filter((f) => /\.(sqlite|db|sqlite3|dump|bak)$/.test(f))
        .map((file) => ({ file, line: 1, snippet: file }));
    },
  },
  {
    id: 'footprint.internal-endpoint-exposed',
    claim: 'A committed file references an internal-only hostname, private IP address, or an unauthenticated-looking debug/admin endpoint.',
    severityHint: 'medium',
    authority: 'repository-content',
    executionPath: 'committed config/doc/example → internal endpoint reference → topology or debug surface disclosed',
    effectKind: 'knowledge', effectAction: 'disclose', effectScope: 'internal-topology',
    chainRoles: ['enabler'],
    uncertainty: ['An internal-looking endpoint reference in committed content is not automatically reachable or currently valid; its live reachability must be adjudicated.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        for (const match of regexMatches(INTERNAL_ENDPOINT_PATTERN, text)) {
          out.push({ file, line: lineOf(text, match.index), snippet: match[0] });
        }
      }
      return out;
    },
  },
  {
    id: 'footprint.sensitive-file-committed',
    claim: 'A file with a sensitive-material name/path (private key, .env, cloud/kube credentials) is committed to the repository.',
    severityHint: 'high',
    authority: 'repository-content',
    executionPath: 'committed sensitive-path file → readable by any repository consumer → credential/config material disclosed',
    effectKind: 'credential-possession', effectAction: 'possess-committed-material', effectScope: 'repository-content',
    chainRoles: ['starter', 'impact'],
    uncertainty: ['A sensitive-shaped filename/path does not prove the file contains live material; its actual content and whether it is a placeholder/example must be adjudicated.'],
    matchesIn(context) {
      return context.files
        .filter((f) => SENSITIVE_FILE_PATH.test(f))
        .map((file) => ({ file, line: 1, snippet: file }));
    },
  },
  {
    id: 'footprint.malicious-repository-boundary',
    claim: 'A repository-controlled path is auto-loaded and executed by a local tool or dev-container without an explicit human review step, so a malicious contributor\'s commit would run automatically for anyone who checks it out.',
    severityHint: 'high',
    authority: 'repository-content',
    executionPath: 'malicious commit → auto-loaded hook/devcontainer path → executed without explicit review on checkout',
    effectKind: 'code-execution', effectAction: 'execute-on-checkout', effectScope: 'developer-machine',
    chainRoles: ['starter', 'impact'],
    executionChain: true,
    environment: 'developer-machine',
    uncertainty: ['An auto-loaded path is not automatically malicious; whether its content is actually hostile can only be proven by independent adjudication, not by this pattern match.'],
    matchesIn(context) {
      const out = [];
      for (const file of context.files) {
        if (AUTO_LOADED_HOOK_PATH.test(file)) {
          out.push({ file, line: 1, snippet: file });
          continue;
        }
        if (DEVCONTAINER_PATH.test(file)) {
          const text = context.readFile(file) ?? '';
          if (/postCreateCommand|postStartCommand|onCreateCommand/.test(text)) {
            out.push({ file, line: 1, snippet: file });
          }
        }
      }
      return out;
    },
  },
];

function sandboxGate(context) {
  const hasReceipt = Boolean(context.projection?.auditFacts?.sandboxReceipt);
  return {
    note: hasReceipt
      ? 'An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim.'
      : 'BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this auto-loaded path actually executes remains unproven pending one.',
  };
}

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `repository-footprint-${rule.id}`,
        semanticFeatures: ['repository-content-as-hostile-evidence', rule.id],
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
          description: `Enumerate alternate committed-content entrypoints for ${rule.id}.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.repository-footprint',
  version: '1.0.0',
  candidateClass: 'repository-footprint',
  description: 'Sensitive files committed and the malicious-repository boundary; repository content is hostile evidence.',
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
          candidateClass: 'repository-footprint',
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
