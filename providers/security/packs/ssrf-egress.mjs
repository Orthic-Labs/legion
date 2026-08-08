// SSRF / egress security pack: request-controlled outbound destinations,
// unbounded redirect-following, and DNS-rebinding preconditions. Every rule
// is a lexical (pattern-only) detector: it never issues a network request,
// never resolves a hostname, never calls a model, and never certifies a
// finding. It only ever emits UNADJUDICATED candidates via the sealed
// candidate-engine.
//
// The egress *environment* (network topology, egress allowlist, deployment
// context) is frequently invisible from source alone. When no allowlist
// control and no deployment/egress-allowlist evidence
// (context.projection.auditFacts.deployment /
// context.projection.auditFacts.egressAllowlist) is available, every
// candidate here is capped at `medium` and carries an explicit
// "environment unknown" uncertainty entry rather than being asserted at its
// uncapped severity. When an allowlist IS observed — either as a model
// control entity or via auditFacts.egressAllowlist — it is modeled as
// `observedControls`, never silently assumed safe.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function findRelatedControl(context, artifactId, controlTypes) {
  if (artifactId) {
    for (const rel of context.relationsTo(artifactId)) {
      if (rel.kind !== 'protects') continue;
      const control = context.entityById.get(rel.from);
      if (control?.kind === 'control' && controlTypes.includes(control.attributes?.controlType)) return control;
    }
  }
  return context.model.entities.find((e) => e.kind === 'control' && controlTypes.includes(e.attributes?.controlType)) ?? null;
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, matchLength, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text.slice(start, end);
}

function testWindow(pattern, text, index, matchLength, radius) {
  if (!pattern) return false;
  return pattern.test(windowAround(text, index, matchLength, radius));
}

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function capSeverity(base, cap) {
  if (!cap) return base;
  return SEVERITY_RANK[base] <= SEVERITY_RANK[cap] ? base : cap;
}

// Egress environment evidence: a declared allowlist or deployment fact from
// the audit projection, per SNIP-18-style upstream evidence. Absent either,
// the environment stays unproven.
function egressEnvironmentEvidence(context) {
  const deployment = context.projection?.auditFacts?.deployment ?? null;
  const egressAllowlist = context.projection?.auditFacts?.egressAllowlist ?? null;
  return { deployment, egressAllowlist, hasEvidence: Boolean(deployment) || Boolean(egressAllowlist) };
}

function environmentGate(context, controlSignal) {
  const { hasEvidence } = egressEnvironmentEvidence(context);
  if (hasEvidence || controlSignal) return { cap: null, uncertainty: [] };
  return {
    cap: 'medium',
    uncertainty: ['Egress destination environment (network topology, egress allowlist, deployment context) is unknown; this claim is bounded to medium severity until that evidence is available.'],
  };
}

const CANDIDATE_CLASS = 'ssrf-egress';
const EGRESS_CALLEES = 'fetch|axios(?:\\.\\w+)?|request|http\\.request|https\\.request|http\\.get|https\\.get|urlopen|got|requests\\.(?:get|post|put|delete)';
const DNS_PINNING_MARKER = /dns\.lookup\s*\(|dnsCache|ssrf-req-filter|safeLookup|pinDns|resolve4Safe|blockPrivateIp|isPrivateIp/i;

const RULES = [
  {
    id: 'ssrf.request-controlled-destination',
    pattern: new RegExp(`\\b(${EGRESS_CALLEES})\\s*\\(\\s*([^()\\n]*\\b(?:request|req)\\.(?:query|body|params)(?:\\.[\\w]+)?\\b[^()\\n]*)\\)`, 'gi'),
    sinkApiOf: (m) => m[1],
    sourceExprOf: (m) => m[2].trim(),
    claim: 'Request-controlled data may determine the destination of a server-side outbound request (SSRF).',
    severityHint: 'high',
    attackerCapabilities: ['control-request-input'],
    preconditionAction: 'supply-destination',
    environment: 'network',
    effectKind: 'network-reachability', effectAction: 'reach', effectScope: 'server-side-egress',
    chainRoles: ['starter', 'pivot'],
    downgrade: {
      controlTypes: ['egress-allowlist', 'url-allowlist', 'ssrf-guard'],
      severityHint: 'low',
      lexicalPattern: /\b(?:isAllowedHost|allowlist|urlAllowList|ssrf-req-filter|validateUrl|isPrivateIp|blockPrivateIp)\b/i,
      lexicalNote: 'An allowlist/SSRF-guard call is present near the outbound request; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['A request-controlled URL argument is not automatically SSRF; internal network topology and allowlisting must be adjudicated.'],
  },
  {
    id: 'ssrf.redirect-following-unbounded',
    pattern: /\b(redirect\s*:\s*['"]follow['"]|maxRedirects\s*:\s*[1-9]\d*|followRedirects\s*:\s*true)\b/g,
    sinkApiOf: () => 'http-client-redirect-config',
    sourceExprOf: (m) => m[1],
    claim: 'An HTTP client is configured to follow redirects without a hop cap, allowing a server-side request to be redirected to an internal or unexpected destination after initial validation.',
    severityHint: 'medium',
    attackerCapabilities: ['control-request-input', 'control-redirect-target'],
    preconditionAction: 'supply-destination',
    environment: 'network',
    effectKind: 'network-reachability', effectAction: 'redirect', effectScope: 'server-side-egress-redirect',
    chainRoles: ['enabler', 'pivot'],
    downgrade: {
      controlTypes: ['egress-allowlist', 'url-allowlist', 'ssrf-guard'],
      severityHint: 'low',
      lexicalPattern: /\b(?:isAllowedHost|allowlist|urlAllowList|ssrf-req-filter|validateUrl|revalidateRedirect)\b/i,
      lexicalNote: 'An allowlist/SSRF-guard call is present near the redirect configuration; treated as a mitigating signal pending adjudication.',
      radius: 300,
    },
    uncertainty: ['Redirect-following alone is not automatically exploitable; whether the initial destination is attacker-influenced and whether redirect targets are re-validated at each hop must be adjudicated.'],
  },
];

function analyze(context) {
  const observations = [];
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    const artifact = findArtifact(context, file);

    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(text)) !== null) {
        if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }

        let severityHint = rule.severityHint;
        let observedControls = [];
        let controlObserved = null;
        let controlSignal = false;
        const uncertainty = [...rule.uncertainty];

        const control = findRelatedControl(context, artifact?.id, rule.downgrade.controlTypes);
        if (control) {
          severityHint = rule.downgrade.severityHint;
          observedControls = [control.id];
          controlObserved = control.name;
          controlSignal = true;
          uncertainty.push(`Observed ${control.attributes?.controlType ?? 'mitigating'} control (${control.name}) on this path; downgraded pending adjudication of coverage completeness.`);
        } else if (testWindow(rule.downgrade.lexicalPattern, text, match.index, match[0].length, rule.downgrade.radius)) {
          severityHint = rule.downgrade.severityHint;
          controlObserved = 'lexical-signal';
          controlSignal = true;
          uncertainty.push(rule.downgrade.lexicalNote);
        } else {
          const { egressAllowlist } = egressEnvironmentEvidence(context);
          if (egressAllowlist) {
            controlSignal = true;
            controlObserved = 'auditFacts.egressAllowlist';
            uncertainty.push('An egress allowlist was observed in upstream deployment facts; whether this specific destination is covered must still be adjudicated.');
          }
        }

        const gate = environmentGate(context, controlSignal);
        if (gate.cap) {
          severityHint = capSeverity(severityHint, gate.cap);
          uncertainty.push(...gate.uncertainty);
        }

        observations.push({
          ruleId: rule.id,
          candidateClass: CANDIDATE_CLASS,
          claim: rule.claim,
          severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: rule.attackerCapabilities,
          preconditions: [{
            kind: 'attacker-position', subject: 'actor:external', action: rule.preconditionAction,
            scope: null, environment: rule.environment, tenant: null,
          }],
          effects: [{
            kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
            object: artifact?.id ?? null, scope: rule.effectScope, environment: rule.environment, tenant: null,
          }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls,
          chainRoles: rule.chainRoles,
          evidenceRefs: artifact?.evidenceRefs ?? [],
          detectorMetadata: {
            file,
            line: lineOf(text, match.index),
            sourceExpr: rule.sourceExprOf(match),
            sinkApi: rule.sinkApiOf(match),
            controlObserved,
            matchDigest: digest(match[0]),
          },
          uncertainty,
        });
      }
    }

    // ssrf.dns-rebinding-unprotected: a whole-file structural absence check —
    // an egress call exists but no DNS-pinning / post-resolution IP
    // revalidation marker is present anywhere in the file.
    EGRESS_SINK_SCAN.lastIndex = 0;
    const egressMatch = EGRESS_SINK_SCAN.exec(text);
    if (egressMatch && !DNS_PINNING_MARKER.test(text)) {
      let severityHint = 'medium';
      const uncertainty = [
        'DNS-rebinding requires the attacker to control a DNS record that resolves to a different (internal) address between validation and the actual connection; whether the destination host is attacker-controlled must be adjudicated.',
      ];
      const gate = environmentGate(context, false);
      if (gate.cap) {
        severityHint = capSeverity(severityHint, gate.cap);
        uncertainty.push(...gate.uncertainty);
      }
      observations.push({
        ruleId: 'ssrf.dns-rebinding-unprotected',
        candidateClass: CANDIDATE_CLASS,
        claim: 'A server-side outbound request has no visible DNS-pinning or post-resolution IP revalidation, leaving the destination vulnerable to DNS-rebinding between validation and connection.',
        severityHint,
        sources: artifact ? [artifact.id] : [],
        sinks: artifact ? [artifact.id] : [],
        attackerCapabilities: ['control-dns-response', 'control-request-input'],
        preconditions: [{
          kind: 'attacker-position', subject: 'actor:external', action: 'control-dns-resolution',
          scope: null, environment: 'network', tenant: null,
        }],
        effects: [{
          kind: 'network-reachability', subject: 'actor:external', action: 'rebind',
          object: artifact?.id ?? null, scope: 'server-side-egress-dns', environment: 'network', tenant: null,
        }],
        assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
        chainRoles: ['starter', 'pivot'],
        evidenceRefs: artifact?.evidenceRefs ?? [],
        detectorMetadata: {
          file,
          line: lineOf(text, egressMatch.index),
          sourceExpr: 'resolved-egress-hostname',
          sinkApi: egressMatch[1],
          controlObserved: null,
          matchDigest: digest(egressMatch[0]),
        },
        uncertainty,
      });
    }
  }
  return observations;
}

const EGRESS_SINK_SCAN = new RegExp(`\\b(${EGRESS_CALLEES})\\s*\\(`, 'i');

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-unmitigated`,
        semanticFeatures: ['egress-destination', rule.id, candidate.detectorMetadata?.sinkApi ?? rule.id],
      };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
          matches.push({
            file,
            line: lineOf(text, match.index),
            semanticFingerprint: digest({ ruleId: rule.id, file, snippet: match[0] }),
            disposition: 'CONFIRMED',
          });
        }
      }
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.id} occurrence across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

function dnsRebindingVariantStrategy() {
  return {
    rootCause() {
      return { class: 'dns-rebinding-unmitigated', semanticFeatures: ['egress-destination', 'no-dns-pinning'] };
    },
    enumerate(context) {
      const matches = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        EGRESS_SINK_SCAN.lastIndex = 0;
        const egressMatch = EGRESS_SINK_SCAN.exec(text);
        if (egressMatch && !DNS_PINNING_MARKER.test(text)) {
          matches.push({
            file, line: lineOf(text, egressMatch.index),
            semanticFingerprint: digest({ ruleId: 'ssrf.dns-rebinding-unprotected', file }),
            disposition: 'CONFIRMED',
          });
        }
      }
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: 'ssrf.dns-rebinding-unprotected-search', kind: 'lexical-fallback',
          description: 'Enumerate every egress call missing a DNS-pinning marker across the denominator.',
          queryDigest: digest('ssrf.dns-rebinding-unprotected'), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.ssrf-egress',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'SSRF, redirect-following, DNS-rebinding, and egress-destination/allowlist controls.',
  rules: [...RULES.map((rule) => ({ id: rule.id })), { id: 'ssrf.dns-rebinding-unprotected' }],
  analyze,
  variantStrategies: {
    ...Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
    'ssrf.dns-rebinding-unprotected': dnsRebindingVariantStrategy(),
  },
});
