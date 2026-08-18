// Observability & forensics security pack: sensitive data leaking into
// error output, missing security events (auth success/failure, privilege
// change, data export), and log injection.
//
// No network imports, no live probing — every observation is derived from
// source text already loaded into the frozen denominator (context.readFile)
// plus, when available, upstream logging evidence surfaced on
// context.projection.auditFacts (auditFacts.loggingTraces). A recorded
// logging trace for the matching event type suppresses a "missing event"
// candidate the same way an observed control suppresses an injection
// candidate elsewhere in this codebase.
//
// Every "missing security event" rule requires only a structured event
// record with non-sensitive identifiers (actor id, action, timestamp,
// resource id, outcome) — never credentials, tokens, PII, or a full request
// body. That constraint is asserted by this pack's test suite.

import { digest } from '../contracts.mjs';

function artifactFor(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function sliceAround(text, index, matchLength, before, after) {
  const start = Math.max(0, index - before);
  const end = Math.min(text.length, index + matchLength + after);
  return text.slice(start, end);
}

function testAround(pattern, text, index, matchLength, before = 0, after = 300) {
  if (!pattern) return false;
  return pattern.test(sliceAround(text, index, matchLength, before, after));
}

// Optional upstream logging telemetry: a recorded observation that a given
// eventType is actually emitted somewhere in the running system for this
// file. Absence never blocks a claim; presence suppresses it, mirroring how
// injection.mjs treats a recorded taint trace.
function loggingTraceFor(context, file, eventType) {
  const traces = context.projection?.auditFacts?.loggingTraces ?? [];
  return traces.find((t) => t.file === file && t.eventType === eventType) ?? null;
}

const NON_SENSITIVE_EVENT_DISCLAIMER = 'The required control is a structured security-event record containing only non-sensitive identifiers (actor id, action, timestamp, resource id, outcome); this claim never requires logging credentials, tokens, PII, or a full request body.';

function baseObservation({
  ruleId, candidateClass, claim, severityHint, expectedEvent,
  sources, sinks, attackerCapabilities, preconditions, effects, chainRoles, evidenceRefs, detectorMetadata, uncertainty,
}) {
  if (!attackerCapabilities?.length) throw new TypeError(`${ruleId}: attackerCapabilities must be non-empty`);
  return {
    ruleId,
    candidateClass,
    claim,
    severityHint,
    sources,
    sinks,
    attackerCapabilities,
    preconditions,
    effects,
    assets: [],
    trustBoundaryCrossings: [],
    requiredControls: [],
    observedControls: [],
    chainRoles,
    evidenceRefs,
    detectorMetadata: { ...detectorMetadata, ...(expectedEvent ? { expectedEvent } : {}) },
    uncertainty,
  };
}

function lexicalVariantStrategy(rootCauseClass, semanticFeatures, findMatches) {
  return {
    rootCause() {
      return { class: rootCauseClass, semanticFeatures };
    },
    enumerate(context) {
      const matches = findMatches(context);
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rootCauseClass}-search`, kind: 'lexical-fallback',
          description: `Enumerate every equivalent ${rootCauseClass} occurrence or event consumer across the denominator.`,
          queryDigest: digest(rootCauseClass), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

const CANDIDATE_CLASS = 'observability-forensics';

// --- patterns -----------------------------------------------------------

const ERROR_LEAK = /res\.(?:json|send)\(\s*\{[^}]*(?:stack\s*:\s*err(?:or)?\.stack|error\s*:\s*err(?:or)?\.stack)[^}]*\}\s*\)|res\.(?:json|send)\(\s*err(?:or)?\.stack\s*\)|res\.(?:json|send)\(\s*\{[^}]*(?:password|token|apiKey|secret|connectionString)[^}]*\}\s*\)/g;
const ERROR_LEAK_GUARD = /NODE_ENV\s*!==?\s*['"]production['"]|isDev\b|isDevelopment\b|redactError\(|sanitizeError\(/i;

const AUTH_SUCCESS_MARKER = /req\.session\.user\s*=|res\.cookie\(\s*['"](?:session|token|jwt)['"]|generateToken\(|issueToken\(|signJwt\(/g;
const AUTH_FAILURE_MARKER = /res\.status\(401\)\.(?:json|send)\(/g;
const PRIVILEGE_CHANGE_MARKER = /\.role\s*=\s*['"]\w+['"]|grantRole\(|setPermissions\(|updateRole\(/g;
const DATA_EXPORT_MARKER = /res\.download\(|res\.attachment\(|exportToCsv\(|exportData\(|streamExport\(/g;

const SECURITY_EVENT_LOG_MARKER = /auditLog\(|securityEvent\(|logger\.(?:info|warn)\(\s*['"](?:auth|privilege|data)\./i;

const LOG_INJECTION = /(?:logger|console)\.(?:info|warn|error|log)\(\s*(?:`[^`\n]*\$\{[^}]*(?:req|request)\.(?:body|query|params)[^}]*\}[^`\n]*`|"[^"\n]*"\s*\+\s*(?:req|request)\.(?:body|query|params)|'[^'\n]*'\s*\+\s*(?:req|request)\.(?:body|query|params))/g;
const LOG_INJECTION_SUPPRESS = /sanitizeLog\(|stripControlChars\(|encodeURIComponent\(/i;

function missingEventRule(context, { ruleId, marker, eventType, claim, severityHint, effectScope }, observations) {
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    const artifact = artifactFor(context, file);
    const evidenceRefs = artifact?.evidenceRefs ?? [];
    if (evidenceRefs.length === 0) continue;
    marker.lastIndex = 0;
    let match;
    while ((match = marker.exec(text)) !== null) {
      if (loggingTraceFor(context, file, eventType)) continue;
      if (testAround(SECURITY_EVENT_LOG_MARKER, text, match.index, match[0].length, 200, 300)) continue;
      observations.push(baseObservation({
        ruleId,
        candidateClass: CANDIDATE_CLASS,
        claim,
        severityHint,
        expectedEvent: eventType,
        sources: [artifact.id], sinks: [artifact.id],
        attackerCapabilities: ['perform-observed-action-without-detection'],
        preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'perform-action', environment: 'application' }],
        effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'evade-detection', object: artifact.id, scope: effectScope, environment: 'application', tenant: null }],
        chainRoles: ['enabler'],
        evidenceRefs,
        detectorMetadata: { file, line: lineOf(text, match.index), observedCodePath: match[0].slice(0, 80) },
        uncertainty: [
          'A security-event logger registered globally or in a shared middleware not visible in this file cannot be ruled out.',
          NON_SENSITIVE_EVENT_DISCLAIMER,
        ],
      }));
    }
  }
}

export default Object.freeze({
  id: 'security.observability-forensics',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Observability and forensic readiness: sensitive data in error output, missing auth/privilege/export security events, and log injection.',
  rules: [
    { id: 'observability.error.sensitive-data-in-output' },
    { id: 'observability.events.missing-auth-success' },
    { id: 'observability.events.missing-auth-failure' },
    { id: 'observability.events.missing-privilege-change' },
    { id: 'observability.events.missing-data-export' },
    { id: 'observability.log.injection' },
  ],

  analyze(context) {
    const observations = [];

    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = artifactFor(context, file);
      const evidenceRefs = artifact?.evidenceRefs ?? [];
      if (evidenceRefs.length === 0) continue;

      // observability.error.sensitive-data-in-output
      ERROR_LEAK.lastIndex = 0;
      let leakMatch;
      while ((leakMatch = ERROR_LEAK.exec(text)) !== null) {
        if (testAround(ERROR_LEAK_GUARD, text, leakMatch.index, leakMatch[0].length, 150, 50)) continue;
        observations.push(baseObservation({
          ruleId: 'observability.error.sensitive-data-in-output',
          candidateClass: CANDIDATE_CLASS,
          claim: 'An error/exception response includes a raw stack trace or a sensitive-looking field with no visible redaction guard.',
          severityHint: 'medium',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['trigger-error-condition'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'trigger-error-condition', environment: 'application' }],
          effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'error-response-body', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, leakMatch.index), matchDigest: digest(leakMatch[0]) },
          uncertainty: ['Whether the leaked detail actually contains exploitable internals (paths, connection strings, credentials) versus a benign message requires adjudication of the error content.'],
        }));
      }

      // observability.log.injection
      LOG_INJECTION.lastIndex = 0;
      let injMatch;
      while ((injMatch = LOG_INJECTION.exec(text)) !== null) {
        if (testAround(LOG_INJECTION_SUPPRESS, text, injMatch.index, injMatch[0].length, 0, 200)) continue;
        observations.push(baseObservation({
          ruleId: 'observability.log.injection',
          candidateClass: CANDIDATE_CLASS,
          claim: 'Request-derived data is concatenated directly into a log statement with no visible sanitization, allowing forged log entries (log injection / log forging).',
          severityHint: 'medium',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['control-request-input'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'integrity-impact', subject: 'actor:external', action: 'inject', object: artifact.id, scope: 'log-stream', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, injMatch.index), matchDigest: digest(injMatch[0]) },
          uncertainty: ['Impact depends on how the log stream is consumed downstream (raw terminal, log-injection-vulnerable dashboard, or a structured/escaped sink).'],
        }));
      }
    }

    missingEventRule(context, {
      ruleId: 'observability.events.missing-auth-success',
      marker: AUTH_SUCCESS_MARKER,
      eventType: 'auth.success',
      claim: 'A successful authentication path (session/token issuance) has no visible security-event record.',
      severityHint: 'low',
      effectScope: 'auth-success-event',
    }, observations);

    missingEventRule(context, {
      ruleId: 'observability.events.missing-auth-failure',
      marker: AUTH_FAILURE_MARKER,
      eventType: 'auth.failure',
      claim: 'A failed authentication branch (401 response) has no visible security-event record.',
      severityHint: 'low',
      effectScope: 'auth-failure-event',
    }, observations);

    missingEventRule(context, {
      ruleId: 'observability.events.missing-privilege-change',
      marker: PRIVILEGE_CHANGE_MARKER,
      eventType: 'privilege.change',
      claim: 'A role/permission mutation has no visible security-event record.',
      severityHint: 'medium',
      effectScope: 'privilege-change-event',
    }, observations);

    missingEventRule(context, {
      ruleId: 'observability.events.missing-data-export',
      marker: DATA_EXPORT_MARKER,
      eventType: 'data.export',
      claim: 'A bulk data export/download path has no visible security-event record.',
      severityHint: 'medium',
      effectScope: 'data-export-event',
    }, observations);

    return observations;
  },

  variantStrategies: {
    'observability.events.missing-auth-success': lexicalVariantStrategy(
      'auth-success-without-security-event',
      ['auth-success-code-path', 'no-security-event-log-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          AUTH_SUCCESS_MARKER.lastIndex = 0;
          let match;
          while ((match = AUTH_SUCCESS_MARKER.exec(text)) !== null) {
            if (testAround(SECURITY_EVENT_LOG_MARKER, text, match.index, match[0].length, 200, 300)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'observability.events.missing-privilege-change': lexicalVariantStrategy(
      'privilege-change-without-security-event',
      ['privilege-change-code-path', 'no-security-event-log-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          PRIVILEGE_CHANGE_MARKER.lastIndex = 0;
          let match;
          while ((match = PRIVILEGE_CHANGE_MARKER.exec(text)) !== null) {
            if (testAround(SECURITY_EVENT_LOG_MARKER, text, match.index, match[0].length, 200, 300)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'observability.events.missing-data-export': lexicalVariantStrategy(
      'data-export-without-security-event',
      ['data-export-code-path', 'no-security-event-log-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          DATA_EXPORT_MARKER.lastIndex = 0;
          let match;
          while ((match = DATA_EXPORT_MARKER.exec(text)) !== null) {
            if (testAround(SECURITY_EVENT_LOG_MARKER, text, match.index, match[0].length, 200, 300)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'observability.log.injection': lexicalVariantStrategy(
      'log-injection-unsanitized-request-input',
      ['request-derived-log-concatenation', 'no-sanitization-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          LOG_INJECTION.lastIndex = 0;
          let match;
          while ((match = LOG_INJECTION.exec(text)) !== null) {
            if (testAround(LOG_INJECTION_SUPPRESS, text, match.index, match[0].length, 0, 200)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
  },
});
