// Browser-facing security pack: CSRF, CORS, cookie SameSite, clickjacking,
// open redirect, OAuth redirect-URI handling, and Content-Security-Policy.
// No network imports, no live probing — every observation is derived from
// source text already loaded into the frozen denominator (context.readFile)
// plus, when available, upstream runtime-header / deployment evidence
// (B5-021) surfaced on context.projection.auditFacts. That evidence is
// optional: every rule that depends on "what is actually served" degrades to
// a capped, explicitly-flagged assumption when it is absent, and never fails
// because it is missing.

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function capSeverity(base, cap) {
  if (!cap) return base;
  return SEVERITY_RANK[base] <= SEVERITY_RANK[cap] ? base : cap;
}

function artifactFor(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function repoWideEvidenceRefs(context) {
  const refs = new Set();
  for (const file of context.files) {
    const artifact = artifactFor(context, file);
    for (const ref of artifact?.evidenceRefs ?? []) refs.add(ref);
  }
  return [...refs].sort();
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function deploymentAssumptionUncertainty(subject) {
  return `Deployment assumption: no runtime header or deployment evidence was available for ${subject}; `
    + 'this claim assumes the observed source configuration is what is actually served, but a reverse '
    + 'proxy, CDN, load balancer, or platform default could add, strip, or override it at runtime.';
}

function runtimeHeaderSnapshot(context) {
  const headers = context.projection?.auditFacts?.runtimeHeaders?.headers;
  return headers && typeof headers === 'object' ? headers : null;
}

function runtimeHeaderCompliance(context, headerKey, isCompliant) {
  const snapshot = runtimeHeaderSnapshot(context);
  if (!snapshot || !Object.prototype.hasOwnProperty.call(snapshot, headerKey)) return null;
  return isCompliant(snapshot[headerKey]);
}

// Full disagreement-aware evaluator for whole-repository boolean-state
// claims ("is this header ever set correctly across the denominator?").
// Returns null when the claim is clean (nothing to emit), otherwise the
// modifiers to apply to the observation.
function evaluateDeploymentAwareClaim({ subject, sourceCompliant, runtimeCompliant, compliantLabel = 'present', nonCompliantLabel = 'absent' }) {
  if (runtimeCompliant === null || runtimeCompliant === undefined) {
    if (sourceCompliant) return null;
    return {
      severityCap: 'medium',
      uncertainty: [deploymentAssumptionUncertainty(subject)],
      deploymentAssumption: { assumption: 'source-config-reflects-served-state', subject },
      disagreement: null,
    };
  }
  if (sourceCompliant === runtimeCompliant) {
    if (runtimeCompliant) return null;
    return { severityCap: null, uncertainty: [], deploymentAssumption: null, disagreement: null };
  }
  return {
    severityCap: 'medium',
    uncertainty: [`Source configuration and observed runtime evidence disagree for ${subject}; both are recorded rather than one being treated as authoritative.`],
    deploymentAssumption: null,
    disagreement: {
      subject,
      sourceValue: sourceCompliant ? compliantLabel : nonCompliantLabel,
      runtimeValue: runtimeCompliant ? compliantLabel : nonCompliantLabel,
    },
  };
}

// Lighter gate for per-occurrence code-level findings: only caps severity and
// adds a deployment-assumption uncertainty entry when no runtime/deployment
// evidence exists at all; does not attempt disagreement detection.
function deploymentGate(context, subject) {
  const hasEvidence = Boolean(runtimeHeaderSnapshot(context)) || Boolean(context.projection?.auditFacts?.deployment);
  if (hasEvidence) return { severityCap: null, uncertainty: [], deploymentAssumption: null };
  return {
    severityCap: 'medium',
    uncertainty: [deploymentAssumptionUncertainty(subject)],
    deploymentAssumption: { assumption: 'source-config-reflects-served-state', subject },
  };
}

function baseObservation({ ruleId, candidateClass, claim, severityHint, primitiveClass, sources, sinks, attackerCapabilities, preconditions, effects, chainRoles, evidenceRefs, detectorMetadata, uncertainty }) {
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
    detectorMetadata: { ...detectorMetadata, primitiveClass },
    uncertainty,
  };
}

const CANDIDATE_CLASS = 'browser-client';

const CSRF_MARKER = /csrf|csurf|xsrf|_csrf|antiforgery/i;
const COOKIE_SESSION_MARKER = /cookie-session|req\.session|res\.cookie|express-session/i;
const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\(\s*['"]([^'"]+)['"]/gi;

const SAMESITE_NONE_WITHOUT_SECURE = /SameSite=None(?![\s\S]{0,80}Secure)/gi;
const SESSION_COOKIE_STATEMENT = /(?:res\.cookie|Set-Cookie)[^\n]{0,40}(?:session|auth|token|jwt)[^\n]{0,150}/gi;

const CORS_WILDCARD_CREDENTIALS = /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]?\*[\s\S]{0,300}Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?(?:true|1)/gi;
const CORS_REFLECTED_ORIGIN = /Access-Control-Allow-Origin['"]?\s*[:,]\s*(?:req|request|ctx)\.(?:headers\.)?origin/gi;
const CORS_ALLOWLIST_MARKER = /allow(?:ed)?Origins?|origin\s*===|includes\(\s*origin\s*\)/i;

const FRAME_PROTECTION_MARKER = /X-Frame-Options|frame-ancestors/i;
const SERVES_HTML_MARKER = /<html|res\.render|getServerSideProps|\.ejs\b|\.hbs\b|app\.get\(\s*['"]\//i;

const OPEN_REDIRECT = /res\.redirect\(\s*(?:req|request)\.(?:query|params|body)\.[a-zA-Z_][\w]*/gi;
const REDIRECT_ALLOWLIST_MARKER = /allowedRedirects|isValidRedirect|startsWith\(\s*['"]\//i;

const OAUTH_REDIRECT_FROM_REQUEST = /redirect_uri['"]?\s*[:=]\s*(?:req|request)\.(?:query|params|body)/gi;
const OAUTH_ALLOWLIST_MARKER = /redirectUriAllowlist|exact.?match|===\s*['"]https?:\/\//i;

const CSP_MARKER = /Content-Security-Policy/i;
const CSP_UNSAFE_INLINE = /Content-Security-Policy[^\n]*unsafe-inline/gi;
const CSP_UNSAFE_EVAL = /Content-Security-Policy[^\n]*unsafe-eval/gi;
const CSP_WILDCARD_SOURCE = /Content-Security-Policy[^;\n]*(?:script-src|default-src|connect-src)[^;\n]*(?<![\w.-])\*(?![\w.-])/gi;

export default Object.freeze({
  id: 'security.browser-client',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Browser-facing surface controls: CSRF, CORS, SameSite, clickjacking, open redirect, OAuth redirect-URI, and CSP.',
  rules: [
    { id: 'csrf.state-changing-route.missing-token' },
    { id: 'csrf.samesite-none-without-secure' },
    { id: 'csrf.samesite-missing' },
    { id: 'cors.wildcard-origin-with-credentials' },
    { id: 'cors.reflected-origin-without-allowlist' },
    { id: 'clickjacking.missing-frame-protection' },
    { id: 'open-redirect.unvalidated-target' },
    { id: 'oauth.redirect-uri.unvalidated' },
    { id: 'csp.missing' },
    { id: 'csp.unsafe-inline' },
    { id: 'csp.unsafe-eval' },
    { id: 'csp.wildcard-source' },
  ],

  analyze(context) {
    const observations = [];
    const combinedText = context.files.map((file) => context.readFile(file) ?? '').join('\n');

    // --- Per-file, code-logic rules (not deployment-dependent) -----------
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = artifactFor(context, file);
      const evidenceRefs = artifact?.evidenceRefs ?? [];
      if (evidenceRefs.length === 0) continue;

      // csrf.state-changing-route.missing-token
      if (COOKIE_SESSION_MARKER.test(text) && !CSRF_MARKER.test(text)) {
        STATE_CHANGING_ROUTE.lastIndex = 0;
        let match;
        while ((match = STATE_CHANGING_ROUTE.exec(text)) !== null) {
          observations.push(baseObservation({
            ruleId: 'csrf.state-changing-route.missing-token',
            candidateClass: CANDIDATE_CLASS,
            claim: `A cookie-session-authenticated ${match[1].toUpperCase()} ${match[2]} route has no visible CSRF token check.`,
            severityHint: 'high',
            primitiveClass: 'exploitable-primitive',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['cross-origin-page-load', 'induce-victim-navigation'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'induce-cross-origin-request', environment: 'application' }],
            effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: artifact.id, scope: 'csrf-protection', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'impact'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, match.index), method: match[1].toUpperCase(), path: match[2] },
            uncertainty: ['A CSRF middleware registered globally elsewhere in the application is not visible from this file alone.'],
          }));
        }
      }

      // csrf.samesite-none-without-secure
      SAMESITE_NONE_WITHOUT_SECURE.lastIndex = 0;
      let noneMatch;
      while ((noneMatch = SAMESITE_NONE_WITHOUT_SECURE.exec(text)) !== null) {
        observations.push(baseObservation({
          ruleId: 'csrf.samesite-none-without-secure',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A cookie sets SameSite=None without a nearby Secure attribute.',
          severityHint: 'medium',
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['cross-origin-page-load'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'induce-cross-origin-request', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: artifact.id, scope: 'samesite-cookie-protection', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, noneMatch.index), cookieAttribute: 'SameSite=None' },
          uncertainty: ['Modern browsers reject SameSite=None cookies without Secure outright; impact depends on the serving browser and transport.'],
        }));
      }

      // csrf.samesite-missing
      SESSION_COOKIE_STATEMENT.lastIndex = 0;
      let cookieMatch;
      while ((cookieMatch = SESSION_COOKIE_STATEMENT.exec(text)) !== null) {
        if (/SameSite/i.test(cookieMatch[0])) continue;
        observations.push(baseObservation({
          ruleId: 'csrf.samesite-missing',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A session or auth cookie is set without any SameSite attribute.',
          severityHint: 'medium',
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['cross-origin-page-load'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'induce-cross-origin-request', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: artifact.id, scope: 'samesite-cookie-protection', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, cookieMatch.index), cookieStatement: cookieMatch[0].slice(0, 60) },
          uncertainty: ['The framework default SameSite value (if any) is not visible from this statement alone.'],
        }));
      }

      // cors.wildcard-origin-with-credentials
      CORS_WILDCARD_CREDENTIALS.lastIndex = 0;
      let corsMatch;
      while ((corsMatch = CORS_WILDCARD_CREDENTIALS.exec(text)) !== null) {
        observations.push(baseObservation({
          ruleId: 'cors.wildcard-origin-with-credentials',
          candidateClass: CANDIDATE_CLASS,
          claim: 'Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true.',
          severityHint: 'critical',
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['cross-origin-page-load'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'induce-cross-origin-request', environment: 'application' }],
          effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'cross-origin-credentialed-response', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, corsMatch.index), header: 'Access-Control-Allow-Origin + Access-Control-Allow-Credentials' },
          uncertainty: ['Browsers reject this exact header combination for credentialed requests in current CORS implementations; impact depends on client behavior.'],
        }));
      }

      // cors.reflected-origin-without-allowlist
      if (!CORS_ALLOWLIST_MARKER.test(text)) {
        CORS_REFLECTED_ORIGIN.lastIndex = 0;
        let reflectMatch;
        while ((reflectMatch = CORS_REFLECTED_ORIGIN.exec(text)) !== null) {
          observations.push(baseObservation({
            ruleId: 'cors.reflected-origin-without-allowlist',
            candidateClass: CANDIDATE_CLASS,
            claim: 'The request Origin header is reflected into Access-Control-Allow-Origin with no visible allowlist check.',
            severityHint: 'high',
            primitiveClass: 'exploitable-primitive',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['cross-origin-page-load'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'induce-cross-origin-request', environment: 'application' }],
            effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'cross-origin-credentialed-response', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'impact'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, reflectMatch.index), header: 'Access-Control-Allow-Origin' },
            uncertainty: ['An allowlist check applied before this statement is executed may exist outside the matched line.'],
          }));
        }
      }

      // open-redirect.unvalidated-target
      if (!REDIRECT_ALLOWLIST_MARKER.test(text)) {
        OPEN_REDIRECT.lastIndex = 0;
        let redirectMatch;
        while ((redirectMatch = OPEN_REDIRECT.exec(text)) !== null) {
          observations.push(baseObservation({
            ruleId: 'open-redirect.unvalidated-target',
            candidateClass: CANDIDATE_CLASS,
            claim: 'A redirect target is taken directly from request input without a visible allowlist or relative-path check.',
            severityHint: 'medium',
            primitiveClass: 'exploitable-primitive',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['craft-malicious-link'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
            effects: [{ kind: 'integrity-impact', subject: 'actor:external', action: 'redirect', object: artifact.id, scope: 'redirect-target', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'enabler'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, redirectMatch.index), config: 'res.redirect target' },
            uncertainty: ['Open redirects are typically chained with phishing or OAuth token theft; standalone impact depends on what trusts the redirecting origin.'],
          }));
        }
      }

      // oauth.redirect-uri.unvalidated
      if (!OAUTH_ALLOWLIST_MARKER.test(text)) {
        OAUTH_REDIRECT_FROM_REQUEST.lastIndex = 0;
        let oauthMatch;
        while ((oauthMatch = OAUTH_REDIRECT_FROM_REQUEST.exec(text)) !== null) {
          observations.push(baseObservation({
            ruleId: 'oauth.redirect-uri.unvalidated',
            candidateClass: CANDIDATE_CLASS,
            claim: 'An OAuth redirect_uri is built from request input with no visible exact-match allowlist.',
            severityHint: 'high',
            primitiveClass: 'exploitable-primitive',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['craft-malicious-link'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
            effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'intercept', object: artifact.id, scope: 'oauth-authorization-code', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'impact'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, oauthMatch.index), config: 'redirect_uri' },
            uncertainty: ['The OAuth provider may independently enforce a registered redirect_uri allowlist outside this repository.'],
          }));
        }
      }

      // csp.unsafe-inline / csp.unsafe-eval / csp.wildcard-source (per-occurrence, deployment-gated)
      for (const [ruleId, pattern, token] of [
        ['csp.unsafe-inline', CSP_UNSAFE_INLINE, "'unsafe-inline'"],
        ['csp.unsafe-eval', CSP_UNSAFE_EVAL, "'unsafe-eval'"],
        ['csp.wildcard-source', CSP_WILDCARD_SOURCE, '*'],
      ]) {
        pattern.lastIndex = 0;
        let cspMatch;
        while ((cspMatch = pattern.exec(text)) !== null) {
          const gate = deploymentGate(context, `Content-Security-Policy ${token}`);
          observations.push(baseObservation({
            ruleId,
            candidateClass: CANDIDATE_CLASS,
            claim: `The Content-Security-Policy configuration includes ${token}, weakening script-source restriction.`,
            severityHint: capSeverity('low', gate.severityCap),
            primitiveClass: 'defense-in-depth',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['inject-html-or-script'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'inject-content', environment: 'application' }],
            effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: artifact.id, scope: 'content-security-policy', environment: 'application', tenant: null }],
            chainRoles: ['enabler'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, cspMatch.index), header: 'Content-Security-Policy', directive: token, ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
            uncertainty: ['A CSP weakness is only exploitable in combination with an independent injection point; it is not itself proof of one.', ...gate.uncertainty],
          }));
        }
      }
    }

    // --- Whole-repository, deployment-aware boolean-state rules ----------

    // clickjacking.missing-frame-protection
    if (SERVES_HTML_MARKER.test(combinedText)) {
      const sourceCompliant = FRAME_PROTECTION_MARKER.test(combinedText);
      const runtimeCompliant = runtimeHeaderCompliance(context, 'x-frame-options', (value) => Boolean(value))
        ?? runtimeHeaderCompliance(context, 'content-security-policy', (value) => /frame-ancestors/i.test(String(value ?? '')));
      const outcome = evaluateDeploymentAwareClaim({ subject: 'X-Frame-Options / frame-ancestors', sourceCompliant, runtimeCompliant });
      if (outcome) {
        observations.push(baseObservation({
          ruleId: 'clickjacking.missing-frame-protection',
          candidateClass: CANDIDATE_CLASS,
          claim: 'No X-Frame-Options header or CSP frame-ancestors directive was found across the scanned, HTML-serving surface.',
          severityHint: capSeverity('low', outcome.severityCap),
          primitiveClass: 'defense-in-depth',
          sources: [],
          sinks: [],
          attackerCapabilities: ['embed-victim-page-in-frame'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'host-malicious-page', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: null, scope: 'frame-protection', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', header: 'X-Frame-Options / Content-Security-Policy frame-ancestors', filesExamined: context.files.length, ...(outcome.disagreement ? { disagreement: outcome.disagreement } : {}), ...(outcome.deploymentAssumption ? { deploymentAssumption: outcome.deploymentAssumption } : {}) },
          uncertainty: outcome.uncertainty,
        }));
      }
    }

    // csp.missing
    {
      const sourceCompliant = CSP_MARKER.test(combinedText);
      const runtimeCompliant = runtimeHeaderCompliance(context, 'content-security-policy', (value) => Boolean(value));
      const outcome = evaluateDeploymentAwareClaim({ subject: 'Content-Security-Policy header', sourceCompliant, runtimeCompliant });
      if (outcome) {
        observations.push(baseObservation({
          ruleId: 'csp.missing',
          candidateClass: CANDIDATE_CLASS,
          claim: 'No Content-Security-Policy was found across the scanned surface.',
          severityHint: capSeverity('low', outcome.severityCap),
          primitiveClass: 'defense-in-depth',
          sources: [],
          sinks: [],
          attackerCapabilities: ['inject-html-or-script'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'inject-content', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: null, scope: 'content-security-policy', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', header: 'Content-Security-Policy', filesExamined: context.files.length, ...(outcome.disagreement ? { disagreement: outcome.disagreement } : {}), ...(outcome.deploymentAssumption ? { deploymentAssumption: outcome.deploymentAssumption } : {}) },
          uncertainty: outcome.uncertainty,
        }));
      }
    }

    return observations;
  },

  variantStrategies: {
    'csrf.state-changing-route.missing-token': {
      rootCause() {
        return {
          class: 'missing-csrf-protection',
          semanticFeatures: ['cookie-session-auth', 'state-changing-route', 'no-csrf-token-check'],
        };
      },
      enumerate(context, signature) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text || !COOKIE_SESSION_MARKER.test(text) || CSRF_MARKER.test(text)) continue;
          STATE_CHANGING_ROUTE.lastIndex = 0;
          let match;
          while ((match = STATE_CHANGING_ROUTE.exec(text)) !== null) {
            matches.push({
              file,
              line: lineOf(text, match.index),
              semanticFingerprint: `sha256:${file}:${match[1]}:${match[2]}`,
              disposition: 'CONFIRMED',
            });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'csrf-route-search', kind: 'lexical-fallback', description: 'Enumerate every cookie-session state-changing route lacking a CSRF marker.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
    'cors.wildcard-origin-with-credentials': {
      rootCause() {
        return { class: 'cors-wildcard-with-credentials', semanticFeatures: ['acao-wildcard', 'acac-true'] };
      },
      enumerate(context) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          CORS_WILDCARD_CREDENTIALS.lastIndex = 0;
          let match;
          while ((match = CORS_WILDCARD_CREDENTIALS.exec(text)) !== null) {
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: `sha256:${file}:cors-wildcard-credentials`, disposition: 'CONFIRMED' });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'cors-header-search', kind: 'lexical-fallback', description: 'Enumerate every wildcard-origin-plus-credentials header combination.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
    'oauth.redirect-uri.unvalidated': {
      rootCause() {
        return { class: 'oauth-redirect-uri-unvalidated', semanticFeatures: ['redirect-uri-from-request', 'no-exact-match-allowlist'] };
      },
      enumerate(context) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text || OAUTH_ALLOWLIST_MARKER.test(text)) continue;
          OAUTH_REDIRECT_FROM_REQUEST.lastIndex = 0;
          let match;
          while ((match = OAUTH_REDIRECT_FROM_REQUEST.exec(text)) !== null) {
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: `sha256:${file}:oauth-redirect-uri`, disposition: 'CONFIRMED' });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'oauth-redirect-search', kind: 'lexical-fallback', description: 'Enumerate every request-derived OAuth redirect_uri without an allowlist.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
  },
});
