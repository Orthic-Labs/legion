// Transport/protocol/cache/proxy security pack: HSTS, HTTPS enforcement,
// security response headers, caching of sensitive content, proxy trust and
// forwarded-header handling, request-smuggling preconditions, and
// content-type behaviour. No network imports, no live probing — every
// observation is derived from source text already loaded into the frozen
// denominator (context.readFile) plus, when available, upstream
// runtime-header / deployment evidence (B5-021) surfaced on
// context.projection.auditFacts. This pack is inherently deployment-shaped:
// every rule here degrades to a capped, explicitly-flagged assumption when
// runtime/deployment evidence is absent, and never fails because it is
// missing.

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

function deploymentEvidence(context) {
  return context.projection?.auditFacts?.deployment ?? null;
}

function runtimeHeaderCompliance(context, headerKey, isCompliant) {
  const snapshot = runtimeHeaderSnapshot(context);
  if (!snapshot || !Object.prototype.hasOwnProperty.call(snapshot, headerKey)) return null;
  return isCompliant(snapshot[headerKey]);
}

// Full disagreement-aware evaluator for whole-repository boolean-state
// claims. Returns null when the claim is clean, otherwise the modifiers to
// apply to the observation. Never silently picks source over runtime, or
// vice versa, when they disagree — both are recorded.
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
// evidence exists at all.
function deploymentGate(context, subject) {
  const hasEvidence = Boolean(runtimeHeaderSnapshot(context)) || Boolean(deploymentEvidence(context));
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

const CANDIDATE_CLASS = 'http-protocol';

const HSTS_MARKER = /Strict-Transport-Security/i;
const HTTP_CREATE_SERVER = /http\.createServer\(/i;
const HTTPS_ENFORCEMENT_MARKER = /https\.createServer\(|forceSSL|requireHTTPS|express-sslify|helmet(?:\s*\(|\.hsts)/i;
const CONTENT_TYPE_OPTIONS_MARKER = /X-Content-Type-Options[^\n]*nosniff/i;

const CONTENT_TYPE_MISSING_CHARSET = /Content-Type['"]?\s*[:,]\s*['"]text\/(?:html|plain)(?:;[^'"]*)?['"]/gi;

const SENSITIVE_ROUTE_MARKER = /req\.(?:session|user)|Authorization|\baccount\b|\bprofile\b|\bbilling\b|\badmin\b/i;
const CACHE_NO_STORE = /Cache-Control['"]?\s*[:,]\s*['"][^'"]*no-store/i;
const CACHE_PUBLIC_OR_MAXAGE = /Cache-Control['"]?\s*[:,]\s*['"][^'"]*(?:public|max-age)/gi;

const TRUST_PROXY_TRUE = /trust proxy['"]?\s*,\s*true/gi;
const FORWARDED_FOR_SECURITY_USE = /X-Forwarded-For/gi;
const SECURITY_DECISION_MARKER = /rateLimit|isAdmin|allowlist|ipWhitelist|\bauth\b/i;
const TRUSTED_PROXY_COUNT_MARKER = /trustedProxies|proxyCount|numProxies/i;

const CONTENT_LENGTH_MARKER = /Content-Length['"]?\s*[:=]/;
const TRANSFER_ENCODING_CHUNKED = /Transfer-Encoding['"]?\s*[:=][^\n]*chunked/i;

const FORWARDED_HEADER_NAIVE_SPLIT = /(?:X-Forwarded-For|X-Forwarded-Host)['"]?\][^\n]*split\(\s*['"],['"]\s*\)\s*\[\s*0\s*\]/gi;
const FORWARDED_HEADER_VALIDATION_MARKER = /trustedProxies|proxyCount|numProxies|validateForwardedHeader/i;

export default Object.freeze({
  id: 'security.http-protocol-cache',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Transport, protocol, cache, and proxy-trust controls: HSTS, HTTPS enforcement, security headers, sensitive-content caching, forwarded-header trust, request-smuggling preconditions, and content-type behaviour.',
  rules: [
    { id: 'hsts.missing' },
    { id: 'https.not-enforced' },
    { id: 'headers.missing-content-type-options' },
    { id: 'headers.content-type-missing-charset' },
    { id: 'cache.sensitive-content-cacheable' },
    { id: 'proxy.trust-misconfigured' },
    { id: 'smuggling.conflicting-content-length-transfer-encoding' },
    { id: 'smuggling.ambiguous-proxy-chain' },
  ],

  analyze(context) {
    const observations = [];
    const combinedText = context.files.map((file) => context.readFile(file) ?? '').join('\n');

    // --- Whole-repository, deployment-aware boolean-state rules ----------

    // hsts.missing
    {
      const sourceCompliant = HSTS_MARKER.test(combinedText);
      const runtimeCompliant = runtimeHeaderCompliance(context, 'strict-transport-security', (value) => Boolean(value));
      const outcome = evaluateDeploymentAwareClaim({ subject: 'Strict-Transport-Security header', sourceCompliant, runtimeCompliant });
      if (outcome) {
        observations.push(baseObservation({
          ruleId: 'hsts.missing',
          candidateClass: CANDIDATE_CLASS,
          claim: 'No Strict-Transport-Security header was found across the scanned surface.',
          severityHint: capSeverity('low', outcome.severityCap),
          primitiveClass: 'defense-in-depth',
          sources: [],
          sinks: [],
          attackerCapabilities: ['active-network-position'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'intercept-network-traffic', environment: 'network' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'downgrade', object: null, scope: 'transport-security', environment: 'network', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', header: 'Strict-Transport-Security', filesExamined: context.files.length, ...(outcome.disagreement ? { disagreement: outcome.disagreement } : {}), ...(outcome.deploymentAssumption ? { deploymentAssumption: outcome.deploymentAssumption } : {}) },
          uncertainty: outcome.uncertainty,
        }));
      }
    }

    // https.not-enforced
    {
      const sourceInsecure = HTTP_CREATE_SERVER.test(combinedText) && !HTTPS_ENFORCEMENT_MARKER.test(combinedText);
      const deployment = deploymentEvidence(context);
      const runtimeCompliant = deployment && typeof deployment.httpsEnforced === 'boolean' ? deployment.httpsEnforced : null;
      const sourceCompliant = !sourceInsecure;
      const outcome = evaluateDeploymentAwareClaim({ subject: 'HTTPS enforcement', sourceCompliant, runtimeCompliant, compliantLabel: 'enforced', nonCompliantLabel: 'not-enforced' });
      if (outcome) {
        observations.push(baseObservation({
          ruleId: 'https.not-enforced',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A plain HTTP server is created with no visible HTTPS enforcement or redirect.',
          severityHint: capSeverity('high', outcome.severityCap),
          primitiveClass: 'exploitable-primitive',
          sources: [],
          sinks: [],
          attackerCapabilities: ['active-network-position'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'intercept-network-traffic', environment: 'network' }],
          effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'intercept', object: null, scope: 'transport-confidentiality', environment: 'network', tenant: null }],
          chainRoles: ['starter', 'enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', config: 'http.createServer without HTTPS enforcement', filesExamined: context.files.length, ...(outcome.disagreement ? { disagreement: outcome.disagreement } : {}), ...(outcome.deploymentAssumption ? { deploymentAssumption: outcome.deploymentAssumption } : {}) },
          uncertainty: outcome.uncertainty,
        }));
      }
    }

    // headers.missing-content-type-options
    {
      const sourceCompliant = CONTENT_TYPE_OPTIONS_MARKER.test(combinedText);
      const runtimeCompliant = runtimeHeaderCompliance(context, 'x-content-type-options', (value) => /nosniff/i.test(String(value ?? '')));
      const outcome = evaluateDeploymentAwareClaim({ subject: 'X-Content-Type-Options header', sourceCompliant, runtimeCompliant });
      if (outcome) {
        observations.push(baseObservation({
          ruleId: 'headers.missing-content-type-options',
          candidateClass: CANDIDATE_CLASS,
          claim: 'No X-Content-Type-Options: nosniff header was found across the scanned surface.',
          severityHint: capSeverity('low', outcome.severityCap),
          primitiveClass: 'defense-in-depth',
          sources: [],
          sinks: [],
          attackerCapabilities: ['host-attacker-controlled-content'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-content', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: null, scope: 'mime-sniffing-protection', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', header: 'X-Content-Type-Options', filesExamined: context.files.length, ...(outcome.disagreement ? { disagreement: outcome.disagreement } : {}), ...(outcome.deploymentAssumption ? { deploymentAssumption: outcome.deploymentAssumption } : {}) },
          uncertainty: outcome.uncertainty,
        }));
      }
    }

    // --- Per-file, deployment-gated rules ---------------------------------
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = artifactFor(context, file);
      const evidenceRefs = artifact?.evidenceRefs ?? [];
      if (evidenceRefs.length === 0) continue;

      // headers.content-type-missing-charset
      CONTENT_TYPE_MISSING_CHARSET.lastIndex = 0;
      let charsetMatch;
      while ((charsetMatch = CONTENT_TYPE_MISSING_CHARSET.exec(text)) !== null) {
        if (/charset/i.test(charsetMatch[0])) continue;
        const gate = deploymentGate(context, 'Content-Type charset');
        observations.push(baseObservation({
          ruleId: 'headers.content-type-missing-charset',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A text response Content-Type is set without an explicit charset.',
          severityHint: capSeverity('low', gate.severityCap),
          primitiveClass: 'defense-in-depth',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['host-attacker-controlled-content'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-content', environment: 'application' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'bypass', object: artifact.id, scope: 'content-type-charset', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, charsetMatch.index), header: 'Content-Type', value: charsetMatch[0], ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
          uncertainty: ['A missing charset primarily matters for legacy browser content-type sniffing; modern browsers are largely unaffected.', ...gate.uncertainty],
        }));
      }

      // cache.sensitive-content-cacheable
      if (SENSITIVE_ROUTE_MARKER.test(text) && !CACHE_NO_STORE.test(text)) {
        CACHE_PUBLIC_OR_MAXAGE.lastIndex = 0;
        const explicitPublicMatch = CACHE_PUBLIC_OR_MAXAGE.exec(text);
        const line = explicitPublicMatch ? lineOf(text, explicitPublicMatch.index) : 1;
        const gate = deploymentGate(context, 'Cache-Control on a sensitive route');
        observations.push(baseObservation({
          ruleId: 'cache.sensitive-content-cacheable',
          candidateClass: CANDIDATE_CLASS,
          claim: explicitPublicMatch
            ? 'A route handling authenticated/sensitive data sets a publicly cacheable Cache-Control value instead of no-store.'
            : 'A route handling authenticated/sensitive data has no Cache-Control: no-store, leaving default caching behavior in effect.',
          severityHint: capSeverity('high', gate.severityCap),
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['shared-cache-or-proxy-access'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'access-shared-cache', environment: 'network' }],
          effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'cached-sensitive-response', environment: 'network', tenant: null }],
          chainRoles: ['enabler', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line, header: 'Cache-Control', ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
          uncertainty: ['Whether an intermediary shared cache is actually present between the attacker and this response depends on the deployment topology.', ...gate.uncertainty],
        }));
      }

      // proxy.trust-misconfigured
      TRUST_PROXY_TRUE.lastIndex = 0;
      const blindTrustMatch = TRUST_PROXY_TRUE.exec(text);
      const rawForwardedForUse = FORWARDED_FOR_SECURITY_USE.test(text) && SECURITY_DECISION_MARKER.test(text) && !TRUSTED_PROXY_COUNT_MARKER.test(text);
      if (blindTrustMatch || rawForwardedForUse) {
        const deployment = deploymentEvidence(context);
        const gate = deploymentGate(context, 'X-Forwarded-For trust / proxy topology');
        const line = blindTrustMatch ? lineOf(text, blindTrustMatch.index) : 1;
        let severityHint = capSeverity('high', gate.severityCap);
        if (deployment && deployment.reverseProxy === false) severityHint = 'critical';
        observations.push(baseObservation({
          ruleId: 'proxy.trust-misconfigured',
          candidateClass: CANDIDATE_CLASS,
          claim: blindTrustMatch
            ? "Proxy trust is enabled unconditionally ('trust proxy', true), accepting forwarded headers from any hop."
            : 'X-Forwarded-For is used for a security decision without a configured trusted-proxy count.',
          severityHint,
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['control-request-headers'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-forwarded-header', environment: 'network' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'spoof', object: artifact.id, scope: 'client-ip-trust', environment: 'network', tenant: null }],
          chainRoles: ['starter', 'control-bypass'],
          evidenceRefs,
          detectorMetadata: { file, line, config: blindTrustMatch ? "trust proxy: true" : 'X-Forwarded-For security decision', reverseProxyKnown: Boolean(deployment), ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
          uncertainty: ['Exploitability depends on whether a trusted reverse proxy actually sits in front of this service and strips client-supplied forwarded headers.', ...gate.uncertainty],
        }));
      }

      // smuggling.conflicting-content-length-transfer-encoding
      if (CONTENT_LENGTH_MARKER.test(text) && TRANSFER_ENCODING_CHUNKED.test(text)) {
        const teMatch = TRANSFER_ENCODING_CHUNKED.exec(text) ?? { index: 0 };
        const gate = deploymentGate(context, 'Content-Length / Transfer-Encoding handling');
        observations.push(baseObservation({
          ruleId: 'smuggling.conflicting-content-length-transfer-encoding',
          candidateClass: CANDIDATE_CLASS,
          claim: 'Both Content-Length and Transfer-Encoding: chunked are handled by custom request code, a precondition for request-smuggling desync when chained through a front-end/back-end proxy pair with disagreeing HTTP parsers.',
          severityHint: capSeverity('medium', gate.severityCap),
          primitiveClass: 'exploitable-primitive',
          sources: [artifact.id],
          sinks: [artifact.id],
          attackerCapabilities: ['control-request-headers'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-conflicting-length-headers', environment: 'network' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'desync', object: artifact.id, scope: 'http-request-boundary', environment: 'network', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, teMatch.index), header: 'Content-Length / Transfer-Encoding', ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
          uncertainty: [
            'This is a precondition only: full request smuggling requires an actual front-end/back-end HTTP parser disagreement across a real proxy chain, which cannot be confirmed by static analysis alone.',
            ...gate.uncertainty,
          ],
        }));
      }

      // smuggling.ambiguous-proxy-chain
      if (!FORWARDED_HEADER_VALIDATION_MARKER.test(text)) {
        FORWARDED_HEADER_NAIVE_SPLIT.lastIndex = 0;
        let naiveMatch;
        while ((naiveMatch = FORWARDED_HEADER_NAIVE_SPLIT.exec(text)) !== null) {
          const gate = deploymentGate(context, 'forwarded-header proxy-chain parsing');
          observations.push(baseObservation({
            ruleId: 'smuggling.ambiguous-proxy-chain',
            candidateClass: CANDIDATE_CLASS,
            claim: 'A forwarded header is parsed by naively taking the first comma-separated value, which is ambiguous when multiple untrusted hops can append their own values.',
            severityHint: capSeverity('medium', gate.severityCap),
            primitiveClass: 'exploitable-primitive',
            sources: [artifact.id],
            sinks: [artifact.id],
            attackerCapabilities: ['control-request-headers'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-forwarded-header', environment: 'network' }],
            effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'spoof', object: artifact.id, scope: 'http-request-boundary', environment: 'network', tenant: null }],
            chainRoles: ['enabler'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, naiveMatch.index), config: 'forwarded-header parsing', ...(gate.deploymentAssumption ? { deploymentAssumption: gate.deploymentAssumption } : {}) },
            uncertainty: [
              'Ambiguity is only exploitable if an untrusted hop can inject its own forwarded-header value ahead of the trusted proxy; the real proxy chain topology is not visible from source.',
              ...gate.uncertainty,
            ],
          }));
        }
      }
    }

    return observations;
  },

  variantStrategies: {
    'hsts.missing': {
      rootCause() {
        return { class: 'missing-hsts', semanticFeatures: ['no-strict-transport-security-header'] };
      },
      enumerate(context) {
        const sourceCompliant = HSTS_MARKER.test(context.files.map((file) => context.readFile(file) ?? '').join('\n'));
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'hsts-header-search', kind: 'lexical-fallback', description: 'Search the denominator for a Strict-Transport-Security header.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches: sourceCompliant ? [] : [{ file: null, line: null, semanticFingerprint: 'sha256:hsts-missing-repository-wide', disposition: 'CONFIRMED' }],
          coverageGaps: [],
        };
      },
    },
    'cache.sensitive-content-cacheable': {
      rootCause() {
        return { class: 'sensitive-content-cacheable', semanticFeatures: ['sensitive-route-marker', 'missing-cache-control-no-store'] };
      },
      enumerate(context) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (text && SENSITIVE_ROUTE_MARKER.test(text) && !CACHE_NO_STORE.test(text)) {
            matches.push({ file, line: 1, semanticFingerprint: `sha256:${file}:sensitive-cacheable`, disposition: 'CONFIRMED' });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'sensitive-cache-search', kind: 'lexical-fallback', description: 'Enumerate every sensitive route missing Cache-Control: no-store.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
    'proxy.trust-misconfigured': {
      rootCause() {
        return { class: 'proxy-trust-misconfigured', semanticFeatures: ['blind-trust-proxy', 'unvalidated-forwarded-for'] };
      },
      enumerate(context) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          TRUST_PROXY_TRUE.lastIndex = 0;
          const blind = TRUST_PROXY_TRUE.exec(text);
          const raw = FORWARDED_FOR_SECURITY_USE.test(text) && SECURITY_DECISION_MARKER.test(text) && !TRUSTED_PROXY_COUNT_MARKER.test(text);
          if (blind || raw) {
            matches.push({ file, line: blind ? lineOf(text, blind.index) : 1, semanticFingerprint: `sha256:${file}:proxy-trust`, disposition: 'CONFIRMED' });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'proxy-trust-search', kind: 'lexical-fallback', description: 'Enumerate every blind proxy-trust or unvalidated forwarded-header configuration.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
  },
});
