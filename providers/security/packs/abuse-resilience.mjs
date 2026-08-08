// Abuse & resilience security pack: global/per-operation rate limiting,
// GraphQL depth/cost/introspection exposure, pagination caps, over-exposed
// response fields, webhook signature verification, mutation idempotency
// keys, resource exhaustion, and circuit-breaker absence.
//
// No network imports, no live probing, no load generation — every
// observation is derived from source text already loaded into the frozen
// denominator (context.readFile) plus, when available, upstream
// performance/cost evidence surfaced on context.projection.auditFacts
// (auditFacts.performanceTraces). A missing rate limit, missing circuit
// breaker, or unbounded GraphQL depth/cost with NO observed cost or
// amplification evidence is reported as a capped, explicitly labelled
// `design-recommendation` (severityHint never exceeds 'low') rather than a
// `proven-primitive` denial-of-service claim. Rules where the source itself
// is the amplification evidence (an attacker-controlled loop/allocation
// size, an attacker-controlled page size funnelled directly into a query, a
// webhook body used before its signature is checked, a payment mutation
// with no idempotency key) are reported as `proven-primitive` because the
// exploit mechanics are directly observed, not merely recommended against.

import { digest } from '../contracts.mjs';

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

function sliceAround(text, index, matchLength, before, after) {
  const start = Math.max(0, index - before);
  const end = Math.min(text.length, index + matchLength + after);
  return text.slice(start, end);
}

function testAround(pattern, text, index, matchLength, before = 0, after = 300) {
  if (!pattern) return false;
  return pattern.test(sliceAround(text, index, matchLength, before, after));
}

// Best-effort cost/amplification evidence lookup: optional upstream
// performance telemetry keyed by file or route. Its absence never blocks a
// claim — it only keeps the claim capped as an availability design
// recommendation rather than a proven denial-of-service primitive.
function performanceEvidenceFor(context, key) {
  const traces = context.projection?.auditFacts?.performanceTraces ?? [];
  return traces.find((t) => t.file === key || t.route === key) ?? null;
}

// Distinguishes a proven denial-of-service primitive from an availability
// design recommendation per the lane contract: `hasDirectAmplificationEvidence`
// is true when the source pattern itself is the amplification vector (e.g.
// an attacker-controlled loop bound or page size funnelled directly into a
// query); otherwise the distinction depends on optional upstream cost
// evidence. Design recommendations are always capped at 'low'.
function availabilityClaimClass(context, key, { hasDirectAmplificationEvidence = false } = {}) {
  if (hasDirectAmplificationEvidence) return { claimClass: 'proven-primitive', severityCap: null, trace: null };
  const trace = performanceEvidenceFor(context, key);
  if (trace && trace.costEvidence) return { claimClass: 'proven-primitive', severityCap: null, trace };
  return { claimClass: 'design-recommendation', severityCap: 'low', trace: null };
}

function baseObservation({
  ruleId, candidateClass, claim, severityHint, claimClass, resource, attackerControlledInput,
  sources, sinks, attackerCapabilities, preconditions, effects, chainRoles, evidenceRefs, detectorMetadata, uncertainty,
}) {
  if (!attackerCapabilities?.length) throw new TypeError(`${ruleId}: attackerCapabilities must be non-empty`);
  if (!resource) throw new TypeError(`${ruleId}: detectorMetadata.resource is required`);
  if (!attackerControlledInput) throw new TypeError(`${ruleId}: detectorMetadata.attackerControlledInput is required`);
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
    detectorMetadata: { ...detectorMetadata, claimClass, resource, attackerControlledInput },
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
          description: `Enumerate every equivalent ${rootCauseClass} endpoint or configuration across the denominator.`,
          queryDigest: digest(rootCauseClass), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: [],
      };
    },
  };
}

const CANDIDATE_CLASS = 'abuse-resilience';

// --- patterns ---------------------------------------------------------

const SERVER_MARKER = /\bapp\.listen\(|createServer\(|fastify\s*\(|new\s+Koa\(\)/;
// Matches both an inline call (`rateLimit(...)`) and a named middleware
// passed by reference (`loginRateLimit`, `resetPasswordThrottle`) — Express
// middleware is idiomatically registered by reference, not only invoked
// inline, so a paren-only pattern would miss the common case.
const RATE_LIMIT_MARKER = /rate.?limit|RateLimiter(?:Memory|Redis)|slowDown\(|throttle/i;

const IDENTITY_ROUTE = /\b(?:app|router)\.(post|put)\(\s*['"]([^'"]*(?:login|signin|sign-in|register|signup|reset-password|resetPassword|forgot-password|send-otp|sendOtp|verify-otp|verifyOtp)[^'"]*)['"]/gi;

const GRAPHQL_SERVER_MARKER = /new\s+ApolloServer\(|new\s+GraphQLSchema\(|graphqlHTTP\(|buildSchema\(/;
const GRAPHQL_DEPTH_LIMIT_MARKER = /depthLimit\(|queryDepthLimit|maxDepth\s*:/i;
const GRAPHQL_COST_MARKER = /costAnalysis|queryComplexity|createComplexityLimitRule|costLimit\s*:/i;
const GRAPHQL_INTROSPECTION_TRUE = /introspection\s*:\s*true/g;

const PAGINATION_UNBOUNDED = /\.(?:limit|take)\s*\(\s*(?:req|request)\.(?:query|params|body)\.\w+\s*\)|(?:take|limit)\s*:\s*(?:req|request)\.(?:query|params|body)\.\w+\b/gi;
const PAGINATION_CAP_MARKER = /Math\.min\(/i;

const SENSITIVE_FIELD_NAME = /password(?:Hash)?|\bssn\b|apiKey|secret|privateKey|creditCard/i;
const RESPONSE_FULL_OBJECT = /res\.(?:json|send)\(\s*(user|account|profile|customer|record|entity)\s*\)/gi;
const FIELD_ALLOWLIST_MARKER = /\.pick\(|\.omit\(|toSafeJSON|sanitizeUser|select\s*:|serialize\(/i;

const WEBHOOK_ROUTE = /(?:app|router)\.(?:post|all)\(\s*['"][^'"]*(?:webhook|callback)[^'"]*['"]/gi;
const BODY_USE_MARKER = /\b(?:process|save|handle|charge|apply|persist|fulfill|db\.\w+|JSON\.parse)\s*\(\s*(?:req|request)\.body/;
const SIGNATURE_VERIFY_MARKER = /verify(?:Webhook)?Signature\(|hmac\.|crypto\.timingSafeEqual\(|\.webhooks\.constructEvent\(/;

const MUTATION_PAYMENT_ROUTE = /(?:app|router)\.post\(\s*['"][^'"]*(?:charge|payment|order|transfer|refund)[^'"]*['"]/gi;
const IDEMPOTENCY_MARKER = /idempotencyKey|Idempotency-Key|idempotency_key/i;

const UNBOUNDED_ALLOCATION = /new\s+Array\(\s*(?:req|request)\.(?:query|body|params)\.\w+\s*\)|Buffer\.alloc\(\s*(?:req|request)\.(?:query|body|params)\.\w+\s*\)|for\s*\(\s*(?:let|var)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(?:req|request)\.(?:query|body|params)\.\w+/g;
const RESOURCE_CAP_MARKER = /Math\.min\(/i;

const OUTBOUND_CALL_MARKER = /axios\.(?:get|post|put|delete|patch)\(|fetch\(\s*['"]https?:\/\/|http\.request\(|https\.request\(/;
const CIRCUIT_BREAKER_MARKER = /opossum|CircuitBreaker\(|new\s+CircuitBreaker|retry\(\s*\{|backoff\(/i;

export default Object.freeze({
  id: 'security.abuse-resilience',
  version: '1.0.0',
  candidateClass: CANDIDATE_CLASS,
  description: 'Abuse resistance and resilience: rate limiting, GraphQL depth/cost/introspection, pagination, over-exposure, webhook integrity, idempotency, resource exhaustion, and circuit breakers.',
  rules: [
    { id: 'abuse.rate-limit.global-missing' },
    { id: 'abuse.rate-limit.operation-missing' },
    { id: 'abuse.graphql.depth-unbounded' },
    { id: 'abuse.graphql.cost-unbounded' },
    { id: 'abuse.graphql.introspection-enabled' },
    { id: 'abuse.pagination.unbounded' },
    { id: 'abuse.data.over-exposed-fields' },
    { id: 'abuse.webhook.signature-missing' },
    { id: 'abuse.webhook.signature-verified-after-use' },
    { id: 'abuse.mutation.idempotency-key-missing' },
    { id: 'abuse.resource.exhaustion-unbounded-input' },
    { id: 'abuse.resilience.circuit-breaker-absent' },
  ],

  analyze(context) {
    const observations = [];
    const combinedText = context.files.map((file) => context.readFile(file) ?? '').join('\n');

    // --- whole-repository boolean-state rules ------------------------

    // abuse.rate-limit.global-missing
    if (SERVER_MARKER.test(combinedText) && !RATE_LIMIT_MARKER.test(combinedText)) {
      const gate = availabilityClaimClass(context, 'global');
      observations.push(baseObservation({
        ruleId: 'abuse.rate-limit.global-missing',
        candidateClass: CANDIDATE_CLASS,
        claim: 'The application serves HTTP requests with no visible global rate limiter.',
        severityHint: capSeverity('medium', gate.severityCap),
        claimClass: gate.claimClass,
        resource: 'all HTTP endpoints',
        attackerControlledInput: 'request volume',
        sources: [], sinks: [],
        attackerCapabilities: ['submit-high-volume-requests'],
        preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'network' }],
        effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: null, scope: 'http-request-capacity', environment: 'network', tenant: null }],
        chainRoles: ['enabler'],
        evidenceRefs: repoWideEvidenceRefs(context),
        detectorMetadata: { scope: 'repository', filesExamined: context.files.length },
        uncertainty: [
          'No global rate-limiter marker is not proof of no rate limiting; a reverse proxy, API gateway, or CDN could enforce it outside this repository.',
          gate.claimClass === 'design-recommendation'
            ? 'No cost or amplification evidence was observed for this surface; reported as an availability design recommendation, not a proven denial-of-service primitive.'
            : `Cost/amplification evidence observed: ${gate.trace?.note ?? 'elevated per-request cost recorded upstream'}.`,
        ],
      }));
    }

    // abuse.resilience.circuit-breaker-absent — always capped design-recommendation:
    // absence of a resilience pattern is a structural gap, not itself proof a
    // downstream dependency can be driven into cascading failure.
    if (OUTBOUND_CALL_MARKER.test(combinedText) && !CIRCUIT_BREAKER_MARKER.test(combinedText)) {
      observations.push(baseObservation({
        ruleId: 'abuse.resilience.circuit-breaker-absent',
        candidateClass: CANDIDATE_CLASS,
        claim: 'The application makes outbound calls to a downstream dependency with no visible circuit breaker, timeout backoff, or retry-budget pattern.',
        severityHint: 'low',
        claimClass: 'design-recommendation',
        resource: 'downstream dependency calls',
        attackerControlledInput: 'indirect — request volume amplifies a slow or failing downstream dependency',
        sources: [], sinks: [],
        attackerCapabilities: ['submit-high-volume-requests'],
        preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'network' }],
        effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: null, scope: 'downstream-dependency-capacity', environment: 'network', tenant: null }],
        chainRoles: ['enabler'],
        evidenceRefs: repoWideEvidenceRefs(context),
        detectorMetadata: { scope: 'repository', filesExamined: context.files.length },
        uncertainty: [
          'Static analysis cannot prove a downstream dependency will actually degrade; this is a resilience design recommendation, never a proven denial-of-service primitive, and is always capped at low severity.',
        ],
      }));
    }

    // abuse.graphql.depth-unbounded / abuse.graphql.cost-unbounded
    if (GRAPHQL_SERVER_MARKER.test(combinedText)) {
      if (!GRAPHQL_DEPTH_LIMIT_MARKER.test(combinedText)) {
        const gate = availabilityClaimClass(context, 'graphql-depth');
        observations.push(baseObservation({
          ruleId: 'abuse.graphql.depth-unbounded',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A GraphQL server is configured with no visible query-depth limit.',
          severityHint: capSeverity('medium', gate.severityCap),
          claimClass: gate.claimClass,
          resource: 'graphql schema',
          attackerControlledInput: 'query nesting depth',
          sources: [], sinks: [],
          attackerCapabilities: ['craft-graphql-query'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: null, scope: 'graphql-resolver-recursion', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', filesExamined: context.files.length },
          uncertainty: [
            gate.claimClass === 'design-recommendation'
              ? 'No resolver cost or amplification evidence was observed; reported as a design recommendation, not a proven denial-of-service primitive.'
              : `Cost/amplification evidence observed: ${gate.trace?.note ?? 'elevated resolver cost recorded upstream'}.`,
          ],
        }));
      }
      if (!GRAPHQL_COST_MARKER.test(combinedText)) {
        const gate = availabilityClaimClass(context, 'graphql-cost');
        observations.push(baseObservation({
          ruleId: 'abuse.graphql.cost-unbounded',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A GraphQL server is configured with no visible query cost/complexity limit.',
          severityHint: capSeverity('medium', gate.severityCap),
          claimClass: gate.claimClass,
          resource: 'graphql schema',
          attackerControlledInput: 'query field selection and arguments',
          sources: [], sinks: [],
          attackerCapabilities: ['craft-graphql-query'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: null, scope: 'graphql-resolver-cost', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs: repoWideEvidenceRefs(context),
          detectorMetadata: { scope: 'repository', filesExamined: context.files.length },
          uncertainty: [
            gate.claimClass === 'design-recommendation'
              ? 'No resolver cost or amplification evidence was observed; reported as a design recommendation, not a proven denial-of-service primitive.'
              : `Cost/amplification evidence observed: ${gate.trace?.note ?? 'elevated resolver cost recorded upstream'}.`,
          ],
        }));
      }
    }

    // --- per-file / per-occurrence rules ------------------------------
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = artifactFor(context, file);
      const evidenceRefs = artifact?.evidenceRefs ?? [];
      if (evidenceRefs.length === 0) continue;

      // abuse.rate-limit.operation-missing
      IDENTITY_ROUTE.lastIndex = 0;
      let idMatch;
      while ((idMatch = IDENTITY_ROUTE.exec(text)) !== null) {
        if (testAround(RATE_LIMIT_MARKER, text, idMatch.index, idMatch[0].length, 0, 300)) continue;
        const routeKey = idMatch[2];
        const gate = availabilityClaimClass(context, routeKey);
        observations.push(baseObservation({
          ruleId: 'abuse.rate-limit.operation-missing',
          candidateClass: CANDIDATE_CLASS,
          claim: `The identity-sensitive operation ${idMatch[1].toUpperCase()} ${routeKey} has no visible per-operation rate limit.`,
          severityHint: capSeverity('high', gate.severityCap),
          claimClass: gate.claimClass,
          resource: `${idMatch[1].toUpperCase()} ${routeKey}`,
          attackerControlledInput: 'request volume against this operation',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['submit-high-volume-requests'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: artifact.id, scope: 'identity-operation-capacity', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, idMatch.index), method: idMatch[1].toUpperCase(), path: routeKey },
          uncertainty: [
            'A rate limiter registered globally elsewhere in the application is not visible from this file alone.',
            gate.claimClass === 'design-recommendation'
              ? 'No cost or amplification evidence was observed for this operation; reported as a design recommendation, not a proven denial-of-service primitive.'
              : `Cost/amplification evidence observed: ${gate.trace?.note ?? 'elevated per-request cost recorded upstream'}.`,
          ],
        }));
      }

      // abuse.graphql.introspection-enabled — directly observed configuration
      // literal; always proven, always capped low as an information-exposure
      // finding rather than a denial-of-service claim.
      GRAPHQL_INTROSPECTION_TRUE.lastIndex = 0;
      let introspectionMatch;
      while ((introspectionMatch = GRAPHQL_INTROSPECTION_TRUE.exec(text)) !== null) {
        observations.push(baseObservation({
          ruleId: 'abuse.graphql.introspection-enabled',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A GraphQL server explicitly enables introspection.',
          severityHint: 'low',
          claimClass: 'proven-primitive',
          resource: 'graphql schema',
          attackerControlledInput: 'introspection query',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['craft-graphql-query'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'graphql-schema-metadata', environment: 'application', tenant: null }],
          chainRoles: ['enabler'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, introspectionMatch.index), config: 'introspection: true' },
          uncertainty: ['Introspection exposure is a reconnaissance aid, not itself a proven denial-of-service or data-access primitive; whether this deployment intends introspection to be public must be adjudicated.'],
        }));
      }

      // abuse.pagination.unbounded — the attacker-controlled page size
      // funnelled directly into the query is itself the amplification
      // evidence, so this is always reported as proven-primitive.
      PAGINATION_UNBOUNDED.lastIndex = 0;
      let pageMatch;
      while ((pageMatch = PAGINATION_UNBOUNDED.exec(text)) !== null) {
        if (testAround(PAGINATION_CAP_MARKER, text, pageMatch.index, pageMatch[0].length, 80, 80)) continue;
        observations.push(baseObservation({
          ruleId: 'abuse.pagination.unbounded',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A list endpoint takes its page size directly from request input with no visible upper-bound cap.',
          severityHint: 'medium',
          claimClass: 'proven-primitive',
          resource: `${file} pagination endpoint`,
          attackerControlledInput: 'page-size / limit / take query parameter',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['control-request-input'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: artifact.id, scope: 'query-result-size', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, pageMatch.index), config: pageMatch[0].slice(0, 60) },
          uncertainty: ['Impact depends on the backing data volume and whether a database-level default limit exists outside this file.'],
        }));
      }

      // abuse.data.over-exposed-fields
      if (SENSITIVE_FIELD_NAME.test(text) && !FIELD_ALLOWLIST_MARKER.test(text)) {
        RESPONSE_FULL_OBJECT.lastIndex = 0;
        let respMatch;
        while ((respMatch = RESPONSE_FULL_OBJECT.exec(text)) !== null) {
          observations.push(baseObservation({
            ruleId: 'abuse.data.over-exposed-fields',
            candidateClass: CANDIDATE_CLASS,
            claim: `A ${respMatch[1]} record is serialized directly into a response with no visible field allowlist, and the file contains a sensitive-looking field name.`,
            severityHint: 'medium',
            claimClass: 'proven-primitive',
            resource: `${file} response serialization`,
            attackerControlledInput: 'endpoint invocation (which fields are returned is server-controlled, not attacker-selected)',
            sources: [artifact.id], sinks: [artifact.id],
            attackerCapabilities: ['invoke-authorized-or-unauthorized-endpoint'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'invoke-endpoint', environment: 'application' }],
            effects: [{ kind: 'confidentiality-impact', subject: 'actor:external', action: 'read', object: artifact.id, scope: 'over-exposed-response-fields', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'impact'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, respMatch.index), config: respMatch[0] },
            uncertainty: ['Whether the sensitive-looking field actually reaches the serialized object (rather than being unrelated code in the same file) requires adjudication of the object shape.'],
          }));
        }
      }

      // abuse.webhook.signature-missing / abuse.webhook.signature-verified-after-use
      WEBHOOK_ROUTE.lastIndex = 0;
      let webhookMatch;
      while ((webhookMatch = WEBHOOK_ROUTE.exec(text)) !== null) {
        const windowText = sliceAround(text, webhookMatch.index, webhookMatch[0].length, 0, 600);
        const hasSignatureCheck = SIGNATURE_VERIFY_MARKER.test(windowText);
        if (!hasSignatureCheck) {
          observations.push(baseObservation({
            ruleId: 'abuse.webhook.signature-missing',
            candidateClass: CANDIDATE_CLASS,
            claim: 'A webhook/callback receiver has no visible signature or authenticity verification anywhere in its handler.',
            severityHint: 'high',
            claimClass: 'proven-primitive',
            resource: `${file} webhook receiver`,
            attackerControlledInput: 'webhook payload body',
            sources: [artifact.id], sinks: [artifact.id],
            attackerCapabilities: ['submit-forged-webhook-request'],
            preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'submit-forged-request', environment: 'application' }],
            effects: [{ kind: 'integrity-impact', subject: 'actor:external', action: 'forge', object: artifact.id, scope: 'webhook-event-trust', environment: 'application', tenant: null }],
            chainRoles: ['starter', 'control-bypass'],
            evidenceRefs,
            detectorMetadata: { file, line: lineOf(text, webhookMatch.index), route: webhookMatch[0] },
            uncertainty: ['A signature check performed by an upstream gateway or middleware not visible in this file cannot be ruled out.'],
          }));
        } else {
          const useMatch = BODY_USE_MARKER.exec(windowText);
          const verifyIndex = windowText.search(SIGNATURE_VERIFY_MARKER);
          if (useMatch && useMatch.index < verifyIndex) {
            observations.push(baseObservation({
              ruleId: 'abuse.webhook.signature-verified-after-use',
              candidateClass: CANDIDATE_CLASS,
              claim: 'A webhook/callback receiver uses the request body before its signature is verified.',
              severityHint: 'high',
              claimClass: 'proven-primitive',
              resource: `${file} webhook receiver`,
              attackerControlledInput: 'webhook payload body',
              sources: [artifact.id], sinks: [artifact.id],
              attackerCapabilities: ['submit-forged-webhook-request'],
              preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'submit-forged-request', environment: 'application' }],
              effects: [{ kind: 'integrity-impact', subject: 'actor:external', action: 'forge', object: artifact.id, scope: 'webhook-event-trust', environment: 'application', tenant: null }],
              chainRoles: ['starter', 'control-bypass'],
              evidenceRefs,
              detectorMetadata: { file, line: lineOf(text, webhookMatch.index), route: webhookMatch[0] },
              uncertainty: ['The verification call is present but its ordering relative to body use is inferred from linear text proximity, not a control-flow graph.'],
            }));
          }
        }
      }

      // abuse.mutation.idempotency-key-missing
      MUTATION_PAYMENT_ROUTE.lastIndex = 0;
      let mutationMatch;
      while ((mutationMatch = MUTATION_PAYMENT_ROUTE.exec(text)) !== null) {
        if (testAround(IDEMPOTENCY_MARKER, text, mutationMatch.index, mutationMatch[0].length, 0, 400)) continue;
        observations.push(baseObservation({
          ruleId: 'abuse.mutation.idempotency-key-missing',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A payment/order mutation endpoint has no visible idempotency-key check, so a replayed request can duplicate the mutation.',
          severityHint: 'medium',
          claimClass: 'proven-primitive',
          resource: mutationMatch[0],
          attackerControlledInput: 'request replay / retry count',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['replay-request'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'replay-request', environment: 'application' }],
          effects: [{ kind: 'integrity-impact', subject: 'actor:external', action: 'duplicate', object: artifact.id, scope: 'financial-mutation', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, mutationMatch.index), route: mutationMatch[0] },
          uncertainty: ['A database-level unique constraint or an upstream gateway-level idempotency layer not visible in this file could still prevent duplication.'],
        }));
      }

      // abuse.resource.exhaustion-unbounded-input — the attacker-controlled
      // loop bound or allocation size is itself the amplification evidence.
      UNBOUNDED_ALLOCATION.lastIndex = 0;
      let allocMatch;
      while ((allocMatch = UNBOUNDED_ALLOCATION.exec(text)) !== null) {
        if (testAround(RESOURCE_CAP_MARKER, text, allocMatch.index, allocMatch[0].length, 100, 200)) continue;
        observations.push(baseObservation({
          ruleId: 'abuse.resource.exhaustion-unbounded-input',
          candidateClass: CANDIDATE_CLASS,
          claim: 'A loop bound or memory allocation size is taken directly from request input with no visible upper-bound cap.',
          severityHint: 'high',
          claimClass: 'proven-primitive',
          resource: `${file} allocation/loop`,
          attackerControlledInput: 'size/count parameter from request',
          sources: [artifact.id], sinks: [artifact.id],
          attackerCapabilities: ['control-request-input'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-input', environment: 'application' }],
          effects: [{ kind: 'availability-impact', subject: 'actor:external', action: 'exhaust', object: artifact.id, scope: 'process-memory-or-cpu', environment: 'application', tenant: null }],
          chainRoles: ['starter', 'impact'],
          evidenceRefs,
          detectorMetadata: { file, line: lineOf(text, allocMatch.index), config: allocMatch[0].slice(0, 80) },
          uncertainty: ['Actual impact depends on the process memory/CPU limits and whether an upstream body-size limit already bounds the input.'],
        }));
      }
    }

    return observations;
  },

  variantStrategies: {
    'abuse.rate-limit.operation-missing': lexicalVariantStrategy(
      'identity-operation-without-rate-limit',
      ['identity-sensitive-route', 'no-rate-limit-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          IDENTITY_ROUTE.lastIndex = 0;
          let match;
          while ((match = IDENTITY_ROUTE.exec(text)) !== null) {
            if (testAround(RATE_LIMIT_MARKER, text, match.index, match[0].length, 0, 300)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, route: match[2] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'abuse.webhook.signature-missing': lexicalVariantStrategy(
      'webhook-without-signature-verification',
      ['webhook-route', 'no-signature-verification'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          WEBHOOK_ROUTE.lastIndex = 0;
          let match;
          while ((match = WEBHOOK_ROUTE.exec(text)) !== null) {
            const windowText = sliceAround(text, match.index, match[0].length, 0, 600);
            if (SIGNATURE_VERIFY_MARKER.test(windowText)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, route: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'abuse.webhook.signature-verified-after-use': lexicalVariantStrategy(
      'webhook-signature-verified-after-body-use',
      ['webhook-route', 'signature-check-after-body-use'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          WEBHOOK_ROUTE.lastIndex = 0;
          let match;
          while ((match = WEBHOOK_ROUTE.exec(text)) !== null) {
            const windowText = sliceAround(text, match.index, match[0].length, 0, 600);
            if (!SIGNATURE_VERIFY_MARKER.test(windowText)) continue;
            const useMatch = BODY_USE_MARKER.exec(windowText);
            const verifyIndex = windowText.search(SIGNATURE_VERIFY_MARKER);
            if (useMatch && useMatch.index < verifyIndex) {
              matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, route: match[0] }), disposition: 'CONFIRMED' });
            }
          }
        }
        return matches;
      },
    ),
    'abuse.mutation.idempotency-key-missing': lexicalVariantStrategy(
      'payment-mutation-without-idempotency-key',
      ['payment-mutation-route', 'no-idempotency-key-marker'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          MUTATION_PAYMENT_ROUTE.lastIndex = 0;
          let match;
          while ((match = MUTATION_PAYMENT_ROUTE.exec(text)) !== null) {
            if (testAround(IDEMPOTENCY_MARKER, text, match.index, match[0].length, 0, 400)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, route: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'abuse.pagination.unbounded': lexicalVariantStrategy(
      'pagination-without-upper-bound',
      ['request-derived-page-size', 'no-math-min-cap'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          PAGINATION_UNBOUNDED.lastIndex = 0;
          let match;
          while ((match = PAGINATION_UNBOUNDED.exec(text)) !== null) {
            if (testAround(PAGINATION_CAP_MARKER, text, match.index, match[0].length, 80, 80)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
    'abuse.resource.exhaustion-unbounded-input': lexicalVariantStrategy(
      'unbounded-request-derived-allocation',
      ['request-derived-loop-or-allocation-size', 'no-math-min-cap'],
      (context) => {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          UNBOUNDED_ALLOCATION.lastIndex = 0;
          let match;
          while ((match = UNBOUNDED_ALLOCATION.exec(text)) !== null) {
            if (testAround(RESOURCE_CAP_MARKER, text, match.index, match[0].length, 100, 200)) continue;
            matches.push({ file, line: lineOf(text, match.index), semanticFingerprint: digest({ file, config: match[0] }), disposition: 'CONFIRMED' });
          }
        }
        return matches;
      },
    ),
  },
});
