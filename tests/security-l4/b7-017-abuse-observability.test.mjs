// B7-017 — abuse, resilience, GraphQL, webhook, and observability packs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import { entity } from '../../providers/security/model-extractors/common.mjs';
import abuseResiliencePack from '../../providers/security/packs/abuse-resilience.mjs';
import observabilityForensicsPack from '../../providers/security/packs/observability-forensics.mjs';

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  cortexGenerationId: 'gen', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function run(pack, filesMap, auditFacts = {}) {
  const files = Object.keys(filesMap).sort();
  const entities = [];
  const evidence = [];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  const plan = {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      cortex: { generationId: BINDING.cortexGenerationId, manifestDigest: BINDING.cortexManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{ id: pack.id, benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files } }],
  };
  const model = {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities, relations: [], initialFacts: [], evidence, coverage: {}, coverageGaps: [],
  };
  const projection = { files, sourceText: filesMap, auditFacts };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

function candidatesById(result, ruleId) {
  return result.candidates.filter((c) => c.ruleId === ruleId);
}

// --- registry parity --------------------------------------------------------

test('registry rule ids match abuse-resilience and observability-forensics pack rule ids exactly, in both directions', () => {
  const registry = JSON.parse(readFileSync(new URL('../../registry/rules/security/abuse-observability.json', import.meta.url), 'utf8'));
  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set([...abuseResiliencePack.rules.map((r) => r.id), ...observabilityForensicsPack.rules.map((r) => r.id)]);
  assert.equal(registryIds.size, registry.rules.length, 'registry rule ids must be unique');
  for (const id of packIds) assert.ok(registryIds.has(id), `registry missing pack rule id ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has a rule id no pack declares: ${id}`);
  assert.deepEqual([...registryIds].sort(), [...packIds].sort());
  for (const rule of registry.rules) {
    assert.ok(['design-recommendation', 'proven-primitive'].includes(rule.claimClass), `${rule.id} claimClass`);
    assert.ok(['security.abuse-resilience', 'security.observability-forensics'].includes(rule.pack), `${rule.id} pack`);
    assert.ok(['abuse-resilience', 'observability-forensics'].includes(rule.class), `${rule.id} class`);
    assert.equal(rule.decisionMode, 'evidence', `${rule.id} decisionMode`);
    assert.equal(rule.cleanClaim, 'never-without-denominator', `${rule.id} cleanClaim`);
    assert.ok(Array.isArray(rule.requiredControls), `${rule.id} requiredControls`);
    assert.ok(Array.isArray(rule.applicability) && rule.applicability.length > 0, `${rule.id} applicability`);
  }
});

// --- forbidden: no offensive/networking imports ------------------------------

test('neither pack imports a live network, process, or worker module', () => {
  const forbidden = /\bnode:https?\b|\bnode:net\b|\bnode:dgram\b|\bnode:child_process\b|\bnode:worker_threads\b|from\s+['"]https?['"]|require\(\s*['"]https?['"]\s*\)|from\s+['"]net['"]|from\s+['"]dgram['"]|from\s+['"]child_process['"]|from\s+['"]worker_threads['"]/;
  for (const relative of ['../../providers/security/packs/abuse-resilience.mjs', '../../providers/security/packs/observability-forensics.mjs']) {
    const source = readFileSync(new URL(relative, import.meta.url), 'utf8');
    assert.ok(!forbidden.test(source), `${relative} must not import a live network/process module`);
  }
});

// --- abuse-resilience: rate limiting -----------------------------------------

test('abuse-resilience flags a server with no global rate limiter as a capped design recommendation without cost evidence', () => {
  const result = run(abuseResiliencePack, { 'server.mjs': "app.listen(3000);" });
  const hits = candidatesById(result, 'abuse.rate-limit.global-missing');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'design-recommendation');
  assert.ok(['info', 'low'].includes(hits[0].severityHint));
  assert.equal(hits[0].detectorMetadata.resource, 'all HTTP endpoints');
  assert.equal(hits[0].detectorMetadata.attackerControlledInput, 'request volume');
  assert.ok(hits[0].attackerCapabilities.length > 0);
});

test('abuse-resilience stays clean on global rate limit when a limiter is present', () => {
  const result = run(abuseResiliencePack, { 'server.mjs': "app.use(rateLimit({ windowMs: 60000 }));\napp.listen(3000);" });
  assert.equal(candidatesById(result, 'abuse.rate-limit.global-missing').length, 0);
});

test('abuse-resilience upgrades the global rate-limit claim to proven-primitive when cost/amplification evidence is present', () => {
  const result = run(
    abuseResiliencePack,
    { 'server.mjs': "app.listen(3000);" },
    { performanceTraces: [{ file: 'global', costEvidence: true, note: 'search endpoint measured at 40x baseline cost per request' }] },
  );
  const hits = candidatesById(result, 'abuse.rate-limit.global-missing');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
});

test('abuse-resilience flags an identity-sensitive operation with no per-operation rate limit and names the resource', () => {
  const result = run(abuseResiliencePack, {
    'auth.mjs': "app.post('/login', (req, res) => { doLogin(req.body); });",
  });
  const hits = candidatesById(result, 'abuse.rate-limit.operation-missing');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.resource, 'POST /login');
  assert.equal(hits[0].detectorMetadata.attackerControlledInput, 'request volume against this operation');
  assert.ok(hits[0].attackerCapabilities.length > 0);
});

test('abuse-resilience stays clean on per-operation rate limit when a limiter is registered near the route', () => {
  const result = run(abuseResiliencePack, {
    'auth.mjs': "app.post('/login', loginRateLimit, (req, res) => { doLogin(req.body); });",
  });
  assert.equal(candidatesById(result, 'abuse.rate-limit.operation-missing').length, 0);
});

// --- abuse-resilience: GraphQL depth/cost/introspection ----------------------

test('abuse-resilience flags a GraphQL server with no depth or cost limit', () => {
  const result = run(abuseResiliencePack, {
    'schema.mjs': "const server = new ApolloServer({ typeDefs, resolvers });",
  });
  assert.equal(candidatesById(result, 'abuse.graphql.depth-unbounded').length, 1);
  assert.equal(candidatesById(result, 'abuse.graphql.cost-unbounded').length, 1);
  for (const hit of [...candidatesById(result, 'abuse.graphql.depth-unbounded'), ...candidatesById(result, 'abuse.graphql.cost-unbounded')]) {
    assert.equal(hit.detectorMetadata.claimClass, 'design-recommendation');
    assert.ok(['info', 'low'].includes(hit.severityHint));
  }
});

test('abuse-resilience stays clean on GraphQL depth/cost when limits are configured', () => {
  const result = run(abuseResiliencePack, {
    'schema.mjs': "const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(5), createComplexityLimitRule(1000)] });",
  });
  assert.equal(candidatesById(result, 'abuse.graphql.depth-unbounded').length, 0);
  assert.equal(candidatesById(result, 'abuse.graphql.cost-unbounded').length, 0);
});

test('abuse-resilience flags explicit GraphQL introspection: true as a proven, low-severity information-exposure primitive', () => {
  const result = run(abuseResiliencePack, {
    'schema.mjs': "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });",
  });
  const hits = candidatesById(result, 'abuse.graphql.introspection-enabled');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
  assert.equal(hits[0].severityHint, 'low');
});

// --- abuse-resilience: pagination / over-exposed fields -----------------------

test('abuse-resilience flags unbounded pagination taken directly from request input', () => {
  const result = run(abuseResiliencePack, {
    'list.mjs': "app.get('/items', (req, res) => { db.items.find().limit(req.query.limit); });",
  });
  const hits = candidatesById(result, 'abuse.pagination.unbounded');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
  assert.equal(hits[0].detectorMetadata.resource, 'list.mjs pagination endpoint');
});

test('abuse-resilience stays clean on pagination when the page size is capped', () => {
  const result = run(abuseResiliencePack, {
    'list.mjs': "app.get('/items', (req, res) => { db.items.find().limit(Math.min(req.query.limit, 100)); });",
  });
  assert.equal(candidatesById(result, 'abuse.pagination.unbounded').length, 0);
});

test('abuse-resilience flags over-exposed fields when a sensitive-looking field name coexists with a full-object response and no allowlist', () => {
  const result = run(abuseResiliencePack, {
    'profile.mjs': "const passwordHash = user.passwordHash;\napp.get('/profile', (req, res) => { res.json(user); });",
  });
  const hits = candidatesById(result, 'abuse.data.over-exposed-fields');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
});

test('abuse-resilience stays clean on over-exposed fields when a field allowlist/pick is present', () => {
  const result = run(abuseResiliencePack, {
    'profile.mjs': "const passwordHash = user.passwordHash;\napp.get('/profile', (req, res) => { res.json(_.pick(user, ['id', 'name'])); });",
  });
  assert.equal(candidatesById(result, 'abuse.data.over-exposed-fields').length, 0);
});

// --- abuse-resilience: webhook signature ordering (behavior-aware) -----------

test('abuse-resilience flags a webhook receiver with no signature verification at all', () => {
  const result = run(abuseResiliencePack, {
    'webhook.mjs': "router.post('/stripe/webhook', (req, res) => { process(req.body); });",
  });
  const hits = candidatesById(result, 'abuse.webhook.signature-missing');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
  assert.equal(hits[0].detectorMetadata.resource, 'webhook.mjs webhook receiver');
});

test('abuse-resilience flags a webhook receiver that uses the body before verifying its signature (ordering matters)', () => {
  const result = run(abuseResiliencePack, {
    'webhook.mjs': "router.post('/stripe/webhook', (req, res) => { process(req.body); verifySignature(req); });",
  });
  assert.equal(candidatesById(result, 'abuse.webhook.signature-missing').length, 0);
  const hits = candidatesById(result, 'abuse.webhook.signature-verified-after-use');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
});

test('abuse-resilience stays clean when a webhook receiver verifies the signature before using the body', () => {
  const result = run(abuseResiliencePack, {
    'webhook.mjs': "router.post('/stripe/webhook', (req, res) => { verifySignature(req); process(req.body); });",
  });
  assert.equal(candidatesById(result, 'abuse.webhook.signature-missing').length, 0);
  assert.equal(candidatesById(result, 'abuse.webhook.signature-verified-after-use').length, 0);
});

// --- abuse-resilience: idempotency / resource exhaustion ---------------------

test('abuse-resilience flags a payment mutation with no idempotency key check', () => {
  const result = run(abuseResiliencePack, {
    'charge.mjs': "app.post('/charge', (req, res) => { chargeCard(req.body.amount); });",
  });
  const hits = candidatesById(result, 'abuse.mutation.idempotency-key-missing');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
});

test('abuse-resilience stays clean on idempotency when a key check is present', () => {
  const result = run(abuseResiliencePack, {
    'charge.mjs': "app.post('/charge', (req, res) => { const key = req.headers['idempotency-key']; chargeCard(req.body.amount); });",
  });
  assert.equal(candidatesById(result, 'abuse.mutation.idempotency-key-missing').length, 0);
});

test('abuse-resilience flags an unbounded, request-derived allocation as a proven resource-exhaustion primitive', () => {
  const result = run(abuseResiliencePack, {
    'export.mjs': "app.post('/export', (req, res) => { const buf = new Array(req.body.count); });",
  });
  const hits = candidatesById(result, 'abuse.resource.exhaustion-unbounded-input');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'proven-primitive');
});

test('abuse-resilience stays clean on resource exhaustion when the size is capped', () => {
  const result = run(abuseResiliencePack, {
    'export.mjs': "app.post('/export', (req, res) => { const buf = new Array(Math.min(req.body.count, 1000)); });",
  });
  assert.equal(candidatesById(result, 'abuse.resource.exhaustion-unbounded-input').length, 0);
});

// --- abuse-resilience: circuit breaker (always capped low) -------------------

test('abuse-resilience flags outbound calls with no circuit breaker as a design recommendation capped at low, always', () => {
  const result = run(abuseResiliencePack, {
    'client.mjs': "const data = await axios.get('https://payments.example.com/charge');",
  }, { performanceTraces: [{ file: 'global', costEvidence: true, note: 'irrelevant to circuit breaker' }] });
  const hits = candidatesById(result, 'abuse.resilience.circuit-breaker-absent');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.claimClass, 'design-recommendation');
  assert.equal(hits[0].severityHint, 'low');
});

test('abuse-resilience stays clean on circuit breaker when a breaker/retry pattern is present', () => {
  const result = run(abuseResiliencePack, {
    'client.mjs': "const breaker = new CircuitBreaker(callPaymentGateway);\nconst data = await axios.get('https://payments.example.com/charge');",
  });
  assert.equal(candidatesById(result, 'abuse.resilience.circuit-breaker-absent').length, 0);
});

// --- acceptance: every abuse candidate names resource + attacker control -----

test('every abuse-resilience candidate names the resource and what the attacker controls, and declares non-empty attacker capabilities', () => {
  const files = {
    'server.mjs': "app.listen(3000);",
    'auth.mjs': "app.post('/login', (req, res) => { doLogin(req.body); });",
    'schema.mjs': "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });",
    'list.mjs': "app.get('/items', (req, res) => { db.items.find().limit(req.query.limit); });",
    'profile.mjs': "const password = user.password;\napp.get('/profile', (req, res) => { res.json(user); });",
    'webhook.mjs': "router.post('/stripe/webhook', (req, res) => { process(req.body); });",
    'charge.mjs': "app.post('/charge', (req, res) => { chargeCard(req.body.amount); });",
    'export.mjs': "app.post('/export', (req, res) => { const buf = new Array(req.body.count); });",
    'client.mjs': "const data = await axios.get('https://payments.example.com/charge');",
  };
  const result = run(abuseResiliencePack, files);
  assert.ok(result.candidates.length > 0);
  for (const candidate of result.candidates) {
    assert.ok(typeof candidate.detectorMetadata.resource === 'string' && candidate.detectorMetadata.resource.length > 0, `${candidate.ruleId} missing resource`);
    assert.ok(typeof candidate.detectorMetadata.attackerControlledInput === 'string' && candidate.detectorMetadata.attackerControlledInput.length > 0, `${candidate.ruleId} missing attackerControlledInput`);
    assert.ok(candidate.attackerCapabilities.length > 0, `${candidate.ruleId} has no attackerCapabilities`);
    assert.ok(typeof candidate.detectorMetadata.claimClass === 'string', `${candidate.ruleId} missing claimClass`);
  }
});

// --- acceptance: design recommendations never exceed low, and are labelled --

test('every design-recommendation candidate across both packs is capped at low severity and labelled as such', () => {
  const files = {
    'server.mjs': "app.listen(3000);",
    'schema.mjs': "const server = new ApolloServer({ typeDefs, resolvers });",
    'client.mjs': "const data = await axios.get('https://payments.example.com/charge');",
  };
  const result = run(abuseResiliencePack, files);
  const designRecommendations = result.candidates.filter((c) => c.detectorMetadata.claimClass === 'design-recommendation');
  assert.ok(designRecommendations.length >= 3, 'expected at least the global rate limit, graphql depth/cost, and circuit-breaker recommendations');
  for (const candidate of designRecommendations) {
    assert.ok(SEVERITY_RANK[candidate.severityHint] <= SEVERITY_RANK.low, `${candidate.ruleId} design-recommendation exceeded low severity`);
  }
  const provenPrimitives = result.candidates.filter((c) => c.detectorMetadata.claimClass === 'proven-primitive');
  assert.equal(provenPrimitives.length, 0, 'no proven-primitive candidates expected from this fixture');
});

// --- observability-forensics: sensitive data in error output -----------------

test('observability-forensics flags a raw stack trace returned to the client', () => {
  const result = run(observabilityForensicsPack, {
    'errors.mjs': "app.use((err, req, res, next) => { res.json({ error: err.stack }); });",
  });
  assert.equal(candidatesById(result, 'observability.error.sensitive-data-in-output').length, 1);
});

test('observability-forensics stays clean when the leak is guarded by a non-production check', () => {
  const result = run(observabilityForensicsPack, {
    'errors.mjs': "app.use((err, req, res, next) => { if (process.env.NODE_ENV !== 'production') { res.json({ error: err.stack }); } });",
  });
  assert.equal(candidatesById(result, 'observability.error.sensitive-data-in-output').length, 0);
});

// --- observability-forensics: missing security events ------------------------

test('observability-forensics flags a session-issuing auth-success path with no security-event record, and names the expected event', () => {
  const result = run(observabilityForensicsPack, {
    'auth.mjs': "app.post('/login', (req, res) => { req.session.user = user; res.send('ok'); });",
  });
  const hits = candidatesById(result, 'observability.events.missing-auth-success');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.expectedEvent, 'auth.success');
});

test('observability-forensics stays clean on auth-success when a security-event log call is present', () => {
  const result = run(observabilityForensicsPack, {
    'auth.mjs': "app.post('/login', (req, res) => { req.session.user = user; auditLog('auth.success', user.id); res.send('ok'); });",
  });
  assert.equal(candidatesById(result, 'observability.events.missing-auth-success').length, 0);
});

test('observability-forensics stays clean on auth-success when an upstream logging trace confirms the event is emitted', () => {
  const result = run(
    observabilityForensicsPack,
    { 'auth.mjs': "app.post('/login', (req, res) => { req.session.user = user; res.send('ok'); });" },
    { loggingTraces: [{ file: 'auth.mjs', eventType: 'auth.success' }] },
  );
  assert.equal(candidatesById(result, 'observability.events.missing-auth-success').length, 0);
});

test('observability-forensics flags a 401 auth-failure branch with no security-event record', () => {
  const result = run(observabilityForensicsPack, {
    'auth.mjs': "app.post('/login', (req, res) => { if (!match) { res.status(401).json({ error: 'invalid' }); } });",
  });
  const hits = candidatesById(result, 'observability.events.missing-auth-failure');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.expectedEvent, 'auth.failure');
});

test('observability-forensics flags a role mutation with no security-event record', () => {
  const result = run(observabilityForensicsPack, {
    'admin.mjs': "app.post('/promote', (req, res) => { user.role = 'admin'; res.send('ok'); });",
  });
  const hits = candidatesById(result, 'observability.events.missing-privilege-change');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.expectedEvent, 'privilege.change');
});

test('observability-forensics flags a bulk export path with no security-event record', () => {
  const result = run(observabilityForensicsPack, {
    'reports.mjs': "app.get('/export', (req, res) => { exportToCsv(allRecords, res); });",
  });
  const hits = candidatesById(result, 'observability.events.missing-data-export');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.expectedEvent, 'data.export');
});

// --- observability-forensics: log injection -----------------------------------

test('observability-forensics flags request-derived data concatenated directly into a log statement', () => {
  const result = run(observabilityForensicsPack, {
    'log.mjs': "logger.info('Login attempt: ' + req.body.username);",
  });
  assert.equal(candidatesById(result, 'observability.log.injection').length, 1);
});

test('observability-forensics stays clean on log injection when the value is sanitized first', () => {
  const result = run(observabilityForensicsPack, {
    'log.mjs': "logger.info('Login attempt: ' + sanitizeLog(req.body.username));",
  });
  assert.equal(candidatesById(result, 'observability.log.injection').length, 0);
});

// --- acceptance: observability findings never demand sensitive logging -------

test('no observability rule claim or uncertainty text demands logging credentials, tokens, PII, or a full request body', () => {
  const files = {
    'auth.mjs': "app.post('/login', (req, res) => { req.session.user = user; if (!match) { res.status(401).json({ error: 'invalid' }); } });",
    'admin.mjs': "app.post('/promote', (req, res) => { user.role = 'admin'; res.send('ok'); });",
    'reports.mjs': "app.get('/export', (req, res) => { exportToCsv(allRecords, res); });",
    'errors.mjs': "app.use((err, req, res, next) => { res.json({ error: err.stack }); });",
    'log.mjs': "logger.info('Login attempt: ' + req.body.username);",
  };
  const result = run(observabilityForensicsPack, files);
  assert.ok(result.candidates.length >= 5);

  // A demand to log the sensitive material itself would read like "log the
  // password" / "include the token in the log" / "log the full request
  // body" without any negating "do not" nearby. None of that phrasing may
  // appear anywhere in claim or uncertainty text.
  const forbiddenDemand = /\blog\b[^.]{0,40}\b(?:password|credential|token|secret|api.?key|pii|full request body)\b/i;
  for (const candidate of result.candidates) {
    const text = [candidate.claim, ...candidate.uncertainty].join(' ');
    const demandMatches = text.match(new RegExp(forbiddenDemand, 'gi')) ?? [];
    for (const snippet of demandMatches) {
      assert.ok(/do not|never|no\b/i.test(text.slice(Math.max(0, text.indexOf(snippet) - 20), text.indexOf(snippet))), `${candidate.ruleId} appears to demand sensitive logging: "${snippet}"`);
    }
  }

  // Every "missing security event" candidate must instead carry the
  // explicit non-sensitive-identifiers disclaimer.
  const missingEventRuleIds = new Set([
    'observability.events.missing-auth-success',
    'observability.events.missing-auth-failure',
    'observability.events.missing-privilege-change',
    'observability.events.missing-data-export',
  ]);
  for (const candidate of result.candidates.filter((c) => missingEventRuleIds.has(c.ruleId))) {
    assert.ok(
      candidate.uncertainty.some((u) => /non-sensitive identifiers/.test(u) && /never requires logging credentials, tokens, PII/.test(u)),
      `${candidate.ruleId} missing the non-sensitive-logging disclaimer`,
    );
  }
});

// --- structural invariants across both packs ---------------------------------

test('every candidate from both packs is adjudication-only, cites evidence, and never carries a final verdict', () => {
  const fixtures = [
    [abuseResiliencePack, {
      'a.mjs': "app.listen(3000); app.post('/login', (req, res) => { doLogin(req.body); });",
      'b.mjs': "router.post('/stripe/webhook', (req, res) => { process(req.body); });",
    }],
    [observabilityForensicsPack, {
      'c.mjs': "app.use((err, req, res, next) => { res.json({ error: err.stack }); });",
      'd.mjs': "logger.info('x: ' + req.body.x);",
    }],
  ];
  for (const [pack, files] of fixtures) {
    const result = run(pack, files);
    assert.ok(result.candidates.length > 0, pack.id);
    assert.deepEqual(result.findings, []);
    for (const candidate of result.candidates) {
      assert.equal(candidate.verdict, 'UNADJUDICATED');
      assert.equal(candidate.adjudicationRequired, true);
      assert.ok(!('severity' in candidate));
      assert.ok(!('evidenceStrength' in candidate));
      assert.ok(candidate.evidenceRefs.length > 0, `${candidate.ruleId} has no evidenceRefs`);
    }
  }
});

// --- variantStrategies enumerate equivalent endpoints / event consumers ------

test('variantStrategies enumerate equivalent endpoint and event-consumer variants for representative rules in both packs', () => {
  const abuseFiles = { 'a.mjs': "app.post('/login', (req, res) => { doLogin(req.body); });" };
  const abuseContext = { files: Object.keys(abuseFiles), denominatorDigest: 'sha256:denom', readFile: (f) => abuseFiles[f] };
  const rateLimitVariant = abuseResiliencePack.variantStrategies['abuse.rate-limit.operation-missing'].enumerate(abuseContext);
  assert.ok(rateLimitVariant.matches.length >= 1);
  assert.equal(rateLimitVariant.denominator.digest, 'sha256:denom');
  assert.ok(rateLimitVariant.strategies.length >= 1);

  const webhookFiles = { 'w.mjs': "router.post('/x/webhook', (req, res) => { process(req.body); });" };
  const webhookContext = { files: Object.keys(webhookFiles), denominatorDigest: 'sha256:denom2', readFile: (f) => webhookFiles[f] };
  const webhookVariant = abuseResiliencePack.variantStrategies['abuse.webhook.signature-missing'].enumerate(webhookContext);
  assert.equal(webhookVariant.matches.length, 1);

  const eventFiles = { 'e.mjs': "app.post('/promote', (req, res) => { user.role = 'admin'; });" };
  const eventContext = { files: Object.keys(eventFiles), denominatorDigest: 'sha256:denom3', readFile: (f) => eventFiles[f] };
  const eventVariant = observabilityForensicsPack.variantStrategies['observability.events.missing-privilege-change'].enumerate(eventContext);
  assert.equal(eventVariant.matches.length, 1);
  assert.ok(eventVariant.strategies.length >= 1);
});

// --- clean / mitigated fixtures produce no candidates for either pack --------

test('both packs stay fully clean on a fully mitigated fixture', () => {
  const files = {
    'app.mjs': [
      "app.use(rateLimit({ windowMs: 60000 }));",
      "app.listen(3000);",
      "app.post('/login', loginRateLimit, (req, res) => {",
      '  doLogin(req.body);',
      "  req.session.user = user;",
      "  auditLog('auth.success', user.id);",
      '  if (!match) {',
      "    auditLog('auth.failure', req.body.username_id);",
      "    res.status(401).json({ error: 'invalid' });",
      '  }',
      '});',
      "const server = new ApolloServer({ typeDefs, resolvers, introspection: false, validationRules: [depthLimit(5), createComplexityLimitRule(1000)] });",
      "app.get('/items', (req, res) => { db.items.find().limit(Math.min(req.query.limit, 100)); });",
      "app.get('/profile', (req, res) => { res.json(_.pick(user, ['id', 'name'])); });",
      "router.post('/stripe/webhook', (req, res) => { verifySignature(req); process(req.body); });",
      "app.post('/charge', (req, res) => { const key = req.headers['idempotency-key']; chargeCard(req.body.amount); });",
      "app.post('/export', (req, res) => { const buf = new Array(Math.min(req.body.count, 1000)); });",
      "const breaker = new CircuitBreaker(callPaymentGateway);",
      "app.use((err, req, res, next) => { if (process.env.NODE_ENV !== 'production') { res.json({ error: err.stack }); } });",
      "logger.info('Login attempt: ' + sanitizeLog(req.body.username));",
      "app.post('/promote', (req, res) => { user.role = 'admin'; auditLog('privilege.change', req.params.id); });",
      "app.get('/export2', (req, res) => { exportToCsv(allRecords, res); auditLog('data.export', req.user.id); });",
    ].join('\n'),
  };
  const abuseResult = run(abuseResiliencePack, files);
  const observabilityResult = run(observabilityForensicsPack, files);
  assert.deepEqual(abuseResult.candidates.map((c) => c.ruleId), []);
  assert.deepEqual(observabilityResult.candidates.map((c) => c.ruleId), []);
});

// --- neutral fixture produces no candidates -----------------------------------

test('both packs emit nothing for neutral source with no abuse or observability markers', () => {
  for (const pack of [abuseResiliencePack, observabilityForensicsPack]) {
    const result = run(pack, { 'plain.mjs': 'export const value = 1;' });
    assert.equal(result.candidates.length, 0, pack.id);
  }
});
