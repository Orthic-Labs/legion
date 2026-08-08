// B7-014 — browser, HTTP, proxy, cache, and protocol packs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import { entity } from '../../providers/security/model-extractors/common.mjs';
import browserClientPack from '../../providers/security/packs/browser-client.mjs';
import httpProtocolCachePack from '../../providers/security/packs/http-protocol-cache.mjs';

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

// --- registry parity -------------------------------------------------------

test('registry rule ids match browser-client and http-protocol-cache pack rule ids exactly, in both directions', () => {
  const registry = JSON.parse(readFileSync(new URL('../../registry/rules/security/browser-http.json', import.meta.url), 'utf8'));
  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set([...browserClientPack.rules.map((r) => r.id), ...httpProtocolCachePack.rules.map((r) => r.id)]);
  assert.equal(registryIds.size, registry.rules.length, 'registry rule ids must be unique');
  for (const id of packIds) assert.ok(registryIds.has(id), `registry missing pack rule id ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has a rule id no pack declares: ${id}`);
  assert.deepEqual([...registryIds].sort(), [...packIds].sort());
  for (const rule of registry.rules) {
    assert.ok(['exploitable-primitive', 'defense-in-depth'].includes(rule.primitiveClass), `${rule.id} primitiveClass`);
    assert.ok(['security.browser-client', 'security.http-protocol-cache'].includes(rule.pack), `${rule.id} pack`);
  }
});

// --- forbidden: no network imports -----------------------------------------

test('neither pack imports or references a live network module', () => {
  const forbidden = /\bnode:https?\b|\bnode:net\b|\bnode:dgram\b|from\s+['"]https?['"]|require\(\s*['"]https?['"]\s*\)|from\s+['"]net['"]|from\s+['"]dgram['"]|require\(\s*['"]net['"]\s*\)|require\(\s*['"]dgram['"]\s*\)/;
  for (const relative of ['../../providers/security/packs/browser-client.mjs', '../../providers/security/packs/http-protocol-cache.mjs']) {
    const source = readFileSync(new URL(relative, import.meta.url), 'utf8');
    assert.ok(!forbidden.test(source), `${relative} must not import a live network module`);
    assert.ok(!source.includes('import '), `${relative} must be self-contained (no imports at all)`);
  }
});

// --- browser-client: CSRF ---------------------------------------------------

test('browser-client flags a cookie-session state-changing route with no CSRF token check', () => {
  const result = run(browserClientPack, {
    'routes.mjs': "app.post('/transfer', (req, res) => { res.cookie('session', token); doTransfer(req.body); });",
  });
  const hits = candidatesById(result, 'csrf.state-changing-route.missing-token');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.primitiveClass, 'exploitable-primitive');
  assert.equal(hits[0].detectorMetadata.method, 'POST');
  assert.equal(hits[0].detectorMetadata.path, '/transfer');
  assert.equal(hits[0].detectorMetadata.file, 'routes.mjs');
  assert.ok(hits[0].evidenceRefs.length > 0);
});

test('browser-client stays clean when a CSRF token check is present', () => {
  const result = run(browserClientPack, {
    'routes.mjs': "app.post('/transfer', (req, res) => { res.cookie('session', token); csrfProtection(req); doTransfer(req.body); });",
  });
  assert.equal(candidatesById(result, 'csrf.state-changing-route.missing-token').length, 0);
});

test('browser-client flags SameSite=None without Secure, and a session cookie with no SameSite at all', () => {
  const result = run(browserClientPack, {
    'cookies.mjs': "res.cookie('sessionToken', v, { SameSite=None });\nres.cookie('authToken', v, { httpOnly: true });",
  });
  assert.ok(candidatesById(result, 'csrf.samesite-none-without-secure').length >= 1);
  assert.ok(candidatesById(result, 'csrf.samesite-missing').length >= 1);
});

// --- browser-client: CORS ---------------------------------------------------

test('browser-client flags Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true', () => {
  const result = run(browserClientPack, {
    'cors.mjs': "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
  });
  const hits = candidatesById(result, 'cors.wildcard-origin-with-credentials');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severityHint, 'critical');
  assert.equal(hits[0].detectorMetadata.primitiveClass, 'exploitable-primitive');
  assert.equal(hits[0].detectorMetadata.header, 'Access-Control-Allow-Origin + Access-Control-Allow-Credentials');
  assert.equal(hits[0].detectorMetadata.file, 'cors.mjs');
  assert.ok(Number.isInteger(hits[0].detectorMetadata.line));
});

test('browser-client flags a reflected Origin header with no allowlist check', () => {
  const result = run(browserClientPack, {
    'cors.mjs': "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);",
  });
  assert.equal(candidatesById(result, 'cors.reflected-origin-without-allowlist').length, 1);
});

// --- browser-client: clickjacking / CSP (deployment-aware, repo-wide) ------

test('browser-client flags missing frame protection and missing CSP as capped defense-in-depth without deployment evidence', () => {
  const result = run(browserClientPack, {
    'page.mjs': "app.get('/', (req, res) => { res.render('index'); });",
  });
  const clickjack = candidatesById(result, 'clickjacking.missing-frame-protection');
  const csp = candidatesById(result, 'csp.missing');
  assert.equal(clickjack.length, 1);
  assert.equal(csp.length, 1);
  for (const hit of [...clickjack, ...csp]) {
    assert.equal(hit.detectorMetadata.primitiveClass, 'defense-in-depth');
    assert.ok(['info', 'low'].includes(hit.severityHint));
    assert.ok(hit.detectorMetadata.deploymentAssumption);
    assert.ok(hit.uncertainty.some((u) => /Deployment assumption/.test(u)));
  }
});

test('browser-client is clean when X-Frame-Options and a strict CSP are both present', () => {
  const result = run(browserClientPack, {
    'page.mjs': "app.get('/', (req, res) => { res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Content-Security-Policy', \"default-src 'self'\"); res.render('index'); });",
  });
  assert.equal(candidatesById(result, 'clickjacking.missing-frame-protection').length, 0);
  assert.equal(candidatesById(result, 'csp.missing').length, 0);
});

test('browser-client flags CSP unsafe-inline, unsafe-eval, and wildcard sources, all capped as defense-in-depth', () => {
  const result = run(browserClientPack, {
    'inline.mjs': "res.setHeader('Content-Security-Policy', \"script-src 'self' 'unsafe-inline'\");",
    'eval.mjs': "res.setHeader('Content-Security-Policy', \"script-src 'self' 'unsafe-eval'\");",
    'wildcard.mjs': "res.setHeader('Content-Security-Policy', \"script-src *\");",
  });
  for (const ruleId of ['csp.unsafe-inline', 'csp.unsafe-eval', 'csp.wildcard-source']) {
    const hits = candidatesById(result, ruleId);
    assert.equal(hits.length, 1, ruleId);
    assert.equal(hits[0].detectorMetadata.primitiveClass, 'defense-in-depth');
    assert.ok(['info', 'low'].includes(hits[0].severityHint), ruleId);
  }
});

// --- browser-client: open redirect / OAuth ---------------------------------

test('browser-client flags an unvalidated redirect target and an unvalidated OAuth redirect_uri', () => {
  const result = run(browserClientPack, {
    'redirect.mjs': 'res.redirect(req.query.next);',
    'oauth.mjs': 'const redirect_uri = req.query.redirect_uri;',
  });
  assert.equal(candidatesById(result, 'open-redirect.unvalidated-target').length, 1);
  assert.equal(candidatesById(result, 'oauth.redirect-uri.unvalidated').length, 1);
});

test('browser-client stays clean when redirect and OAuth targets are allowlisted', () => {
  const result = run(browserClientPack, {
    'redirect.mjs': "if (isValidRedirect(req.query.next)) res.redirect(req.query.next);",
    'oauth.mjs': "const redirect_uri = req.query.redirect_uri; if (redirect_uri === 'https://app.example.com/callback') {}",
  });
  assert.equal(candidatesById(result, 'open-redirect.unvalidated-target').length, 0);
  assert.equal(candidatesById(result, 'oauth.redirect-uri.unvalidated').length, 0);
});

// --- http-protocol-cache: HSTS / HTTPS / security headers ------------------

test('http-protocol-cache flags a plain HTTP server with no HTTPS enforcement', () => {
  const result = run(httpProtocolCachePack, {
    'server.mjs': "http.createServer((req, res) => { res.end('ok'); }).listen(80);",
  });
  const hits = candidatesById(result, 'https.not-enforced');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.primitiveClass, 'exploitable-primitive');
});

test('http-protocol-cache keeps runtime and source disagreement visible instead of silently resolving it', () => {
  const result = run(
    httpProtocolCachePack,
    { 'server.mjs': "res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');" },
    { runtimeHeaders: { headers: { 'strict-transport-security': null } } },
  );
  const hits = candidatesById(result, 'hsts.missing');
  assert.equal(hits.length, 1);
  assert.deepEqual(hits[0].detectorMetadata.disagreement, {
    subject: 'Strict-Transport-Security header',
    sourceValue: 'present',
    runtimeValue: 'absent',
  });
  assert.equal(hits[0].detectorMetadata.deploymentAssumption, undefined);
});

test('http-protocol-cache is clean when the runtime header matches a compliant source header', () => {
  const result = run(
    httpProtocolCachePack,
    { 'server.mjs': "res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');" },
    { runtimeHeaders: { headers: { 'strict-transport-security': 'max-age=63072000; includeSubDomains' } } },
  );
  assert.equal(candidatesById(result, 'hsts.missing').length, 0);
});

// --- http-protocol-cache: cache / proxy / smuggling / content-type ---------

test('http-protocol-cache proxy-trust candidates cite the exact file, line, and config key', () => {
  const result = run(httpProtocolCachePack, { 'app.mjs': "const x = 1;\napp.set('trust proxy', true);\n" });
  const hits = candidatesById(result, 'proxy.trust-misconfigured');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.file, 'app.mjs');
  assert.equal(hits[0].detectorMetadata.line, 2);
  assert.equal(hits[0].detectorMetadata.config, 'trust proxy: true');
});

test('http-protocol-cache flags a publicly cacheable authenticated route and stays clean with no-store', () => {
  const dirty = run(httpProtocolCachePack, {
    'profile.mjs': "app.get('/profile', (req, res) => { res.setHeader('Cache-Control', 'public, max-age=600'); res.send(req.session.user); });",
  });
  assert.equal(candidatesById(dirty, 'cache.sensitive-content-cacheable').length, 1);

  const clean = run(httpProtocolCachePack, {
    'profile.mjs': "app.get('/profile', (req, res) => { res.setHeader('Cache-Control', 'no-store'); res.send(req.session.user); });",
  });
  assert.equal(candidatesById(clean, 'cache.sensitive-content-cacheable').length, 0);
});

test('http-protocol-cache flags conflicting Content-Length/Transfer-Encoding as a request-smuggling precondition only', () => {
  const result = run(httpProtocolCachePack, {
    'raw.mjs': "const head = 'Content-Length: ' + len + '\\r\\nTransfer-Encoding: chunked\\r\\n';",
  });
  const hits = candidatesById(result, 'smuggling.conflicting-content-length-transfer-encoding');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detectorMetadata.primitiveClass, 'exploitable-primitive');
  assert.ok(hits[0].uncertainty.some((u) => /precondition only/.test(u)));
});

test('http-protocol-cache flags a naive first-hop split of a forwarded header as an ambiguous proxy chain', () => {
  const result = run(httpProtocolCachePack, {
    'forward.mjs': "const ip = req.headers['x-forwarded-for'].split(',')[0];",
  });
  assert.equal(candidatesById(result, 'smuggling.ambiguous-proxy-chain').length, 1);
});

test('http-protocol-cache flags a text response Content-Type with no charset', () => {
  const result = run(httpProtocolCachePack, {
    'render.mjs': "res.setHeader('Content-Type', 'text/html');",
  });
  assert.equal(candidatesById(result, 'headers.content-type-missing-charset').length, 1);
});

// --- acceptance: missing deployment evidence limits claims -----------------

test('http-protocol-cache: missing deployment evidence caps every deployment-aware candidate at medium and records an explicit assumption', () => {
  const files = {
    'server.mjs': "http.createServer((req, res) => { res.end('ok'); });",
    'proxy.mjs': "app.set('trust proxy', true);",
    'profile.mjs': "app.get('/profile', (req, res) => { res.setHeader('Cache-Control', 'public, max-age=600'); res.send(req.session.user); });",
  };
  const result = run(httpProtocolCachePack, files);
  assert.ok(result.candidates.length > 0);
  for (const candidate of result.candidates) {
    assert.ok(SEVERITY_RANK[candidate.severityHint] <= SEVERITY_RANK.medium, `${candidate.ruleId} exceeded medium without deployment evidence`);
    assert.ok(candidate.detectorMetadata.deploymentAssumption, `${candidate.ruleId} missing deploymentAssumption metadata`);
    assert.ok(candidate.uncertainty.some((u) => /Deployment assumption/.test(u)), `${candidate.ruleId} missing deployment-assumption uncertainty`);
  }
});

test('browser-client: missing deployment evidence never exceeds medium for header-based claims', () => {
  const result = run(browserClientPack, { 'page.mjs': "app.get('/', (req, res) => { res.render('index'); });" });
  for (const candidate of result.candidates) {
    assert.ok(SEVERITY_RANK[candidate.severityHint] <= SEVERITY_RANK.medium, candidate.ruleId);
  }
});

// --- clean / mitigated fixtures produce no candidates -----------------------

test('both packs stay fully clean on a mitigated fixture: CSRF token, SameSite=Strict+Secure, strict CSP, frame protection, HSTS, nosniff, and no-store on an authenticated route', () => {
  const files = {
    'app.mjs': [
      "app.get('/', (req, res) => { res.render('index'); });",
      "app.post('/update', (req, res) => {",
      '  csrfProtection(req);',
      "  res.cookie('session', token, { httpOnly: true, sameSite: 'Strict', secure: true });",
      "  res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self'\");",
      "  res.setHeader('X-Frame-Options', 'DENY');",
      "  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');",
      "  res.setHeader('X-Content-Type-Options', 'nosniff');",
      '  if (req.session.user) {',
      "    res.setHeader('Cache-Control', 'no-store');",
      '  }',
      '});',
    ].join('\n'),
  };
  const browserResult = run(browserClientPack, files);
  const protocolResult = run(httpProtocolCachePack, files);
  assert.deepEqual(browserResult.candidates.map((c) => c.ruleId), []);
  assert.deepEqual(protocolResult.candidates.map((c) => c.ruleId), []);
});

// --- structural invariants across both packs --------------------------------

test('every candidate from both packs is adjudication-only, cites evidence, and never carries a final verdict', () => {
  const fixtures = [
    [browserClientPack, {
      'a.mjs': "app.post('/x', (req, res) => { res.cookie('session', t); doThing(req.body); });",
      'b.mjs': "res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Credentials', 'true');",
    }],
    [httpProtocolCachePack, {
      'c.mjs': "http.createServer((req, res) => { res.end('ok'); });",
      'd.mjs': "app.set('trust proxy', true);",
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
      assert.ok(typeof candidate.detectorMetadata.primitiveClass === 'string', `${candidate.ruleId} missing detectorMetadata.primitiveClass`);
    }
  }
});

// --- variantStrategies enumerate route/config variants ---------------------

test('variantStrategies enumerate route and configuration variants for representative rules in both packs', () => {
  const filesMap = { 'a.mjs': "app.post('/x', (req, res) => { res.cookie('session', t); doThing(req.body); });" };
  const context = { files: Object.keys(filesMap), denominatorDigest: 'sha256:denom', readFile: (f) => filesMap[f] };
  const csrfVariant = browserClientPack.variantStrategies['csrf.state-changing-route.missing-token'].enumerate(context);
  assert.ok(csrfVariant.matches.length >= 1);
  assert.equal(csrfVariant.denominator.digest, 'sha256:denom');
  assert.ok(csrfVariant.strategies.length >= 1);

  const hstsVariant = httpProtocolCachePack.variantStrategies['hsts.missing'].enumerate({
    files: ['b.mjs'], denominatorDigest: 'sha256:denom2', readFile: () => 'no headers here',
  });
  assert.equal(hstsVariant.matches.length, 1);
});
