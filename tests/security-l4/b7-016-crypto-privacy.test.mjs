import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import { entity } from '../../providers/security/model-extractors/common.mjs';
import cryptoIdentityPack from '../../providers/security/packs/crypto-identity-protocols.mjs';
import dataPrivacyPack from '../../providers/security/packs/data-privacy.mjs';

const registryPath = fileURLToPath(new URL('../../registry/rules/security/crypto-data-privacy.json', import.meta.url));
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));

const cryptoSourcePath = fileURLToPath(new URL('../../providers/security/packs/crypto-identity-protocols.mjs', import.meta.url));
const privacySourcePath = fileURLToPath(new URL('../../providers/security/packs/data-privacy.mjs', import.meta.url));

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  cortexGenerationId: 'gen', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(pack, files) {
  return {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      cortex: { generationId: BINDING.cortexGenerationId, manifestDigest: BINDING.cortexManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{
      id: pack.id,
      benchmark: { requiredForCleanClaim: true },
      denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files },
    }],
  };
}

function modelFor(files, { extraEntities = [], extraRelations = [] } = {}) {
  const entities = [];
  const evidence = [];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  entities.push(...extraEntities);
  return {
    schemaVersion: 1, kind: 'security-surface-model',
    binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities, relations: extraRelations, initialFacts: [], evidence,
    coverage: {}, coverageGaps: [],
  };
}

function run(pack, sourceByFile, options = {}) {
  const files = Object.keys(sourceByFile);
  const plan = planFor(pack, files);
  const model = modelFor(files, options);
  const projection = { files, sourceText: sourceByFile, auditFacts: options.auditFacts ?? {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

// ---------------------------------------------------------------------------
// Registry <-> pack rule-id parity (both directions), both packs.
// ---------------------------------------------------------------------------

test('registry rule ids and pack rule ids are in exact two-way parity across both packs', () => {
  assert.equal(registry.schemaVersion, 1);
  assert.ok(Array.isArray(registry.rules) && registry.rules.length > 0);

  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set([
    ...cryptoIdentityPack.rules.map((r) => r.id),
    ...dataPrivacyPack.rules.map((r) => r.id),
  ]);

  for (const id of packIds) assert.ok(registryIds.has(id), `registry is missing pack rule ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has an orphan rule ${id} not exported by either pack`);
  assert.equal(registryIds.size, packIds.size);

  for (const rule of registry.rules) {
    assert.equal(typeof rule.version, 'string');
    assert.ok(rule.pack === 'security.crypto-identity-protocols' || rule.pack === 'security.data-privacy');
    assert.equal(typeof rule.class, 'string');
    assert.ok(['primitive', 'protocol', 'lifecycle'].includes(rule.layer), `${rule.id} has an unexpected layer ${rule.layer}`);
    assert.equal(typeof rule.decisionMode, 'string');
    assert.equal(typeof rule.cleanClaim, 'string');
    assert.ok(Array.isArray(rule.requiredControls));
    assert.ok(Array.isArray(rule.applicability));
  }
});

test('no rule id or registry claim string names a regulation as a compliance verdict', () => {
  const forbidden = /GDPR|CCPA|HIPAA/i;
  for (const rule of registry.rules) {
    assert.ok(!forbidden.test(rule.id), `${rule.id} names a regulation`);
    assert.ok(!forbidden.test(JSON.stringify(rule)), `${rule.id} record names a regulation`);
  }
  const cryptoSource = readFileSync(cryptoSourcePath, 'utf8');
  const privacySource = readFileSync(privacySourcePath, 'utf8');
  assert.ok(!forbidden.test(cryptoSource), 'crypto-identity-protocols.mjs must not infer regulatory compliance');
  assert.ok(!forbidden.test(privacySource), 'data-privacy.mjs must not infer regulatory compliance');
});

// ---------------------------------------------------------------------------
// crypto-identity-protocols.mjs — primitive layer.
// ---------------------------------------------------------------------------

test('weak-hash in a security context is named, high severity, and layer=primitive', () => {
  const result = run(cryptoIdentityPack, { 'hash.mjs': 'const digest = md5(password + salt);' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.weak-hash-security-context');
  assert.ok(c, 'expected weak-hash candidate');
  assert.equal(c.severityHint, 'high');
  assert.equal(c.detectorMetadata.layer, 'primitive');
  assert.equal(c.detectorMetadata.primitive, 'md5');
  assert.equal(c.detectorMetadata.useContext, 'password');
  assert.equal(c.detectorMetadata.file, 'hash.mjs');
  assert.equal(typeof c.detectorMetadata.line, 'number');
  assert.equal(c.verdict, 'UNADJUDICATED');
  assert.ok(c.evidenceRefs.length > 0);
});

test('weak-hash used for a non-security purpose (cache key) is never high severity', () => {
  const result = run(cryptoIdentityPack, { 'cache.mjs': 'const cacheKey = md5(JSON.stringify(payload));' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.weak-hash-security-context');
  assert.ok(c, 'expected a capped candidate, not silence');
  assert.notEqual(c.severityHint, 'high');
  assert.notEqual(c.severityHint, 'critical');
  assert.equal(c.detectorMetadata.useContext, 'cachekey');
});

test('weak-hash with an ambiguous context is medium, not high', () => {
  const result = run(cryptoIdentityPack, { 'ambiguous.mjs': 'const h = md5(data);' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.weak-hash-security-context');
  assert.ok(c);
  assert.equal(c.severityHint, 'medium');
  assert.equal(c.detectorMetadata.useContext, 'unspecified');
});

test('weak cipher algorithm/mode is named with primitive and layer=primitive', () => {
  const result = run(cryptoIdentityPack, { 'cipher.mjs': "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);" });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.weak-cipher-algorithm');
  assert.ok(c);
  assert.equal(c.detectorMetadata.layer, 'primitive');
  assert.equal(c.detectorMetadata.primitive, 'des-ede3-cbc');
  assert.equal(c.severityHint, 'high');
});

test('Math.random used for session/token material is flagged as insecure randomness', () => {
  const result = run(cryptoIdentityPack, { 'token.mjs': "const token = Math.random().toString(36); // session token" });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.insecure-randomness');
  assert.ok(c);
  assert.equal(c.detectorMetadata.primitive, 'Math.random');
  assert.equal(c.severityHint, 'high');
});

test('Math.random used with no security context nearby produces no insecure-randomness candidate', () => {
  const result = run(cryptoIdentityPack, { 'jitter.mjs': 'const delay = Math.random() * 100;' });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.primitive.insecure-randomness'));
});

test('crypto.randomBytes for token generation produces no insecure-randomness candidate', () => {
  const result = run(cryptoIdentityPack, { 'token.mjs': "const token = crypto.randomBytes(32).toString('hex');" });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.primitive.insecure-randomness'));
});

test('hardcoded cipher key and hardcoded JWT secret are both flagged', () => {
  const result = run(cryptoIdentityPack, {
    'keys.mjs': [
      "const c = crypto.createCipheriv('aes-256-cbc', 'MySuperSecretKey1234567890AB', iv);",
      "jwt.sign(payload, 'hardcoded-static-secret-value');",
    ].join('\n'),
  });
  const cipherKey = result.candidates.find((x) => x.ruleId === 'crypto.primitive.hardcoded-encryption-key' && x.detectorMetadata.primitive === 'cipher-key');
  const jwtSecret = result.candidates.find((x) => x.ruleId === 'crypto.primitive.hardcoded-encryption-key' && x.detectorMetadata.primitive === 'jwt-signing-secret');
  assert.ok(cipherKey);
  assert.ok(jwtSecret);
});

test('encryption usage with no rotation/KMS marker anywhere flags key-rotation-absent repo-wide', () => {
  const result = run(cryptoIdentityPack, { 'cipher.mjs': "crypto.createCipheriv('aes-256-cbc', key, iv);" });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.key-rotation-absent');
  assert.ok(c);
  assert.equal(c.detectorMetadata.layer, 'primitive');
  assert.ok(c.evidenceRefs.length > 0);
});

test('encryption usage with a KMS/rotation marker present suppresses key-rotation-absent', () => {
  const result = run(cryptoIdentityPack, { 'cipher.mjs': "crypto.createCipheriv('aes-256-cbc', key, iv); // rotated via KeyManagementService" });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.primitive.key-rotation-absent'));
});

test('password hashed directly with sha256 (no KDF) is flagged as unsalted-fast', () => {
  const result = run(cryptoIdentityPack, { 'auth.mjs': 'const hash = sha256(password);' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.primitive.password-hash-unsalted-fast');
  assert.ok(c);
  assert.equal(c.detectorMetadata.primitive, 'sha256');
  assert.equal(c.detectorMetadata.useContext, 'password-hashing');
});

test('bcrypt password hashing produces no candidates at all', () => {
  const result = run(cryptoIdentityPack, { 'auth.mjs': 'const hash = await bcrypt.hash(password, 10);' });
  assert.equal(result.candidates.length, 0);
});

test('argon2 password hashing produces no candidates at all', () => {
  const result = run(cryptoIdentityPack, { 'auth.mjs': 'const hash = await argon2.hash(password);' });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// crypto-identity-protocols.mjs — protocol layer.
// ---------------------------------------------------------------------------

test('OAuth authorize URL without state is flagged; layer=protocol', () => {
  const result = run(cryptoIdentityPack, {
    'oauth.mjs': "const url = 'https://idp.example.com/authorize?client_id=abc123&redirect_uri=https://app.example.com/cb&scope=email&code_challenge=xyz&code_challenge_method=S256';",
  });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.oauth-missing-state');
  assert.ok(c);
  assert.equal(c.detectorMetadata.layer, 'protocol');
  assert.equal(c.detectorMetadata.primitive, 'oauth-state-parameter');
});

test('OAuth authorize URL without PKCE code_challenge is flagged', () => {
  const result = run(cryptoIdentityPack, {
    'oauth.mjs': "const url = 'https://idp.example.com/authorize?client_id=abc123&redirect_uri=cb&state=xyz789&scope=email';",
  });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.oauth-missing-pkce');
  assert.ok(c);
  assert.equal(c.detectorMetadata.layer, 'protocol');
});

test('OIDC authorize URL (scope=openid) without nonce is flagged', () => {
  const result = run(cryptoIdentityPack, {
    'oidc.mjs': "const url = 'https://idp.example.com/authorize?client_id=abc&redirect_uri=cb&state=xyz&code_challenge=abc&code_challenge_method=S256&scope=openid';",
  });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.oidc-missing-nonce');
  assert.ok(c);
});

test('OAuth/OIDC authorize URL with state, PKCE, and nonce all present produces no protocol candidates', () => {
  const result = run(cryptoIdentityPack, {
    'oidc.mjs': "const url = 'https://idp.example.com/authorize?client_id=abc&redirect_uri=cb&state=xyz&code_challenge=abc&code_challenge_method=S256&scope=openid&nonce=n0nce123';",
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.protocol.oauth-missing-state'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.protocol.oauth-missing-pkce'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.protocol.oidc-missing-nonce'));
});

test('SAML response processed with signature validation explicitly disabled is flagged', () => {
  const result = run(cryptoIdentityPack, { 'saml.mjs': 'saml.validateResponse(response, { wantAssertionsSigned: false });' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.saml-assertion-signature-unvalidated');
  assert.ok(c);
  assert.equal(c.detectorMetadata.layer, 'protocol');
  assert.match(c.claim, /explicitly disabled/);
});

test('SAML assertion parsed with no visible signature check at all is flagged', () => {
  const result = run(cryptoIdentityPack, { 'saml.mjs': 'saml.parseAssertion(xml);' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.saml-assertion-signature-unvalidated');
  assert.ok(c);
});

test('SAML response validated with a visible signature-check marker produces no candidate', () => {
  const result = run(cryptoIdentityPack, { 'saml.mjs': 'saml.validateResponse(response); // verifySignature(cert) runs first' });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.protocol.saml-assertion-signature-unvalidated'));
});

test('token verification without audience/issuer options is flagged', () => {
  const result = run(cryptoIdentityPack, { 'verify.mjs': 'jwt.verify(token, publicKey);' });
  const c = result.candidates.find((x) => x.ruleId === 'crypto.protocol.oidc-missing-audience-issuer-check');
  assert.ok(c);
  assert.deepEqual(c.detectorMetadata.missing.sort(), ['audience', 'issuer']);
});

test('token verification with audience and issuer options produces no candidate', () => {
  const result = run(cryptoIdentityPack, {
    'verify.mjs': "jwt.verify(token, publicKey, { audience: 'my-app', issuer: 'https://idp.example.com' });",
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'crypto.protocol.oidc-missing-audience-issuer-check'));
});

// ---------------------------------------------------------------------------
// Primitive vs protocol: never conflated.
// ---------------------------------------------------------------------------

test('primitive-layer and protocol-layer findings never conflate across a combined fixture', () => {
  const result = run(cryptoIdentityPack, {
    'combined.mjs': [
      'const digest = md5(password + salt);',
      "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);",
      "const token = Math.random().toString(36); // session token",
      "const url = 'https://idp.example.com/authorize?client_id=abc&redirect_uri=cb&scope=openid';",
      'saml.parseAssertion(xml);',
      'jwt.verify(token, publicKey);',
    ].join('\n'),
  });
  assert.ok(result.candidates.length >= 6);
  for (const c of result.candidates) {
    assert.equal(c.detectorMetadata.layer, c.ruleId.startsWith('crypto.primitive.') ? 'primitive' : 'protocol');
    if (c.detectorMetadata.layer === 'primitive') {
      assert.ok(!/\boauth\b|\bsaml\b|\boidc\b|\baudience\b|\bissuer\b|\bnonce\b|\bpkce\b/i.test(c.claim), `primitive claim leaks a protocol conclusion: ${c.claim}`);
    } else {
      assert.ok(!/\bmd5\b|\bsha-?1\b|weak cipher|Math\.random/i.test(c.claim), `protocol claim leaks a primitive conclusion: ${c.claim}`);
    }
  }
});

// ---------------------------------------------------------------------------
// data-privacy.mjs — data class + lifecycle stage binding.
// ---------------------------------------------------------------------------

const LIFECYCLE_STAGES = new Set(['collect', 'store', 'process', 'transmit', 'retain', 'export', 'delete']);

test('every data-privacy rule binds a dataClass and a valid lifecycleStage', () => {
  const fixtures = {
    'privacy.log.sensitive-data-unredacted': { 'log.mjs': "logger.info('user login', user.email);" },
    'privacy.collect.pii-without-consent': { 'signup.mjs': 'function signup(req) {\n  const { email, phone } = req.body;\n}' },
    'privacy.store.unencrypted-pii': { 'store.mjs': 'await db.users.save({ email: user.email, password: user.password });' },
    'privacy.transmit.unencrypted-channel': { 'transmit.mjs': "fetch('http://api.example.com/track', { method: 'POST', body: JSON.stringify({ email: user.email }) });" },
    'privacy.retain.unbounded-retention': { 'retain.mjs': 'await db.users.save({ email: user.email });' },
    'privacy.retain.backup-unencrypted': { 'backup-users.mjs': 'const record = { email: user.email, address: user.address };' },
    'privacy.export.unrestricted-data-export': { 'export.mjs': "function exportUsers(req, res) {\n  const rows = buildRows(users, ['email', 'phone']);\n  res.send(rows);\n}" },
    'privacy.delete.no-erasure-path': { 'delete.mjs': 'await db.users.save({ email: user.email });' },
    'privacy.process.tenant-data-crossover': {
      'tenant.mjs': "function adminQuery() {\n  return Project.find({ status: 'active' });\n}\nfunction scopedQuery(tenantId) {\n  return Project.find({ tenantId, status: 'active' });\n}",
    },
  };
  for (const [ruleId, sourceByFile] of Object.entries(fixtures)) {
    const result = run(dataPrivacyPack, sourceByFile);
    const c = result.candidates.find((x) => x.ruleId === ruleId);
    assert.ok(c, `expected a candidate for ${ruleId}`);
    assert.equal(c.verdict, 'UNADJUDICATED');
    assert.ok(c.evidenceRefs.length > 0, `${ruleId} candidate must carry evidence`);
    assert.equal(typeof c.detectorMetadata.dataClass, 'string');
    assert.ok(c.detectorMetadata.dataClass.length > 0, `${ruleId} must name a dataClass`);
    assert.ok(LIFECYCLE_STAGES.has(c.detectorMetadata.lifecycleStage), `${ruleId} has an invalid lifecycleStage ${c.detectorMetadata.lifecycleStage}`);
  }
});

test('redacted logging produces no privacy.log candidate', () => {
  const result = run(dataPrivacyPack, { 'log.mjs': "logger.info('user login', redact(user.email));" });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'privacy.log.sensitive-data-unredacted'));
});

// ---------------------------------------------------------------------------
// High-impact privacy claims require observed sensitive-data classification.
// ---------------------------------------------------------------------------

test('a high-impact privacy finding with no observed classification is capped at medium with explicit uncertainty', () => {
  const result = run(dataPrivacyPack, { 'store.mjs': 'await db.users.save({ email: user.email, password: user.password });' });
  const c = result.candidates.find((x) => x.ruleId === 'privacy.store.unencrypted-pii');
  assert.ok(c);
  assert.equal(c.severityHint, 'medium');
  assert.equal(c.detectorMetadata.classificationObserved, false);
  assert.ok(c.uncertainty.some((u) => /classification/i.test(u)), 'must carry an explicit classification uncertainty');
});

test('a high-impact privacy finding with an observed model data-store classification is not capped', () => {
  const file = 'store.mjs';
  const dataStore = entity('data-store', 'users-table', { dataClass: 'pii', file }, ['ev:store']);
  const result = run(dataPrivacyPack, { [file]: 'await db.users.save({ email: user.email, password: user.password });' }, {
    extraEntities: [dataStore],
  });
  const c = result.candidates.find((x) => x.ruleId === 'privacy.store.unencrypted-pii');
  assert.ok(c);
  assert.equal(c.severityHint, 'high');
  assert.equal(c.detectorMetadata.classificationObserved, true);
  assert.equal(c.detectorMetadata.dataClass, 'pii');
});

test('a high-impact privacy finding with an observed audit-facts classification is not capped', () => {
  const file = 'store.mjs';
  const result = run(dataPrivacyPack, { [file]: 'await db.users.save({ email: user.email, password: user.password });' }, {
    auditFacts: { dataPrivacy: { classifications: [{ file, dataClass: 'financial' }] } },
  });
  const c = result.candidates.find((x) => x.ruleId === 'privacy.store.unencrypted-pii');
  assert.ok(c);
  assert.equal(c.severityHint, 'high');
  assert.equal(c.detectorMetadata.classificationObserved, true);
  assert.equal(c.detectorMetadata.dataClass, 'financial');
});

// ---------------------------------------------------------------------------
// Marketing privacy claims cross-link to copy/docs findings via claimRefs.
// ---------------------------------------------------------------------------

test('a marketing privacy claim contradicted by tracking code is flagged without a claim-proof artifact and records the gap as an uncertainty', () => {
  const result = run(dataPrivacyPack, {
    'docs/privacy-policy.md': 'We do not track your activity across our site.',
    'analytics.mjs': "mixpanel.track('page_view', { distinct_id: user.id });",
  });
  const c = result.candidates.find((x) => x.ruleId === 'privacy.claim.marketing-mismatch');
  assert.ok(c);
  assert.deepEqual(c.detectorMetadata.claimRefs, []);
  assert.ok(c.uncertainty.some((u) => /no claim-proof/i.test(u)));
});

test('a marketing privacy claim links to a claim-proof artifact when one is available', () => {
  const result = run(dataPrivacyPack, {
    'docs/privacy-policy.md': 'We do not track your activity across our site.',
    'analytics.mjs': "mixpanel.track('page_view', { distinct_id: user.id });",
  }, {
    auditFacts: {
      claimProof: {
        claims: [{ id: 'claim-1', file: 'docs/privacy-policy.md', text: 'We do not track your activity across our site. Ever.' }],
      },
    },
  });
  const c = result.candidates.find((x) => x.ruleId === 'privacy.claim.marketing-mismatch');
  assert.ok(c);
  assert.deepEqual(c.detectorMetadata.claimRefs, ['claim-1']);
  assert.ok(c.uncertainty.some((u) => /cross-linked/i.test(u)));
});

test('no candidates emitted for entirely neutral source across both packs', () => {
  const neutral = { 'neutral.mjs': 'export const value = 1;' };
  assert.equal(run(cryptoIdentityPack, neutral).candidates.length, 0);
  assert.equal(run(dataPrivacyPack, neutral).candidates.length, 0);
});
