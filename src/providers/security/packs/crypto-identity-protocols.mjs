// Crypto / identity-protocol security pack: weak algorithms, insecure
// randomness, key handling, password-hashing choice, and OAuth/OIDC/SAML
// protocol boundaries.
//
// Every rule stamps `detectorMetadata.layer` as either `'primitive'` (a
// cryptographic algorithm/material choice) or `'protocol'` (a boundary check
// in an identity-federation flow). The two layers are never allowed to imply
// each other: a weak-primitive finding never claims a protocol is broken,
// and a protocol finding never claims the underlying primitive is weak.
// Every candidate also names the primitive/protocol element, the use
// context it was observed in, and any control observed nearby — see
// `detectorMetadata.{primitive, useContext, controlObserved}`.
//
// Lexical (pattern-only) detection throughout: never runs a payload, never
// calls a model, never certifies a finding. Candidates are UNADJUDICATED
// allegations via the sealed candidate-engine.

import { digest } from '../contracts.mjs';

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, matchLength, radius = 200) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text.slice(start, end);
}

function repoWideEvidenceRefs(context) {
  const refs = new Set();
  for (const file of context.files) {
    const artifact = findArtifact(context, file);
    for (const ref of artifact?.evidenceRefs ?? []) refs.add(ref);
  }
  return [...refs].sort();
}

const SECURITY_CONTEXT = /password|passwd|secret|token|session|credential|\bauth\b|signature|hmac|api[_-]?key|reset[_-]?code|otp\b/i;
const NON_SECURITY_CONTEXT = /cache[_-]?key|etag|checksum|dedup(?:e|licat)?|idempotenc|content[_-]?hash|fingerprint(?!.*password)/i;
const HMAC_GUARD = /createHmac\s*\(\s*['"](?:md5|sha1)['"]/i;

const WEAK_HASH_CALL = /\b(md5|sha1)\s*\(/gi;

const WEAK_CIPHER_CALL = /createCipher(?:iv)?\s*\(\s*['"]([\w-]+)['"]/gi;
const WEAK_ALGO_NAMES = /^(?:des(?:-ede3)?(?:-cbc)?|rc4(?:-40)?|bf-ecb|(?:aes-(?:128|192|256)-)?ecb|.*-ecb)$/i;

const MATH_RANDOM_CALL = /Math\.random\(\)/g;
const RANDOMNESS_SECURITY_CONTEXT = /token|otp\b|session|reset[_-]?code|password|api[_-]?key|nonce|salt|secret|verification[_-]?code|session[_-]?id/i;
const SECURE_RANDOM_MARKER = /crypto\.randomBytes|crypto\.randomUUID|randomBytes\s*\(|getRandomValues|secureRandom/i;

const HARDCODED_CIPHER_KEY = /createCipheriv\s*\(\s*['"][\w-]+['"]\s*,\s*['"][^'"$]{8,}['"]/gi;
const HARDCODED_JWT_SECRET = /jwt\.sign\s*\(\s*[^,]+,\s*['"][^'"$]{8,}['"]/gi;

const ENCRYPTION_USAGE_MARKER = /createCipheriv\s*\(|crypto\.createCipher\s*\(/i;
const KEY_ROTATION_MARKER = /key[_-]?rotation|rotateKey|kms\.|KeyManagementService|SecretsManager|key[_-]?vault/i;

const UNSALTED_PASSWORD_HASH = /\b(?:md5|sha1|sha256|sha512)\s*\(\s*(?:password|pwd|passwd)\b/gi;
const PASSWORD_KDF_MARKER = /bcrypt|scrypt|argon2|pbkdf2/i;

const OAUTH_AUTHORIZE_URL = /\/(?:oauth2?\/)?authorize\?[^\n'"`]*client_id=[^\n'"`]*/gi;
const STATE_PARAM = /[?&]state=/i;
const PKCE_PARAM = /code_challenge=/i;
const OPENID_SCOPE = /scope=[^&\n'"`]*openid/i;
const NONCE_PARAM = /[?&]nonce=/i;

const SAML_RESPONSE_HANDLER = /\bsaml\w*\.(?:validate|parse|process)(?:Response|Assertion)?\s*\(/gi;
const SAML_SIGNATURE_CONTROL = /verifySignature|checkSignature|validateSignature|wantAssertionsSigned\s*:\s*true|certificate\s*[:=]/i;
const SAML_EXPLICIT_DISABLE = /wantAssertionsSigned\s*:\s*false|ignoreSignature\s*:\s*true|disableSignatureValidation/i;

const TOKEN_VERIFY_CALL = /\b(?:jwt\.verify|jose\.jwtVerify|verifyIdToken)\s*\(/gi;
const AUDIENCE_OPTION = /\baudience\s*[:=]|\baud\s*[:=]/i;
const ISSUER_OPTION = /\bissuer\s*[:=]|\biss\s*[:=]/i;

function classifyHashUseContext(text, index, matchLength) {
  const win = windowAround(text, index, matchLength, 200);
  if (SECURITY_CONTEXT.test(win)) return { useContext: SECURITY_CONTEXT.exec(win)[0].toLowerCase(), severityHint: 'high' };
  if (NON_SECURITY_CONTEXT.test(win)) return { useContext: NON_SECURITY_CONTEXT.exec(win)[0].toLowerCase(), severityHint: 'low' };
  return { useContext: 'unspecified', severityHint: 'medium' };
}

function makeObservation({
  ruleId, layer, claim, severityHint, primitive, useContext, controlObserved,
  file, line, artifact, extraMeta = {}, effectKind, effectAction, effectScope,
  chainRoles, uncertainty, evidenceRefs,
}) {
  return {
    ruleId,
    candidateClass: 'crypto-identity-protocols',
    claim,
    severityHint,
    sources: artifact ? [artifact.id] : [],
    sinks: artifact ? [artifact.id] : [],
    attackerCapabilities: layer === 'protocol' ? ['craft-malicious-link', 'control-network-position'] : ['read-repository', 'compromise-key-material'],
    preconditions: [{
      kind: 'attacker-position', subject: 'actor:external',
      action: layer === 'protocol' ? 'induce-protocol-flow' : 'observe-cryptographic-material',
      scope: null, environment: 'application', tenant: null,
    }],
    effects: [{
      kind: effectKind, subject: 'actor:external', action: effectAction,
      object: artifact?.id ?? null, scope: effectScope, environment: 'application', tenant: null,
    }],
    assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
    chainRoles,
    evidenceRefs: evidenceRefs ?? artifact?.evidenceRefs ?? [],
    detectorMetadata: {
      file, line, layer, primitive, useContext,
      controlObserved: controlObserved ?? null,
      ...extraMeta,
    },
    uncertainty,
  };
}

// Each rule exposes `detect(context)` returning an array of raw findings
// shared between `analyze()` and the rule's variant-strategy `enumerate()`,
// so detection logic is written exactly once per rule.
const RULES = [
  {
    id: 'crypto.primitive.weak-hash-security-context',
    layer: 'primitive',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        WEAK_HASH_CALL.lastIndex = 0;
        let m;
        while ((m = WEAK_HASH_CALL.exec(text)) !== null) {
          if (HMAC_GUARD.test(windowAround(text, m.index, m[0].length, 20))) continue;
          const { useContext, severityHint } = classifyHashUseContext(text, m.index, m[0].length);
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint,
            primitive: m[1].toLowerCase(), useContext,
            claim: useContext === 'unspecified'
              ? `A ${m[1].toUpperCase()} hash call was observed with an unclear (non-security-labeled) use context.`
              : `A ${m[1].toUpperCase()} hash is used in a ${useContext} context; ${m[1].toUpperCase()} is unsuitable for security-sensitive hashing.`,
            uncertainty: useContext === 'low' || severityHint === 'low'
              ? ['The surrounding text suggests a non-security (e.g. cache-key or ETag) use; severity is capped pending adjudication of actual use.']
              : useContext === 'unspecified'
                ? ['No explicit security or non-security keyword was found near this call; the use context is inferred and unproven.']
                : [],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'reverse-or-collide', effectScope: 'weak-hash-primitive',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.primitive.weak-cipher-algorithm',
    layer: 'primitive',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        WEAK_CIPHER_CALL.lastIndex = 0;
        let m;
        while ((m = WEAK_CIPHER_CALL.exec(text)) !== null) {
          if (!WEAK_ALGO_NAMES.test(m[1])) continue;
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint: 'high',
            primitive: m[1].toLowerCase(), useContext: 'symmetric-encryption',
            claim: `A symmetric cipher is configured with a weak or broken algorithm/mode (${m[1]}).`,
            uncertainty: ['Whether this cipher instance protects data at rest, in transit, or neither must be adjudicated.'],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'confidentiality-impact', effectAction: 'decrypt', effectScope: 'weak-cipher-primitive',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.primitive.insecure-randomness',
    layer: 'primitive',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        MATH_RANDOM_CALL.lastIndex = 0;
        let m;
        while ((m = MATH_RANDOM_CALL.exec(text)) !== null) {
          const win = windowAround(text, m.index, m[0].length, 150);
          if (!RANDOMNESS_SECURITY_CONTEXT.test(win)) continue;
          if (SECURE_RANDOM_MARKER.test(win)) continue;
          const ctxMatch = RANDOMNESS_SECURITY_CONTEXT.exec(win);
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint: 'high',
            primitive: 'Math.random', useContext: ctxMatch ? ctxMatch[0].toLowerCase() : 'unspecified',
            claim: 'A non-cryptographic pseudo-random generator (Math.random) appears to produce security-sensitive material.',
            uncertainty: ['Whether this value is used directly as issued credential material or only as a UI/display value must be adjudicated.'],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'credential-possession', effectAction: 'predict', effectScope: 'insecure-randomness',
        chainRoles: ['starter', 'enabler'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.primitive.hardcoded-encryption-key',
    layer: 'primitive',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        for (const [pattern, primitive] of [[HARDCODED_CIPHER_KEY, 'cipher-key'], [HARDCODED_JWT_SECRET, 'jwt-signing-secret']]) {
          pattern.lastIndex = 0;
          let m;
          while ((m = pattern.exec(text)) !== null) {
            found.push({
              file, line: lineOf(text, m.index), artifact, severityHint: 'high',
              primitive, useContext: primitive === 'cipher-key' ? 'symmetric-encryption' : 'token-signing',
              claim: `A ${primitive === 'cipher-key' ? 'cipher key' : 'JWT signing secret'} literal is embedded directly in source rather than sourced from a key store.`,
              uncertainty: ['Whether this literal is a placeholder, a test fixture, or a value that is actually deployed must be adjudicated.'],
              matchDigest: digest(m[0].slice(0, 40) + file + m.index),
            });
          }
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'credential-possession', effectAction: 'possess', effectScope: 'hardcoded-key-material',
        chainRoles: ['starter', 'enabler'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.primitive.key-rotation-absent',
    layer: 'primitive',
    detect(context) {
      const combined = context.files.map((f) => context.readFile(f) ?? '').join('\n');
      if (!ENCRYPTION_USAGE_MARKER.test(combined)) return [];
      if (KEY_ROTATION_MARKER.test(combined)) return [];
      return [{
        file: null, line: null, artifact: null, severityHint: 'low',
        primitive: 'symmetric-encryption-key', useContext: 'repository-wide',
        claim: 'Encryption key usage was observed across the scanned surface with no visible rotation, KMS, or secrets-manager marker.',
        uncertainty: ['A key-rotation policy or KMS binding may exist outside this repository (an external secrets manager, deployment config, or infrastructure-as-code repository).'],
        matchDigest: digest('key-rotation-absent'),
        repoWide: true,
      }];
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: null,
        extraMeta: { scope: 'repository' },
        effectKind: 'integrity-impact', effectAction: 'persist-compromise', effectScope: 'key-rotation-absent',
        chainRoles: ['enabler'], uncertainty: f.uncertainty,
        evidenceRefs: this._repoRefs,
      });
    },
  },
  {
    id: 'crypto.primitive.password-hash-unsalted-fast',
    layer: 'primitive',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        UNSALTED_PASSWORD_HASH.lastIndex = 0;
        let m;
        while ((m = UNSALTED_PASSWORD_HASH.exec(text)) !== null) {
          if (PASSWORD_KDF_MARKER.test(windowAround(text, m.index, m[0].length, 150))) continue;
          const algo = /^\w+/.exec(m[0])[0];
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint: 'high',
            primitive: algo.toLowerCase(), useContext: 'password-hashing',
            claim: `A password is hashed directly with ${algo} rather than a slow, salted password-hashing KDF (bcrypt/scrypt/argon2/pbkdf2).`,
            uncertainty: ['Whether an application-level pepper or salt is applied elsewhere in the call chain must be adjudicated.'],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'credential-possession', effectAction: 'offline-crack', effectScope: 'password-hash-primitive',
        chainRoles: ['starter', 'enabler'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.protocol.oauth-missing-state',
    layer: 'protocol',
    detect(context) {
      return detectAuthorizeUrlGap(context, {
        gapPattern: STATE_PARAM, primitive: 'oauth-state-parameter',
        claim: 'An OAuth authorize URL is constructed without a state parameter, so CSRF binding of the authorization response is not visible.',
        effectScope: 'oauth-state-missing',
      });
    },
    build: buildAuthorizeUrlObservation,
  },
  {
    id: 'crypto.protocol.oauth-missing-pkce',
    layer: 'protocol',
    detect(context) {
      return detectAuthorizeUrlGap(context, {
        gapPattern: PKCE_PARAM, primitive: 'oauth-pkce-code-challenge',
        claim: 'An OAuth authorize URL is constructed without a PKCE code_challenge, so the authorization-code exchange is not bound to a client-held verifier.',
        effectScope: 'oauth-pkce-missing',
      });
    },
    build: buildAuthorizeUrlObservation,
  },
  {
    id: 'crypto.protocol.oidc-missing-nonce',
    layer: 'protocol',
    detect(context) {
      return detectAuthorizeUrlGap(context, {
        gapPattern: NONCE_PARAM, primitive: 'oidc-nonce',
        claim: 'An OpenID Connect authorize URL (scope=openid) is constructed without a nonce, so the ID token is not bound to this authentication request.',
        effectScope: 'oidc-nonce-missing',
        requireScope: OPENID_SCOPE,
      });
    },
    build: buildAuthorizeUrlObservation,
  },
  {
    id: 'crypto.protocol.saml-assertion-signature-unvalidated',
    layer: 'protocol',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        SAML_RESPONSE_HANDLER.lastIndex = 0;
        let m;
        while ((m = SAML_RESPONSE_HANDLER.exec(text)) !== null) {
          const win = windowAround(text, m.index, m[0].length, 200);
          const explicitDisable = SAML_EXPLICIT_DISABLE.test(win);
          const hasControl = SAML_SIGNATURE_CONTROL.test(win);
          if (!explicitDisable && hasControl) continue;
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint: 'high',
            primitive: 'saml-assertion-signature', useContext: 'saml-response-processing',
            claim: explicitDisable
              ? 'SAML assertion-signature validation is explicitly disabled on the response-processing path.'
              : 'A SAML response/assertion is processed with no visible signature-validation call.',
            uncertainty: ['A signature-validating SAML library default (rather than an explicit call in this file) is not visible from this file alone.'],
            matchDigest: digest(m[0] + file + m.index),
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        effectKind: 'control-bypass', effectAction: 'forge-assertion', effectScope: 'saml-signature-validation',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
  {
    id: 'crypto.protocol.oidc-missing-audience-issuer-check',
    layer: 'protocol',
    detect(context) {
      const found = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = findArtifact(context, file);
        TOKEN_VERIFY_CALL.lastIndex = 0;
        let m;
        while ((m = TOKEN_VERIFY_CALL.exec(text)) !== null) {
          const win = windowAround(text, m.index, m[0].length, 200);
          const hasAudience = AUDIENCE_OPTION.test(win);
          const hasIssuer = ISSUER_OPTION.test(win);
          if (hasAudience && hasIssuer) continue;
          const missing = [!hasAudience ? 'audience' : null, !hasIssuer ? 'issuer' : null].filter(Boolean);
          found.push({
            file, line: lineOf(text, m.index), artifact, severityHint: 'high',
            primitive: 'id-token-verification', useContext: 'token-verification',
            claim: `A token-verification call has no visible ${missing.join(' or ')} check, so a token issued for a different audience or by a different issuer may be accepted.`,
            uncertainty: ['A default audience/issuer bound at the verifier-library-configuration level (outside this call) is not visible from this call site alone.'],
            matchDigest: digest(m[0] + file + m.index),
            missing,
          });
        }
      }
      return found;
    },
    build(f) {
      return makeObservation({
        ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
        primitive: f.primitive, useContext: f.useContext, controlObserved: null,
        file: f.file, line: f.line, artifact: f.artifact,
        extraMeta: { missing: f.missing },
        effectKind: 'control-bypass', effectAction: 'accept-cross-audience-token', effectScope: 'oidc-audience-issuer-check',
        chainRoles: ['starter', 'impact'], uncertainty: f.uncertainty,
      });
    },
  },
];

function detectAuthorizeUrlGap(context, { gapPattern, primitive, claim, effectScope, requireScope }) {
  const found = [];
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    const artifact = findArtifact(context, file);
    OAUTH_AUTHORIZE_URL.lastIndex = 0;
    let m;
    while ((m = OAUTH_AUTHORIZE_URL.exec(text)) !== null) {
      if (requireScope && !requireScope.test(m[0])) continue;
      if (gapPattern.test(m[0])) continue;
      found.push({
        file, line: lineOf(text, m.index), artifact, severityHint: 'high',
        primitive, useContext: 'authorization-code-flow', claim,
        uncertainty: ['The parameter may be appended by a client library at request time rather than present in this literal URL construction.'],
        matchDigest: digest(m[0] + file + m.index + primitive),
        _effectScope: effectScope,
      });
    }
  }
  return found;
}

function buildAuthorizeUrlObservation(f) {
  return makeObservation({
    ruleId: this.id, layer: this.layer, claim: f.claim, severityHint: f.severityHint,
    primitive: f.primitive, useContext: f.useContext, controlObserved: null,
    file: f.file, line: f.line, artifact: f.artifact,
    effectKind: 'control-bypass', effectAction: 'bypass', effectScope: f._effectScope,
    chainRoles: ['enabler'], uncertainty: f.uncertainty,
  });
}

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-gap`,
        layer: rule.layer,
        primitive: candidate.detectorMetadata?.primitive ?? null,
        missingControl: null,
        semanticFeatures: [rule.layer, candidate.detectorMetadata?.primitive ?? rule.id],
      };
    },
    enumerate(context) {
      const rawRepoRefs = repoWideEvidenceRefs(context);
      const findings = rule.detect(context);
      const matches = findings.map((f) => ({
        file: f.file ?? 'repository',
        line: f.line ?? 0,
        semanticFingerprint: f.matchDigest,
        disposition: 'CONFIRMED',
      }));
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.layer} finding for ${rule.id} across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches,
        coverageGaps: rawRepoRefs.length ? [] : [],
      };
    },
  };
}

export default Object.freeze({
  id: 'security.crypto-identity-protocols',
  version: '1.0.0',
  candidateClass: 'crypto-identity-protocols',
  description: 'Cryptographic primitive strength/misuse and OAuth/OIDC/SAML protocol boundaries, kept as two never-conflated layers.',
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const rule of RULES) {
      const repoRefs = repoWideEvidenceRefs(context);
      rule._repoRefs = repoRefs;
      const findings = rule.detect(context);
      for (const f of findings) {
        observations.push(rule.build(f));
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
