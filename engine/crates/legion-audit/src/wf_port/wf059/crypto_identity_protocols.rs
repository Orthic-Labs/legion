//! Port of `src/providers/security/packs/crypto-identity-protocols.mjs`.
//!
//! Weak algorithms, insecure randomness, key handling, password-hashing
//! choice, and OAuth/OIDC/SAML protocol boundaries. Every rule stamps
//! `detectorMetadata.layer` as `"primitive"` or `"protocol"`, and the two
//! layers never imply each other, exactly as the JS module comment states.

use super::common::{digest, line_of, window_around, Context, Fact, Observation};
use std::sync::LazyLock;
use regex::Regex;
use serde_json::json;

static SECURITY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)password|passwd|secret|token|session|credential|\bauth\b|signature|hmac|api[_-]?key|reset[_-]?code|otp\b").unwrap()
});
// JS: /cache[_-]?key|etag|checksum|dedup(?:e|licat)?|idempotenc|content[_-]?hash|fingerprint(?!.*password)/i
// The `fingerprint(?!.*password)` branch (a negative lookahead) is handled
// separately in `classify_hash_use_context` below since the `regex` crate
// has no lookaround; every other alternative is a plain regex.
static NON_SECURITY_CONTEXT_PLAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)cache[_-]?key|etag|checksum|dedup(?:e|licat)?|idempotenc|content[_-]?hash").unwrap()
});
static FINGERPRINT_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)fingerprint").unwrap());
static PASSWORD_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)password").unwrap());

static HMAC_GUARD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)createHmac\s*\(\s*['"](?:md5|sha1)['"]"#).unwrap());

static WEAK_HASH_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(md5|sha1)\s*\(").unwrap());

static WEAK_CIPHER_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)createCipher(?:iv)?\s*\(\s*['"]([\w-]+)['"]"#).unwrap());
static WEAK_ALGO_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:des(?:-ede3)?(?:-cbc)?|rc4(?:-40)?|bf-ecb|(?:aes-(?:128|192|256)-)?ecb|.*-ecb)$").unwrap()
});

static MATH_RANDOM_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Math\.random\(\)").unwrap());
static RANDOMNESS_SECURITY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)token|otp\b|session|reset[_-]?code|password|api[_-]?key|nonce|salt|secret|verification[_-]?code|session[_-]?id").unwrap()
});
static SECURE_RANDOM_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)crypto\.randomBytes|crypto\.randomUUID|randomBytes\s*\(|getRandomValues|secureRandom").unwrap());

static HARDCODED_CIPHER_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)createCipheriv\s*\(\s*['"][\w-]+['"]\s*,\s*['"][^'"$]{8,}['"]"#).unwrap());
static HARDCODED_JWT_SECRET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)jwt\.sign\s*\(\s*[^,]+,\s*['"][^'"$]{8,}['"]"#).unwrap());

static ENCRYPTION_USAGE_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)createCipheriv\s*\(|crypto\.createCipher\s*\(").unwrap());
static KEY_ROTATION_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)key[_-]?rotation|rotateKey|kms\.|KeyManagementService|SecretsManager|key[_-]?vault").unwrap());

static UNSALTED_PASSWORD_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:md5|sha1|sha256|sha512)\s*\(\s*(?:password|pwd|passwd)\b").unwrap());
static PASSWORD_KDF_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)bcrypt|scrypt|argon2|pbkdf2").unwrap());

static OAUTH_AUTHORIZE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)/(?:oauth2?/)?authorize\?[^\n'"`]*client_id=[^\n'"`]*"#).unwrap());
static STATE_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[?&]state=").unwrap());
static PKCE_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)code_challenge=").unwrap());
static OPENID_SCOPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)scope=[^&\n'"`]*openid"#).unwrap());
static NONCE_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[?&]nonce=").unwrap());

static SAML_RESPONSE_HANDLER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bsaml\w*\.(?:validate|parse|process)(?:Response|Assertion)?\s*\(").unwrap());
static SAML_SIGNATURE_CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)verifySignature|checkSignature|validateSignature|wantAssertionsSigned\s*:\s*true|certificate\s*[:=]").unwrap()
});
static SAML_EXPLICIT_DISABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)wantAssertionsSigned\s*:\s*false|ignoreSignature\s*:\s*true|disableSignatureValidation").unwrap()
});

static TOKEN_VERIFY_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:jwt\.verify|jose\.jwtVerify|verifyIdToken)\s*\(").unwrap());
static AUDIENCE_OPTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\baudience\s*[:=]|\baud\s*[:=]").unwrap());
static ISSUER_OPTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bissuer\s*[:=]|\biss\s*[:=]").unwrap());

struct UseContext {
    use_context: String,
    severity_hint: &'static str,
}

/// Port of `classifyHashUseContext`, with the `fingerprint(?!.*password)`
/// negative-lookahead branch of `NON_SECURITY_CONTEXT` implemented directly:
/// a `fingerprint` match only counts as a non-security signal when no
/// `password` occurs anywhere after it in the window.
fn classify_hash_use_context(text: &str, index: usize, match_len: usize) -> UseContext {
    let win = window_around(text, index, match_len, 200);
    if let Some(m) = SECURITY_CONTEXT.find(win) {
        return UseContext { use_context: m.as_str().to_lowercase(), severity_hint: "high" };
    }
    if let Some(m) = NON_SECURITY_CONTEXT_PLAIN.find(win) {
        return UseContext { use_context: m.as_str().to_lowercase(), severity_hint: "low" };
    }
    if let Some(m) = FINGERPRINT_WORD.find(win) {
        let after = &win[m.end()..];
        if !PASSWORD_WORD.is_match(after) {
            return UseContext { use_context: "fingerprint".to_string(), severity_hint: "low" };
        }
    }
    UseContext { use_context: "unspecified".to_string(), severity_hint: "medium" }
}

struct RawFinding {
    file: Option<String>,
    line: Option<usize>,
    severity_hint: String,
    claim: String,
    uncertainty: Vec<String>,
    layer: &'static str,
    primitive: String,
    use_context: String,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: Vec<&'static str>,
    extra_meta: serde_json::Value,
}

fn make_observation(rule_id: &str, ctx: &Context, f: RawFinding) -> Observation {
    let artifact = f.file.as_deref().and_then(|file| ctx.find_artifact(file));
    let attacker_capabilities = if f.layer == "protocol" {
        vec!["craft-malicious-link".to_string(), "control-network-position".to_string()]
    } else {
        vec!["read-repository".to_string(), "compromise-key-material".to_string()]
    };
    let precondition_action = if f.layer == "protocol" {
        "induce-protocol-flow"
    } else {
        "observe-cryptographic-material"
    };
    let mut metadata = json!({
        "file": f.file,
        "line": f.line,
        "layer": f.layer,
        "primitive": f.primitive,
        "useContext": f.use_context,
        "controlObserved": serde_json::Value::Null,
    });
    if let serde_json::Value::Object(extra) = f.extra_meta {
        if let serde_json::Value::Object(m) = &mut metadata {
            for (k, v) in extra {
                m.insert(k, v);
            }
        }
    }
    Observation {
        rule_id: rule_id.to_string(),
        candidate_class: "crypto-identity-protocols".to_string(),
        claim: f.claim,
        severity_hint: f.severity_hint,
        sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
        sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
        attacker_capabilities,
        preconditions: vec![Fact {
            kind: "attacker-position".to_string(),
            subject: "actor:external".to_string(),
            action: precondition_action.to_string(),
            object: None,
            scope: None,
            environment: "application".to_string(),
            tenant: None,
        }],
        effects: vec![Fact {
            kind: f.effect_kind.to_string(),
            subject: "actor:external".to_string(),
            action: f.effect_action.to_string(),
            object: artifact.map(|a| a.id.clone()),
            scope: Some(f.effect_scope.to_string()),
            environment: "application".to_string(),
            tenant: None,
        }],
        assets: vec![],
        trust_boundary_crossings: vec![],
        required_controls: vec![],
        observed_controls: vec![],
        chain_roles: f.chain_roles.into_iter().map(String::from).collect(),
        evidence_refs: Vec::new(),
        detector_metadata: metadata,
        uncertainty: f.uncertainty,
    }
}

fn detect_weak_hash(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in WEAK_HASH_CALL.captures_iter(text) {
            let whole = m.get(0).unwrap();
            if HMAC_GUARD.is_match(window_around(text, whole.start(), whole.len(), 20)) {
                continue;
            }
            let algo = m.get(1).unwrap().as_str();
            let use_ctx = classify_hash_use_context(text, whole.start(), whole.len());
            let claim = if use_ctx.use_context == "unspecified" {
                format!("A {} hash call was observed with an unclear (non-security-labeled) use context.", algo.to_uppercase())
            } else {
                format!(
                    "A {} hash is used in a {} context; {} is unsuitable for security-sensitive hashing.",
                    algo.to_uppercase(),
                    use_ctx.use_context,
                    algo.to_uppercase()
                )
            };
            let uncertainty = if use_ctx.use_context == "low" || use_ctx.severity_hint == "low" {
                vec!["The surrounding text suggests a non-security (e.g. cache-key or ETag) use; severity is capped pending adjudication of actual use.".to_string()]
            } else if use_ctx.use_context == "unspecified" {
                vec!["No explicit security or non-security keyword was found near this call; the use context is inferred and unproven.".to_string()]
            } else {
                vec![]
            };
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                severity_hint: use_ctx.severity_hint.to_string(),
                claim,
                uncertainty,
                layer: "primitive",
                primitive: algo.to_lowercase(),
                use_context: use_ctx.use_context,
                effect_kind: "confidentiality-impact",
                effect_action: "reverse-or-collide",
                effect_scope: "weak-hash-primitive",
                chain_roles: vec!["enabler"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_weak_cipher(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in WEAK_CIPHER_CALL.captures_iter(text) {
            let whole = m.get(0).unwrap();
            let algo = m.get(1).unwrap().as_str();
            if !WEAK_ALGO_NAMES.is_match(algo) {
                continue;
            }
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                severity_hint: "high".to_string(),
                claim: format!("A symmetric cipher is configured with a weak or broken algorithm/mode ({algo})."),
                uncertainty: vec!["Whether this cipher instance protects data at rest, in transit, or neither must be adjudicated.".to_string()],
                layer: "primitive",
                primitive: algo.to_lowercase(),
                use_context: "symmetric-encryption".to_string(),
                effect_kind: "confidentiality-impact",
                effect_action: "decrypt",
                effect_scope: "weak-cipher-primitive",
                chain_roles: vec!["enabler"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_insecure_randomness(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in MATH_RANDOM_CALL.find_iter(text) {
            let win = window_around(text, m.start(), m.len(), 150);
            if !RANDOMNESS_SECURITY_CONTEXT.is_match(win) {
                continue;
            }
            if SECURE_RANDOM_MARKER.is_match(win) {
                continue;
            }
            let use_context = RANDOMNESS_SECURITY_CONTEXT
                .find(win)
                .map(|c| c.as_str().to_lowercase())
                .unwrap_or_else(|| "unspecified".to_string());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                severity_hint: "high".to_string(),
                claim: "A non-cryptographic pseudo-random generator (Math.random) appears to produce security-sensitive material.".to_string(),
                uncertainty: vec!["Whether this value is used directly as issued credential material or only as a UI/display value must be adjudicated.".to_string()],
                layer: "primitive",
                primitive: "Math.random".to_string(),
                use_context,
                effect_kind: "credential-possession",
                effect_action: "predict",
                effect_scope: "insecure-randomness",
                chain_roles: vec!["starter", "enabler"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_hardcoded_encryption_key(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for (pattern, primitive, use_context) in [
            (&*HARDCODED_CIPHER_KEY, "cipher-key", "symmetric-encryption"),
            (&*HARDCODED_JWT_SECRET, "jwt-signing-secret", "token-signing"),
        ] {
            for m in pattern.find_iter(text) {
                let claim = format!(
                    "A {} literal is embedded directly in source rather than sourced from a key store.",
                    if primitive == "cipher-key" { "cipher key" } else { "JWT signing secret" }
                );
                out.push(RawFinding {
                    file: Some(file.clone()),
                    line: Some(line_of(text, m.start())),
                    severity_hint: "high".to_string(),
                    claim,
                    uncertainty: vec!["Whether this literal is a placeholder, a test fixture, or a value that is actually deployed must be adjudicated.".to_string()],
                    layer: "primitive",
                    primitive: primitive.to_string(),
                    use_context: use_context.to_string(),
                    effect_kind: "credential-possession",
                    effect_action: "possess",
                    effect_scope: "hardcoded-key-material",
                    chain_roles: vec!["starter", "enabler"],
                    extra_meta: json!({}),
                });
            }
        }
    }
    out
}

fn detect_key_rotation_absent(ctx: &Context) -> Vec<RawFinding> {
    let combined: String = ctx.files.iter().map(|f| ctx.read_file(f)).collect::<Vec<_>>().join("\n");
    if !ENCRYPTION_USAGE_MARKER.is_match(&combined) {
        return vec![];
    }
    if KEY_ROTATION_MARKER.is_match(&combined) {
        return vec![];
    }
    vec![RawFinding {
        file: None,
        line: None,
        severity_hint: "low".to_string(),
        claim: "Encryption key usage was observed across the scanned surface with no visible rotation, KMS, or secrets-manager marker.".to_string(),
        uncertainty: vec!["A key-rotation policy or KMS binding may exist outside this repository (an external secrets manager, deployment config, or infrastructure-as-code repository).".to_string()],
        layer: "primitive",
        primitive: "symmetric-encryption-key".to_string(),
        use_context: "repository-wide".to_string(),
        effect_kind: "integrity-impact",
        effect_action: "persist-compromise",
        effect_scope: "key-rotation-absent",
        chain_roles: vec!["enabler"],
        extra_meta: json!({ "scope": "repository" }),
    }]
}

fn detect_unsalted_password_hash(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in UNSALTED_PASSWORD_HASH.find_iter(text) {
            if PASSWORD_KDF_MARKER.is_match(window_around(text, m.start(), m.len(), 150)) {
                continue;
            }
            let algo = m.as_str().split(|c: char| !c.is_alphanumeric()).next().unwrap_or("");
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                severity_hint: "high".to_string(),
                claim: format!("A password is hashed directly with {algo} rather than a slow, salted password-hashing KDF (bcrypt/scrypt/argon2/pbkdf2)."),
                uncertainty: vec!["Whether an application-level pepper or salt is applied elsewhere in the call chain must be adjudicated.".to_string()],
                layer: "primitive",
                primitive: algo.to_lowercase(),
                use_context: "password-hashing".to_string(),
                effect_kind: "credential-possession",
                effect_action: "offline-crack",
                effect_scope: "password-hash-primitive",
                chain_roles: vec!["starter", "enabler"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn detect_authorize_url_gap(
    ctx: &Context,
    gap_pattern: &Regex,
    primitive: &str,
    claim: &str,
    effect_scope: &'static str,
    require_scope: Option<&Regex>,
) -> Vec<(RawFinding, &'static str)> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in OAUTH_AUTHORIZE_URL.find_iter(text) {
            let matched = m.as_str();
            if let Some(req) = require_scope {
                if !req.is_match(matched) {
                    continue;
                }
            }
            if gap_pattern.is_match(matched) {
                continue;
            }
            out.push((
                RawFinding {
                    file: Some(file.clone()),
                    line: Some(line_of(text, m.start())),
                    severity_hint: "high".to_string(),
                    claim: claim.to_string(),
                    uncertainty: vec!["The parameter may be appended by a client library at request time rather than present in this literal URL construction.".to_string()],
                    layer: "protocol",
                    primitive: primitive.to_string(),
                    use_context: "authorization-code-flow".to_string(),
                    effect_kind: "control-bypass",
                    effect_action: "bypass",
                    effect_scope,
                    chain_roles: vec!["enabler"],
                    extra_meta: json!({}),
                },
                effect_scope,
            ));
        }
    }
    out
}

fn detect_saml_signature(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in SAML_RESPONSE_HANDLER.find_iter(text) {
            let win = window_around(text, m.start(), m.len(), 200);
            let explicit_disable = SAML_EXPLICIT_DISABLE.is_match(win);
            let has_control = SAML_SIGNATURE_CONTROL.is_match(win);
            if !explicit_disable && has_control {
                continue;
            }
            let claim = if explicit_disable {
                "SAML assertion-signature validation is explicitly disabled on the response-processing path.".to_string()
            } else {
                "A SAML response/assertion is processed with no visible signature-validation call.".to_string()
            };
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                severity_hint: "high".to_string(),
                claim,
                uncertainty: vec!["A signature-validating SAML library default (rather than an explicit call in this file) is not visible from this file alone.".to_string()],
                layer: "protocol",
                primitive: "saml-assertion-signature".to_string(),
                use_context: "saml-response-processing".to_string(),
                effect_kind: "control-bypass",
                effect_action: "forge-assertion",
                effect_scope: "saml-signature-validation",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_oidc_audience_issuer(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in TOKEN_VERIFY_CALL.find_iter(text) {
            let win = window_around(text, m.start(), m.len(), 200);
            let has_audience = AUDIENCE_OPTION.is_match(win);
            let has_issuer = ISSUER_OPTION.is_match(win);
            if has_audience && has_issuer {
                continue;
            }
            let mut missing = Vec::new();
            if !has_audience {
                missing.push("audience");
            }
            if !has_issuer {
                missing.push("issuer");
            }
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                severity_hint: "high".to_string(),
                claim: format!(
                    "A token-verification call has no visible {} check, so a token issued for a different audience or by a different issuer may be accepted.",
                    missing.join(" or ")
                ),
                uncertainty: vec!["A default audience/issuer bound at the verifier-library-configuration level (outside this call) is not visible from this call site alone.".to_string()],
                layer: "protocol",
                primitive: "id-token-verification".to_string(),
                use_context: "token-verification".to_string(),
                effect_kind: "control-bypass",
                effect_action: "accept-cross-audience-token",
                effect_scope: "oidc-audience-issuer-check",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({ "missing": missing }),
            });
        }
    }
    out
}

/// Faithful port of the module default export's `analyze(context)`.
pub fn analyze(ctx: &Context) -> Vec<Observation> {
    let mut out = Vec::new();
    for f in detect_weak_hash(ctx) {
        out.push(make_observation("crypto.primitive.weak-hash-security-context", ctx, f));
    }
    for f in detect_weak_cipher(ctx) {
        out.push(make_observation("crypto.primitive.weak-cipher-algorithm", ctx, f));
    }
    for f in detect_insecure_randomness(ctx) {
        out.push(make_observation("crypto.primitive.insecure-randomness", ctx, f));
    }
    for f in detect_hardcoded_encryption_key(ctx) {
        out.push(make_observation("crypto.primitive.hardcoded-encryption-key", ctx, f));
    }
    for f in detect_key_rotation_absent(ctx) {
        out.push(make_observation("crypto.primitive.key-rotation-absent", ctx, f));
    }
    for f in detect_unsalted_password_hash(ctx) {
        out.push(make_observation("crypto.primitive.password-hash-unsalted-fast", ctx, f));
    }
    for (f, _) in detect_authorize_url_gap(
        ctx,
        &STATE_PARAM,
        "oauth-state-parameter",
        "An OAuth authorize URL is constructed without a state parameter, so CSRF binding of the authorization response is not visible.",
        "oauth-state-missing",
        None,
    ) {
        out.push(make_observation("crypto.protocol.oauth-missing-state", ctx, f));
    }
    for (f, _) in detect_authorize_url_gap(
        ctx,
        &PKCE_PARAM,
        "oauth-pkce-code-challenge",
        "An OAuth authorize URL is constructed without a PKCE code_challenge, so the authorization-code exchange is not bound to a client-held verifier.",
        "oauth-pkce-missing",
        None,
    ) {
        out.push(make_observation("crypto.protocol.oauth-missing-pkce", ctx, f));
    }
    for (f, _) in detect_authorize_url_gap(
        ctx,
        &NONCE_PARAM,
        "oidc-nonce",
        "An OpenID Connect authorize URL (scope=openid) is constructed without a nonce, so the ID token is not bound to this authentication request.",
        "oidc-nonce-missing",
        Some(&OPENID_SCOPE),
    ) {
        out.push(make_observation("crypto.protocol.oidc-missing-nonce", ctx, f));
    }
    for f in detect_saml_signature(ctx) {
        out.push(make_observation("crypto.protocol.saml-assertion-signature-unvalidated", ctx, f));
    }
    for f in detect_oidc_audience_issuer(ctx) {
        out.push(make_observation("crypto.protocol.oidc-missing-audience-issuer-check", ctx, f));
    }
    out
}

/// Mirrors the JS module's exported `id`/`version`/`description` constants,
/// useful for a future registry wiring pass.
pub const PACK_ID: &str = "security.crypto-identity-protocols";
pub const PACK_VERSION: &str = "1.0.0";

#[allow(dead_code)]
fn _unused_digest_reexport() -> String {
    digest("unused")
}
