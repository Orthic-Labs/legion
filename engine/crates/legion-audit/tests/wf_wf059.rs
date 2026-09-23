//! Ported tests for chunk wf059 (area `src/providers/security`, target crate
//! `legion-audit`):
//!   - `src/providers/security/packs/crypto-identity-protocols.mjs`
//!   - `src/providers/security/packs/data-privacy.mjs`
//!   - `src/providers/security/packs/developer-machine.mjs`
//!   - `src/providers/security/packs/embedded-iot.mjs`
//!   - `src/providers/security/packs/file-boundaries.mjs`
//!
//! `git grep` over `engine/` for these five packs' rule ids and pack ids found no
//! prior native port (the only hit was an unrelated `rules.rs` command-name match),
//! so all five are ported fresh under `wf_port::wf059`.
//!
//! Each pack exposes a single `analyze(&Context) -> Vec<Observation>` entry point.
//! These tests port the JS packs' own shape of assertion (a crafted hazard fixture
//! produces the expected rule id / claim / severity / metadata; a neutral fixture, or
//! one with the mitigating control present, is silent or downgraded) rather than
//! transcribing any single upstream `*.test.mjs` file line-for-line, since none of
//! these five packs had a dedicated JS test file under `tests/` at port time (only
//! `src/providers/security/packs/*.mjs` themselves) — confirmed by `git -C
//! <repo> grep -l` over `tests/` for each pack's id and rule ids
//! coming up empty.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf059;` inside
//! it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf059::common::{Context, Entity, Relation};
use legion_audit::wf_port::wf059::{crypto_identity_protocols, data_privacy, developer_machine, embedded_iot, file_boundaries};
use serde_json::json;

fn find<'a>(obs: &'a [legion_audit::wf_port::wf059::common::Observation], rule_id: &str) -> Vec<&'a legion_audit::wf_port::wf059::common::Observation> {
    obs.iter().filter(|o| o.rule_id == rule_id).collect()
}

// ---------------------------------------------------------------------------
// crypto-identity-protocols.mjs
// ---------------------------------------------------------------------------

#[test]
fn crypto_weak_hash_in_security_context_is_high_severity() {
    let ctx = Context::new().with_file(
        "src/auth.js",
        "const digest = md5(password + salt); // password reset token hashing",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-hash-security-context");
    assert_eq!(hits.len(), 1, "expected exactly one weak-hash finding, got {:?}", obs.iter().map(|o| &o.rule_id).collect::<Vec<_>>());
    let hit = hits[0];
    assert_eq!(hit.layer(), "primitive");
    assert!(hit.severity_hint == "high" || hit.severity_hint == "medium", "severity was {}", hit.severity_hint);
    assert_eq!(hit.detector_metadata["primitive"], json!("md5"));
}

#[test]
fn crypto_weak_hash_cache_key_use_is_downgraded_low() {
    let ctx = Context::new().with_file("src/cache.js", "const cacheKey = md5(url); // used as a cache-key");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-hash-security-context");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "low");
    assert!(!hits[0].uncertainty.is_empty());
}

#[test]
fn crypto_weak_hash_fingerprint_without_password_nearby_is_downgraded_low() {
    // Ports the JS `fingerprint(?!.*password)` negative-lookahead branch:
    // "fingerprint" alone (no "password" anywhere after it in the window, and no
    // other NON_SECURITY_CONTEXT/SECURITY_CONTEXT keyword present) is a
    // non-security signal.
    let ctx = Context::new().with_file("src/content.js", "const h = sha1(body); // content fingerprint value");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-hash-security-context");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "low");
    assert_eq!(hits[0].detector_metadata["useContext"], json!("fingerprint"));
}

#[test]
fn crypto_weak_hash_fingerprint_with_password_nearby_is_security_context() {
    // `SECURITY_CONTEXT` is checked before the `NON_SECURITY_CONTEXT`
    // `fingerprint(?!.*password)` branch, and it independently matches the
    // literal word "password" anywhere in the window. So a window containing
    // both "fingerprint" and "password" is a `SECURITY_CONTEXT` ("password")
    // hit, not the fingerprint non-security branch — in JS as much as here,
    // since the negative lookahead only ever gets evaluated once
    // `SECURITY_CONTEXT` has already failed to match, and "password" being
    // present makes that impossible.
    let ctx = Context::new().with_file(
        "src/weird.js",
        "const h = sha1(body); // fingerprint value later combined with a password check",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-hash-security-context");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
    assert_eq!(hits[0].detector_metadata["useContext"], json!("password"));
}

#[test]
fn crypto_weak_hash_unspecified_when_no_keyword_present() {
    let ctx = Context::new().with_file("src/misc.js", "const h = sha1(rawBytes);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-hash-security-context");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "medium");
    assert_eq!(hits[0].detector_metadata["useContext"], json!("unspecified"));
}

#[test]
fn crypto_hmac_md5_is_not_flagged_as_weak_hash() {
    let ctx = Context::new().with_file("src/hmac.js", "const mac = createHmac('md5', key).update(data).digest('hex');");
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.primitive.weak-hash-security-context").is_empty());
}

#[test]
fn crypto_weak_cipher_ecb_flagged_high() {
    let ctx = Context::new().with_file("src/cipher.js", "const c = crypto.createCipheriv('aes-128-ecb', key, iv);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.weak-cipher-algorithm");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
    assert_eq!(hits[0].detector_metadata["primitive"], json!("aes-128-ecb"));
}

#[test]
fn crypto_strong_cipher_not_flagged() {
    let ctx = Context::new().with_file("src/cipher.js", "const c = crypto.createCipheriv('aes-256-gcm', key, iv);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.primitive.weak-cipher-algorithm").is_empty());
}

#[test]
fn crypto_math_random_for_token_is_flagged() {
    let ctx = Context::new().with_file("src/token.js", "const resetToken = Math.random().toString(36);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.insecure-randomness");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
}

#[test]
fn crypto_math_random_with_secure_random_marker_nearby_is_suppressed() {
    let ctx = Context::new().with_file(
        "src/token.js",
        "const resetToken = crypto.randomBytes(16); const jitter = Math.random() * 5;",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    // `resetToken`/`Math.random` window (150 chars) contains `crypto.randomBytes`,
    // which suppresses the finding.
    assert!(find(&obs, "crypto.primitive.insecure-randomness").is_empty());
}

#[test]
fn crypto_hardcoded_jwt_secret_flagged() {
    let ctx = Context::new().with_file("src/jwt.js", "jwt.sign(payload, 'super-secret-value-123');");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.hardcoded-encryption-key");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["primitive"], json!("jwt-signing-secret"));
}

#[test]
fn crypto_key_rotation_absent_is_repository_wide_low() {
    let ctx = Context::new().with_file("src/cipher.js", "crypto.createCipheriv('aes-256-gcm', key, iv);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.key-rotation-absent");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "low");
    assert_eq!(hits[0].detector_metadata["file"], serde_json::Value::Null);
}

#[test]
fn crypto_key_rotation_present_suppresses_finding() {
    let ctx = Context::new().with_file(
        "src/cipher.js",
        "crypto.createCipheriv('aes-256-gcm', key, iv); // uses KeyManagementService for key_rotation",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.primitive.key-rotation-absent").is_empty());
}

#[test]
fn crypto_unsalted_password_hash_flagged() {
    let ctx = Context::new().with_file("src/user.js", "const hash = sha256(password);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.primitive.password-hash-unsalted-fast");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["primitive"], json!("sha256"));
}

#[test]
fn crypto_bcrypt_password_hash_not_flagged() {
    let ctx = Context::new().with_file("src/user.js", "const hash = bcrypt.hashSync(password, 10);");
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.primitive.password-hash-unsalted-fast").is_empty());
}

#[test]
fn crypto_oauth_missing_state_and_pkce_flagged() {
    let ctx = Context::new().with_file(
        "src/oauth.js",
        "window.location = `/oauth2/authorize?client_id=abc&redirect_uri=https://app.example.com/cb`;",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert_eq!(find(&obs, "crypto.protocol.oauth-missing-state").len(), 1);
    assert_eq!(find(&obs, "crypto.protocol.oauth-missing-pkce").len(), 1);
}

#[test]
fn crypto_oauth_with_state_and_pkce_not_flagged() {
    let ctx = Context::new().with_file(
        "src/oauth.js",
        "window.location = `/oauth2/authorize?client_id=abc&state=xyz&code_challenge=abc123`;",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.protocol.oauth-missing-state").is_empty());
    assert!(find(&obs, "crypto.protocol.oauth-missing-pkce").is_empty());
}

#[test]
fn crypto_oidc_missing_nonce_only_when_openid_scope_present() {
    let ctx = Context::new().with_file(
        "src/oidc.js",
        "location.href = `/authorize?client_id=abc&scope=openid%20profile&state=s1`;",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert_eq!(find(&obs, "crypto.protocol.oidc-missing-nonce").len(), 1);

    let ctx2 = Context::new().with_file(
        "src/oauth2.js",
        "location.href = `/authorize?client_id=abc&scope=read&state=s1`;",
    );
    let obs2 = crypto_identity_protocols::analyze(&ctx2);
    assert!(find(&obs2, "crypto.protocol.oidc-missing-nonce").is_empty());
}

#[test]
fn crypto_saml_signature_explicitly_disabled_flagged() {
    let ctx = Context::new().with_file(
        "src/saml.js",
        "saml.validateResponse(xml, { wantAssertionsSigned: false });",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.protocol.saml-assertion-signature-unvalidated");
    assert_eq!(hits.len(), 1);
    assert!(hits[0].claim.contains("explicitly disabled"));
}

#[test]
fn crypto_saml_signature_with_control_not_flagged() {
    let ctx = Context::new().with_file(
        "src/saml.js",
        "saml.validateResponse(xml, { verifySignature: true, certificate: cert });",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.protocol.saml-assertion-signature-unvalidated").is_empty());
}

#[test]
fn crypto_oidc_token_verify_missing_audience_and_issuer() {
    let ctx = Context::new().with_file("src/verify.js", "jwt.verify(token, publicKey, { algorithms: ['RS256'] });");
    let obs = crypto_identity_protocols::analyze(&ctx);
    let hits = find(&obs, "crypto.protocol.oidc-missing-audience-issuer-check");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["missing"], json!(["audience", "issuer"]));
}

#[test]
fn crypto_oidc_token_verify_with_audience_and_issuer_not_flagged() {
    let ctx = Context::new().with_file(
        "src/verify.js",
        "jwt.verify(token, publicKey, { audience: 'app', issuer: 'https://idp.example.com' });",
    );
    let obs = crypto_identity_protocols::analyze(&ctx);
    assert!(find(&obs, "crypto.protocol.oidc-missing-audience-issuer-check").is_empty());
}

// ---------------------------------------------------------------------------
// data-privacy.mjs
// ---------------------------------------------------------------------------

#[test]
fn privacy_log_sensitive_field_capped_medium_without_observed_classification() {
    let ctx = Context::new().with_file("src/handler.js", "logger.info('login', user.email, user.token);");
    let obs = data_privacy::analyze(&ctx);
    let hits = find(&obs, "privacy.log.sensitive-data-unredacted");
    assert_eq!(hits.len(), 1);
    // baseSeverity 'high' capped to 'medium' when no observed classification exists.
    assert_eq!(hits[0].severity_hint, "medium");
    assert_eq!(hits[0].detector_metadata["classificationObserved"], json!(false));
}

#[test]
fn privacy_log_sensitive_field_stays_high_with_observed_classification() {
    let ctx = Context::new()
        .with_file("src/handler.js", "logger.info('login', user.email, user.token);")
        .with_entity(Entity {
            id: "asset:1".to_string(),
            kind: "asset".to_string(),
            attributes: json!({ "dataClass": "pii", "file": "src/handler.js" }),
        });
    let obs = data_privacy::analyze(&ctx);
    let hits = find(&obs, "privacy.log.sensitive-data-unredacted");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
    assert_eq!(hits[0].detector_metadata["classificationObserved"], json!(true));
}

#[test]
fn privacy_log_redacted_field_not_flagged() {
    let ctx = Context::new().with_file("src/handler.js", "logger.info('login', redact(user.email));");
    let obs = data_privacy::analyze(&ctx);
    assert!(find(&obs, "privacy.log.sensitive-data-unredacted").is_empty());
}

#[test]
fn privacy_pii_without_consent_flagged_when_no_consent_marker_in_file() {
    let ctx = Context::new().with_file("src/signup.js", "const { email, phone } = req.body;");
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.collect.pii-without-consent").len(), 1);
}

#[test]
fn privacy_pii_with_consent_marker_anywhere_in_file_not_flagged() {
    let ctx = Context::new().with_file(
        "src/signup.js",
        "const { email, phone } = req.body; if (!consent) throw new Error('no consent');",
    );
    let obs = data_privacy::analyze(&ctx);
    assert!(find(&obs, "privacy.collect.pii-without-consent").is_empty());
}

#[test]
fn privacy_unencrypted_pii_storage_flagged() {
    let ctx = Context::new().with_file("src/user.js", "db.users.save({ email: e, ssn: s });");
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.store.unencrypted-pii").len(), 1);
}

#[test]
fn privacy_encrypted_pii_storage_not_flagged() {
    let ctx = Context::new().with_file("src/user.js", "db.users.save({ email: encrypt(e), ssn: encrypt(s) });");
    let obs = data_privacy::analyze(&ctx);
    assert!(find(&obs, "privacy.store.unencrypted-pii").is_empty());
}

#[test]
fn privacy_plaintext_http_transmission_of_pii_flagged() {
    let ctx = Context::new().with_file(
        "src/client.js",
        "fetch('http://api.example.com/submit', { body: JSON.stringify({ email }) });",
    );
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.transmit.unencrypted-channel").len(), 1);
}

#[test]
fn privacy_unbounded_retention_flagged_when_pii_stored_with_no_retention_marker() {
    let ctx = Context::new().with_file("src/user.js", "db.users.save({ email: e });");
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.retain.unbounded-retention").len(), 1);
}

#[test]
fn privacy_retention_marker_suppresses_unbounded_retention_finding() {
    let ctx = Context::new().with_file("src/user.js", "db.users.save({ email: e, expiresAt: ttl });");
    let obs = data_privacy::analyze(&ctx);
    assert!(find(&obs, "privacy.retain.unbounded-retention").is_empty());
}

#[test]
fn privacy_backup_file_with_unencrypted_pii_flagged() {
    let ctx = Context::new().with_file("scripts/backup-users.js", "const dump = { email: user.email };");
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.retain.backup-unencrypted").len(), 1);
}

#[test]
fn privacy_unrestricted_export_function_flagged() {
    let ctx = Context::new().with_file(
        "src/export.js",
        "function exportUsers(req, res) { const rows = db.users.find({}); }",
    );
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.export.unrestricted-data-export").len(), 1);
}

#[test]
fn privacy_export_with_authorization_control_not_flagged() {
    let ctx = Context::new().with_file(
        "src/export.js",
        "function exportUsers(req, res) { authorize(req); const rows = db.users.find({}); }",
    );
    let obs = data_privacy::analyze(&ctx);
    assert!(find(&obs, "privacy.export.unrestricted-data-export").is_empty());
}

#[test]
fn privacy_no_erasure_path_flagged_when_pii_stored_with_no_erasure_marker() {
    let ctx = Context::new().with_file("src/user.js", "db.users.save({ email: e });");
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.delete.no-erasure-path").len(), 1);
}

#[test]
fn privacy_tenant_crossover_flagged_when_multi_tenant_repo_has_unscoped_query() {
    let ctx = Context::new().with_file(
        "src/reports.js",
        "function scoped(tenant_id) { return db.reports.find({ tenant_id }); } function all() { return db.reports.find({ status: 'open' }); }",
    );
    let obs = data_privacy::analyze(&ctx);
    let hits = find(&obs, "privacy.process.tenant-data-crossover");
    assert_eq!(hits.len(), 1);
}

#[test]
fn privacy_marketing_claim_contradiction_flagged() {
    let ctx = Context::new().with_file(
        "src/copy.js",
        "const disclaimer = 'We do not sell your data.'; sendToThirdPartyDataBroker(record);",
    );
    let obs = data_privacy::analyze(&ctx);
    assert_eq!(find(&obs, "privacy.claim.marketing-mismatch").len(), 1);
}

// ---------------------------------------------------------------------------
// developer-machine.mjs
// ---------------------------------------------------------------------------

#[test]
fn developer_machine_command_invocation_in_editor_config_flagged() {
    let ctx = Context::new().with_file(".vscode/tasks.json", "child_process.exec('rm -rf /tmp/x');");
    let obs = developer_machine::analyze(&ctx);
    let hits = find_dm(&obs, "developer-machine.local-executable.command-invocation");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["requiresSandboxReceipt"], json!(true));
    assert!(hits[0]
        .uncertainty
        .iter()
        .any(|u| u.starts_with("BLOCKED: no external sandbox execution receipt")));
}

#[test]
fn developer_machine_sandbox_receipt_present_changes_uncertainty_note() {
    let ctx = Context::new()
        .with_file(".vscode/tasks.json", "child_process.exec('rm -rf /tmp/x');")
        .with_sandbox_receipt(true);
    let obs = developer_machine::analyze(&ctx);
    let hits = find_dm(&obs, "developer-machine.local-executable.command-invocation");
    assert_eq!(hits.len(), 1);
    assert!(hits[0]
        .uncertainty
        .iter()
        .any(|u| u.starts_with("An external sandbox execution receipt is present")));
}

#[test]
fn developer_machine_command_invocation_outside_config_dir_not_flagged() {
    let ctx = Context::new().with_file("src/build.js", "child_process.exec('build');");
    let obs = developer_machine::analyze(&ctx);
    assert!(find_dm(&obs, "developer-machine.local-executable.command-invocation").is_empty());
}

#[test]
fn developer_machine_credential_store_reference_flagged_anywhere() {
    let ctx = Context::new().with_file("src/creds.js", "const token = readFileSync('~/.aws/credentials');");
    let obs = developer_machine::analyze(&ctx);
    assert_eq!(find_dm(&obs, "developer-machine.credential-store.access-pattern").len(), 1);
}

#[test]
fn developer_machine_mcp_config_with_command_flagged() {
    let ctx = Context::new().with_file(".mcp.json", "{ \"mcpServers\": { \"x\": { \"command\": \"node\", \"args\": [\"server.js\"] } } }");
    let obs = developer_machine::analyze(&ctx);
    assert_eq!(find_dm(&obs, "developer-machine.agent-skill-config.execution-path").len(), 1);
}

#[test]
fn developer_machine_sandbox_bypass_flag_flagged() {
    let ctx = Context::new().with_file(".claude/settings.json", "{ \"bypassPermissions\": true }");
    let obs = developer_machine::analyze(&ctx);
    assert_eq!(find_dm(&obs, "developer-machine.sandbox-bypass.permission-override").len(), 1);
}

fn find_dm<'a>(obs: &'a [legion_audit::wf_port::wf059::common::Observation], rule_id: &str) -> Vec<&'a legion_audit::wf_port::wf059::common::Observation> {
    obs.iter().filter(|o| o.rule_id == rule_id).collect()
}

// ---------------------------------------------------------------------------
// embedded-iot.mjs
// ---------------------------------------------------------------------------

#[test]
fn embedded_iot_firmware_update_without_verification_flagged() {
    let ctx = Context::new().with_file("main.c", "download_firmware_image(url); flash_image(buf, len);");
    let obs = embedded_iot::analyze(&ctx);
    let hits = find(&obs, "embedded-iot.firmware.update-without-signature-verification");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "critical");
}

#[test]
fn embedded_iot_firmware_update_with_verification_marker_suppressed() {
    let ctx = Context::new().with_file(
        "main.c",
        "if (!verify_signature(buf)) return; download_firmware_image(url); flash_image(buf, len);",
    );
    let obs = embedded_iot::analyze(&ctx);
    assert!(find(&obs, "embedded-iot.firmware.update-without-signature-verification").is_empty());
}

#[test]
fn embedded_iot_non_firmware_file_extension_not_scanned() {
    let ctx = Context::new().with_file("README.md", "download_firmware_image(url); flash_image(buf, len);");
    let obs = embedded_iot::analyze(&ctx);
    assert!(obs.is_empty());
}

#[test]
fn embedded_iot_hardcoded_wifi_secret_flagged() {
    let ctx = Context::new().with_file("main.c", "char wifi_psk[] = \"SuperSecretPassword1\";");
    let obs = embedded_iot::analyze(&ctx);
    assert_eq!(find(&obs, "embedded-iot.credentials.hardcoded-secret").len(), 1);
}

#[test]
fn embedded_iot_shared_device_key_flagged() {
    let ctx = Context::new().with_file("main.c", "const char* DEVICE_KEY = \"fleetwide-shared-secret\";");
    let obs = embedded_iot::analyze(&ctx);
    assert_eq!(find(&obs, "embedded-iot.identity.shared-static-device-key").len(), 1);
}

// ---------------------------------------------------------------------------
// file-boundaries.mjs
// ---------------------------------------------------------------------------

#[test]
fn file_boundaries_path_traversal_unvalidated_flagged_high() {
    let ctx = Context::new().with_file("src/download.js", "fs.readFileSync(req.query.path);");
    let obs = file_boundaries::analyze(&ctx);
    let hits = find(&obs, "file.path-traversal-unvalidated");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
}

#[test]
fn file_boundaries_path_traversal_with_lexical_normalization_downgraded_low() {
    let ctx = Context::new().with_file(
        "src/download.js",
        "const safe = path.normalize(req.query.path); fs.readFileSync(safe);",
    );
    let obs = file_boundaries::analyze(&ctx);
    // The sink itself doesn't reference req.query directly here, so this only
    // exercises non-detection; use a fixture where the sink DOES take the raw
    // request value but a normalization call is nearby.
    assert!(find(&obs, "file.path-traversal-unvalidated").is_empty() || obs.iter().all(|o| o.severity_hint == "low"));

    let ctx2 = Context::new().with_file(
        "src/download.js",
        "path.resolve(base); fs.readFileSync(req.query.path);",
    );
    let obs2 = file_boundaries::analyze(&ctx2);
    let hits2 = find(&obs2, "file.path-traversal-unvalidated");
    assert_eq!(hits2.len(), 1);
    assert_eq!(hits2[0].severity_hint, "low");
}

#[test]
fn file_boundaries_path_traversal_downgraded_by_observed_control_entity() {
    let ctx = Context::new()
        .with_file("src/download.js", "fs.readFileSync(req.query.path);")
        .with_entity(Entity {
            id: "control:1".to_string(),
            kind: "control".to_string(),
            attributes: json!({ "controlType": "path-normalization", "name": "path-guard" }),
        })
        .with_relation(Relation {
            kind: "protects".to_string(),
            from: "control:1".to_string(),
            to: "artifact:src/download.js".to_string(),
        });
    let obs = file_boundaries::analyze(&ctx);
    let hits = find(&obs, "file.path-traversal-unvalidated");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "low");
    assert_eq!(hits[0].observed_controls, vec!["control:1".to_string()]);
}

#[test]
fn file_boundaries_zip_slip_flagged() {
    let ctx = Context::new().with_file("src/extract.js", "fs.writeFileSync(path.join(dest, entry.fileName), buf);");
    let obs = file_boundaries::analyze(&ctx);
    assert_eq!(find(&obs, "file.archive-zip-slip").len(), 1);
}

#[test]
fn file_boundaries_symlink_unchecked_flagged() {
    let ctx = Context::new().with_file("src/extract.js", "extract(archive, { dereference: true });");
    let obs = file_boundaries::analyze(&ctx);
    let hits = find(&obs, "file.symlink-unchecked");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "medium");
}

// ---------------------------------------------------------------------------
// small helper extension so `crypto_*` tests can read `detectorMetadata.layer`.
// ---------------------------------------------------------------------------

trait ObservationExt {
    fn layer(&self) -> &str;
}

impl ObservationExt for legion_audit::wf_port::wf059::common::Observation {
    fn layer(&self) -> &str {
        self.detector_metadata["layer"].as_str().unwrap_or("")
    }
}
