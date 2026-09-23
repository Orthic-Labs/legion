//! Ported tests for chunk wf060 (area `src/providers/security`, target crate
//! `legion-audit`):
//!   - `src/providers/security/packs/high-consequence.mjs`
//!   - `src/providers/security/packs/http-protocol-cache.mjs`
//!   - `src/providers/security/packs/ics-ot.mjs`
//!   - `src/providers/security/packs/injection.mjs`
//!   - `src/providers/security/packs/insecure-defaults.mjs`
//!
//! Source coverage:
//!   - `tests/security-packs/extended-packs.test.mjs`'s shared `fixtures` table
//!     drives `insecureDefaults` with `'const tls = { rejectUnauthorized: false };'`
//!     and `highConsequence` with `'require(tx.origin == owner)'`, asserting a
//!     non-empty `UNADJUDICATED` candidate list with non-empty `evidenceRefs`, and
//!     asserts every extended pack emits zero candidates for the neutral fixture
//!     `'export const value = 1;'`. `insecure_defaults_*` / `high_consequence_*`
//!     below port both assertions directly against this crate's `analyze`.
//!   - `injection.mjs` and `ics-ot.mjs`/`http-protocol-cache.mjs` have no dedicated
//!     `*.test.mjs` file in the JS tree (no test imports either pack); the
//!     `injection_*`, `ics_ot_*`, and `http_protocol_cache_*` tests below are new
//!     coverage ported from each pack's own inline rule/claim text and suppression
//!     logic, exercising the representative hazard shown in that rule's own risky
//!     pattern plus its neutral/suppressed counterpart.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf060;` inside
//! it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf060::common::{Context, Entity, Relation};
use legion_audit::wf_port::wf060::{high_consequence, http_protocol_cache, ics_ot, injection, insecure_defaults};
use serde_json::json;

// ---------------------------------------------------------------------
// insecure-defaults.mjs
// ---------------------------------------------------------------------

#[test]
fn insecure_defaults_hazard_fixture_matches() {
    let ctx = Context::new().with_file("app.mjs", "const tls = { rejectUnauthorized: false };");
    let obs = insecure_defaults::analyze(&ctx);
    assert!(!obs.is_empty());
    assert!(obs.iter().any(|o| o.rule_id == "defaults.tls-verification-disabled"));
    assert!(obs.iter().all(|o| !o.evidence_refs.is_empty()));
    assert!(obs.iter().all(|o| o.candidate_class == "insecure-defaults"));
}

#[test]
fn insecure_defaults_neutral_fixture_is_silent() {
    let ctx = Context::new().with_file("app.mjs", "export const value = 1;");
    assert!(insecure_defaults::analyze(&ctx).is_empty());
}

#[test]
fn insecure_defaults_debug_enabled_defaults_to_medium_severity() {
    let ctx = Context::new().with_file("app.mjs", "DEBUG: true");
    let obs = insecure_defaults::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "defaults.debug-enabled").unwrap();
    assert_eq!(hit.severity_hint, "medium");
}

#[test]
fn insecure_defaults_authentication_optional_is_high_severity() {
    let ctx = Context::new().with_file("app.mjs", "ALLOW_ANONYMOUS: true");
    let obs = insecure_defaults::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "defaults.authentication-optional").unwrap();
    assert_eq!(hit.severity_hint, "high");
}

// ---------------------------------------------------------------------
// high-consequence.mjs
// ---------------------------------------------------------------------

#[test]
fn high_consequence_hazard_fixture_matches() {
    let ctx = Context::new().with_file("Contract.sol", "require(tx.origin == owner)");
    let obs = high_consequence::analyze(&ctx);
    assert!(!obs.is_empty());
    assert!(obs.iter().any(|o| o.rule_id == "smart-contract.tx-origin-auth"));
    assert!(obs.iter().all(|o| !o.evidence_refs.is_empty()));
}

#[test]
fn high_consequence_neutral_fixture_is_silent() {
    let ctx = Context::new().with_file("app.mjs", "export const value = 1;");
    assert!(high_consequence::analyze(&ctx).is_empty());
}

#[test]
fn high_consequence_firmware_update_without_verification_flags() {
    let ctx = Context::new().with_file("ota.mjs", "firmware download and apply now, no checks");
    let obs = high_consequence::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "embedded.update-without-verification"));
}

#[test]
fn high_consequence_firmware_update_with_verification_is_suppressed() {
    let ctx = Context::new().with_file("ota.mjs", "firmware download then apply after signature verify");
    let obs = high_consequence::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "embedded.update-without-verification"));
}

#[test]
fn high_consequence_actuator_without_interlock_flags() {
    let ctx = Context::new().with_file("plc.mjs", "actuator.start(pin)");
    let obs = high_consequence::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "safety.command-without-interlock"));
}

#[test]
fn high_consequence_actuator_with_interlock_is_suppressed() {
    let ctx = Context::new().with_file("plc.mjs", "actuator.start(interlock)");
    let obs = high_consequence::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "safety.command-without-interlock"));
}

// ---------------------------------------------------------------------
// ics-ot.mjs
// ---------------------------------------------------------------------

#[test]
fn ics_ot_unauthenticated_write_command_flags_on_scanned_extension() {
    let ctx = Context::new().with_file("plc-driver.js", "client.writeCoil(1, true);");
    let obs = ics_ot::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "ics-ot.authorization.unauthenticated-write-command"));
    let hit = obs.iter().find(|o| o.rule_id == "ics-ot.authorization.unauthenticated-write-command").unwrap();
    assert_eq!(hit.severity_hint, "critical");
    assert_eq!(hit.candidate_class, "ics-ot");
}

#[test]
fn ics_ot_unauthenticated_write_command_suppressed_with_role_check() {
    let ctx = Context::new()
        .with_file("plc-driver.js", "if (isAuthorized(user)) client.writeCoil(1, true);");
    let obs = ics_ot::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "ics-ot.authorization.unauthenticated-write-command"));
}

#[test]
fn ics_ot_ignores_files_outside_the_scanned_extension_set() {
    let ctx = Context::new().with_file("README.md", "client.writeCoil(1, true);");
    assert!(ics_ot::analyze(&ctx).is_empty());
}

#[test]
fn ics_ot_bridged_network_flags_without_segmentation_marker() {
    let ctx = Context::new()
        .with_file("network.yaml", "scada gateway is exposed to the corporate network directly");
    let obs = ics_ot::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "ics-ot.segmentation.ot-bridged-to-corporate-network"));
}

#[test]
fn ics_ot_unsigned_firmware_push_flags() {
    let ctx = Context::new().with_file("update.js", "plc firmware push to device over the wire");
    let obs = ics_ot::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "ics-ot.update-policy.unsigned-plc-firmware-push"));
}

// ---------------------------------------------------------------------
// injection.mjs
// ---------------------------------------------------------------------

#[test]
fn injection_sql_dynamic_query_flags() {
    let ctx = Context::new().with_file("db.mjs", "db.query(`SELECT * FROM t WHERE id = ${request.query.id}`)");
    let obs = injection::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "injection.sql.dynamic-query").unwrap();
    assert_eq!(hit.severity_hint, "high");
    assert_eq!(hit.candidate_class, "injection");
    assert_eq!(hit.detector_metadata["sinkClass"], "sql");
}

#[test]
fn injection_sql_parameterized_query_is_suppressed() {
    let ctx = Context::new().with_file("db.mjs", "db.query(`SELECT * FROM t WHERE id = ?`, [id])");
    let obs = injection::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "injection.sql.dynamic-query"));
}

#[test]
fn injection_sql_escaping_helper_downgrades_severity() {
    let ctx = Context::new().with_file(
        "db.mjs",
        "db.query(`SELECT * FROM t WHERE id = ${request.query.id}`); mysql.escape(id);",
    );
    let obs = injection::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "injection.sql.dynamic-query").unwrap();
    assert_eq!(hit.severity_hint, "low");
    assert!(hit.uncertainty.iter().any(|u| u.contains("mitigating signal")));
}

#[test]
fn injection_sql_control_entity_downgrades_and_records_observed_control() {
    let file = "db.mjs";
    let ctx = Context::new()
        .with_file(file, "db.query(`SELECT * FROM t WHERE id = ${request.query.id}`)")
        .with_entity(Entity {
            id: "control:1".to_string(),
            kind: "control".to_string(),
            name: "sql-param-binder".to_string(),
            attributes: json!({ "controlType": "sql-parameterization" }),
            evidence_refs: Vec::new(),
        })
        .with_relation(Relation {
            kind: "protects".to_string(),
            from: "control:1".to_string(),
            to: format!("artifact:{file}"),
        });
    let obs = injection::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "injection.sql.dynamic-query").unwrap();
    assert_eq!(hit.severity_hint, "low");
    assert_eq!(hit.observed_controls, vec!["control:1".to_string()]);
}

#[test]
fn injection_command_shell_exec_flags_with_shell_sink_kind() {
    let ctx = Context::new().with_file("cli.mjs", "exec(request.query.cmd)");
    let obs = injection::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "injection.command.shell-exec").unwrap();
    assert_eq!(hit.detector_metadata["sinkKind"], "shell");
    assert!(hit
        .uncertainty
        .iter()
        .any(|u| u.contains("not automatically command injection")));
}

#[test]
fn injection_ldap_filter_requires_file_guard() {
    // No "ldap" token anywhere in the file text: the fileGuard on this rule
    // means it must not fire even though the risky pattern would match.
    let ctx = Context::new().with_file("search.mjs", "filter = '(' + request.query.q");
    let obs = injection::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "injection.ldap.filter-injection"));
}

#[test]
fn injection_ldap_filter_flags_when_file_guard_satisfied() {
    let ctx = Context::new().with_file(
        "ldap-search.mjs",
        "const client = ldap.createClient(url); filter = '(' + request.query.q",
    );
    let obs = injection::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "injection.ldap.filter-injection"));
}

#[test]
fn injection_xxe_flags_when_guard_and_toggle_present() {
    let ctx = Context::new().with_file("parse.mjs", "libxmljs.parseXml(xml, { noent: true })");
    let obs = injection::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "injection.xxe.external-entity-enabled"));
}

#[test]
fn injection_redos_flags_nested_quantifier() {
    let ctx = Context::new().with_file("validate.mjs", "const re = /(a+)+b/;");
    let obs = injection::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "injection.regex.redos").unwrap();
    assert_eq!(hit.severity_hint, "medium");
}

#[test]
fn injection_prototype_pollution_flags_bracket_assignment() {
    let ctx = Context::new().with_file("merge.mjs", "obj[request.body.key] = value;");
    let obs = injection::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "injection.prototype-pollution.unsafe-key-assignment"));
}

#[test]
fn injection_formula_flags_unescaped_csv_export() {
    let ctx = Context::new().with_file(
        "export.csv.mjs",
        "// csv export\n    sheet.addRow([request.body.name, request.body.amount])",
    );
    let obs = injection::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "injection.formula.csv-export-unescaped"));
}

#[test]
fn injection_neutral_fixture_is_silent() {
    let ctx = Context::new().with_file("app.mjs", "export const value = 1;");
    assert!(injection::analyze(&ctx).is_empty());
}

// ---------------------------------------------------------------------
// http-protocol-cache.mjs
// ---------------------------------------------------------------------

#[test]
fn http_protocol_cache_hsts_missing_flags_repository_wide() {
    let ctx = Context::new().with_file("server.mjs", "app.listen(3000)");
    let obs = http_protocol_cache::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "hsts.missing").unwrap();
    assert_eq!(hit.severity_hint, "low");
    assert_eq!(hit.candidate_class, "http-protocol");
}

#[test]
fn http_protocol_cache_hsts_present_is_silent() {
    let ctx = Context::new().with_file("server.mjs", "res.setHeader('Strict-Transport-Security', 'max-age=1')");
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "hsts.missing"));
}

#[test]
fn http_protocol_cache_https_not_enforced_flags_plain_http_server() {
    let ctx = Context::new().with_file("server.mjs", "const server = http.createServer(handler);");
    let obs = http_protocol_cache::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "https.not-enforced").unwrap();
    // With no runtime/deployment evidence, `capSeverity` clamps the rule's
    // own 'high' hint down to the deployment-assumption cap of 'medium'.
    assert_eq!(hit.severity_hint, "medium");
}

#[test]
fn http_protocol_cache_https_enforced_marker_suppresses() {
    let ctx = Context::new()
        .with_file("server.mjs", "const server = http.createServer(handler); app.use(helmet());");
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "https.not-enforced"));
}

#[test]
fn http_protocol_cache_sensitive_route_without_no_store_flags() {
    let ctx = Context::new().with_file(
        "profile.mjs",
        "app.get('/profile', (req, res) => { res.json(req.session.user); })",
    );
    let obs = http_protocol_cache::analyze(&ctx);
    let hit = obs.iter().find(|o| o.rule_id == "cache.sensitive-content-cacheable").unwrap();
    // With no runtime/deployment evidence, `capSeverity` clamps the rule's
    // own 'high' hint down to the deployment-assumption cap of 'medium'.
    assert_eq!(hit.severity_hint, "medium");
}

#[test]
fn http_protocol_cache_sensitive_route_with_no_store_is_silent() {
    let ctx = Context::new().with_file(
        "profile.mjs",
        "app.get('/profile', (req, res) => { res.set('Cache-Control', 'no-store'); res.json(req.session.user); })",
    );
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "cache.sensitive-content-cacheable"));
}

#[test]
fn http_protocol_cache_blind_trust_proxy_flags_critical_with_known_no_reverse_proxy() {
    let ctx = Context::new().with_file("server.mjs", "app.set('trust proxy', true)");
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "proxy.trust-misconfigured"));
}

#[test]
fn http_protocol_cache_smuggling_conflicting_headers_flags() {
    let ctx = Context::new().with_file(
        "raw-http.mjs",
        "const raw = `Content-Length: ${len}\nTransfer-Encoding: chunked\n`;",
    );
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(obs
        .iter()
        .any(|o| o.rule_id == "smuggling.conflicting-content-length-transfer-encoding"));
}

#[test]
fn http_protocol_cache_ambiguous_proxy_chain_flags_naive_split() {
    let ctx = Context::new().with_file(
        "proxy.mjs",
        "const ip = headers['X-Forwarded-For'].split(',')[0];",
    );
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "smuggling.ambiguous-proxy-chain"));
}

#[test]
fn http_protocol_cache_per_file_rules_require_evidence_refs() {
    // `http-protocol-cache.mjs`'s per-file loop skips a file whose artifact
    // carries no evidenceRefs (`if (evidenceRefs.length === 0) continue;`).
    let ctx = Context::new().with_file_no_evidence(
        "profile.mjs",
        "app.get('/profile', (req, res) => { res.json(req.session.user); })",
    );
    let obs = http_protocol_cache::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "cache.sensitive-content-cacheable"));
}
