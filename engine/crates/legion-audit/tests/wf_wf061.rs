//! Port of the JS test assertions for chunk wf061's five security packs
//! (`src/providers/security/packs/{mobile,native-workspace,observability-forensics,
//! output-handling,parser-serialization}.mjs`), driving the Rust port in
//! `legion_audit::wf_port::wf061`.

use std::collections::BTreeMap;

use legion_audit::wf_port::wf061::{
    mobile, native_workspace, observability_forensics, output_handling, parser_serialization,
    Entity, LoggingTrace, OutputHandlingTrace, PackContext, Relation, SecurityModel,
};
use serde_json::json;

fn artifact(id: &str, path: &str) -> Entity {
    let mut attrs = BTreeMap::new();
    attrs.insert("path".to_string(), json!(path));
    Entity {
        id: id.to_string(),
        kind: "repository-artifact".to_string(),
        name: path.to_string(),
        attributes: attrs,
        evidence_refs: vec![format!("evidence:{id}")],
    }
}

fn ctx_for<'a>(
    model: &'a SecurityModel,
    files: &[(&str, &str)],
) -> PackContext<'a> {
    let mut source_text = BTreeMap::new();
    let mut file_list = Vec::new();
    for (path, text) in files {
        source_text.insert(path.to_string(), text.to_string());
        file_list.push(path.to_string());
    }
    PackContext {
        files: file_list,
        source_text,
        model: Some(model),
        relations: Vec::new(),
        denominator_digest: "sha256:test".to_string(),
        output_handling_traces: Vec::new(),
        logging_traces: Vec::new(),
    }
}

// =================================================================================================
// native-workspace.mjs
// =================================================================================================

#[test]
fn native_workspace_shell_string_command_matches() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("main.rs", "Command::new(\"sh\").arg(\"-c\")")]);
    let obs = native_workspace::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "native.shell-string-command"));
    let o = obs.iter().find(|o| o.rule_id == "native.shell-string-command").unwrap();
    assert_eq!(o.severity_hint, "high");
    assert_eq!(o.effect_kind, "code-execution");
    assert_eq!(o.effect_action, "execute");
    assert_eq!(o.candidate_class, "native-workspace");
}

#[test]
fn native_workspace_updater_insecure_transport_default_medium_bypass() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("updater.js", "download(config)... fetch('http://example.com/artifact.bin')")]);
    let obs = native_workspace::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "native.updater-insecure-transport").expect("expected match");
    // JS factory defaults: severityHint 'medium', effectAction 'bypass' when omitted.
    assert_eq!(o.severity_hint, "medium");
    assert_eq!(o.effect_action, "bypass");
}

#[test]
fn native_workspace_plugin_untrusted_path_matches() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("loader.js", "plugin config load(process.env.PLUGIN_PATH)")]);
    let obs = native_workspace::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "native.plugin-untrusted-path"));
}

#[test]
fn native_workspace_no_match_on_clean_file() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("clean.rs", "fn main() { println!(\"hello\"); }")]);
    let obs = native_workspace::analyze(&ctx);
    assert!(obs.is_empty());
}

// =================================================================================================
// output-handling.mjs
// =================================================================================================

#[test]
fn output_handling_html_body_unescaped_detects_inner_html() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.js", "el.innerHTML = request.body.content;")]);
    let obs = output_handling::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "output.html.body-unescaped").expect("expected match");
    assert_eq!(o.severity_hint, "high");
    assert_eq!(o.detector_metadata["sinkEngine"], "innerHTML");
    assert_eq!(o.detector_metadata["detectionMethod"], "lexical-pattern");
}

#[test]
fn output_handling_html_body_unescaped_suppressed_by_dompurify() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.js", "el.innerHTML = DOMPurify.sanitize(request.body.content);")]);
    let obs = output_handling::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "output.html.body-unescaped"));
}

#[test]
fn output_handling_react_dangerously_set_inner_html_sink_engine() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("App.jsx", "<div dangerouslySetInnerHTML={{ __html: input }} />")]);
    let obs = output_handling::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "output.html.body-unescaped").expect("expected match");
    assert_eq!(o.detector_metadata["sinkEngine"], "react-dangerously-set-inner-html");
}

#[test]
fn output_handling_open_redirect_downgraded_by_observed_control() {
    let mut control_attrs = BTreeMap::new();
    control_attrs.insert("controlType".to_string(), json!("redirect-allowlist"));
    let control = Entity {
        id: "control:1".to_string(),
        kind: "control".to_string(),
        name: "Redirect allowlist check".to_string(),
        attributes: control_attrs,
        evidence_refs: vec![],
    };
    let art = artifact("artifact:1", "routes.js");
    let model = SecurityModel { entities: vec![control.clone(), art.clone()] };
    let mut ctx = ctx_for(&model, &[("routes.js", "redirect(request.query.next)")]);
    ctx.relations.push(Relation { kind: "protects".to_string(), from: control.id.clone(), to: art.id.clone() });
    let obs = output_handling::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "output.url.open-redirect").expect("expected match");
    assert_eq!(o.severity_hint, "low");
    assert_eq!(o.observed_controls, vec!["control:1".to_string()]);
}

#[test]
fn output_handling_stored_unescaped_render_lexical_downgrade() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("view.ejs", "<%- safeContent %>")]);
    let obs = output_handling::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "output.stored.unescaped-render").expect("expected match");
    assert_eq!(o.severity_hint, "low");
}

#[test]
fn output_handling_sast_trace_marks_detection_method() {
    let model = SecurityModel::default();
    let mut ctx = ctx_for(&model, &[("app.js", "el.innerHTML = request.body.content;")]);
    ctx.output_handling_traces.push(OutputHandlingTrace { file: "app.js".to_string(), output_context: "html-body".to_string() });
    let obs = output_handling::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "output.html.body-unescaped").expect("expected match");
    assert_eq!(o.detector_metadata["detectionMethod"], "sast-trace");
}

// =================================================================================================
// parser-serialization.mjs
// =================================================================================================

#[test]
fn parser_unsafe_deserialization_pickle_loads() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.py", "data = pickle.loads(request.body)")]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.unsafe-deserialization").expect("expected match");
    assert_eq!(o.severity_hint, "high");
    assert_eq!(o.detector_metadata["sinkApi"], "pickle.loads");
    assert_eq!(o.detector_metadata["sourceExpr"], "request.body");
}

#[test]
fn parser_unsafe_deserialization_downgraded_by_safe_loader() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.py", "data = yaml.load(stream, Loader=SafeLoader)")]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.unsafe-deserialization").expect("expected match");
    assert_eq!(o.severity_hint, "low");
}

#[test]
fn parser_xml_billion_laughs_requires_file_guard() {
    let model = SecurityModel::default();
    // No XML-parser marker in the file -> the fileGuard blocks the rule entirely.
    let ctx = ctx_for(&model, &[("app.py", "resolve_entities = True")]);
    let obs = parser_serialization::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "parser.xml-billion-laughs"));
}

#[test]
fn parser_xml_billion_laughs_matches_with_guard_present() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.py", "from lxml import etree\nparser = etree.XMLParser(resolve_entities = True)")]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.xml-billion-laughs").expect("expected match");
    assert_eq!(o.severity_hint, "medium");
}

#[test]
fn parser_decompression_bomb_matches() {
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("app.py", "tarfile.extractall(path)")]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.decompression-bomb").expect("expected match");
    assert_eq!(o.detector_metadata["sinkApi"], "tarfile.extractall");
}

#[test]
fn parser_unbounded_recursion_matches_self_call() {
    let model = SecurityModel::default();
    let text = "function parseNode(node) {\n  doStuff();\n  parseNode(node.child);\n}";
    let ctx = ctx_for(&model, &[("parser.js", text)]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.unbounded-recursion").expect("expected match");
    assert_eq!(o.detector_metadata["sinkApi"], "parseNode");
    assert_eq!(o.severity_hint, "medium");
}

#[test]
fn parser_unbounded_recursion_downgraded_by_depth_guard_in_match() {
    let model = SecurityModel::default();
    let text = "function parseNode(node, depth) {\n  if (depth > maxDepth) return;\n  parseNode(node.child, depth + 1);\n}";
    let ctx = ctx_for(&model, &[("parser.js", text)]);
    let obs = parser_serialization::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "parser.unbounded-recursion").expect("expected match");
    assert_eq!(o.severity_hint, "low");
}

#[test]
fn parser_unbounded_recursion_no_match_without_self_call() {
    let model = SecurityModel::default();
    let text = "function parseNode(node) {\n  return node.value;\n}";
    let ctx = ctx_for(&model, &[("parser.js", text)]);
    let obs = parser_serialization::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "parser.unbounded-recursion"));
}

// =================================================================================================
// observability-forensics.mjs
// =================================================================================================

#[test]
fn observability_error_leak_stack_trace() {
    let art = artifact("artifact:1", "handler.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("handler.js", "res.json({ error: err.stack })")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "observability.error.sensitive-data-in-output"));
}

#[test]
fn observability_error_leak_suppressed_in_dev_guard() {
    let art = artifact("artifact:1", "handler.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("handler.js", "if (isDev) { res.json({ error: err.stack }) }")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "observability.error.sensitive-data-in-output"));
}

#[test]
fn observability_requires_artifact_with_evidence() {
    // No artifact for the file at all -> rules requiring an artifact are skipped.
    let model = SecurityModel::default();
    let ctx = ctx_for(&model, &[("handler.js", "res.json({ error: err.stack })")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(obs.is_empty());
}

#[test]
fn observability_log_injection_matches() {
    let art = artifact("artifact:1", "handler.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("handler.js", "logger.info(`request: ${req.body.name}`)")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "observability.log.injection"));
}

#[test]
fn observability_log_injection_suppressed_by_sanitizer() {
    let art = artifact("artifact:1", "handler.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("handler.js", "logger.info(`request: ${req.body.name}`); sanitizeLog(req.body.name)")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "observability.log.injection"));
}

#[test]
fn observability_missing_auth_success_event() {
    let art = artifact("artifact:1", "auth.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("auth.js", "req.session.user = user;")]);
    let obs = observability_forensics::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "observability.events.missing-auth-success").expect("expected match");
    assert_eq!(o.detector_metadata["expectedEvent"], "auth.success");
}

#[test]
fn observability_auth_success_suppressed_by_security_event_marker() {
    let art = artifact("artifact:1", "auth.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("auth.js", "req.session.user = user; auditLog('auth.success', user.id);")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "observability.events.missing-auth-success"));
}

#[test]
fn observability_auth_success_suppressed_by_logging_trace() {
    let art = artifact("artifact:1", "auth.js");
    let model = SecurityModel { entities: vec![art] };
    let mut ctx = ctx_for(&model, &[("auth.js", "req.session.user = user;")]);
    ctx.logging_traces.push(LoggingTrace { file: "auth.js".to_string(), event_type: "auth.success".to_string() });
    let obs = observability_forensics::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "observability.events.missing-auth-success"));
}

#[test]
fn observability_missing_privilege_change_and_data_export() {
    let art = artifact("artifact:1", "admin.js");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("admin.js", "user.role = 'admin'; res.download('/export.csv');")]);
    let obs = observability_forensics::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "observability.events.missing-privilege-change"));
    assert!(obs.iter().any(|o| o.rule_id == "observability.events.missing-data-export"));
}

// =================================================================================================
// mobile.mjs
// =================================================================================================

fn permission_entity(id: &str, permission: &str, file: &str) -> Entity {
    let mut attrs = BTreeMap::new();
    attrs.insert("permission".to_string(), json!(permission));
    attrs.insert("file".to_string(), json!(file));
    Entity {
        id: id.to_string(),
        kind: "permission-scope".to_string(),
        name: permission.to_string(),
        attributes: attrs,
        evidence_refs: vec![format!("evidence:{id}")],
    }
}

#[test]
fn mobile_dangerous_permission_declared() {
    let entity = permission_entity("perm:1", "android.permission.CAMERA", "AndroidManifest.xml");
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("AndroidManifest.xml", "<uses-permission android:name=\"android.permission.CAMERA\"/>")]);
    let obs = mobile::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "mobile.permission.dangerous-declared").expect("expected match");
    assert_eq!(o.severity_hint, "medium");
    assert!(o.claim.contains("android.permission.CAMERA"));
}

#[test]
fn mobile_dangerous_permission_stripped_is_skipped() {
    let entity = permission_entity("perm:1", "android.permission.CAMERA", "AndroidManifest.xml");
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("AndroidManifest.xml", "<uses-permission android:name=\"android.permission.CAMERA\" tools:node=\"remove\"/>")]);
    let obs = mobile::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "mobile.permission.dangerous-declared"));
}

#[test]
fn mobile_non_dangerous_permission_ignored() {
    let entity = permission_entity("perm:1", "android.permission.INTERNET", "AndroidManifest.xml");
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("AndroidManifest.xml", "<uses-permission android:name=\"android.permission.INTERNET\"/>")]);
    let obs = mobile::analyze(&ctx);
    assert!(obs.is_empty());
}

#[test]
fn mobile_deep_link_unvalidated_high_severity() {
    let mut attrs = BTreeMap::new();
    attrs.insert("entrypointType".to_string(), json!("deep-link"));
    attrs.insert("file".to_string(), json!("Manifest.xml"));
    let entity = Entity { id: "ep:1".to_string(), kind: "entrypoint".to_string(), name: "deeplink".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("Manifest.xml", "<intent-filter><data android:scheme=\"myapp\"/></intent-filter>")]);
    let obs = mobile::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "mobile.deep-link.entrypoint-unvalidated").expect("expected match");
    assert_eq!(o.severity_hint, "high");
}

#[test]
fn mobile_deep_link_downgraded_by_auto_verify() {
    let mut attrs = BTreeMap::new();
    attrs.insert("entrypointType".to_string(), json!("deep-link"));
    attrs.insert("file".to_string(), json!("Manifest.xml"));
    let entity = Entity { id: "ep:1".to_string(), kind: "entrypoint".to_string(), name: "deeplink".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("Manifest.xml", "<intent-filter android:autoVerify=\"true\"><data android:scheme=\"myapp\"/></intent-filter>")]);
    let obs = mobile::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "mobile.deep-link.entrypoint-unvalidated").expect("expected match");
    assert_eq!(o.severity_hint, "medium");
}

#[test]
fn mobile_exported_component_no_permission_gate() {
    let mut attrs = BTreeMap::new();
    attrs.insert("entrypointType".to_string(), json!("exported-component"));
    attrs.insert("file".to_string(), json!("Manifest.xml"));
    let entity = Entity { id: "ep:1".to_string(), kind: "entrypoint".to_string(), name: "comp".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("Manifest.xml", "<activity android:exported=\"true\"/>")]);
    let obs = mobile::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "mobile.exported-component.no-permission-gate"));
}

#[test]
fn mobile_exported_component_with_permission_gate_no_finding() {
    let mut attrs = BTreeMap::new();
    attrs.insert("entrypointType".to_string(), json!("exported-component"));
    attrs.insert("file".to_string(), json!("Manifest.xml"));
    let entity = Entity { id: "ep:1".to_string(), kind: "entrypoint".to_string(), name: "comp".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("Manifest.xml", "<activity android:exported=\"true\" android:permission=\"com.app.PERM\"/>")]);
    let obs = mobile::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "mobile.exported-component.no-permission-gate"));
}

#[test]
fn mobile_webview_bridge_exposed() {
    let mut source_attrs = BTreeMap::new();
    source_attrs.insert("sourceKind".to_string(), json!("webview-js"));
    source_attrs.insert("file".to_string(), json!("Bridge.kt"));
    let source = Entity { id: "src:1".to_string(), kind: "source".to_string(), name: "webview".to_string(), attributes: source_attrs, evidence_refs: vec!["ev:src".to_string()] };

    let mut sink_attrs = BTreeMap::new();
    sink_attrs.insert("sinkKind".to_string(), json!("native-bridge"));
    sink_attrs.insert("file".to_string(), json!("Bridge.kt"));
    let sink = Entity { id: "sink:1".to_string(), kind: "sink".to_string(), name: "bridge".to_string(), attributes: sink_attrs, evidence_refs: vec!["ev:sink".to_string()] };

    let model = SecurityModel { entities: vec![source.clone(), sink.clone()] };
    let mut ctx = ctx_for(&model, &[("Bridge.kt", "@JavascriptInterface fun call() {}")]);
    ctx.relations.push(Relation { kind: "calls".to_string(), from: source.id.clone(), to: sink.id.clone() });
    let obs = mobile::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "mobile.webview.js-bridge-exposed").expect("expected match");
    assert_eq!(o.severity_hint, "high");
    assert_eq!(o.evidence_refs, vec!["ev:sink".to_string(), "ev:src".to_string()]);
}

#[test]
fn mobile_storage_insecure_sensitive_data() {
    let art = artifact("artifact:1", "Prefs.java");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("Prefs.java", "SharedPreferences prefs = getSharedPreferences(\"x\", 0); prefs.edit().putString(\"password\", value).apply();")]);
    let obs = mobile::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "mobile.storage.insecure-sensitive-data"));
}

#[test]
fn mobile_storage_mitigated_by_encrypted_prefs() {
    let art = artifact("artifact:1", "Prefs.java");
    let model = SecurityModel { entities: vec![art] };
    let ctx = ctx_for(&model, &[("Prefs.java", "EncryptedSharedPreferences.create(...); SharedPreferences prefs = getSharedPreferences(\"x\", 0); // password")]);
    let obs = mobile::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "mobile.storage.insecure-sensitive-data"));
}

#[test]
fn mobile_backup_enabled_without_exclusion() {
    let mut attrs = BTreeMap::new();
    attrs.insert("controlType".to_string(), json!("data-backup"));
    attrs.insert("controlState".to_string(), json!("absent"));
    attrs.insert("file".to_string(), json!("AndroidManifest.xml"));
    let entity = Entity { id: "ctl:1".to_string(), kind: "control".to_string(), name: "backup".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("AndroidManifest.xml", "")]);
    let obs = mobile::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "mobile.backup.enabled-without-exclusion"));
}

#[test]
fn mobile_transport_cleartext_allowed() {
    let mut attrs = BTreeMap::new();
    attrs.insert("controlType".to_string(), json!("transport-security"));
    attrs.insert("controlState".to_string(), json!("absent"));
    let entity = Entity { id: "ctl:1".to_string(), kind: "control".to_string(), name: "transport".to_string(), attributes: attrs, evidence_refs: vec![] };
    let model = SecurityModel { entities: vec![entity] };
    let ctx = ctx_for(&model, &[("x.xml", "")]);
    let obs = mobile::analyze(&ctx);
    assert!(obs.iter().any(|o| o.rule_id == "mobile.transport.cleartext-allowed"));
}

#[test]
fn mobile_signing_debug_config_in_release() {
    let art = artifact("artifact:1", "app/build.gradle");
    let model = SecurityModel { entities: vec![art] };
    let text = "android {\n  buildTypes {\n    release {\n      signingConfig signingConfigs.debug\n    }\n  }\n}\n";
    let ctx = ctx_for(&model, &[("app/build.gradle", text)]);
    let obs = mobile::analyze(&ctx);
    let o = obs.iter().find(|o| o.rule_id == "mobile.signing.debug-config-in-release").expect("expected match");
    assert_eq!(o.severity_hint, "critical");
}

#[test]
fn mobile_signing_skips_non_gradle_files() {
    let art = artifact("artifact:1", "notes.txt");
    let model = SecurityModel { entities: vec![art] };
    let text = "release { signingConfig signingConfigs.debug }";
    let ctx = ctx_for(&model, &[("notes.txt", text)]);
    let obs = mobile::analyze(&ctx);
    assert!(!obs.iter().any(|o| o.rule_id == "mobile.signing.debug-config-in-release"));
}
