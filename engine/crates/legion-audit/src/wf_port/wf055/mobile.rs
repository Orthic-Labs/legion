//! Port of `src/providers/security/model-extractors/mobile.mjs`.
//!
//! Mobile extractor (B7-007): Android/iOS manifest and config repository
//! text plus upstream package-manifest evidence from the Blueprint
//! projection. Extracts declared permissions, deep links, JS/native
//! bridges, exported components, and backup/cleartext-traffic flags.
//!
//! Repository/config text and upstream projection facts only. No device
//! connection, no emulator, no app install, no network probe of any kind.
//!
//! NOTE on a JS source quirk *not* reproduced here: `EXPORTED_COMPONENT_PATTERN`
//! (`/android:exported="true"/g`) and `GRAPHQL_INTROSPECTION_TRUE`-style
//! module-scoped `/g` regexes retain `lastIndex` state across the JS
//! `for (const file of files)` loop iterations when called with `.test()`.
//! That means, in the original source, a match late in one file's text can
//! leave `lastIndex` positioned such that a match earlier in the *next*
//! file's text is missed until the following call resets it (on a `false`
//! result `.test()` resets `lastIndex` to 0). This Rust port evaluates each
//! file's text independently (`Regex::is_match`, which is stateless) and so
//! does not reproduce that per-file statefulness bug; the intended
//! per-file detection (every file with the literal marker is flagged) is
//! preserved, and this port is a strict superset in this bounded regard.
//! No test in the ported test file exercises the buggy path (which would
//! require multiple files sharing the same iteration).

use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::wf_port::wf052::contracts::stable_id;
use crate::wf_port::wf055::common::{entity, fact, relation, FactFields};

static MOBILE_FILE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|/)(AndroidManifest\.xml|.*\.gradle(\.kts)?|Info\.plist|.*\.plist|Podfile|capacitor\.config\.(json|ts|js)|ionic\.config\.json|app\.json|pubspec\.yaml)$",
    )
    .expect("valid regex")
});
static MOBILE_DEP_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(react-native|expo|@capacitor/core|cordova|@ionic/)").expect("valid regex"));

static ANDROID_PERMISSION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<uses-permission[^>]*android:name="([^"]+)""#).expect("valid regex"));
static IOS_USAGE_DESCRIPTION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<key>(NS\w*UsageDescription)</key>").expect("valid regex"));
static INTENT_FILTER_CONTEXT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<intent-filter\b.*?</intent-filter>").expect("valid regex")
});
static ANDROID_SCHEME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"android:scheme="([^"]+)""#).expect("valid regex"));
static IOS_URL_SCHEME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"CFBundleURLSchemes").expect("valid regex"));
static APP_LINKS_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"applinks:|android:autoVerify="true""#).expect("valid regex"));
static JS_NATIVE_BRIDGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"@ReactMethod|addJavascriptInterface|JavascriptInterface|WKScriptMessageHandler|NativeModules|evaluateJavascript|postMessage\s*\(")
        .expect("valid regex")
});
static EXPORTED_COMPONENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"android:exported="true""#).expect("valid regex"));
static ALLOW_BACKUP_TRUE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"android:allowBackup="true""#).expect("valid regex"));
static ALLOW_BACKUP_FALSE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"android:allowBackup="false""#).expect("valid regex"));
static CLEARTEXT_ANDROID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"android:usesCleartextTraffic="true""#).expect("valid regex"));
static CLEARTEXT_IOS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)NSAllowsArbitraryLoads</key>\s*<true\s*/>").expect("valid regex")
});

/// A repository file as this extractor needs it: its path and, if the
/// upstream projection rendered source text for it, that text. `None`
/// mirrors JS `sourceText[file] === undefined` (a matched mobile
/// config file the projection never rendered text for); `Some(String::new())`
/// mirrors JS `''` (rendered but empty, silently skipped).
pub type MobileFile = (String, Option<String>);

#[derive(Default, Clone)]
pub struct MobileExtraction {
    pub entities: Vec<Value>,
    pub relations: Vec<Value>,
    pub evidence: Vec<Value>,
    pub initial_facts: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
}

/// Port of `isMobileDependency(projection)`: true if any package-manifest
/// dependency name matches `MOBILE_DEP_PATTERN`.
fn is_mobile_dependency(manifest_dependencies: &[String]) -> bool {
    manifest_dependencies.iter().any(|dep| MOBILE_DEP_PATTERN.is_match(dep))
}

/// Port of `extractMobile({ root, plan, projection, files, lensRegistry })`.
///
/// `manifest_dependencies` stands in for
/// `projection.auditFacts.packageManifests[*].dependencies` flattened.
pub fn extract_mobile(files: &[MobileFile], manifest_dependencies: &[String]) -> MobileExtraction {
    let mut out = MobileExtraction::default();
    let mut saw_mobile_signal = is_mobile_dependency(manifest_dependencies);

    // JS/native bridge code lives in ordinary source files, not the
    // manifest/plist config files scanned below, so it gets its own pass
    // over the full denominator.
    for (file, text) in files {
        let Some(text) = text else { continue };
        if text.is_empty() {
            continue;
        }
        if JS_NATIVE_BRIDGE_PATTERN.is_match(text) {
            saw_mobile_signal = true;
            let evidence_ref = stable_id("mobile-bridge-evidence", &json!({ "file": file }));
            let js_source = entity(
                "source",
                &format!("webview JS caller {file}"),
                json!({ "file": file, "sourceKind": "webview-js", "trust": "untrusted" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let native_sink = entity(
                "sink",
                &format!("native bridge handler {file}"),
                json!({ "file": file, "sinkKind": "native-bridge" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let js_source_id = js_source["id"].as_str().unwrap_or_default().to_string();
            let native_sink_id = native_sink["id"].as_str().unwrap_or_default().to_string();
            out.entities.push(js_source);
            out.entities.push(native_sink);
            out.relations.push(relation(
                "calls",
                &js_source_id,
                &native_sink_id,
                &[evidence_ref.clone()],
                json!({}),
                None,
                None,
            ));
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "JS/native bridge",
            }));
        }
    }

    for (file, text) in files {
        if !MOBILE_FILE_PATTERN.is_match(file) {
            continue;
        }

        let Some(text) = text else {
            out.coverage_gaps.push(json!({
                "kind": "missing-rendered-configuration",
                "domain": "mobile",
                "file": file,
                "reason": "file matched a mobile manifest/config pattern but no source text was projected for it",
            }));
            continue;
        };
        if text.is_empty() {
            continue;
        }
        saw_mobile_signal = true;

        let mut permission_names: BTreeSet<String> = BTreeSet::new();
        for cap in ANDROID_PERMISSION_PATTERN.captures_iter(text) {
            permission_names.insert(cap[1].to_string());
        }
        for cap in IOS_USAGE_DESCRIPTION_PATTERN.captures_iter(text) {
            permission_names.insert(cap[1].to_string());
        }
        // JS iterates `for (const name of permissionNames)` over a `Set`,
        // which preserves first-insertion order (Android matches before
        // iOS matches, in source order within each). A `BTreeSet` instead
        // yields lexical order; the resulting entity *set* is identical,
        // only emission order can differ, which does not change any
        // ported test's assertions (each test checks membership/shape, not
        // sequence, matching how the JS test suite for this file asserts).
        for name in &permission_names {
            let evidence_ref = stable_id("mobile-permission-evidence", &json!({ "file": file, "name": name }));
            let permission = entity(
                "permission-scope",
                &format!("declared permission {name}"),
                json!({ "file": file, "permission": name }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            out.entities.push(permission);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": format!("Declared permission {name}"),
            }));
        }

        let mut deep_link_schemes: BTreeSet<String> = BTreeSet::new();
        for block in INTENT_FILTER_CONTEXT_PATTERN.find_iter(text) {
            for cap in ANDROID_SCHEME_PATTERN.captures_iter(block.as_str()) {
                deep_link_schemes.insert(cap[1].to_string());
            }
        }
        let has_deep_link = !deep_link_schemes.is_empty()
            || IOS_URL_SCHEME_PATTERN.is_match(text)
            || APP_LINKS_PATTERN.is_match(text);
        if has_deep_link {
            let evidence_ref = stable_id("mobile-deep-link-evidence", &json!({ "file": file }));
            let schemes: Vec<Value> = deep_link_schemes.iter().cloned().map(Value::String).collect();
            let entrypoint = entity(
                "entrypoint",
                &format!("deep link entrypoint {file}"),
                json!({
                    "file": file,
                    "entrypointType": "deep-link",
                    "schemes": schemes,
                    "trust": "untrusted",
                }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let entrypoint_id = entrypoint["id"].as_str().unwrap_or_default().to_string();
            out.entities.push(entrypoint);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Deep link entrypoint",
            }));
            out.initial_facts.push(fact(
                "network-reachability",
                FactFields {
                    subject: Some("actor:external".into()),
                    action: Some("reach".into()),
                    object: Some(entrypoint_id),
                    scope: Some("mobile".into()),
                    attributes: Some(json!({ "vector": "deep-link" })),
                    ..Default::default()
                },
                &[evidence_ref],
            ));
        }

        if EXPORTED_COMPONENT_PATTERN.is_match(text) {
            let evidence_ref = stable_id("mobile-exported-evidence", &json!({ "file": file }));
            let exported = entity(
                "entrypoint",
                &format!("exported component {file}"),
                json!({ "file": file, "entrypointType": "exported-component" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let exported_id = exported["id"].as_str().unwrap_or_default().to_string();
            out.entities.push(exported);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Exported Android component",
            }));
            out.initial_facts.push(fact(
                "network-reachability",
                FactFields {
                    subject: Some("actor:external".into()),
                    action: Some("reach".into()),
                    object: Some(exported_id),
                    scope: Some("mobile".into()),
                    attributes: Some(json!({ "vector": "on-device-inter-app" })),
                    ..Default::default()
                },
                &[evidence_ref],
            ));
        }

        if ALLOW_BACKUP_TRUE_PATTERN.is_match(text) || ALLOW_BACKUP_FALSE_PATTERN.is_match(text) {
            let evidence_ref = stable_id("mobile-backup-evidence", &json!({ "file": file }));
            let control_state = if ALLOW_BACKUP_TRUE_PATTERN.is_match(text) { "absent" } else { "enforced" };
            let control = crate::wf_port::wf055::common::control_entity(
                "data-backup",
                &format!("application backup policy {file}"),
                &[evidence_ref.clone()],
                json!({ "controlState": control_state }),
            );
            out.entities.push(control);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Application backup policy",
            }));
        }

        if CLEARTEXT_ANDROID_PATTERN.is_match(text) || CLEARTEXT_IOS_PATTERN.is_match(text) {
            let evidence_ref = stable_id("mobile-cleartext-evidence", &json!({ "file": file }));
            let control = crate::wf_port::wf055::common::control_entity(
                "transport-security",
                &format!("cleartext traffic policy {file}"),
                &[evidence_ref.clone()],
                json!({ "controlState": "absent" }),
            );
            out.entities.push(control);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Cleartext traffic allowed",
            }));
        }
    }

    if !saw_mobile_signal {
        out.coverage_gaps.push(json!({
            "kind": "mobile-context-not-detected",
            "domain": "mobile",
            "reason": "no mobile manifest/config file or mobile framework dependency found in the denominator",
        }));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signal_at_all_reports_mobile_context_not_detected() {
        let out = extract_mobile(&[("src/index.js".into(), Some("console.log('hi')".into()))], &[]);
        assert_eq!(out.coverage_gaps.len(), 1);
        assert_eq!(out.coverage_gaps[0]["kind"], "mobile-context-not-detected");
    }

    #[test]
    fn mobile_dependency_alone_suppresses_context_gap() {
        let out = extract_mobile(&[], &["react-native".into()]);
        assert!(out.coverage_gaps.is_empty());
    }

    #[test]
    fn android_manifest_permissions_are_extracted() {
        let text = r#"<manifest><uses-permission android:name="android.permission.CAMERA"/></manifest>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let permission = out
            .entities
            .iter()
            .find(|e| e["kind"] == "permission-scope")
            .expect("permission entity present");
        assert_eq!(permission["attributes"]["permission"], "android.permission.CAMERA");
        assert!(out.coverage_gaps.is_empty());
    }

    #[test]
    fn ios_usage_description_is_extracted_from_plist() {
        let text = "<dict><key>NSCameraUsageDescription</key><string>Camera access</string></dict>";
        let out = extract_mobile(&[("ios/App/Info.plist".into(), Some(text.into()))], &[]);
        let permission = out
            .entities
            .iter()
            .find(|e| e["kind"] == "permission-scope")
            .expect("permission entity present");
        assert_eq!(permission["attributes"]["permission"], "NSCameraUsageDescription");
    }

    #[test]
    fn deep_link_scheme_inside_intent_filter_produces_entrypoint_and_fact() {
        let text = r#"<intent-filter><data android:scheme="myapp"/></intent-filter>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let entrypoint = out
            .entities
            .iter()
            .find(|e| e["kind"] == "entrypoint" && e["attributes"]["entrypointType"] == "deep-link")
            .expect("deep link entrypoint present");
        assert_eq!(entrypoint["attributes"]["schemes"], json!(["myapp"]));
        assert_eq!(out.initial_facts.len(), 1);
        assert_eq!(out.initial_facts[0]["attributes"]["vector"], "deep-link");
    }

    #[test]
    fn ios_url_scheme_key_alone_triggers_deep_link_without_named_scheme() {
        let text = "<key>CFBundleURLSchemes</key><array><string>myapp</string></array>";
        let out = extract_mobile(&[("ios/App/Info.plist".into(), Some(text.into()))], &[]);
        let entrypoint = out
            .entities
            .iter()
            .find(|e| e["kind"] == "entrypoint")
            .expect("entrypoint present");
        assert_eq!(entrypoint["attributes"]["schemes"], json!([]));
    }

    #[test]
    fn exported_component_produces_entrypoint_and_inter_app_fact() {
        let text = r#"<activity android:name=".Main" android:exported="true"/>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let exported = out
            .entities
            .iter()
            .find(|e| e["attributes"]["entrypointType"] == "exported-component")
            .expect("exported component present");
        assert_eq!(exported["kind"], "entrypoint");
        assert_eq!(out.initial_facts[0]["attributes"]["vector"], "on-device-inter-app");
    }

    #[test]
    fn allow_backup_true_reports_absent_control_state() {
        let text = r#"<application android:allowBackup="true"/>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let control = out.entities.iter().find(|e| e["kind"] == "control").expect("control present");
        assert_eq!(control["attributes"]["controlType"], "data-backup");
        assert_eq!(control["attributes"]["controlState"], "absent");
    }

    #[test]
    fn allow_backup_false_reports_enforced_control_state() {
        let text = r#"<application android:allowBackup="false"/>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let control = out.entities.iter().find(|e| e["kind"] == "control").expect("control present");
        assert_eq!(control["attributes"]["controlState"], "enforced");
    }

    #[test]
    fn cleartext_android_true_reports_absent_transport_security_control() {
        let text = r#"<application android:usesCleartextTraffic="true"/>"#;
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), Some(text.into()))], &[]);
        let control = out.entities.iter().find(|e| e["kind"] == "control").expect("control present");
        assert_eq!(control["attributes"]["controlType"], "transport-security");
        assert_eq!(control["attributes"]["controlState"], "absent");
    }

    #[test]
    fn cleartext_ios_arbitrary_loads_true_reports_absent_transport_security_control() {
        let text = "<key>NSAllowsArbitraryLoads</key>\n<true/>";
        let out = extract_mobile(&[("ios/App/Info.plist".into(), Some(text.into()))], &[]);
        let control = out.entities.iter().find(|e| e["kind"] == "control").expect("control present");
        assert_eq!(control["attributes"]["controlType"], "transport-security");
    }

    #[test]
    fn js_native_bridge_in_ordinary_source_file_is_detected_outside_manifest_pass() {
        let text = "class Bridge { @ReactMethod public void doThing() {} }";
        let out = extract_mobile(&[("android/app/src/main/java/Bridge.java".into(), Some(text.into()))], &[]);
        assert_eq!(out.relations.len(), 1);
        assert_eq!(out.relations[0]["kind"], "calls");
        assert_eq!(out.entities.len(), 2);
        assert!(out.entities.iter().any(|e| e["kind"] == "source"));
        assert!(out.entities.iter().any(|e| e["kind"] == "sink"));
        assert!(out.coverage_gaps.is_empty());
    }

    #[test]
    fn matched_config_file_with_no_projected_text_reports_missing_rendered_configuration() {
        let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".into(), None)], &[]);
        assert_eq!(out.coverage_gaps.len(), 1);
        assert_eq!(out.coverage_gaps[0]["kind"], "missing-rendered-configuration");
        assert_eq!(out.coverage_gaps[0]["file"], "app/src/main/AndroidManifest.xml");
    }

    #[test]
    fn non_matching_file_with_no_text_is_not_flagged_as_missing_configuration() {
        let out = extract_mobile(&[("src/index.js".into(), None)], &[]);
        // Not a mobile-pattern file, so no coverage gap from the second
        // pass; still reports mobile-context-not-detected since nothing
        // else was observed.
        assert_eq!(out.coverage_gaps.len(), 1);
        assert_eq!(out.coverage_gaps[0]["kind"], "mobile-context-not-detected");
    }

    #[test]
    fn pubspec_and_podfile_and_gradle_kts_match_the_file_pattern() {
        for name in ["pubspec.yaml", "ios/Podfile", "android/app/build.gradle.kts"] {
            assert!(MOBILE_FILE_PATTERN.is_match(name), "expected {name} to match");
        }
    }
}
