//! Rust port of `tests/native-family-runner.test.mjs`, exercising the
//! production entry point `run_native_families` in
//! `legion_audit::native_providers::p10_runtime::build_and_runner`.
//!
//! NOTE: this test module assumes the integrator wires
//! `pub mod build_and_runner;` into
//! `engine/crates/legion-audit/src/native_providers/p10_runtime/mod.rs`
//! (and `pub mod p10_runtime;` into `native_providers/mod.rs`), and that the
//! crate is reachable as `legion_audit::native_providers::p10_runtime::build_and_runner`.

use legion_audit::native_providers::p10_runtime::build_and_runner::run_native_families;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

// Serializes the one test that mutates the process-wide `PATH` env var so
// it cannot race with other tests in this file running in parallel threads.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fixture(files: &[(&str, &str)]) -> PathBuf {
    // A counter (not just PID + wall-clock nanos) guarantees uniqueness even
    // when parallel #[test] threads in this same process call `fixture()`
    // back-to-back: on Windows, SystemTime::now() resolution is much coarser
    // than nanoseconds, so two threads can otherwise get the same "unique"
    // name and race on the same directory, letting one test's fixture files
    // bleed into another's.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut root = std::env::temp_dir();
    let unique = format!(
        "audit-native-{}-{}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        seq,
        std::thread::current().id()
    );
    root.push(unique);
    fs::create_dir_all(&root).unwrap();
    for (file, content) in files {
        let path = root.join(file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }
    root
}

fn plan(families: &[(&str, &[&str])]) -> serde_json::Value {
    let coverage_families: Vec<serde_json::Value> = families
        .iter()
        .map(|(id, paths)| json!({ "id": id, "denominator": { "paths": paths } }))
        .collect();
    json!({ "coverageFamilies": coverage_families })
}

#[test]
fn laravel_provider_detects_mass_assignment_and_raw_sql_hazards() {
    let root = fixture(&[
        ("composer.json", "{\"require\":{\"laravel/framework\":\"^12\"}}"),
        ("app/Service.php", "<?php Model::unguard(); DB::unprepared($sql);"),
    ]);
    let results = run_native_families(
        &root,
        &plan(&[
            ("language.php", &["composer.json", "app/Service.php"]),
            ("framework.laravel", &["composer.json", "app/Service.php"]),
        ]),
    );
    let laravel = results.iter().find(|item| item.family == "framework.laravel").unwrap();
    assert_eq!(laravel.status, "fail");
    let mut rule_ids: Vec<&str> = laravel.findings.iter().map(|f| f.rule_id.as_str()).collect();
    rule_ids.sort_unstable();
    assert_eq!(rule_ids, vec!["laravel-raw-sql", "laravel-unguard"]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn aspnet_and_spring_framework_checks_are_deterministic() {
    let root = fixture(&[
        ("Api/Program.cs", "services.AddCors(x => x.AllowAnyOrigin().AllowCredentials());"),
        ("src/Security.java", "http.csrf(csrf -> csrf.disable()); requestMatchers(\"/admin\").permitAll();"),
    ]);
    let results = run_native_families(
        &root,
        &plan(&[("framework.aspnet", &["Api/Program.cs"]), ("framework.spring", &["src/Security.java"])]),
    );
    assert_eq!(results.iter().find(|item| item.family == "framework.aspnet").unwrap().status, "fail");
    assert_eq!(results.iter().find(|item| item.family == "framework.spring").unwrap().status, "fail");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn missing_native_toolchain_is_unproven_never_clean() {
    let _guard = ENV_LOCK.lock().unwrap();
    let root = fixture(&[("src/main.go", "package main")]);
    let old_path = std::env::var("PATH").ok();
    std::env::set_var("PATH", "");
    let results = run_native_families(&root, &plan(&[("language.go", &["src/main.go"])]));
    match old_path {
        Some(p) => std::env::set_var("PATH", p),
        None => std::env::remove_var("PATH"),
    }
    let go = results.iter().find(|item| item.family == "language.go").unwrap();
    assert_eq!(go.status, "unproven");
    assert!(!go.complete);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn tailwind_dynamic_class_construction_is_surfaced() {
    let root = fixture(&[("src/App.tsx", "return <div className={`bg-${tone}`}/>")]);
    let results = run_native_families(&root, &plan(&[("framework.tailwind", &["src/App.tsx"])]));
    let tailwind = results.iter().find(|item| item.family == "framework.tailwind").unwrap();
    assert!(tailwind.findings.iter().any(|f| f.rule_id == "tailwind-dynamic-class"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn react_provider_catches_dangerous_html_and_missing_effect_cleanup() {
    let root = fixture(&[(
        "src/App.tsx",
        "import { useEffect } from 'react';\nexport function App(){ useEffect(()=>{ window.addEventListener('resize', resize); }, []); return <div dangerouslySetInnerHTML={{__html: html}}/> }",
    )]);
    let results = run_native_families(&root, &plan(&[("framework.react", &["src/App.tsx"])]));
    let react = results.iter().find(|item| item.family == "framework.react").unwrap();
    assert_eq!(react.status, "pass");
    assert!(react.findings.iter().any(|f| f.rule_id == "react-dangerous-html"));
    assert!(react.findings.iter().any(|f| f.rule_id == "react-effect-cleanup"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn tauri_provider_compares_invoke_calls_against_registered_commands() {
    let root = fixture(&[
        ("src/App.tsx", "invoke('delete_everything')"),
        ("src-tauri/src/lib.rs", "#[tauri::command]\nfn safe_command() {}"),
        ("src-tauri/tauri.conf.json", "{}"),
    ]);
    let results = run_native_families(
        &root,
        &plan(&[(
            "framework.tauri",
            &["src/App.tsx", "src-tauri/src/lib.rs", "src-tauri/tauri.conf.json"],
        )]),
    );
    let tauri = results.iter().find(|item| item.family == "framework.tauri").unwrap();
    assert_eq!(tauri.status, "fail");
    assert!(tauri.findings.iter().any(|f| f.rule_id == "tauri-unregistered-command"));
    let _ = fs::remove_dir_all(&root);
}
