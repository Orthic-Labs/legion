//! Integration tests for the ported `wf_port::w2_013` module, mirroring
//! `skills/designer/engine/scripts/detector/{findings.mjs,node/file-system.mjs,
//! profile/profiler.mjs}` and the pure-logic slices of
//! `detector/engines/{static-html/detect-html.mjs,visual/screenshot-contrast.mjs}`.

use legion_runtime::wf_port::w2_013::detect_html::classify_img_src;
use legion_runtime::wf_port::w2_013::file_system::{
    build_import_graph, detect_framework_config, is_port_listening_tcp, resolve_import, walk_dir,
};
use legion_runtime::wf_port::w2_013::findings::build_finding;
use legion_runtime::wf_port::w2_013::profiler::{
    percentile, record_profile_event, summarize_detector_profile, DetectorProfile, ProfileMeta,
};
use legion_runtime::wf_port::w2_013::screenshot_contrast::{
    contrast_ratio, pick_percentile, sanitize_screenshot_clip, Clip, Rgb,
};
use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wf_w2_013_integration_{name}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// -- findings.mjs -----------------------------------------------------------

#[test]
fn finding_assembly_matches_js_shape_and_warning_default() {
    let f = build_finding(
        "broken-image",
        "Broken image reference",
        "img element has no usable src",
        "",
        "index.html",
        r#"<img src="#">"#,
        0,
    );
    assert_eq!(f.antipattern, "broken-image");
    assert_eq!(f.severity, "warning");
    assert_eq!(f.line, 0);
}

// -- node/file-system.mjs ----------------------------------------------------

#[test]
fn walk_dir_and_import_graph_end_to_end() {
    let root = tmpdir("walk_import");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/index.ts"), "import './app';\n").unwrap();
    std::fs::write(root.join("src/app.ts"), "export const app = 1;\n").unwrap();
    std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    std::fs::write(root.join("node_modules/pkg/index.js"), "module.exports = {}").unwrap();

    let files = walk_dir(&root);
    let file_names: HashSet<String> = files
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().to_string_lossy().to_string())
        .collect();
    assert!(file_names.contains("src/index.ts"));
    assert!(file_names.contains("src/app.ts"));
    assert!(!file_names.iter().any(|f| f.starts_with("node_modules")));

    let graph = build_import_graph(&files);
    let index_ts = root.join("src/index.ts");
    let app_ts = root.join("src/app.ts");
    assert!(graph[&index_ts].contains(&app_ts));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn resolve_import_bare_specifier_is_skipped() {
    let files: HashSet<PathBuf> = HashSet::new();
    assert_eq!(resolve_import("react-dom", std::path::Path::new("/x"), &files), None);
}

#[test]
fn detect_framework_config_finds_next_js_with_default_port() {
    let root = tmpdir("nextjs");
    std::fs::write(root.join("next.config.js"), "module.exports = {}").unwrap();
    let detected = detect_framework_config(&root).unwrap();
    assert_eq!(detected.name, "Next.js");
    assert_eq!(detected.port, 3000);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn is_port_listening_tcp_true_when_something_is_listening() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let status = is_port_listening_tcp(port);
    assert!(status.listening);
    assert_eq!(status.matched, Some(true));
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    handle.join().unwrap();
}

// -- profile/profiler.mjs ----------------------------------------------------

#[test]
fn profiler_records_and_summarizes_events() {
    let mut profile = DetectorProfile::new();
    let meta = ProfileMeta::new("static-html", "element", "border-rules", "index.html");
    record_profile_event(&mut profile, &meta, 5.0, 1, vec!["side-tab".to_string()]);
    record_profile_event(&mut profile, &meta, 15.0, 0, vec![]);

    let summary = summarize_detector_profile(&profile);
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].calls, 2);
    assert_eq!(summary[0].total_ms, 20.0);
    assert_eq!(summary[0].findings, 1);
}

#[test]
fn percentile_helper_matches_js_ceil_formula_for_p95() {
    let sorted = (1..=20).map(|n| n as f64).collect::<Vec<_>>();
    // ceil(0.95*20)-1 = ceil(19)-1 = 18 -> sorted[18] = 19
    assert_eq!(percentile(&sorted, 95.0), 19.0);
}

// -- engines/visual/screenshot-contrast.mjs (pure slices) --------------------

#[test]
fn sanitize_clip_and_contrast_ratio_roundtrip() {
    let clip = sanitize_screenshot_clip(
        Some(Clip { x: 0, y: 0, width: 4000, height: 1000 }),
        Some(1600),
    )
    .unwrap();
    assert_eq!(clip, Clip { x: 0, y: 0, width: 1600, height: 320 });

    let black = Rgb { r: 0.0, g: 0.0, b: 0.0 };
    let white = Rgb { r: 255.0, g: 255.0, b: 255.0 };
    assert!(contrast_ratio(black, white) > 20.9);

    let ratios = vec![2.0, 4.0, 6.0, 8.0, 10.0];
    assert_eq!(pick_percentile(&ratios, 10.0), 2.0);
}

// -- engines/static-html/detect-html.mjs (pure slice) -------------------------

#[test]
fn classify_img_src_flags_broken_images_and_passes_real_src() {
    assert!(classify_img_src(None).is_some());
    assert!(classify_img_src(Some("#")).is_some());
    assert!(classify_img_src(Some("")).is_some());
    assert!(classify_img_src(Some("/hero.png")).is_none());
}

// Sanity: writer used std::io::Write via `write!` earlier in file_system
// tests; keep the import used here too, for a config file fixture.
#[test]
fn detect_framework_config_reads_port_from_config_file() {
    let root = tmpdir("port_from_config");
    let mut f = std::fs::File::create(root.join("nuxt.config.ts")).unwrap();
    writeln!(f, "export default {{ server: {{ port: 4500 }} }}").unwrap();
    let detected = detect_framework_config(&root).unwrap();
    assert_eq!(detected.name, "Nuxt");
    assert_eq!(detected.port, 4500);
    let _ = std::fs::remove_dir_all(&root);
}
