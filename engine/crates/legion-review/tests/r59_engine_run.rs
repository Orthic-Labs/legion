//! Packet r59: tests for `engine_run.rs`/`health_check_run.rs`, the
//! orchestration halves of `src/lib/review/engine.py` and
//! `src/lib/review/health_check.py` that wire the previously-ported pure
//! logic (`engine_logic.rs`/`health_check_logic.rs`) to config, cache, and
//! a fake provider. No network calls and no subprocesses: the provider
//! boundary is `JuryProvider`, exercised here only with in-memory fakes.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_review::wf_port::w2_050::cache::Cache;
use legion_review::wf_port::w2_050::config::load_models_config;
use legion_review::wf_port::w2_051::engine_run::{
    build_prompts, load_lenses, Engine, EngineError, JuryProvider, LensCfg, Lenses, NoVisionPrep,
};
use legion_review::wf_port::w2_051::health_check_run::{run as health_run, to_health_config};
use legion_review::wf_port::w2_052::base::{ProviderError, ProviderImage};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "legion-review-r59-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

const MODELS_YAML: &str = r#"
prompt_version: 2
providers:
  good:
    type: openai_compat
    parallel_safe: true
  flaky:
    type: openai_compat
    parallel_safe: true
  off:
    type: openai_compat
    disabled: true
skills:
  review:
    rubric: rubric.txt
    jurors:
      - id: a
        provider: good
        model: model-a
      - id: b
        provider: flaky
        model: model-b
        fallbacks:
          - provider: good
            model: model-a-fb
    escalation:
      - trigger: jury_split
        provider: good
        model: escalation-model
"#;

/// A `JuryProvider` fake whose response is scripted per `model`, with a
/// call counter so tests can assert cache hits didn't re-invoke it.
struct FakeProvider {
    responses: BTreeMap<String, Result<String, ProviderError>>,
    calls: std::sync::atomic::AtomicU64,
}

impl FakeProvider {
    fn new(responses: Vec<(&str, Result<String, ProviderError>)>) -> Self {
        Self {
            responses: responses.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            calls: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl JuryProvider for FakeProvider {
    fn call(
        &self,
        model: &str,
        _system: &str,
        _user: &str,
        _max_tokens: i64,
        _images: Option<&[ProviderImage]>,
    ) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.responses.get(model) {
            Some(Ok(text)) => Ok(text.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err(ProviderError::new(format!("no fake response for {model}"))),
        }
    }
}

fn setup(cache_label: &str) -> (PathBuf, Cache) {
    let root = tmp_dir(&format!("{cache_label}-root"));
    std::fs::write(root.join("rubric.txt"), "Rate 1-10.").unwrap();
    let cache = Cache::new(root.join("cache")).unwrap();
    (root, cache)
}

fn load_cfg(root: &PathBuf) -> legion_review::wf_port::w2_050::config::ModelsConfig {
    let path = root.join("models.yaml");
    std::fs::write(&path, MODELS_YAML).unwrap();
    load_models_config(&path).expect("valid config")
}

// ---------- engine.py: build_prompts ----------

#[test]
fn build_prompts_terse_jury_round_trips_rubric_and_input() {
    let lenses = Lenses::new();
    let (system, user) = build_prompts("RUBRIC BODY", "USER INPUT", false, &lenses, None, "jury");
    assert_eq!(system, "Jury juror. Follow rubric. Output JSON only.");
    assert_eq!(user, "RUBRIC:\nRUBRIC BODY\n\nINPUT:\nUSER INPUT\n");
}

#[test]
fn build_prompts_council_panel_uses_council_role() {
    let lenses = Lenses::new();
    let (system, _user) = build_prompts("R", "U", false, &lenses, None, "council");
    assert!(system.starts_with("Council adviser."));
}

#[test]
fn build_prompts_vision_puts_rubric_in_system_and_minimal_user() {
    let lenses = Lenses::new();
    let (system, user) = build_prompts("RUBRIC", "ctx line", true, &lenses, None, "jury");
    assert!(system.starts_with("RUBRIC"));
    assert!(system.contains("reviewing the IMAGE"));
    assert!(user.starts_with("An image is attached"));
    assert!(user.contains("ctx line"));
}

#[test]
fn build_prompts_applies_lens_preamble_and_question() {
    let mut lenses = Lenses::new();
    lenses.insert(
        "skeptic".to_string(),
        LensCfg {
            preamble: "Be skeptical.  ".to_string(),
            lens_question: "skeptic_take".to_string(),
        },
    );
    let (system, _user) = build_prompts("R", "U", false, &lenses, Some("skeptic"), "jury");
    assert!(system.contains("# LENS (skeptic)\nBe skeptical."));
    assert!(system.contains("answers.skeptic_take"));
}

#[test]
fn load_lenses_missing_file_is_empty_not_error() {
    let lenses = load_lenses("/nonexistent/lenses.yaml").expect("missing file is not an error");
    assert!(lenses.is_empty());
}

// ---------- engine.py: Engine::run ----------

#[test]
fn run_happy_path_parses_verdicts_and_synthesizes_majority() {
    let (root, cache) = setup("happy");
    let cfg = load_cfg(&root);
    let lenses = Lenses::new();

    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(FakeProvider::new(vec![
            ("model-a", Ok(r#"{"verdict":"PASS","score":8}"#.to_string())),
            ("escalation-model", Ok(r#"{"verdict":"PASS","score":7}"#.to_string())),
        ])),
    );
    providers.insert(
        "flaky".to_string(),
        Box::new(FakeProvider::new(vec![(
            "model-b",
            Ok(r#"{"verdict":"PASS","score":9}"#.to_string()),
        )])),
    );

    let engine = Engine::new(&cfg, &root, lenses, providers, cache);
    let flags = BTreeMap::new();
    let result = engine
        .run(
            "review",
            "no packet fence here",
            &flags,
            true, // no_cache
            true, // no_escalation
            false, // enforce_packet — legacy (no-fence) input must not hard-fail
            "jury",
            None,
            &NoVisionPrep,
        )
        .expect("run should succeed");

    assert_eq!(result.jurors.len(), 2);
    // Sorted by juror_id.
    assert_eq!(result.jurors[0].juror_id, "a");
    assert_eq!(result.jurors[1].juror_id, "b");
    assert!(result.jurors.iter().all(|j| j.parsed_ok));
    assert_eq!(result.synthesis.majority_verdict, "PASS");
    assert_eq!(result.synthesis.majority_count, "2/2");
    assert!(!result.synthesis.split);
    assert!(!result.has_packet);
}

#[test]
fn run_unknown_skill_errors() {
    let (root, cache) = setup("unknown-skill");
    let cfg = load_cfg(&root);
    let providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
    let flags = BTreeMap::new();
    let err = engine
        .run("nope", "x", &flags, true, true, true, "jury", None, &NoVisionPrep)
        .expect_err("unknown skill must error");
    match err {
        EngineError::SkillNotFound(name) => assert_eq!(name, "nope"),
        other => panic!("expected SkillNotFound, got {other:?}"),
    }
}

#[test]
fn run_invalid_packet_hard_fails_when_enforced() {
    let (root, cache) = setup("bad-packet");
    let cfg = load_cfg(&root);
    let providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
    let flags = BTreeMap::new();
    // A packet fence with no required sections: has a fence (not the
    // legacy no-fence path) but fails validation.
    let bad_input = "```packet\nSOMETHING: x\n```";
    let err = engine
        .run("review", bad_input, &flags, true, true, true, "jury", None, &NoVisionPrep)
        .expect_err("invalid packet must hard-fail when enforce_packet=true");
    assert!(matches!(err, EngineError::PacketInvalid(_)));
}

#[test]
fn run_disabled_provider_falls_through_to_fallback() {
    let (root, cache) = setup("fallback");
    // Rewrite the config so juror "a" is on the disabled provider directly.
    let yaml = r#"
prompt_version: 1
providers:
  off:
    type: openai_compat
    disabled: true
  good:
    type: openai_compat
    parallel_safe: true
skills:
  review:
    rubric: rubric.txt
    jurors:
      - id: a
        provider: off
        model: dead-model
        fallbacks:
          - provider: good
            model: live-model
"#;
    let path = root.join("models.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = load_models_config(&path).unwrap();

    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(FakeProvider::new(vec![(
            "live-model",
            Ok(r#"{"verdict":"PASS","score":5}"#.to_string()),
        )])),
    );

    let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
    let flags = BTreeMap::new();
    let result = engine
        .run("review", "x", &flags, true, true, false, "jury", None, &NoVisionPrep)
        .unwrap();
    assert_eq!(result.jurors.len(), 1);
    let j = &result.jurors[0];
    assert!(j.parsed_ok);
    assert!(j.fallback_used);
    assert_eq!(j.model, "live-model");
}

#[test]
fn run_all_fallbacks_exhausted_returns_error_result() {
    let (root, cache) = setup("exhausted");
    let cfg = load_cfg(&root);
    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(FakeProvider::new(vec![(
            "model-a",
            Err(ProviderError::with_status("boom", 500, false)),
        )])),
    );
    providers.insert(
        "flaky".to_string(),
        Box::new(FakeProvider::new(vec![(
            "model-b",
            Err(ProviderError::new("also dead")),
        )])),
    );
    let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
    let flags = BTreeMap::new();
    let result = engine
        .run("review", "x", &flags, true, true, false, "jury", None, &NoVisionPrep)
        .unwrap();
    let a = result.jurors.iter().find(|j| j.juror_id == "a").unwrap();
    assert_eq!(a.verdict, "ERROR");
    assert_eq!(a.error.as_deref(), Some("boom"));
    let b = result.jurors.iter().find(|j| j.juror_id == "b").unwrap();
    assert_eq!(b.verdict, "ERROR");
    // b's chain is flaky/model-b then good/model-a-fb (no fake for that
    // model on "good" -> also errors) so it exhausts both.
    assert!(b.error.is_some());
}

#[test]
fn run_caches_parsed_result_and_skips_second_provider_call() {
    let (root, cache) = setup("cache-hit");
    let yaml = r#"
prompt_version: 1
providers:
  good:
    type: openai_compat
    parallel_safe: true
skills:
  review:
    rubric: rubric.txt
    jurors:
      - id: a
        provider: good
        model: model-a
"#;
    let path = root.join("models.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = load_models_config(&path).unwrap();

    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(FakeProvider::new(vec![(
            "model-a",
            Ok(r#"{"verdict":"PASS","score":6}"#.to_string()),
        )])),
    );

    // First run: no_cache=false, populates the cache.
    let flags = BTreeMap::new();
    {
        let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
        let r1 = engine
            .run("review", "same input", &flags, false, true, false, "jury", None, &NoVisionPrep)
            .unwrap();
        assert!(r1.jurors[0].parsed_ok);
        assert!(!r1.jurors[0].cache_hit);

        // Second run against the SAME engine (same cache dir, same input):
        // the cache lookup should short-circuit the provider call.
        let r2 = engine
            .run("review", "same input", &flags, false, true, false, "jury", None, &NoVisionPrep)
            .unwrap();
        assert!(r2.jurors[0].cache_hit);
        assert_eq!(r2.jurors[0].verdict, "PASS");
    }
}

#[test]
fn run_escalation_triggers_on_jury_split() {
    let (root, cache) = setup("escalation");
    let cfg = load_cfg(&root);
    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(FakeProvider::new(vec![
            ("model-a", Ok(r#"{"verdict":"PASS","score":8}"#.to_string())),
            ("escalation-model", Ok(r#"{"verdict":"FAIL","score":2}"#.to_string())),
        ])),
    );
    providers.insert(
        "flaky".to_string(),
        Box::new(FakeProvider::new(vec![(
            "model-b",
            Ok(r#"{"verdict":"FAIL","score":1}"#.to_string()),
        )])),
    );
    let engine = Engine::new(&cfg, &root, Lenses::new(), providers, cache);
    let flags = BTreeMap::new();
    let result = engine
        .run(
            "review", "x", &flags, true, /* no_cache */
            false, /* no_escalation = false -> escalation runs */
            false, "jury", None, &NoVisionPrep,
        )
        .unwrap();
    assert!(result.synthesis.split);
    assert_eq!(result.escalation.len(), 1);
    assert_eq!(result.escalation[0].juror_id, "escalation:good");
    assert_eq!(result.escalation[0].verdict, "FAIL");
}

// ---------- health_check.py ----------

struct HealthFakeProvider {
    outcome: Result<&'static str, (i32, &'static str)>,
}

impl JuryProvider for HealthFakeProvider {
    fn call(
        &self,
        _model: &str,
        _system: &str,
        _user: &str,
        _max_tokens: i64,
        _images: Option<&[ProviderImage]>,
    ) -> Result<String, ProviderError> {
        match self.outcome {
            Ok(text) => Ok(text.to_string()),
            Err((status, msg)) => Err(ProviderError::with_status(msg, status, false)),
        }
    }
}

#[test]
fn to_health_config_collects_skill_jurors_and_escalation() {
    let (root, _cache) = setup("hc-config");
    let cfg = load_cfg(&root);
    let health_cfg = to_health_config(&cfg);
    assert!(health_cfg.skills.contains_key("review"));
    let (jurors, escalation) = &health_cfg.skills["review"];
    assert_eq!(jurors.len(), 2);
    assert_eq!(escalation.len(), 1);
}

#[test]
fn health_check_run_flags_unreachable_primary_and_sets_nonzero_exit() {
    let (root, _cache) = setup("hc-run");
    let cfg = load_cfg(&root);

    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(HealthFakeProvider { outcome: Ok("ok") }),
    );
    providers.insert(
        "flaky".to_string(),
        Box::new(HealthFakeProvider {
            outcome: Err((404, "model not found")),
        }),
    );
    // "off" is disabled in config but still enumerated if wired; leave
    // unwired here (mirrors Python's provider build failure -> None).

    let (json_output, exit_code) = health_run(
        &["--json".to_string(), "--primary-only".to_string()],
        &cfg,
        &providers,
    );
    assert_eq!(exit_code, 1, "flaky/model-b is a PRIMARY unreachable seat");
    let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    let broken = parsed["primary_broken"].as_array().unwrap();
    assert!(broken.iter().any(|v| v.as_str().unwrap().contains("flaky")));
}

#[test]
fn health_check_run_table_mode_all_ok_exits_zero() {
    let (root, _cache) = setup("hc-table");
    let yaml = r#"
providers:
  good:
    type: openai_compat
skills:
  review:
    rubric: rubric.txt
    jurors:
      - id: a
        provider: good
        model: model-a
"#;
    let path = root.join("models.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = load_models_config(&path).unwrap();

    let mut providers: BTreeMap<String, Box<dyn JuryProvider>> = BTreeMap::new();
    providers.insert(
        "good".to_string(),
        Box::new(HealthFakeProvider { outcome: Ok("ok") }),
    );

    let (table, exit_code) = health_run(&[], &cfg, &providers);
    assert_eq!(exit_code, 0);
    assert!(table.contains("STATUS"));
    assert!(table.contains("model-a"));
    assert!(!table.contains("PRIMARY seats unreachable"));
}
