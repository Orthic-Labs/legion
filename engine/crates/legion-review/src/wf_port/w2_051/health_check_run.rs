//! r59: closes the orchestration gap `health_check_logic.rs` left open —
//! the live-probing, config-wired half of `src/lib/review/health_check.py`
//! (`enumerate_models`'s config adapter, `classify`'s live call, and
//! `main`'s table/JSON rendering + exit-code CLI entrypoint).
//!
//! The network probe (`provider_obj.call(...)`) sits behind
//! [`engine_run::JuryProvider`], the same trait `engine.py`'s port uses —
//! same shape, same fake-driven tests, no real HTTP.

use std::collections::BTreeMap;
use std::time::Instant;

use super::super::w2_050::config::ModelsConfig as ConfigModelsConfig;
use super::super::w2_052::base::ProviderError;
use super::engine_run::JuryProvider;
use super::health_check_logic::{
    classify, enumerate_models, primary_broken, ClassifyResult, EscalationSpec, JurorSpec,
    ModelRow, ModelsConfig as HealthModelsConfig, ProbeOutcome,
};

pub const PROBE_SYSTEM: &str = "Reply with the single character: ok";
pub const PROBE_USER: &str = "ok";

/// Port of `enumerate_models`'s config read: adapts the shared
/// `w2_050::config::ModelsConfig` (panels + skills) into the
/// `health_check_logic` module's reduced `ModelsConfig` shape.
pub fn to_health_config(cfg: &ConfigModelsConfig) -> HealthModelsConfig {
    let mut panels = BTreeMap::new();
    for (name, panel) in &cfg.panels {
        let jurors = panel
            .jurors
            .iter()
            .map(|j| JurorSpec {
                id: j.id.clone(),
                provider: j.provider.clone(),
                model: j.model.clone(),
                fallbacks: j
                    .fallbacks
                    .iter()
                    .map(|fb| (fb.provider.clone(), fb.model.clone()))
                    .collect(),
            })
            .collect();
        panels.insert(name.clone(), jurors);
    }

    let mut skills = BTreeMap::new();
    for (name, skill) in &cfg.skills {
        let jurors = skill
            .jurors
            .iter()
            .map(|j| JurorSpec {
                id: j.id.clone(),
                provider: j.provider.clone(),
                model: j.model.clone(),
                fallbacks: j
                    .fallbacks
                    .iter()
                    .map(|fb| (fb.provider.clone(), fb.model.clone()))
                    .collect(),
            })
            .collect();
        let escalation = skill
            .escalation
            .iter()
            .map(|e| EscalationSpec {
                provider: Some(e.provider.clone()),
                model: Some(e.model.clone()),
            })
            .collect();
        skills.insert(name.clone(), (jurors, escalation));
    }

    HealthModelsConfig { panels, skills }
}

/// One fully classified row, mirroring the Python `results.append({...})` dict.
#[derive(Debug, Clone)]
pub struct HealthRow {
    pub provider: String,
    pub model: String,
    pub primary: bool,
    pub disabled_provider: bool,
    pub primary_seats: Vec<String>,
    pub fallback_seats: Vec<String>,
    pub classify: ClassifyResult,
}

/// Port of `classify`'s live half: runs the probe through `provider` (or
/// treats a `None` entry as "provider not built", matching Python's
/// `providers.get(provider_name)` returning `None` after a failed
/// `build_provider`), then defers to the pure `classify` decision tree.
pub fn probe_and_classify(provider: Option<&dyn JuryProvider>, model: &str) -> ClassifyResult {
    let Some(provider) = provider else {
        return classify(&ProbeOutcome::NoProvider);
    };
    let t0 = Instant::now();
    match provider.call(model, PROBE_SYSTEM, PROBE_USER, 1024, None) {
        Ok(raw) => classify(&ProbeOutcome::Ok {
            raw: Some(raw),
            latency_ms: t0.elapsed().as_millis() as i64,
        }),
        Err(ProviderError {
            message,
            status,
            is_quota,
        }) => classify(&ProbeOutcome::ProviderError {
            status,
            is_quota,
            message,
            latency_ms: t0.elapsed().as_millis() as i64,
        }),
    }
}

/// Port of `main`'s per-model enumeration + probing loop (everything up to
/// rendering). `providers` maps provider name to `Some(provider)` when it
/// built successfully, `None` when `build_provider` failed (mirrors
/// Python's `try: providers[name] = build_provider(...) except Exception:
/// providers[name] = None`); a name entirely absent from the map is also
/// treated as "not built".
pub fn run_probes(
    cfg: &ConfigModelsConfig,
    providers: &BTreeMap<String, Box<dyn JuryProvider>>,
    primary_only: bool,
) -> Vec<HealthRow> {
    let health_cfg = to_health_config(cfg);
    let models = enumerate_models(&health_cfg);
    let mut rows = Vec::new();
    for ((provider_name, model), usage) in models {
        let is_primary = !usage.primary_seats.is_empty();
        if primary_only && !is_primary {
            continue;
        }
        let disabled = cfg
            .providers
            .get(&provider_name)
            .and_then(|c| c.disabled)
            .unwrap_or(false);
        let classify = probe_and_classify(providers.get(&provider_name).map(|b| b.as_ref()), &model);
        rows.push(HealthRow {
            provider: provider_name,
            model,
            primary: is_primary,
            disabled_provider: disabled,
            primary_seats: usage.primary_seats,
            fallback_seats: usage.fallback_seats,
            classify,
        });
    }
    rows
}

fn status_icon(status: &str) -> &'static str {
    match status {
        "ok" => "\u{2705}",
        "unreachable" => "\u{26D4}",
        "auth" => "\u{1F512}",
        "busy" => "\u{1F553}",
        "no_key" => "\u{00B7}",
        "error" | "no_provider" => "\u{26A0}\u{FE0F}",
        _ => "?",
    }
}

/// Port of `main`'s table-mode rendering (`--json` unset).
pub fn render_table(rows: &[HealthRow]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:12} {:9} {:46} {:8} DETAIL\n",
        "STATUS", "PROVIDER", "MODEL", "ROLE"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');
    for r in rows {
        let role = if r.primary { "PRIMARY" } else { "fallback" };
        let icon = status_icon(&r.classify.status);
        let detail: String = r.classify.detail.chars().take(44).collect();
        out.push_str(&format!(
            "{icon} {:10} {:9} {:46} {:8} {detail}\n",
            r.classify.status, r.provider, r.model, role
        ));
    }
    let broken: Vec<&HealthRow> = rows
        .iter()
        .filter(|r| r.primary && matches!(r.classify.status.as_str(), "unreachable" | "auth" | "error"))
        .collect();
    if !broken.is_empty() {
        out.push_str("\n\u{26D4} PRIMARY seats unreachable (panels silently collapse to fallbacks):\n");
        for r in &broken {
            out.push_str(&format!(
                "   {}/{} \u{2014} seats: {}\n",
                r.provider,
                r.model,
                r.primary_seats.join(", ")
            ));
        }
    }
    let mut no_key: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in rows {
        if r.classify.status == "no_key" {
            no_key.insert(&r.provider);
        }
    }
    if !no_key.is_empty() {
        let names: Vec<&str> = no_key.into_iter().collect();
        out.push_str(&format!(
            "\n\u{00B7} providers with no key in this env (untested): {}\n",
            names.join(", ")
        ));
    }
    out
}

/// Port of `main`'s `--json` rendering.
pub fn render_json(rows: &[HealthRow]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "provider": r.provider,
                "model": r.model,
                "primary": r.primary,
                "disabled_provider": r.disabled_provider,
                "primary_seats": r.primary_seats,
                "fallback_seats": r.fallback_seats,
                "status": r.classify.status,
                "http": r.classify.http,
                "detail": r.classify.detail,
                "latency_ms": r.classify.latency_ms,
            })
        })
        .collect();
    let broken: Vec<&HealthRow> = rows
        .iter()
        .filter(|r| r.primary && matches!(r.classify.status.as_str(), "unreachable" | "auth" | "error"))
        .collect();
    let primary_broken: Vec<String> = broken.iter().map(|r| format!("{}/{}", r.provider, r.model)).collect();
    serde_json::json!({ "results": results, "primary_broken": primary_broken })
}

/// Port of `health_check.py`'s `main()` CLI entrypoint: `args` mirrors
/// `sys.argv[1:]` (`--json`, `--primary-only`). Returns the text to print
/// on stdout and the process exit code (`sys.exit(1 if primary_broken else 0)`).
pub fn run(
    args: &[String],
    cfg: &ConfigModelsConfig,
    providers: &BTreeMap<String, Box<dyn JuryProvider>>,
) -> (String, i32) {
    let json = args.iter().any(|a| a == "--json");
    let primary_only = args.iter().any(|a| a == "--primary-only");

    let rows = run_probes(cfg, providers, primary_only);
    let row_refs: Vec<ModelRow> = rows
        .iter()
        .map(|r| ModelRow {
            primary: r.primary,
            status: r.classify.status.clone(),
        })
        .collect();
    let exit_code = if primary_broken(&row_refs).is_empty() { 0 } else { 1 };

    let output = if json {
        serde_json::to_string_pretty(&render_json(&rows)).unwrap_or_default()
    } else {
        render_table(&rows)
    };
    (output, exit_code)
}
