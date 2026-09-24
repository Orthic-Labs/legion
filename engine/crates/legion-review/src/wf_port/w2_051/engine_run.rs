//! r59: closes the orchestration gap `engine_logic.rs` left open — the
//! live-HTTP-calling, config/cache-wired half of `src/lib/review/engine.py`
//! (`Engine.__init__`, `Engine.run`, `Engine._build_prompts`,
//! `Engine._run_juror`, `Engine._maybe_escalate`, `Engine._load_lenses`).
//!
//! Per the port brief, subprocess/network orchestration is portable when
//! the I/O itself sits behind a trait: [`JuryProvider`] stands in for
//! `providers.py`'s `Provider.call`/`call_with_metadata`, and
//! [`VisionPrep`] stands in for `vision_input.prepare_vision_payload`.
//! Both are exercised in tests with fakes, never real HTTP or a real
//! browser. The deterministic transforms this wires together
//! (`normalized_usage`, `accounting`, `parse_juror_json`,
//! `provider_prompts`, `execution_units`, `triggered_escalations`,
//! `synthesize`) live in `engine_logic.rs` and are reused unchanged.
//!
//! One faithful deviation, called out because it changes a *performance*
//! characteristic and not an output: Python runs each execution unit on a
//! `ThreadPoolExecutor` and merges results `as_completed`; this port runs
//! units sequentially. Because both implementations sort the merged
//! `results` by `juror_id` before returning (`results.sort(key=lambda r:
//! r.juror_id)`), the *output* — which is everything a caller can observe
//! or a test can assert on — is identical for identical inputs; only wall
//! clock time differs, and only when a caller wires multiple slow
//! providers into the same run.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::super::w2_050::cache::Cache;
use super::super::w2_050::config::{Escalation, Juror, ModelsConfig, Provider as ProviderCfg};
use super::super::w2_052::base::{JurorResult, ProviderError, ProviderImage};
use super::super::w2_052::packet::{validate_packet, PacketValidation};
use super::engine_logic::{
    accounting, execution_units, normalized_usage, parse_juror_json, provider_prompts,
    synthesize, Accounting, EscalationRule, JurorResultSummary, JurorSeat, Synthesis,
};

/// One lens entry from `lenses.yaml`: `{preamble, lens_question}`.
#[derive(Debug, Clone, Default)]
pub struct LensCfg {
    pub preamble: String,
    pub lens_question: String,
}

pub type Lenses = BTreeMap<String, LensCfg>;

/// Port of `_load_lenses`: parses the same shape `lenses.yaml` uses
/// (`{name: {preamble, lens_question}}`); a missing file mirrors Python's
/// `{}` (no lenses configured), not an error.
pub fn load_lenses(path: impl AsRef<Path>) -> Result<Lenses, EngineError> {
    let path = path.as_ref();
    if !path.is_file() {
        return Ok(Lenses::new());
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| EngineError::Config(format!("{}: failed to read: {e}", path.display())))?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| EngineError::Config(format!("{}: yaml error: {e}", path.display())))?;
    let mut out = Lenses::new();
    if let serde_yaml::Value::Mapping(map) = parsed {
        for (k, v) in map {
            let Some(name) = k.as_str() else { continue };
            let preamble = v
                .get("preamble")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            let lens_question = v
                .get("lens_question")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            out.insert(
                name.to_string(),
                LensCfg {
                    preamble,
                    lens_question,
                },
            );
        }
    }
    Ok(out)
}

/// Port of `class ProviderError`/`ValueError`/`PacketValidationError` sites
/// `Engine.run` can raise.
#[derive(Debug, Clone)]
pub enum EngineError {
    Config(String),
    SkillNotFound(String),
    PacketInvalid(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Config(msg) => write!(f, "{msg}"),
            EngineError::SkillNotFound(skill) => {
                write!(f, "skill not found in models.yaml: {skill}")
            }
            EngineError::PacketInvalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// Stands in for `providers.py`'s `Provider.call`/`Provider.call_with_metadata`
/// — the live HTTP boundary `engine.py` calls through. `call_with_metadata`
/// defaults to "unsupported" (`Ok(None)`), mirroring Python's
/// `hasattr(provider, "call_with_metadata")` gate: callers without it fall
/// back to `call` and mark `usage_complete = false`, exactly as Python does.
pub trait JuryProvider {
    fn call(
        &self,
        model: &str,
        system: &str,
        user: &str,
        max_tokens: i64,
        images: Option<&[ProviderImage]>,
    ) -> Result<String, ProviderError>;

    /// `Ok(Some((text, usage)))` mirrors a successful `call_with_metadata`
    /// return; `Ok(None)` mirrors the provider not implementing it at all
    /// (dispatch falls back to `call`); `Err` mirrors it raising.
    fn call_with_metadata(
        &self,
        _model: &str,
        _system: &str,
        _user: &str,
        _max_tokens: i64,
        _images: Option<&[ProviderImage]>,
    ) -> Result<Option<(String, Option<Map<String, Value>>)>, ProviderError> {
        Ok(None)
    }
}

/// Stands in for `vision_input.prepare_vision_payload`. `engine.py` treats
/// any exception here as a soft failure — degrade to text-only rather than
/// fail the whole run — so this returns a plain error string a caller may
/// log, never propagated.
pub trait VisionPrep {
    fn prepare(&self, user_input: &str) -> Result<Vec<ProviderImage>, String>;
}

/// A `VisionPrep` that always yields no images — for skills that never set
/// `needs_vision_input`, or for tests that don't exercise the vision path.
pub struct NoVisionPrep;
impl VisionPrep for NoVisionPrep {
    fn prepare(&self, _user_input: &str) -> Result<Vec<ProviderImage>, String> {
        Ok(Vec::new())
    }
}

fn lens_block(lenses: &Lenses, lens: Option<&str>) -> String {
    let Some(lens_name) = lens else {
        return String::new();
    };
    let Some(cfg) = lenses.get(lens_name) else {
        return String::new();
    };
    let preamble = cfg.preamble.trim_end();
    let mut block = format!("\n\n# LENS ({lens_name})\n{preamble}");
    if !cfg.lens_question.is_empty() {
        block.push_str(&format!(
            "\n\nIn addition to the rubric's shared questions, answer \
this lens-specific question in the output under `answers.{}` (\u{2264}200c).",
            cfg.lens_question
        ));
    }
    block
}

/// Port of `Engine._build_prompts`.
pub fn build_prompts(
    rubric: &str,
    user_input: &str,
    is_vision: bool,
    lenses: &Lenses,
    lens: Option<&str>,
    panel_name: &str,
) -> (String, String) {
    let preamble_block = lens_block(lenses, lens);
    if is_vision {
        let system = format!(
            "{rubric}{preamble_block}\n\nYou are reviewing the IMAGE attached to the user message. \
Output one minified JSON object matching the OUTPUT schema above. \
Every field MUST be grounded in what is visibly rendered in that image."
        );
        let user = format!(
            "An image is attached to this message — review THIS screenshot.\n\nCONTEXT:\n{user_input}"
        );
        return (system, user);
    }
    let role = if panel_name == "council" {
        "Council adviser"
    } else {
        "Jury juror"
    };
    let system = format!("{role}. Follow rubric. Output JSON only.{preamble_block}");
    let user = format!("RUBRIC:\n{rubric}\n\nINPUT:\n{user_input}\n");
    (system, user)
}

fn get_str(obj: &Map<String, Value>, key: &str, default: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| default.to_string())
}

fn get_i64(obj: &Map<String, Value>, key: &str) -> i64 {
    obj.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn get_object_map(obj: &Map<String, Value>, key: &str) -> BTreeMap<String, Value> {
    match obj.get(key) {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => BTreeMap::new(),
    }
}

fn get_array(obj: &Map<String, Value>, key: &str) -> Vec<Value> {
    match obj.get(key) {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

/// Full result of `Engine.run`, mirroring the Python `dict` return shape.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub skill: String,
    pub panel: String,
    pub flags: BTreeMap<String, bool>,
    pub rubric_file: String,
    pub prompt_version: i64,
    pub packet_ok: bool,
    pub packet_errors: Vec<String>,
    pub packet_warnings: Vec<String>,
    pub packet_section_count: usize,
    pub has_packet: bool,
    pub jurors: Vec<JurorResult>,
    pub escalation: Vec<JurorResult>,
    pub accounting: Accounting,
    pub synthesis: Synthesis,
}

fn summarize(r: &JurorResult) -> JurorResultSummary {
    let usage = super::engine_logic::Usage {
        input_tokens: r
            .usage
            .get("input_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        output_tokens: r
            .usage
            .get("output_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        total_tokens: r
            .usage
            .get("total_tokens")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
    };
    JurorResultSummary {
        juror_id: r.juror_id.clone(),
        call_count: r.call_count,
        usage,
        usage_complete: r.usage_complete,
        cache_hit: r.cache_hit,
        parsed_ok: r.parsed_ok,
        verdict: r.verdict.clone(),
        score: r.score,
        degraded: r.degraded,
    }
}

/// Port of `class Engine`.
pub struct Engine<'a> {
    pub config: &'a ModelsConfig,
    pub root: PathBuf,
    pub lenses: Lenses,
    pub providers: BTreeMap<String, Box<dyn JuryProvider + 'a>>,
    pub cache: Cache,
    pub prompt_version: i64,
}

impl<'a> Engine<'a> {
    pub fn new(
        config: &'a ModelsConfig,
        root: impl Into<PathBuf>,
        lenses: Lenses,
        providers: BTreeMap<String, Box<dyn JuryProvider + 'a>>,
        cache: Cache,
    ) -> Self {
        let prompt_version = config.prompt_version.unwrap_or(1);
        Self {
            config,
            root: root.into(),
            lenses,
            providers,
            cache,
            prompt_version,
        }
    }

    /// Port of `Engine.run`.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        skill: &str,
        user_input: &str,
        flags: &BTreeMap<String, bool>,
        no_cache: bool,
        no_escalation: bool,
        enforce_packet: bool,
        panel_name: &str,
        jurors_override: Option<&[Juror]>,
        vision_prep: &dyn VisionPrep,
    ) -> Result<RunResult, EngineError> {
        let skill_cfg = self
            .config
            .skills
            .get(skill)
            .ok_or_else(|| EngineError::SkillNotFound(skill.to_string()))?;

        let packet_validation: PacketValidation = validate_packet(user_input);
        let legacy_no_packet = packet_validation.is_legacy_no_packet();
        if !packet_validation.errors.is_empty() && !legacy_no_packet {
            let msg = format!(
                "jury packet invalid for skill '{skill}': {} error(s), {} warning(s). First error: {}",
                packet_validation.errors.len(),
                packet_validation.warnings.len(),
                packet_validation.errors[0],
            );
            if enforce_packet {
                return Err(EngineError::PacketInvalid(msg));
            }
        }
        let has_packet = packet_validation.errors.is_empty() && !packet_validation.sections.is_empty();

        let rubric_rel = skill_cfg.rubric.clone().unwrap_or_default();
        let rubric_path = self.root.join(&rubric_rel);
        let rubric = fs::read_to_string(&rubric_path)
            .map_err(|e| EngineError::Config(format!("{}: {e}", rubric_path.display())))?;

        let is_vision = skill_cfg.needs_vision_input.unwrap_or(false);
        let (system_prompt, user_prompt) =
            build_prompts(&rubric, user_input, is_vision, &self.lenses, None, panel_name);

        let vision_images: Vec<ProviderImage> = if is_vision {
            vision_prep.prepare(user_input).unwrap_or_default()
        } else {
            Vec::new()
        };

        let jurors_cfg: &[Juror] = jurors_override.unwrap_or(&skill_cfg.jurors);
        let seats: Vec<JurorSeat> = jurors_cfg
            .iter()
            .map(|j| JurorSeat {
                provider: j.provider.clone(),
            })
            .collect();
        let parallel_safe = |p: &str| -> bool {
            self.config
                .providers
                .get(p)
                .and_then(|c| c.parallel_safe)
                .unwrap_or(false)
        };
        let units = execution_units(&seats, &parallel_safe);

        // Map units of seats back to the owning Juror configs (seats carry
        // only `provider`; recover the original Juror by walking
        // `jurors_cfg` in the same grouped order `execution_units` used).
        let mut remaining: Vec<&Juror> = jurors_cfg.iter().collect();
        let mut results: Vec<JurorResult> = Vec::new();
        for unit in &units {
            for _seat in unit {
                // Pull the next not-yet-run juror matching this seat's
                // provider, preserving jurors_cfg's original relative order
                // per provider (matches the Python grouping's list order).
                if let Some(pos) = remaining.iter().position(|j| j.provider == _seat.provider) {
                    let juror = remaining.remove(pos);
                    let r = self.run_juror(
                        juror,
                        &system_prompt,
                        &user_prompt,
                        no_cache,
                        &vision_images,
                        is_vision,
                    );
                    results.push(r);
                }
            }
        }
        results.sort_by(|a, b| a.juror_id.cmp(&b.juror_id));

        let escalation_results: Vec<JurorResult> = if !no_escalation {
            self.maybe_escalate(skill_cfg, &system_prompt, &user_prompt, &results, flags)
        } else {
            Vec::new()
        };

        let all_summaries: Vec<JurorResultSummary> = results
            .iter()
            .chain(escalation_results.iter())
            .map(summarize)
            .collect();
        let result_summaries: Vec<JurorResultSummary> = results.iter().map(summarize).collect();
        let escalation_summaries: Vec<JurorResultSummary> =
            escalation_results.iter().map(summarize).collect();

        Ok(RunResult {
            skill: skill.to_string(),
            panel: panel_name.to_string(),
            flags: flags.clone(),
            rubric_file: rubric_rel,
            prompt_version: self.prompt_version,
            packet_ok: packet_validation.ok,
            packet_errors: packet_validation.errors,
            packet_warnings: packet_validation.warnings,
            packet_section_count: packet_validation.sections.len(),
            has_packet,
            jurors: results,
            escalation: escalation_results,
            accounting: accounting(&all_summaries),
            synthesis: synthesize(&result_summaries, &escalation_summaries),
        })
    }

    /// Port of `Engine._run_juror`.
    fn run_juror(
        &self,
        juror_cfg: &Juror,
        system: &str,
        user: &str,
        no_cache: bool,
        vision_images: &[ProviderImage],
        is_vision: bool,
    ) -> JurorResult {
        let mut chain: Vec<(String, String, bool)> =
            vec![(juror_cfg.provider.clone(), juror_cfg.model.clone(), false)];
        for fb in &juror_cfg.fallbacks {
            chain.push((fb.provider.clone(), fb.model.clone(), true));
        }

        let juror_can_vision = juror_cfg.vision.unwrap_or(false);
        let mut images_for_juror: Option<Vec<ProviderImage>> =
            if juror_can_vision && !vision_images.is_empty() {
                Some(vision_images.to_vec())
            } else {
                None
            };
        if let (Some(imgs), Some(max_images)) = (&mut images_for_juror, juror_cfg.max_images) {
            if max_images >= 0 && (max_images as usize) < imgs.len() {
                imgs.truncate(max_images as usize);
            }
        }

        let lens = juror_cfg.lens.clone();
        let mut last_err: Option<String> = None;
        let mut call_count: i64 = 0;
        let mut usage_map: BTreeMap<String, i64> = [
            ("input_tokens", 0),
            ("output_tokens", 0),
            ("total_tokens", 0),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let mut usage_complete = true;

        for (provider_name, model, is_fallback) in &chain {
            let provider_cfg: Option<&ProviderCfg> = self.config.providers.get(provider_name);
            if provider_cfg.map(|c| c.disabled.unwrap_or(false)).unwrap_or(false) {
                last_err = Some(format!("{provider_name} disabled in models.yaml"));
                continue;
            }

            let vision_digest = if let Some(imgs) = &images_for_juror {
                let mut h = Sha256::new();
                for im in imgs {
                    h.update(im.b64.as_bytes());
                }
                hex::encode(h.finalize())[..16].to_string()
            } else {
                String::new()
            };
            let cache_input = format!(
                "{user}|vision:{vision_digest}|lens:{}",
                lens.as_deref().unwrap_or("default")
            );
            let cache_key = Cache::make_key(
                "",
                &cache_input,
                provider_name,
                model,
                self.prompt_version,
            );

            if !no_cache {
                if let Some(cached) = self.cache.get(&cache_key) {
                    let parsed_ok = cached.get("parsed_ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if parsed_ok {
                        if let Value::Object(obj) = cached {
                            let mut result = JurorResult::new(
                                juror_cfg.id.clone(),
                                obj.get("provider").and_then(|v| v.as_str()).unwrap_or(provider_name).to_string(),
                                obj.get("model").and_then(|v| v.as_str()).unwrap_or(model).to_string(),
                            );
                            result.verdict = get_str(&obj, "verdict", "ERROR");
                            result.score = get_i64(&obj, "score");
                            result.top_concern = get_str(&obj, "top_concern", "");
                            result.scores = get_object_map(&obj, "scores");
                            result.answers = get_object_map(&obj, "answers");
                            result.blockers = get_array(&obj, "blockers");
                            result.raw_response = get_str(&obj, "raw_response", "");
                            result.parsed_ok = true;
                            result.latency_ms = get_i64(&obj, "latency_ms");
                            result.degraded = obj.get("degraded").and_then(|v| v.as_bool()).unwrap_or(false);
                            result.fallback_used = *is_fallback;
                            result.lens = lens.clone();
                            result.call_count = 0;
                            result.usage = BTreeMap::new();
                            result.usage_complete = true;
                            result.cache_hit = true;
                            return result;
                        }
                    }
                }
            }

            let Some(provider) = self.providers.get(provider_name) else {
                last_err = Some(format!("{provider_name}: no provider wired"));
                continue;
            };
            let degraded = provider_cfg.and_then(|c| c.flag_degraded).unwrap_or(false);
            let provider_cap = provider_cfg.and_then(|c| c.max_output_tokens).unwrap_or(8192);
            let seat_cap = juror_cfg
                .max_tokens
                .unwrap_or(if is_vision { 4096 } else { 3072 });
            let max_tokens = seat_cap.min(provider_cap);

            let block = lens_block(&self.lenses, lens.as_deref());
            let final_system = format!("{system}{block}").trim().to_string();
            let (call_system, call_user) =
                provider_prompts(provider_name, &final_system, user, is_vision);
            call_count += 1;

            let t0 = Instant::now();
            let images_slice = images_for_juror.as_deref();
            let call_result = provider.call_with_metadata(
                model,
                &call_system,
                &call_user,
                max_tokens,
                images_slice,
            );
            let raw_result: Result<String, ProviderError> = match call_result {
                Ok(Some((text, usage))) => {
                    if let Some(observed) = normalized_usage(usage.as_ref()) {
                        *usage_map.get_mut("input_tokens").unwrap() += observed.input_tokens;
                        *usage_map.get_mut("output_tokens").unwrap() += observed.output_tokens;
                        *usage_map.get_mut("total_tokens").unwrap() += observed.total_tokens;
                    } else {
                        usage_complete = false;
                    }
                    Ok(text)
                }
                Ok(None) => {
                    usage_complete = false;
                    provider.call(model, &call_system, &call_user, max_tokens, images_slice)
                }
                Err(e) => Err(e),
            };

            match raw_result {
                Ok(raw) => {
                    let latency_ms = t0.elapsed().as_millis() as i64;
                    let parsed = parse_juror_json(Some(&raw));
                    let mut result = JurorResult::new(juror_cfg.id.clone(), provider_name.clone(), model.clone());
                    if let Some(obj) = &parsed.object {
                        result.verdict = get_str(obj, "verdict", "ERROR");
                        result.score = get_i64(obj, "score");
                        result.top_concern = get_str(obj, "top_concern", "");
                        result.scores = get_object_map(obj, "scores");
                        result.answers = get_object_map(obj, "answers");
                        result.blockers = get_array(obj, "blockers");
                    } else {
                        result.verdict = parsed.verdict.clone();
                        result.top_concern = parsed.top_concern.clone();
                    }
                    result.raw_response = raw;
                    result.parsed_ok = parsed.parsed_ok;
                    result.latency_ms = latency_ms;
                    result.degraded = degraded;
                    result.fallback_used = *is_fallback;
                    result.lens = lens.clone();
                    result.call_count = call_count;
                    result.usage = usage_map
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::from(*v)))
                        .collect();
                    result.usage_complete = usage_complete;

                    let mut d = result.to_dict();
                    if let Value::Object(m) = &mut d {
                        m.insert("lens".to_string(), lens.clone().map(Value::String).unwrap_or(Value::Null));
                    }
                    if result.parsed_ok {
                        let _ = self.cache.set(&cache_key, &d);
                        return result;
                    }
                    let _ = self.cache.set_error(&cache_key, &d);
                    last_err = Some(format!("{provider_name}/{model} returned unparseable JSON"));
                    continue;
                }
                Err(e) => {
                    last_err = Some(e.message.clone());
                    let _ = self.cache.set_error(
                        &cache_key,
                        &serde_json::json!({
                            "error": last_err,
                            "provider": provider_name,
                            "model": model,
                        }),
                    );
                    continue;
                }
            }
        }

        let mut result = JurorResult::new(juror_cfg.id.clone(), chain[0].0.clone(), chain[0].1.clone());
        result.verdict = "ERROR".to_string();
        result.error = Some(last_err.unwrap_or_else(|| "all fallbacks exhausted".to_string()));
        result.call_count = call_count;
        result.usage = usage_map
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(*v)))
            .collect();
        result.usage_complete = usage_complete;
        result
    }

    /// Port of `Engine._maybe_escalate`.
    fn maybe_escalate(
        &self,
        skill_cfg: &super::super::w2_050::config::Skill,
        system: &str,
        user: &str,
        results: &[JurorResult],
        flags: &BTreeMap<String, bool>,
    ) -> Vec<JurorResult> {
        let rules: Vec<EscalationRule> = skill_cfg
            .escalation
            .iter()
            .map(|e: &Escalation| EscalationRule {
                trigger: e.trigger.clone(),
                provider: e.provider.clone(),
                model: e.model.clone(),
            })
            .collect();
        let verdicts: Vec<String> = results
            .iter()
            .filter(|r| r.parsed_ok)
            .map(|r| r.verdict.clone())
            .collect();
        let flags_hm: std::collections::HashMap<String, bool> =
            flags.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let triggered = super::engine_logic::triggered_escalations(&rules, &verdicts, &flags_hm);
        if triggered.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();
        for rule in triggered {
            let Some(provider) = self.providers.get(&rule.provider) else {
                let mut result =
                    JurorResult::new(format!("escalation:{}", rule.provider), rule.provider.clone(), rule.model.clone());
                result.verdict = "ERROR".to_string();
                result.error = Some(format!("{}: no provider wired", rule.provider));
                result.call_count = 1;
                out.push(result);
                continue;
            };
            let t0 = Instant::now();
            let call_result = provider.call_with_metadata(&rule.model, system, user, 1024, None);
            let raw_result: Result<(String, bool, BTreeMap<String, Value>), ProviderError> = match call_result {
                Ok(Some((text, usage))) => {
                    let observed = normalized_usage(usage.as_ref());
                    let usage_complete = observed.is_some();
                    let usage_out = observed
                        .map(|u| {
                            BTreeMap::from([
                                ("input_tokens".to_string(), Value::from(u.input_tokens)),
                                ("output_tokens".to_string(), Value::from(u.output_tokens)),
                                ("total_tokens".to_string(), Value::from(u.total_tokens)),
                            ])
                        })
                        .unwrap_or_default();
                    Ok((text, usage_complete, usage_out))
                }
                Ok(None) => provider
                    .call(&rule.model, system, user, 1024, None)
                    .map(|text| (text, false, BTreeMap::new())),
                Err(e) => Err(e),
            };
            match raw_result {
                Ok((raw, usage_complete, usage)) => {
                    let parsed = parse_juror_json(Some(&raw));
                    let mut result = JurorResult::new(
                        format!("escalation:{}", rule.provider),
                        rule.provider.clone(),
                        rule.model.clone(),
                    );
                    if let Some(obj) = &parsed.object {
                        result.verdict = get_str(obj, "verdict", "ERROR");
                        result.score = get_i64(obj, "score");
                        result.top_concern = get_str(obj, "top_concern", "");
                        result.scores = get_object_map(obj, "scores");
                        result.answers = get_object_map(obj, "answers");
                        result.blockers = get_array(obj, "blockers");
                    } else {
                        result.verdict = parsed.verdict.clone();
                        result.top_concern = parsed.top_concern.clone();
                    }
                    result.raw_response = raw;
                    result.parsed_ok = parsed.parsed_ok;
                    result.latency_ms = t0.elapsed().as_millis() as i64;
                    result.call_count = 1;
                    result.usage = usage;
                    result.usage_complete = usage_complete;
                    out.push(result);
                }
                Err(e) => {
                    let mut result = JurorResult::new(
                        format!("escalation:{}", rule.provider),
                        rule.provider.clone(),
                        rule.model.clone(),
                    );
                    result.verdict = "ERROR".to_string();
                    result.error = Some(e.message.clone());
                    result.call_count = 1;
                    out.push(result);
                }
            }
        }
        out
    }
}
