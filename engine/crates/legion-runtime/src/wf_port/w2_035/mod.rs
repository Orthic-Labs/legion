//! Port of `src/lib/auto-jury.mjs` (chunk w2_035) — the shared
//! post-artifact review hook used by content/ad pipelines to run the
//! "council" jury CLI, parse its verdict, and enforce ship/don't-ship gating.
//!
//! Ported faithfully:
//!   - `clip` string truncation helper
//!   - `formatCouncilCliError`
//!   - `KIND_TO_SKILL` / `VISUAL_KINDS` lookups (`kind_to_skill`, `is_visual_kind`)
//!   - QA rubric loading + formatting (`_loadQARubricsLib` / `_formatQARubric`)
//!   - `finalDecisionFromCouncilVerdict`
//!   - `buildCouncilInput` (packet envelope, text-artifact embedding, QA rubric
//!     overlay, audio recipe / screen composite injection, vision footer)
//!   - `_formatScreenComposite`
//!   - `runAutoJury` orchestration (spawn the council CLI, write input/verdict
//!     files, decide ship/don't-ship) and `runAutoJuryBatch`
//!   - `_writeLedgerFromVerdict` (spawns the Python ledger helper the same
//!     way the JS did)
//!
//! Not ported: nothing dropped — Membrane/Blueprint are not referenced by
//! this file. The council CLI and ledger writer remain external Python
//! processes exactly as in the source; this module only faithfully
//! reproduces the JS side of the contract (argument building, timeouts,
//! file I/O, and verdict interpretation).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

/// Default council CLI timeout, mirrors `DEFAULT_COUNCIL_TIMEOUT_MS` (10 min).
pub const DEFAULT_COUNCIL_TIMEOUT_MS: u64 = 10 * 60_000;

/// Mirrors `_clip(value, limit = 1200)`.
pub fn clip(value: &str, limit: usize) -> String {
    if value.chars().count() > limit {
        let truncated: String = value.chars().take(limit).collect();
        format!("{truncated}...")
    } else {
        value.to_string()
    }
}

/// Result of resolving `AUTO_JURY_TIMEOUT_MS`, mirrors `_councilTimeoutMs`.
pub fn council_timeout_ms(env_value: Option<&str>) -> u64 {
    match env_value {
        None => DEFAULT_COUNCIL_TIMEOUT_MS,
        Some(raw) => match raw.trim().parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 => n.floor() as u64,
            _ => DEFAULT_COUNCIL_TIMEOUT_MS,
        },
    }
}

/// Details about how a council CLI invocation failed, mirrors the fields
/// `formatCouncilCliError` reads off the child_process error object.
#[derive(Debug, Default, Clone)]
pub struct CouncilCliFailure {
    pub stderr: Option<String>,
    pub stdout: Option<String>,
    pub timed_out: bool,
    pub status: Option<i32>,
    pub signal: Option<String>,
    pub code: Option<String>,
}

/// Mirrors `formatCouncilCliError(err, { skill, artifactPath, timeoutMs })`.
pub fn format_council_cli_error(
    err: &CouncilCliFailure,
    skill: &str,
    artifact_path: &str,
    timeout_ms: u64,
) -> String {
    let stderr = clip(err.stderr.as_deref().unwrap_or(""), 1200);
    let stdout = clip(err.stdout.as_deref().unwrap_or(""), 1200);

    let mut details: Vec<String> = Vec::new();
    if err.timed_out {
        details.push(format!("timed out after {}s", (timeout_ms as f64 / 1000.0).round() as i64));
    }
    if let Some(status) = err.status {
        details.push(format!("status={status}"));
    }
    if let Some(signal) = &err.signal {
        details.push(format!("signal={signal}"));
    }
    if let Some(code) = &err.code {
        details.push(format!("code={code}"));
    }
    if !stderr.is_empty() {
        details.push(format!("stderr: {stderr}"));
    } else {
        details.push("stderr: <empty>".to_string());
    }
    if !stdout.is_empty() {
        details.push(format!("stdout: {stdout}"));
    }

    format!(
        "auto-jury: council CLI failed for {skill} on {artifact_path}. {}",
        details.join("; ")
    )
}

/// Mirrors `KIND_TO_SKILL`.
pub fn kind_to_skill(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "video" => "jury-video",
        "image" => "jury-image",
        "copy" => "jury-blogs",
        "blog" => "jury-blogs",
        "brand" => "jury-brand-voice",
        "ad" => "jury-ad",
        "design" => "jury-design",
        "plan" => "jury-plan",
        "business" => "jury-business-plan",
        "idea" => "jury-idea",
        "launch" => "jury-launch",
        "offer" => "jury-offer",
        "strategy" => "jury-content-strategy",
        "compliance" => "jury-compliance-risk",
        "code" => "jury-code",
        _ => return None,
    })
}

/// All keys `kind_to_skill` recognizes, in declaration order — mirrors
/// `Object.keys(KIND_TO_SKILL)` as used in the "unknown kind" error message.
pub const KIND_TO_SKILL_KEYS: &[&str] = &[
    "video", "image", "copy", "blog", "brand", "ad", "design", "plan", "business", "idea",
    "launch", "offer", "strategy", "compliance", "code",
];

/// Mirrors `VISUAL_KINDS`.
pub fn is_visual_kind(kind: &str) -> bool {
    matches!(kind, "video" | "image" | "design" | "ad" | "launch")
}

/// Mirrors the `TEXT_KINDS` set used by `buildCouncilInput` to decide
/// whether to embed the artifact body.
fn is_text_kind(kind: &str) -> bool {
    matches!(
        kind,
        "plan"
            | "doc"
            | "spec"
            | "brief"
            | "business-plan"
            | "launch"
            | "content-strategy"
            | "idea"
            | "offer"
            | "compliance-risk"
            | "priority"
            | "brand-voice"
            | "blogs"
            | "cold-email"
    )
}

/// Mirrors the `looksLikeText` regex `/\.(md|markdown|txt|json|mdx)$/i`.
fn looks_like_text(artifact_path: &str) -> bool {
    let lower = artifact_path.to_ascii_lowercase();
    [".md", ".markdown", ".txt", ".json", ".mdx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// Load `recipes/video/qa-rubrics.json`, mirrors `_loadQARubricsLib` (falls
/// back to `{ rubrics_by_shot_type: {} }` on any read/parse failure — no
/// panics, no caching required since callers own the caching lifetime).
pub fn load_qa_rubrics_lib(path: &Path) -> Value {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => v,
            Err(_) => json!({ "rubrics_by_shot_type": {} }),
        },
        Err(_) => json!({ "rubrics_by_shot_type": {} }),
    }
}

/// Mirrors `_formatQARubric(key)`.
pub fn format_qa_rubric(lib: &Value, key: &str) -> String {
    let rubrics = lib.get("rubrics_by_shot_type").and_then(Value::as_object);
    let rubric = rubrics.and_then(|m| m.get(key));

    let Some(rubric) = rubric else {
        let keys: Vec<&str> = rubrics
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        return format!(
            "(unknown qaRubric key \"{key}\" — auto-jury skipped overlay)\nValid keys: {}",
            keys.join(", ")
        );
    };

    let mut out: Vec<String> = Vec::new();
    if let Some(use_case) = rubric.get("_use").and_then(Value::as_str) {
        out.push(format!("Use case: {use_case}"));
    }
    if let Some(dims) = rubric.get("dimensions").and_then(Value::as_object) {
        out.push(String::new());
        out.push("Dimensions (score each 1-10):".to_string());
        for (dim, desc) in dims {
            let desc = desc.as_str().unwrap_or_default();
            out.push(format!("  - {dim}: {desc}"));
        }
    }
    if let Some(must_pass) = rubric.get("must_pass").and_then(Value::as_array) {
        if !must_pass.is_empty() {
            out.push(String::new());
            out.push("Must pass (any failure = SHIP-WITH-FIXES at minimum):".to_string());
            for m in must_pass {
                out.push(format!("  - {}", m.as_str().unwrap_or_default()));
            }
        }
    }
    if let Some(threshold) = rubric.get("ship_threshold") {
        out.push(String::new());
        let threshold_str = value_to_display(threshold);
        out.push(format!("Ship threshold: {threshold_str}"));
    }
    if let Some(note) = rubric.get("note").and_then(Value::as_str) {
        out.push(String::new());
        out.push(format!("Note: {note}"));
    }
    out.join("\n")
}

/// JS template-literal string coercion for a JSON value (mirrors `${value}`
/// on whatever JSON.parse produced — strings render bare, everything else
/// renders via its JSON text).
fn value_to_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Mirrors `finalDecisionFromCouncilVerdict(verdict)`.
pub fn final_decision_from_council_verdict(verdict: &Value) -> String {
    let empty = json!({});
    let synthesis = verdict.get("synthesis").unwrap_or(&empty);

    if synthesis.get("any_error").and_then(Value::as_bool) == Some(true) {
        return "NEEDS-REVISION".to_string();
    }
    if synthesis.get("split").and_then(Value::as_bool) == Some(true) {
        return "NEEDS-REVISION".to_string();
    }
    if let Some(majority_count) = synthesis.get("majority_count").and_then(Value::as_str) {
        if let Some((yes, total)) = parse_majority_count(majority_count) {
            if total > 0 && (yes as f64) <= (total as f64) / 2.0 {
                return "NEEDS-REVISION".to_string();
            }
        }
    }

    let candidate = verdict
        .get("final_verdict")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| verdict.get("verdict").and_then(Value::as_str).filter(|s| !s.is_empty()))
        .or_else(|| verdict.get("decision").and_then(Value::as_str).filter(|s| !s.is_empty()))
        .or_else(|| {
            synthesis
                .get("majority_verdict")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            synthesis
                .get("final_verdict")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("");

    candidate.to_uppercase()
}

/// Mirrors the `/^(\d+)\/(\d+)$/` match on `majority_count`.
fn parse_majority_count(s: &str) -> Option<(u64, u64)> {
    let (yes, total) = s.split_once('/')?;
    if yes.is_empty() || total.is_empty() {
        return None;
    }
    if !yes.bytes().all(|b| b.is_ascii_digit()) || !total.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((yes.parse().ok()?, total.parse().ok()?))
}

/// Mirrors `_formatScreenComposite(sc)`. Returns `None` when `sc.screenComposite`
/// is missing, exactly like the JS early return.
pub fn format_screen_composite(sc: &Value) -> Option<String> {
    let composite = sc.get("screenComposite")?;
    if composite.is_null() {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let shot_name = sc.get("shotName").and_then(Value::as_str).unwrap_or("(unnamed)");
    out.push(format!("### Shot `{shot_name}`"));
    if let Some(start) = sc.get("shotStartS") {
        if !start.is_null() {
            out.push(format!("Shot start in final cut: {}s", value_to_display(start)));
        }
    }

    let mask = composite.get("screenMask");
    let corner = |name: &str| -> (String, String) {
        let c = mask.and_then(|m| m.get(name));
        (
            c.and_then(|c| c.get("x")).map(value_to_display).unwrap_or_default(),
            c.and_then(|c| c.get("y")).map(value_to_display).unwrap_or_default(),
        )
    };
    let (tlx, tly) = corner("topLeft");
    let (trx, tryv) = corner("topRight");
    let (blx, bly) = corner("bottomLeft");
    let (brx, bry) = corner("bottomRight");
    out.push(format!(
        "Screen mask (canvas pixels): TL({tlx},{tly}) TR({trx},{tryv}) BL({blx},{bly}) BR({brx},{bry})"
    ));

    out.push("Overlays (back-to-front):".to_string());
    if let Some(overlays) = composite.get("overlays").and_then(Value::as_array) {
        for o in overlays {
            out.push(format_overlay(o));
        }
    }

    Some(out.join("\n"))
}

fn format_overlay(o: &Value) -> String {
    let recipe = o.get("recipe").and_then(Value::as_str).unwrap_or("");
    match recipe {
        "chat_message_typing" => {
            let words = o.get("words").cloned().unwrap_or(Value::Null);
            let word_times = o.get("wordTimes").cloned().unwrap_or(Value::Null);
            let sent_at = o.get("sentAt");
            let sent_at_str = match sent_at {
                Some(v) if !v.is_null() => format!(", sentAt={}s", value_to_display(v)),
                _ => String::new(),
            };
            let mut line = format!(
                "  - chat_message_typing: words {} at times {}s{}",
                words, word_times, sent_at_str
            );
            if let Some(thread) = o.get("thread").and_then(Value::as_array) {
                if !thread.is_empty() {
                    for t in thread {
                        let side = t.get("side").and_then(Value::as_str).unwrap_or_default();
                        let text = t.get("text").and_then(Value::as_str).unwrap_or_default();
                        line.push_str(&format!("\n      thread ({side}): \"{text}\""));
                    }
                }
            }
            line
        }
        "window_switch_animation" => {
            let from = o.get("fromWindow").map(value_to_display).unwrap_or_default();
            let to = o.get("toWindow").map(value_to_display).unwrap_or_default();
            let switch_at = o.get("switchAt").map(value_to_display).unwrap_or_default();
            let duration = match o.get("durationS") {
                Some(v) if !v.is_null() => format!(" (slide {}s)", value_to_display(v)),
                _ => String::new(),
            };
            format!("  - window_switch_animation: {from} → {to} at {switch_at}s{duration}")
        }
        "wake_word_pulse" => {
            let pulse_at = o.get("pulseAt").map(value_to_display).unwrap_or_default();
            let hold = match o.get("holdFromS") {
                Some(v) if !v.is_null() => format!(", holdFromS={}s", value_to_display(v)),
                _ => String::new(),
            };
            format!("  - wake_word_pulse: pulseAt={pulse_at}s{hold}")
        }
        "sent_tick" => {
            let tick_at = o.get("tickAt").map(value_to_display).unwrap_or_default();
            format!("  - sent_tick: tickAt={tick_at}s")
        }
        "notification_toast" => {
            let text = o.get("text").and_then(Value::as_str).unwrap_or_default();
            let sender = match o.get("sender").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => format!(" from {s}"),
                _ => String::new(),
            };
            let toast_at = o.get("toastAt").map(value_to_display).unwrap_or_default();
            let hold = match o.get("holdS") {
                Some(v) if !v.is_null() => format!(" (hold {}s)", value_to_display(v)),
                _ => String::new(),
            };
            format!("  - notification_toast: \"{text}\"{sender} at {toast_at}s{hold}")
        }
        "screen_glow_only" => {
            "  - screen_glow_only: (no UI overlay — screen reads as ambient glow)".to_string()
        }
        other => format!("  - {other}: (unknown recipe — jury cannot verify)"),
    }
}

/// Input to `build_council_input`, mirrors the `{ kind, artifactPath, context }`
/// destructure in `buildCouncilInput`.
pub struct BuildCouncilInputArgs<'a> {
    pub kind: &'a str,
    pub artifact_path: &'a str,
    pub context: &'a Value,
    /// Pre-loaded QA rubric library (result of `load_qa_rubrics_lib`), used
    /// only when `context.qaRubric` is set. Pass `None` to skip the overlay
    /// entirely (equivalent to the file being unreadable).
    pub qa_rubrics_lib: Option<&'a Value>,
}

/// Mirrors `buildCouncilInput({ kind, artifactPath, context })`.
pub fn build_council_input(args: BuildCouncilInputArgs<'_>) -> String {
    let BuildCouncilInputArgs { kind, artifact_path, context, qa_rubrics_lib } = args;
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Auto-jury input — {kind}"));
    lines.push(String::new());

    if let Some(packet) = context.get("packet").and_then(Value::as_object) {
        lines.push("```packet".to_string());
        for (section, value) in packet {
            if let Some(arr) = value.as_array() {
                lines.push(format!("{section}:"));
                for v in arr {
                    lines.push(format!("  - {}", value_to_display(v)));
                }
            } else {
                lines.push(format!("{section}: {}", value_to_display(value)));
            }
        }
        lines.push("```".to_string());
        lines.push(String::new());
    }

    lines.push(format!("Artifact: {artifact_path}"));
    push_ctx_str(&mut lines, context, "brand", "Brand");
    push_ctx_str(&mut lines, context, "campaign", "Campaign");
    push_ctx_str(&mut lines, context, "shot", "Shot");
    if let Some(v) = context.get("duration") {
        if !v.is_null() {
            lines.push(format!("Duration: {}s", value_to_display(v)));
        }
    }
    push_ctx_str(&mut lines, context, "resolution", "Resolution");
    push_ctx_str(&mut lines, context, "aspect", "Aspect");
    lines.push(String::new());

    if let Some(prompt) = context.get("prompt").and_then(Value::as_str) {
        if !prompt.is_empty() {
            lines.push("## Prompt".to_string());
            lines.push(prompt.to_string());
            lines.push(String::new());
        }
    }

    if let Some(frames) = context.get("framePaths").and_then(Value::as_array) {
        if !frames.is_empty() {
            lines.push("## Extracted frames (vision-grounded jurors will see these)".to_string());
            for f in frames {
                lines.push(format!("- {}", value_to_display(f)));
            }
            lines.push(String::new());
        }
    }

    if let Some(rules) = context.get("brandRules").and_then(Value::as_str) {
        if !rules.is_empty() {
            lines.push("## Brand rules".to_string());
            lines.push(rules.to_string());
            lines.push(String::new());
        }
    }

    if let Some(notes) = context.get("notes").and_then(Value::as_str) {
        if !notes.is_empty() {
            lines.push("## Pipeline notes".to_string());
            lines.push(notes.to_string());
            lines.push(String::new());
        }
    }

    let is_text = is_text_kind(kind);
    let looks_text = looks_like_text(artifact_path);
    if (is_text || looks_text) && !artifact_path.is_empty() {
        const MAX_EMBED: usize = 200 * 1024;
        lines.push("## Artifact contents".to_string());
        lines.push(String::new());
        match fs::read_to_string(artifact_path) {
            Ok(body) => {
                let orig_len = body.len();
                let (body, truncated) = if body.len() > MAX_EMBED {
                    // byte-safe truncation to MAX_EMBED bytes, matching JS's
                    // UTF-16-unit slice closely enough for ASCII/UTF-8 text.
                    let mut end = MAX_EMBED;
                    while !body.is_char_boundary(end) {
                        end -= 1;
                    }
                    (body[..end].to_string(), true)
                } else {
                    (body, false)
                };
                lines.push(body);
                if truncated {
                    lines.push(String::new());
                    lines.push(format!(
                        "(...truncated to first {MAX_EMBED} bytes of {orig_len} total bytes)"
                    ));
                }
            }
            Err(e) => {
                lines.push(format!("(could not read artifact: {e})"));
            }
        }
        lines.push(String::new());
    }

    if let Some(qa_rubric) = context.get("qaRubric").and_then(Value::as_str) {
        if !qa_rubric.is_empty() {
            if let Some(lib) = qa_rubrics_lib {
                let rubric_block = format_qa_rubric(lib, qa_rubric);
                if !rubric_block.is_empty() {
                    lines.push("## Shot-type rubric overlay".to_string());
                    lines.push(format!(
                        "Source: recipes/video/qa-rubrics.json#rubrics_by_shot_type.{qa_rubric}"
                    ));
                    lines.push(
                        "Score against THESE dimensions in addition to the base rubric. Apply the must_pass + ship_threshold rules below.".to_string(),
                    );
                    lines.push(String::new());
                    lines.push(rubric_block);
                    lines.push(String::new());
                }
            }
        }
    }

    if let Some(audio_recipes) = context.get("audioRecipes").and_then(Value::as_array) {
        if !audio_recipes.is_empty() {
            lines.push("## Audio recipe references (per-layer presets resolved from recipes/video/audio.json)".to_string());
            lines.push("Each layer below was filled from a recipe key. Jurors should verify the tonal feel matches the recipe (e.g. founder_direct = warm conversational, premium_narrator = deliberate full-stop). Inline manifest overrides win where they are listed.".to_string());
            lines.push(String::new());
            for ar in audio_recipes {
                let Some(audio_recipe) = ar.get("audioRecipe").and_then(Value::as_str) else {
                    continue;
                };
                if audio_recipe.is_empty() {
                    continue;
                }
                let tag = match ar.get("error").and_then(Value::as_str) {
                    Some(err) if !err.is_empty() => {
                        format!("✗ {}", err.split('.').next().unwrap_or(err))
                    }
                    _ => format!(
                        "{}:{}",
                        ar.get("namespace").and_then(Value::as_str).unwrap_or_default(),
                        audio_recipe
                    ),
                };
                let derived = ar
                    .get("derivedSource")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .or_else(|| ar.get("derivedVoice").and_then(Value::as_str).filter(|s| !s.is_empty()))
                    .unwrap_or("");
                let index = ar.get("index").map(value_to_display).unwrap_or_default();
                let typ = ar.get("type").map(value_to_display).unwrap_or_default();
                let derived_suffix = if derived.is_empty() {
                    String::new()
                } else {
                    format!("  →  {derived}")
                };
                lines.push(format!("  - layer {index} ({typ}) → {tag}{derived_suffix}"));
            }
            lines.push(String::new());
        }
    }

    if let Some(composites) = context.get("screenComposites").and_then(Value::as_array) {
        if !composites.is_empty() {
            lines.push("## Screen composite specs (Remotion overlays per shot)".to_string());
            lines.push("The shots below were rendered with `image_recipe.depth = \"foreground_object_blur\"` so the screen is soft glow, then a deterministic Remotion overlay was composited on top. Jurors must verify the on-screen content matches the spec listed here, NOT the Veo-hallucinated content underneath.".to_string());
            lines.push(String::new());
            for sc in composites {
                if let Some(block) = format_screen_composite(sc) {
                    lines.push(block);
                    lines.push(String::new());
                }
            }
        }
    }

    if is_visual_kind(kind) {
        lines.push("## Council vision input".to_string());
        lines.push("Vision-capable jurors (NIM Nemotron Omni + Gemini 2.5 Flash)".to_string());
        lines.push("receive the base64-encoded image(s) and any video keyframes".to_string());
        lines.push("extracted from the paths above. The brand_lens juror is text-only".to_string());
        lines.push("by design — it scores voice/brand fit from the description.".to_string());
    }

    lines.join("\n")
}

fn push_ctx_str(lines: &mut Vec<String>, context: &Value, key: &str, label: &str) {
    if let Some(v) = context.get(key).and_then(Value::as_str) {
        if !v.is_empty() {
            lines.push(format!("{label}: {v}"));
        }
    }
}

// ---------------------------------------------------------------------
// Orchestration: runAutoJury / runAutoJuryBatch / ledger write
// ---------------------------------------------------------------------

/// Errors `run_auto_jury` can return, mirrors the `throw new Error(...)`
/// call sites in `runAutoJury`.
#[derive(Debug, thiserror::Error)]
pub enum AutoJuryError {
    #[error("auto-jury: unknown kind \"{0}\". Allowed: {1}")]
    UnknownKind(String, String),
    #[error("auto-jury: artifactPath required")]
    MissingArtifactPath,
    #[error("{0}")]
    CouncilCliFailed(String),
    #[error("auto-jury BLOCKED — {skill} returned \"{verdict}\" for {artifact}. See {verdict_path} for jurors' reasoning. To bypass: re-run with auto-jury failHard=false or fix the issue and rebuild.")]
    Blocked {
        skill: String,
        verdict: String,
        artifact: String,
        verdict_path: String,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Environment/config the JS module derived from `WORKSPACE_ROOT` and
/// `process.env`. Mirrors `WORKSPACE_ROOT`, `COUNCIL_PY`, `PYTHON`,
/// `PYTHON_ARGS`.
pub struct AutoJuryConfig {
    pub workspace_root: PathBuf,
    pub council_py: PathBuf,
    pub python_bin: String,
    pub python_args: Vec<String>,
}

impl AutoJuryConfig {
    /// Mirrors the module-scope const derivation, given the workspace root
    /// (the JS derives it from `import.meta.url`; callers here pass it in
    /// since Rust has no equivalent of a module's own file location at
    /// runtime).
    pub fn from_env(workspace_root: PathBuf) -> Self {
        let is_windows = cfg!(target_os = "windows");
        let council_py = std::env::var("JURY_CLI")
            .map(PathBuf::from)
            .unwrap_or_else(|_| workspace_root.join("tools").join("review").join("jury.py"));
        let python_bin = std::env::var("PYTHON_BIN").unwrap_or_else(|_| {
            if is_windows { "py".to_string() } else { "python3".to_string() }
        });
        let python_args = if std::env::var("PYTHON_BIN").is_ok() {
            vec![]
        } else if is_windows {
            vec!["-3.11".to_string()]
        } else {
            vec![]
        };
        Self { workspace_root, council_py, python_bin, python_args }
    }
}

/// Arguments to `run_auto_jury`, mirrors the destructured options object.
pub struct RunAutoJuryArgs<'a> {
    pub kind: &'a str,
    pub artifact_path: &'a str,
    pub context: Value,
    pub fail_hard: bool,
    pub out_dir: Option<PathBuf>,
}

/// Mirrors `runAutoJury({...})`. Spawns the council CLI, writes the input
/// and verdict files, writes the ledger, and enforces ship/don't-ship.
pub fn run_auto_jury(cfg: &AutoJuryConfig, args: RunAutoJuryArgs<'_>) -> Result<Value, AutoJuryError> {
    let RunAutoJuryArgs { kind, artifact_path, context, fail_hard, out_dir } = args;

    let skill = kind_to_skill(kind)
        .ok_or_else(|| AutoJuryError::UnknownKind(kind.to_string(), KIND_TO_SKILL_KEYS.join(", ")))?;
    if artifact_path.is_empty() {
        return Err(AutoJuryError::MissingArtifactPath);
    }

    let artifact_dir = Path::new(artifact_path).parent().unwrap_or_else(|| Path::new("."));
    let verdict_dir = out_dir.unwrap_or_else(|| artifact_dir.join("jury"));
    if !verdict_dir.exists() {
        fs::create_dir_all(&verdict_dir)?;
    }
    let artifact_basename = Path::new(artifact_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| artifact_path.to_string());
    let verdict_path = verdict_dir.join(format!("{artifact_basename}.verdict.json"));
    let input_path = verdict_dir.join(format!("{artifact_basename}.input.md"));

    let qa_rubrics_path = cfg.workspace_root.join("tools").join("recipes").join("video").join("qa-rubrics.json");
    let qa_rubrics_lib = load_qa_rubrics_lib(&qa_rubrics_path);
    let input = build_council_input(BuildCouncilInputArgs {
        kind,
        artifact_path,
        context: &context,
        qa_rubrics_lib: Some(&qa_rubrics_lib),
    });
    fs::write(&input_path, &input)?;

    let mut cli_args: Vec<String> = cfg.python_args.clone();
    cli_args.push(cfg.council_py.to_string_lossy().to_string());
    cli_args.push(skill.to_string());
    cli_args.push("--input".to_string());
    cli_args.push(input_path.to_string_lossy().to_string());
    cli_args.push("--json".to_string());

    if let Some(flags) = context.get("rubricFlags").and_then(Value::as_object) {
        for (k, v) in flags {
            cli_args.push("--flag".to_string());
            cli_args.push(format!("{k}={}", value_to_display(v)));
        }
    }
    if let Some(qa_rubric) = context.get("qaRubric").and_then(Value::as_str) {
        if !qa_rubric.is_empty() {
            cli_args.push("--flag".to_string());
            cli_args.push(format!("qa_rubric={qa_rubric}"));
        }
    }

    let timeout_env = std::env::var("AUTO_JURY_TIMEOUT_MS").ok();
    let timeout_ms = council_timeout_ms(timeout_env.as_deref());

    let output = run_with_timeout(&cfg.python_bin, &cli_args, Duration::from_millis(timeout_ms));

    let raw = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        Ok(out) => {
            let failure = CouncilCliFailure {
                stderr: Some(String::from_utf8_lossy(&out.stderr).to_string()),
                stdout: Some(String::from_utf8_lossy(&out.stdout).to_string()),
                timed_out: false,
                status: out.status.code(),
                signal: None,
                code: None,
            };
            return Err(AutoJuryError::CouncilCliFailed(format_council_cli_error(
                &failure,
                skill,
                artifact_path,
                timeout_ms,
            )));
        }
        Err(TimeoutOrIoError::TimedOut) => {
            let failure = CouncilCliFailure {
                stderr: None,
                stdout: None,
                timed_out: true,
                status: None,
                signal: Some("SIGTERM".to_string()),
                code: None,
            };
            return Err(AutoJuryError::CouncilCliFailed(format_council_cli_error(
                &failure,
                skill,
                artifact_path,
                timeout_ms,
            )));
        }
        Err(TimeoutOrIoError::Io(e)) => {
            let failure = CouncilCliFailure {
                stderr: None,
                stdout: None,
                timed_out: false,
                status: None,
                signal: None,
                code: Some(e.kind().to_string()),
            };
            return Err(AutoJuryError::CouncilCliFailed(format_council_cli_error(
                &failure,
                skill,
                artifact_path,
                timeout_ms,
            )));
        }
    };

    let mut verdict: Value = serde_json::from_str(&raw).unwrap_or_else(|_| {
        json!({ "raw_output": raw, "parse_error": true })
    });

    let now = std::time::SystemTime::now();
    let timestamp = httpdate_like_iso8601(now);
    if let Value::Object(ref mut map) = verdict {
        map.insert(
            "auto_jury_meta".to_string(),
            json!({
                "kind": kind,
                "skill": skill,
                "artifact": artifact_path,
                "input": input_path.to_string_lossy(),
                "timestamp": timestamp,
                "vision_active": is_visual_kind(kind),
                "failHard": fail_hard,
            }),
        );
    }

    fs::write(&verdict_path, serde_json::to_string_pretty(&verdict).unwrap_or_default())?;

    write_ledger_from_verdict(cfg, &verdict, artifact_path, &verdict_path);

    let final_decision = final_decision_from_council_verdict(&verdict);
    let blocked = is_blocked(&final_decision);

    if blocked && fail_hard {
        return Err(AutoJuryError::Blocked {
            skill: skill.to_string(),
            verdict: final_decision,
            artifact: artifact_basename,
            verdict_path: verdict_path.to_string_lossy().to_string(),
        });
    }

    Ok(verdict)
}

/// Mirrors the `/DON'?T[-\s_]?SHIP|NEEDS[-\s_]?REVISION|REVISE|REJECT|BLOCK|FAIL|ERROR|PARSE/`
/// blocked-verdict regex (case-sensitive on the already-uppercased `final`).
fn is_blocked(final_decision: &str) -> bool {
    let re = regex::Regex::new(
        r"DON'?T[-\s_]?SHIP|NEEDS[-\s_]?REVISION|REVISE|REJECT|BLOCK|FAIL|ERROR|PARSE",
    )
    .expect("static regex");
    re.is_match(final_decision)
}

/// Minimal ISO-8601 UTC timestamp, mirrors `new Date().toISOString()`
/// closely enough for a metadata stamp (millisecond precision, `Z` suffix).
fn httpdate_like_iso8601(now: std::time::SystemTime) -> String {
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // Civil-from-days algorithm (Howard Hinnant), avoids adding a chrono dep.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_ = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_ <= 2 { y + 1 } else { y };
    format!("{y:04}-{m_:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

enum TimeoutOrIoError {
    TimedOut,
    Io(std::io::Error),
}

/// Spawns `program args...`, polling for completion up to `timeout`. Mirrors
/// `execFileSync(..., { timeout, maxBuffer, stdio: ['ignore','pipe','pipe'] })`:
/// on timeout the child is killed and a `TimedOut` error is returned, same as
/// `execFileSync` throwing with `err.killed === true`.
fn run_with_timeout(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<std::process::Output, TimeoutOrIoError> {
    use std::process::Stdio;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(TimeoutOrIoError::Io)?;

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().map_err(TimeoutOrIoError::Io);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(TimeoutOrIoError::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(TimeoutOrIoError::Io(e)),
        }
    }
}

/// Mirrors `_writeLedgerFromVerdict`. Best-effort: logs (in JS terms,
/// "warns") and returns without failing the caller on any error, exactly
/// like the source ("Failure to write the ledger is logged but does NOT
/// throw").
fn write_ledger_from_verdict(cfg: &AutoJuryConfig, verdict: &Value, artifact_path: &str, verdict_path: &Path) {
    let ledger_path = {
        let s = verdict_path.to_string_lossy();
        PathBuf::from(s.strip_suffix(".verdict.json").map(|p| format!("{p}.verdict.ledger.json")).unwrap_or_else(|| format!("{s}.verdict.ledger.json")))
    };

    let mut juror_blockers: Map<String, Value> = Map::new();
    if let Some(jurors) = verdict.get("jurors").and_then(Value::as_array) {
        for j in jurors {
            let Some(juror_id) = j.get("juror_id").and_then(Value::as_str) else {
                continue;
            };
            let blockers = j.get("blockers").and_then(Value::as_array).cloned().unwrap_or_default();
            if blockers.is_empty() {
                continue;
            }
            juror_blockers.insert(juror_id.to_string(), Value::Array(blockers));
        }
    }

    let payload = json!({
        "artifact": artifact_path,
        "verdict_path": verdict_path.to_string_lossy(),
        "juror_blockers": Value::Object(juror_blockers),
    });
    let payload_path = PathBuf::from(format!("{}.ledger-payload.json", verdict_path.to_string_lossy()));
    if fs::write(&payload_path, payload.to_string()).is_err() {
        return;
    }

    let lib_dir = std::env::var("JURY_LIB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cfg.workspace_root.join("tools").join("review"));
    let helper_dir = verdict_path.parent().unwrap_or_else(|| Path::new("."));
    let helper_path = helper_dir.join(".ledger-write.py");
    let helper = format!(
        "\nimport json\nimport sys\nfrom pathlib import Path\nsys.path.insert(0, r\"{}\")\nfrom ledger import Ledger, register_verdict_round, save_ledger, load_ledger\n\npayload = json.loads(Path(r\"{}\").read_text(encoding=\"utf-8\"))\nledger_path = Path(r\"{}\")\nledger = load_ledger(ledger_path) or Ledger(schema_version=1, artifact=payload[\"artifact\"])\nregister_verdict_round(\n    ledger,\n    verdict_path=payload[\"verdict_path\"],\n    juror_blockers=payload[\"juror_blockers\"],\n)\nsave_ledger(ledger, ledger_path)\nprint(f\"ledger → {{ledger_path}}\")\n",
        lib_dir.to_string_lossy(),
        payload_path.to_string_lossy(),
        ledger_path.to_string_lossy(),
    );

    if fs::write(&helper_path, &helper).is_err() {
        let _ = fs::remove_file(&payload_path);
        return;
    }

    let py = std::env::var("PYTHON_BIN").unwrap_or_else(|_| "py".to_string());
    let py_args: Vec<String> = if std::env::var("PYTHON_BIN").is_ok() {
        vec![]
    } else {
        vec!["-3.11".to_string()]
    };
    let mut cmd = Command::new(&py);
    cmd.args(&py_args).arg(&helper_path);
    let _ = cmd.output();

    let _ = fs::remove_file(&payload_path);
    let _ = fs::remove_file(&helper_path);
}

/// One batch item, mirrors an entry in the `items` array passed to
/// `runAutoJuryBatch`.
pub struct BatchItem<'a> {
    pub kind: &'a str,
    pub artifact_path: &'a str,
    pub context: Value,
    pub out_dir: Option<PathBuf>,
}

/// Mirrors `runAutoJuryBatch(items, { failHard })`.
pub fn run_auto_jury_batch(
    cfg: &AutoJuryConfig,
    items: Vec<BatchItem<'_>>,
    fail_hard: bool,
) -> Result<(Vec<Value>, Vec<(String, String)>), AutoJuryError> {
    let mut verdicts = Vec::new();
    let mut blocked = Vec::new();
    for item in items {
        let artifact_path = item.artifact_path.to_string();
        match run_auto_jury(
            cfg,
            RunAutoJuryArgs {
                kind: item.kind,
                artifact_path: item.artifact_path,
                context: item.context,
                fail_hard,
                out_dir: item.out_dir,
            },
        ) {
            Ok(v) => verdicts.push(v),
            Err(err) => {
                let msg = err.to_string();
                blocked.push((artifact_path, msg.clone()));
                if fail_hard {
                    return Err(err);
                }
            }
        }
    }
    Ok((verdicts, blocked))
}

/// Recognized `kind` values, exposed for callers that want to validate
/// before calling `run_auto_jury`.
pub fn known_kinds() -> HashSet<&'static str> {
    KIND_TO_SKILL_KEYS.iter().copied().collect()
}
