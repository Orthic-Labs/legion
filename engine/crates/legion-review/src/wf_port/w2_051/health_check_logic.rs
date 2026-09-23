//! Port of the pure logic in `src/lib/review/health_check.py` — enumerating
//! configured jury models and classifying a probe outcome. The actual
//! network probe (`provider_obj.call(...)`) and `models.yaml`/`config.py`
//! loading are outside this chunk's scope (no Rust config/provider layer
//! exists here yet); `enumerate_models`/`classify` are ported as pure
//! functions over already-parsed inputs so the model-enumeration and
//! status-classification rules stay unit-testable and exactly faithful.

use std::collections::BTreeMap;

/// One `(provider, model)` pair's seat usage, mirroring
/// `{"primary_seats": [...], "fallback_seats": [...]}`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SeatUsage {
    pub primary_seats: Vec<String>,
    pub fallback_seats: Vec<String>,
}

/// A juror entry as it appears in a panel or skill lineup.
#[derive(Debug, Clone)]
pub struct JurorSpec {
    pub id: String,
    pub provider: String,
    pub model: String,
    pub fallbacks: Vec<(String, String)>,
}

/// An escalation rule entry, only counted when it names a provider+model.
#[derive(Debug, Clone)]
pub struct EscalationSpec {
    pub provider: Option<String>,
    pub model: Option<String>,
}

/// Input config shape reduced to what `enumerate_models` reads:
/// `panels: {name -> jurors}` and `skills: {name -> (jurors, escalation)}`.
#[derive(Debug, Clone, Default)]
pub struct ModelsConfig {
    pub panels: BTreeMap<String, Vec<JurorSpec>>,
    pub skills: BTreeMap<String, (Vec<JurorSpec>, Vec<EscalationSpec>)>,
}

/// Port of `enumerate_models`. Keyed by `(provider, model)`; ordering of
/// the two seat-kind vectors follows call order (panels first, alphabetical
/// by panel name since the input is a `BTreeMap`, then skills).
pub fn enumerate_models(cfg: &ModelsConfig) -> BTreeMap<(String, String), SeatUsage> {
    let mut seen: BTreeMap<(String, String), SeatUsage> = BTreeMap::new();
    let mut note = |provider: &str, model: &str, seat: String, is_primary: bool| {
        let rec = seen.entry((provider.to_string(), model.to_string())).or_default();
        if is_primary {
            rec.primary_seats.push(seat);
        } else {
            rec.fallback_seats.push(seat);
        }
    };

    for (panel, jurors) in &cfg.panels {
        for juror in jurors {
            let seat = format!("panel:{panel}:{}", juror.id);
            note(&juror.provider, &juror.model, seat.clone(), true);
            for (fb_provider, fb_model) in &juror.fallbacks {
                note(fb_provider, fb_model, format!("{seat}.fb"), false);
            }
        }
    }

    for (skill, (jurors, escalation)) in &cfg.skills {
        for j in jurors {
            let seat = format!("{skill}:{}", j.id);
            note(&j.provider, &j.model, seat.clone(), true);
            for (fb_provider, fb_model) in &j.fallbacks {
                note(fb_provider, fb_model, format!("{seat}.fb"), false);
            }
        }
        for rule in escalation {
            if let (Some(provider), Some(model)) = (&rule.provider, &rule.model) {
                note(provider, model, format!("{skill}:escalation"), false);
            }
        }
    }

    seen
}

/// Outcome of a probe call, already reduced from a provider exception to
/// its distinguishing fields (status code / message), since this crate has
/// no provider/HTTP layer of its own in scope.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// The provider was never built (missing config): `{"status":
    /// "no_provider", ...}`.
    NoProvider,
    /// A successful call: `raw` is the (possibly empty) response text.
    Ok { raw: Option<String>, latency_ms: i64 },
    /// A `ProviderError`: `status` mirrors `getattr(e, "status", None)`,
    /// `is_quota` mirrors `getattr(e, "is_quota", False)`, `message` is
    /// `str(e)`.
    ProviderError {
        status: Option<i32>,
        is_quota: bool,
        message: String,
        latency_ms: i64,
    },
    /// Any other exception: `{type}: {message}`.
    Other { type_name: String, message: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassifyResult {
    pub status: String,
    pub http: Option<i32>,
    pub detail: String,
    pub latency_ms: Option<i64>,
}

/// Port of `classify`'s status-kind decision tree (the probe call itself
/// is the caller's responsibility; this takes its already-observed
/// outcome).
pub fn classify(outcome: &ProbeOutcome) -> ClassifyResult {
    match outcome {
        ProbeOutcome::NoProvider => ClassifyResult {
            status: "no_provider".to_string(),
            http: None,
            detail: "provider not built (missing config)".to_string(),
            latency_ms: None,
        },
        ProbeOutcome::Ok { raw, latency_ms } => {
            let detail: String = raw.as_deref().unwrap_or("").trim().chars().take(40).collect();
            ClassifyResult {
                status: "ok".to_string(),
                http: None,
                detail,
                latency_ms: Some(*latency_ms),
            }
        }
        ProbeOutcome::ProviderError {
            status,
            is_quota,
            message,
            latency_ms,
        } => {
            let msg_lower = message.to_lowercase();
            let kind = if msg_lower.contains("no key") || msg_lower.contains("no api key") {
                "no_key"
            } else if *status == Some(404)
                || msg_lower.contains("not found")
                || msg_lower.contains("does not exist")
                || msg_lower.contains("unknown model")
            {
                "unreachable"
            } else if matches!(status, Some(401) | Some(403)) {
                "auth"
            } else if matches!(status, Some(429) | Some(503) | Some(504)) || *is_quota {
                "busy"
            } else {
                "error"
            };
            ClassifyResult {
                status: kind.to_string(),
                http: *status,
                detail: message.chars().take(120).collect(),
                latency_ms: Some(*latency_ms),
            }
        }
        ProbeOutcome::Other { type_name, message } => ClassifyResult {
            status: "error".to_string(),
            http: None,
            detail: format!("{type_name}: {}", message.chars().take(120).collect::<String>()),
            latency_ms: None,
        },
    }
}

/// A fully classified model row, for the `primary_broken` gate below.
#[derive(Debug, Clone)]
pub struct ModelRow {
    pub primary: bool,
    pub status: String,
}

/// Port of the `primary_broken` filter driving the CLI's nonzero exit:
/// PRIMARY seats whose status is unreachable/auth/error.
pub fn primary_broken(rows: &[ModelRow]) -> Vec<&ModelRow> {
    rows.iter()
        .filter(|r| r.primary && matches!(r.status.as_str(), "unreachable" | "auth" | "error"))
        .collect()
}
