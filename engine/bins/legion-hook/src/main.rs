#![forbid(unsafe_code)]

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use legion_application::{NativeApplication, NativeApplicationConfig};
use legion_contracts::{
    AgentId, AuthorityKind, CapabilityUsage, ChallengePass, ComputePosture, ContextUsage,
    CostUsage, EffectClass, EffectRequest, OutcomeResult, RequestId, RoleDecision, Route,
    RouteOutcomeTrace, SemanticRequirement, TaskId, TraceId,
};
use serde_json::{Map, Value};

mod codex;
mod error;
mod protocol;

use error::HookError;
use protocol::{HookRequest, HookResponse};

/// Embedded because installed customers may have no copy of the development
/// workspace (or its Arcane files). This is response policy, not effect policy:
/// the Guard only transports it on SessionStart; Arcane owns its meaning.
const SESSION_START_CONTEXT: &str = r#"Complete the requested outcome within explicit constraints; use a skill only when its operation and inputs fit the request, and delegate only when coordination pays for itself. Inspect the relevant production flow before repairing, choose the smallest complete repair and cheapest decisive checks, and cite fresh evidence for any claim that work is done. Sage and Oracle are optional (Sage for design or adjudication, Oracle for review on explicit request or a concrete outcome or safety risk), contracts apply only to explicit or locked work, and report only states actually reached."#;
const SESSION_START_SYSTEM_MESSAGE: &str = "LEGION:ACTIVE";
const MAX_TRANSCRIPT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STOP_REOPENINGS: u64 = 3;

/// Translate one versioned host frame into an explicit, strongly enforced
/// decision. Lifecycle/post-effect observations are safe to acknowledge;
/// pre-effect frames must carry enough typed identity to reach native policy.
pub fn dispatch(request: HookRequest) -> HookResponse {
    let started = Instant::now();
    let provenance = pinned_session_provenance(&request);
    let response = dispatch_inner(request.clone());
    emit_route_trace(&request, &response, started.elapsed(), provenance.as_ref());
    emit_child_lifecycle(&request, &response);
    response
}

fn dispatch_inner(request: HookRequest) -> HookResponse {
    let event_type = request.event_type.clone();
    if let Err(error) = request.validate() {
        return response_for_error(event_type, error);
    }
    if let Some(response) = deterministic_arcane_control(&request) {
        return response;
    }

    if request.is_lifecycle() {
        if matches!(request.event_type.as_str(), "Stop" | "stop") {
            return stop_response(&request);
        }
        return HookResponse::allowed(request.event_type, "lifecycle observation accepted");
    }
    if request.is_post_effect() {
        return HookResponse::allowed(request.event_type, "post-effect observation accepted");
    }
    if !request.is_pre_effect() {
        return HookResponse::denied(
            request.event_type,
            "ARC_HOST_EVENT_INVALID",
            "unsupported hook event",
            "strong",
        );
    }

    if is_destructive_command(&request.payload) {
        return HookResponse::denied(
            request.event_type,
            "ARC_EFFECT_CLASS_UNAUTHORIZED",
            "destructive command class is blocked; use a bounded, reversible alternative",
            "strong",
        );
    }
    if rewrite_push_requires_approval(&request.payload) {
        return HookResponse::denied(
            request.event_type,
            "ARC_APPROVAL_REQUIRED",
            "git push rewrites published history; rewrite it manually if you mean to",
            "strong",
        );
    }

    let effect = match effect_request(&request) {
        Ok(Some(effect)) => effect,
        Ok(None) => {
            return HookResponse::allowed(
                request.event_type,
                "MCP tool carries no external effect; observation allowed",
            )
        }
        Err(message) => {
            return HookResponse::denied(
                request.event_type,
                "ARC_HOST_EVENT_INVALID",
                message,
                "strong",
            )
        }
    };

    let application = match native_application() {
        Ok(application) => application,
        Err(_) => return policy_unavailable_response(request.event_type),
    };

    authorize_effect(request.event_type, &effect, &application)
}

fn deterministic_arcane_control(request: &HookRequest) -> Option<HookResponse> {
    if !request.is_lifecycle() {
        return None;
    }
    let payload = request.payload.as_object()?;
    if let Some(challenge) = payload.get("challengePass") {
        let Some(challenge) = challenge.as_object() else {
            return Some(HookResponse::denied(
                request.event_type.clone(),
                "ARC_CHALLENGE_INVALID",
                "challenge pass must be an object",
                "strong",
            ));
        };
        let pass = challenge.get("passCount").and_then(Value::as_u64);
        let result = challenge.get("result").and_then(Value::as_str);
        if pass != Some(1) || !matches!(result, Some("KEEP" | "NARROW" | "REVISE")) {
            return Some(HookResponse::denied(
                request.event_type.clone(),
                "ARC_CHALLENGE_INVALID",
                "one challenge pass must end KEEP, NARROW or REVISE",
                "strong",
            ));
        }
        return Some(HookResponse::allowed(
            request.event_type.clone(),
            "bounded falsification accepted; pass count is exhausted",
        ));
    }
    if payload.get("routeUncertain").and_then(Value::as_bool) == Some(true) {
        let prior = payload
            .get("priorEscalations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if prior != 0 {
            return Some(HookResponse::denied(
                request.event_type.clone(),
                "ARC_ESCALATION_RECURSION",
                "route uncertainty permits one stronger-model execution",
                "strong",
            ));
        }
        return Some(HookResponse::allowed(
            request.event_type.clone(),
            "route uncertainty selected one stronger working-model execution with direct response",
        ));
    }
    None
}

fn policy_unavailable_response(event_type: String) -> HookResponse {
    HookResponse::denied(
        event_type,
        "ARC_NATIVE_POLICY_UNAVAILABLE",
        "native policy configuration is unavailable",
        "unsupported",
    )
}

/// Stop is an Arcane-owned postflight delivered through the Guard event. The
/// Guard delivers the cognitive response policy through this event but does
/// not own it. Completion verification is proportional: the typed requirement
/// below determines whether a fresh Oracle receipt must be checked.
fn stop_response(request: &HookRequest) -> HookResponse {
    if stop_reentry_exhausted(&request.payload) {
        return HookResponse::allowed(request.event_type.clone(), "stop re-entry cap reached");
    }
    if let Err(error) = validate_stop_verification(&request.payload) {
        let (code, reason) = match error {
            StopVerificationError::Required => (
                "ARC_VERIFICATION_REQUIRED",
                "the typed verification requirement needs a fresh Oracle PASS receipt",
            ),
            StopVerificationError::Invalid => (
                "ARC_ORACLE_RECEIPT_INVALID",
                "the Oracle receipt is missing, stale, unbound, or not a PASS",
            ),
        };
        return HookResponse::denied(request.event_type.clone(), code, reason, "strong");
    }
    // Assistant wording is not completion evidence. Optional response policy
    // cannot reopen a turn; only the explicit verification requirement above
    // may deny Stop. A later semantic classifier must remain bounded.
    HookResponse::allowed(request.event_type.clone(), "lifecycle observation accepted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopVerificationError {
    Required,
    Invalid,
}

enum StopVerificationRequirement {
    None,
    Oracle {
        subject_digest: Option<String>,
        source_revision: Option<String>,
    },
}

/// Stop never infers assurance from a mutation. A route/completion producer
/// must explicitly set `verificationRequirement`; only the Oracle requirement
/// consumes a receipt, and that receipt is bound to the exact delivery digest
/// and source revision supplied by the producer.
fn validate_stop_verification(payload: &Value) -> Result<(), StopVerificationError> {
    let object = payload.as_object().ok_or(StopVerificationError::Invalid)?;
    let requirement = object
        .get("verificationRequirement")
        .or_else(|| object.get("verification_requirement"));
    let Some(requirement) = requirement else {
        return Ok(());
    };

    let requirement = match requirement {
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "none" => StopVerificationRequirement::None,
            "oracle" | "oracle_completion_validation" | "oracle-completion-validation" => {
                StopVerificationRequirement::Oracle {
                    subject_digest: explicit_delivery_digest(object),
                    source_revision: explicit_source_revision(object),
                }
            }
            _ => return Err(StopVerificationError::Invalid),
        },
        Value::Object(value) => {
            let kind = value
                .get("kind")
                .and_then(Value::as_str)
                .map(|kind| kind.trim().to_ascii_lowercase());
            if !optional_string_fields_valid(
                value,
                &[
                    "kind",
                    "required",
                    "subjectDigest",
                    "subject_digest",
                    "sourceRevision",
                    "source_revision",
                ],
            ) || !object_has_only_keys(
                value,
                &[
                    "kind",
                    "required",
                    "subjectDigest",
                    "subject_digest",
                    "sourceRevision",
                    "source_revision",
                ],
            ) || value
                .get("required")
                .is_some_and(|required| required.as_bool() != Some(true))
            {
                return Err(StopVerificationError::Invalid);
            }
            match kind.as_deref() {
                Some("none") => StopVerificationRequirement::None,
                Some("oracle")
                | Some("oracle_completion_validation")
                | Some("oracle-completion-validation") => StopVerificationRequirement::Oracle {
                    subject_digest: first_string(value, &["subjectDigest", "subject_digest"])
                        .or_else(|| explicit_delivery_digest(object)),
                    source_revision: first_string(value, &["sourceRevision", "source_revision"])
                        .or_else(|| explicit_source_revision(object)),
                },
                _ => return Err(StopVerificationError::Invalid),
            }
        }
        _ => return Err(StopVerificationError::Invalid),
    };
    let StopVerificationRequirement::Oracle {
        subject_digest: required_subject_digest,
        source_revision: required_source_revision,
    } = requirement
    else {
        return Ok(());
    };
    let expected_subject = required_subject_digest.ok_or(StopVerificationError::Required)?;
    if !is_sha256_digest(&expected_subject)
        || explicit_delivery_digest(object).is_some_and(|digest| digest != expected_subject)
    {
        return Err(StopVerificationError::Invalid);
    }
    let receipt = object
        .get("oracleReceipt")
        .or_else(|| object.get("oracle_receipt"))
        .cloned()
        .or_else(|| read_oracle_receipt(object))
        .ok_or(StopVerificationError::Required)?;
    validate_oracle_pass_receipt(
        &receipt,
        &expected_subject,
        required_source_revision.as_deref(),
    )
}

fn explicit_delivery_digest(object: &Map<String, Value>) -> Option<String> {
    first_string(
        object,
        &[
            "subjectDigest",
            "subject_digest",
            "deliveryDigest",
            "delivery_digest",
            "artifactStateDigest",
            "artifact_state_digest",
            "artifactDigest",
            "artifact_digest",
            "diffDigest",
            "diff_digest",
            "deliveryClaimDigest",
            "delivery_claim_digest",
        ],
    )
}

fn explicit_source_revision(object: &Map<String, Value>) -> Option<String> {
    first_string(object, &["sourceRevision", "source_revision"])
}

fn read_oracle_receipt(object: &Map<String, Value>) -> Option<Value> {
    let path = first_string(object, &["oracleReceiptPath", "oracle_receipt_path"])?;
    let metadata = fs::metadata(&path).ok()?;
    if metadata.len() > MAX_TRANSCRIPT_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn validate_oracle_pass_receipt(
    receipt: &Value,
    expected_subject: &str,
    expected_source_revision: Option<&str>,
) -> Result<(), StopVerificationError> {
    let object = receipt.as_object().ok_or(StopVerificationError::Invalid)?;
    if !object_has_only_keys(
        object,
        &[
            "schemaVersion",
            "kind",
            "validationId",
            "runId",
            "verdict",
            "scope",
            "subject",
            "sourcesInspected",
            "findings",
            "repairRecheck",
            "sourceRevision",
            "validatedAt",
        ],
    ) || object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || object.get("kind").and_then(Value::as_str) != Some("legion-oracle-completion-validation")
        || object.get("verdict").and_then(Value::as_str) != Some("PASS")
    {
        return Err(StopVerificationError::Invalid);
    }
    if !is_ocv_id(object.get("validationId").and_then(Value::as_str), "ocv_")
        || !is_ocv_id(object.get("runId").and_then(Value::as_str), "run_")
    {
        return Err(StopVerificationError::Invalid);
    }

    let scope = object
        .get("scope")
        .and_then(Value::as_object)
        .ok_or(StopVerificationError::Invalid)?;
    let raw_turns = scope
        .get("rawUserTurns")
        .and_then(Value::as_array)
        .ok_or(StopVerificationError::Invalid)?;
    if raw_turns.is_empty()
        || raw_turns
            .iter()
            .any(|turn| turn.as_str().is_none_or(|turn| turn.trim().is_empty()))
        || scope
            .get("reconstructedScope")
            .and_then(Value::as_str)
            .is_none_or(|scope| scope.trim().is_empty())
    {
        return Err(StopVerificationError::Invalid);
    }

    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or(StopVerificationError::Invalid)?;
    if subject
        .get("description")
        .and_then(Value::as_str)
        .is_none_or(|description| description.trim().is_empty())
        || subject.get("digest").and_then(Value::as_str) != Some(expected_subject)
    {
        return Err(StopVerificationError::Invalid);
    }
    let sources = object
        .get("sourcesInspected")
        .and_then(Value::as_array)
        .ok_or(StopVerificationError::Invalid)?;
    if sources.is_empty()
        || sources.iter().any(|source| {
            source
                .as_str()
                .is_none_or(|source| source.trim().is_empty())
        })
    {
        return Err(StopVerificationError::Invalid);
    }
    if object
        .get("findings")
        .and_then(Value::as_array)
        .is_none_or(|findings| !findings.is_empty())
    {
        return Err(StopVerificationError::Invalid);
    }
    let repair = object
        .get("repairRecheck")
        .and_then(Value::as_object)
        .ok_or(StopVerificationError::Invalid)?;
    if repair
        .get("repairCount")
        .and_then(Value::as_u64)
        .is_none_or(|count| count > 1)
        || repair
            .get("recheckCount")
            .and_then(Value::as_u64)
            .is_none_or(|count| count > 1)
    {
        return Err(StopVerificationError::Invalid);
    }
    let source_revision = object
        .get("sourceRevision")
        .and_then(Value::as_str)
        .filter(|revision| !revision.trim().is_empty())
        .ok_or(StopVerificationError::Invalid)?;
    if expected_source_revision.is_some_and(|expected| expected != source_revision) {
        return Err(StopVerificationError::Invalid);
    }
    if !is_current_rfc3339_timestamp(object.get("validatedAt").and_then(Value::as_str)) {
        return Err(StopVerificationError::Invalid);
    }
    Ok(())
}

fn object_has_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn optional_string_fields_valid(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().all(|key| {
        !object.contains_key(*key)
            || object
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
    })
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_ocv_id(value: Option<&str>, prefix: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    let suffix = value.strip_prefix(prefix).unwrap_or_default();
    suffix.len() == 26
        && suffix
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&byte))
}

fn is_rfc3339_timestamp(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() >= 20
        && [4, 7, 10, 13, 16].iter().all(|index| {
            bytes.get(*index).is_some_and(|byte| {
                matches!(*index, 10) && (*byte == b'T' || *byte == b't')
                    || matches!(*index, 4 | 7) && *byte == b'-'
                    || matches!(*index, 13 | 16) && *byte == b':'
            })
        })
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && valid_rfc3339_suffix(&bytes[19..])
}

fn valid_rfc3339_suffix(value: &[u8]) -> bool {
    let zone = value
        .iter()
        .position(|byte| matches!(*byte, b'Z' | b'z' | b'+' | b'-'));
    let Some(zone) = zone else {
        return false;
    };
    let fraction_valid = if zone == 0 {
        true
    } else {
        value[0] == b'.'
            && value[1..zone].len() >= 1
            && value[1..zone].iter().all(u8::is_ascii_digit)
    };
    if !fraction_valid {
        return false;
    }
    match value[zone] {
        b'Z' | b'z' => zone + 1 == value.len(),
        b'+' | b'-' => {
            zone + 6 == value.len()
                && value[zone + 1..zone + 3].iter().all(u8::is_ascii_digit)
                && value[zone + 3] == b':'
                && value[zone + 4..zone + 6].iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

const MAX_ORACLE_RECEIPT_AGE_SECS: i64 = 24 * 60 * 60;
const MAX_ORACLE_FUTURE_SKEW_SECS: i64 = 12 * 60 * 60;

fn is_current_rfc3339_timestamp(value: Option<&str>) -> bool {
    let Some(timestamp) = rfc3339_timestamp_seconds(value) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_secs() as i64;
    if timestamp <= now {
        now - timestamp <= MAX_ORACLE_RECEIPT_AGE_SECS
    } else {
        timestamp - now <= MAX_ORACLE_FUTURE_SKEW_SECS
    }
}

fn rfc3339_timestamp_seconds(value: Option<&str>) -> Option<i64> {
    let value = value?;
    if !is_rfc3339_timestamp(Some(value)) {
        return None;
    }
    let bytes = value.as_bytes();
    let year = ascii_digits(bytes, 0, 4)?;
    let month = ascii_digits(bytes, 5, 7)?;
    let day = ascii_digits(bytes, 8, 10)?;
    let hour = ascii_digits(bytes, 11, 13)?;
    let minute = ascii_digits(bytes, 14, 16)?;
    let second = ascii_digits(bytes, 17, 19)?;
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let zone = bytes[19..]
        .iter()
        .position(|byte| matches!(*byte, b'Z' | b'z' | b'+' | b'-'))?
        + 19;
    let offset_seconds = match bytes[zone] {
        b'Z' | b'z' => 0,
        b'+' | b'-' => {
            let offset_hour = ascii_digits(bytes, zone + 1, zone + 3)?;
            let offset_minute = ascii_digits(bytes, zone + 4, zone + 6)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let offset = offset_hour * 60 * 60 + offset_minute * 60;
            if bytes[zone] == b'+' {
                offset
            } else {
                -offset
            }
        }
        _ => return None,
    };
    Some(
        days_from_civil(year, month, day) * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second
            - offset_seconds,
    )
}

fn ascii_digits(bytes: &[u8], start: usize, end: usize) -> Option<i64> {
    let digits = bytes.get(start..end)?;
    (!digits.is_empty() && digits.iter().all(u8::is_ascii_digit)).then(|| {
        digits
            .iter()
            .fold(0_i64, |value, digit| value * 10 + i64::from(*digit - b'0'))
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn stop_reentry_exhausted(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    [
        "stopOrdinal",
        "stop_ordinal",
        "stopAttempts",
        "stop_attempts",
        "reopenings",
    ]
    .iter()
    .filter_map(|key| object.get(*key).and_then(Value::as_u64))
    .any(|value| value >= MAX_STOP_REOPENINGS)
}

fn authorize_effect(
    event_type: String,
    effect: &EffectRequest,
    application: &NativeApplication,
) -> HookResponse {
    match application.authorize_hook(effect) {
        Ok(()) => {
            if matches!(
                effect.effect_class,
                EffectClass::MCP_UNCLASSIFIED_OBSERVATION
            ) {
                // Name the tool and say plainly that classification failed,
                // even on the allow path, so an operator reviewing receipts
                // can see and act on it (tighten the pack, or fix the
                // third-party tool's naming) rather than the decision
                // reading as an ordinary silent allow.
                HookResponse::allowed(
                    event_type,
                    format!(
                        "tool '{}' could not be classified as any known effect; allowed as an unclassified MCP observation per policy",
                        effect.target
                    ),
                )
            } else {
                HookResponse::allowed(event_type, "authorized")
            }
        }
        Err(_) => {
            let message = match effect.effect_class {
                EffectClass::EXTERNAL_SIDE_EFFECT => format!(
                    "native policy denied effect: tool '{}' is a positively classified external side effect (write/send/delete) via MCP (fail-closed default; no policy rule allows EXTERNAL_SIDE_EFFECT for this target/operation)",
                    effect.target
                ),
                EffectClass::MCP_UNCLASSIFIED_OBSERVATION => format!(
                    "native policy denied effect: tool '{}' could not be classified as any known effect; classification failed and the configured policy denies unclassified MCP observations for this target/operation",
                    effect.target
                ),
                _ => format!(
                    "native policy denied effect: {:?} on '{}' (operation '{}')",
                    effect.effect_class, effect.target, effect.operation
                ),
            };
            HookResponse::denied(event_type, "ARC_POLICY_DENIED", &message, "strong")
        }
    }
}

fn response_for_error(event_type: String, error: HookError) -> HookResponse {
    if matches!(&error, HookError::InvalidRequest(message) if message == "event type is unsupported")
    {
        return HookResponse::denied(
            event_type,
            "ARC_HOST_EVENT_INVALID",
            "unsupported hook event",
            "strong",
        );
    }
    let health = match &error {
        HookError::InvalidRequest(_)
        | HookError::MalformedInput(_)
        | HookError::UnsupportedVersion(_) => "strong",
        HookError::Io(_) | HookError::Serialization(_) => "unsupported",
    };
    HookResponse::denied(event_type, error.code(), error.public_message(), health)
}

/// Policy is never simply absent: the normal installed state is the
/// canonical default Guard policy, always present. `LEGION_NATIVE_APPLICATION_CONFIG`
/// lets a project narrow or extend that baseline; when unset, the Guard
/// falls back to `NativeApplicationConfig::default_for_repository`, which
/// carries the same embedded default policy pack. Any failure here —
/// malformed override config, or the embedded default itself failing to
/// validate or build — is a real Guard failure and must fail closed, never
/// fall through to ambient allow.
fn native_application() -> Result<NativeApplication, String> {
    let source = match std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        Ok(source) => source,
        Err(std::env::VarError::NotPresent) => return default_native_application(),
        Err(error) => return Err(error.to_string()),
    };
    if source.trim().is_empty() {
        return Err("native application configuration is empty".into());
    }
    NativeApplicationConfig::from_versioned_source(&source)
        .and_then(NativeApplicationConfig::build)
        .map_err(|error| error.to_string())
}

fn default_native_application() -> Result<NativeApplication, String> {
    let repository_id = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".into());
    NativeApplicationConfig::default_for_repository(repository_id)
        .map_err(|error| error.to_string())
}

fn effect_request(request: &HookRequest) -> Result<Option<EffectRequest>, String> {
    let payload = request
        .payload
        .as_object()
        .ok_or_else(|| "request payload must be a JSON object".to_owned())?;
    let source = payload
        .get("effectRequest")
        .or_else(|| payload.get("effect_request"))
        .and_then(Value::as_object)
        .unwrap_or(payload);
    let effect = source
        .get("effect")
        .and_then(Value::as_object)
        .unwrap_or(source);
    let tool_name = first_string(source, &["toolName", "tool_name"])
        .or_else(|| first_string(payload, &["toolName", "tool_name"]));
    let command = command_value(source).or_else(|| command_value(payload));
    let class_name = first_string(effect, &["effectClass", "effect_class"])
        .or_else(|| first_string(source, &["effectClass", "effect_class"]))
        .or_else(|| first_string(payload, &["effectClass", "effect_class"]));
    let explicit_class = ["effectClass", "effect_class"].iter().any(|key| {
        effect.contains_key(*key) || source.contains_key(*key) || payload.contains_key(*key)
    });

    let tool_input = source
        .get("tool_input")
        .or_else(|| source.get("toolInput"))
        .or_else(|| payload.get("tool_input"))
        .or_else(|| payload.get("toolInput"))
        .and_then(Value::as_object);
    let explicit_operation = first_string(effect, &["operation"])
        .or_else(|| first_string(source, &["operation"]))
        .or_else(|| first_string(payload, &["operation"]))
        .or_else(|| tool_input.and_then(|input| first_string(input, &["operation", "action"])));
    let operation_hint = explicit_operation.clone().or_else(|| tool_name.clone());
    let effect_class = if explicit_class {
        // An explicit unknown class is never guessed from a tool name.
        parse_effect_class(
            class_name.as_deref(),
            tool_name.as_deref(),
            command.as_deref(),
        )
    } else if tool_name
        .as_deref()
        .is_some_and(|name| is_mcp_tool(name) && !is_first_party_host_tool(name))
    {
        // MCP tool names and operations are third-party controlled: a server
        // can name itself anything. A verb allowlist ("write"/"send"/"delete")
        // is therefore a denylist an untrusted server can trivially dodge by
        // naming a tool `exec`, `push_files`, `post`, `create`, `put`, `run`,
        // etc. A positive write/send/delete signal (or an explicit
        // non-MCP-specific class) still resolves to a concrete class here.
        // Anything else is unclassified rather than mislabeled as an external
        // side effect. Route it to a dedicated class so policy emits a truthful
        // receipt. Canonical policy leaves unclassified tools ambient under
        // host permissions; explicit policy can still deny them.
        Some(
            mcp_external_side_effect(tool_name.as_deref(), explicit_operation.as_deref())
                .or_else(|| parse_effect_class(None, tool_name.as_deref(), command.as_deref()))
                .or_else(|| {
                    tool_name
                        .as_deref()
                        .filter(|name| is_known_read_only_tool(name))
                        .map(|_| EffectClass::MCP_KNOWN_OBSERVATION)
                })
                .unwrap_or(EffectClass::MCP_UNCLASSIFIED_OBSERVATION),
        )
    } else {
        // A host tool the classifier does not recognise is not thereby
        // dangerous. Returning None here refused it outright -- TaskStop, for
        // one, which destroys nothing -- and reported only "effect class is
        // missing or unsupported", which says nothing an operator can act on.
        // The destructive gates run earlier against the command itself, so an
        // unrecognised named tool belongs with ordinary execution.
        parse_effect_class(None, tool_name.as_deref(), command.as_deref())
            .or_else(|| tool_name.as_deref().map(|_| EffectClass::COMMAND_EXEC))
    };
    let Some(effect_class) = effect_class else {
        return Err(format!(
            "effect class is missing or unsupported (tool {:?}, command {:?})",
            tool_name.as_deref().unwrap_or("<none>"),
            command
                .as_deref()
                .map(|value| &value[..value.len().min(60)]),
        ));
    };

    let target = first_string(effect, &["target"])
        .or_else(|| first_string(source, &["target"]))
        .or_else(|| first_string(payload, &["target"]))
        .or_else(|| {
            tool_input.and_then(|input| first_string(input, &["file_path", "path", "url", "query"]))
        })
        .or_else(|| tool_name.clone().filter(|name| is_mcp_tool(name)))
        .or_else(|| command.clone())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "effect target is missing".to_owned())?;
    let operation = operation_hint
        .or_else(|| Some(default_operation(effect_class).to_owned()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "effect operation is missing".to_owned())?;

    let source_revision = first_string(source, &["sourceRevision", "source_revision"])
        .or_else(|| first_string(payload, &["sourceRevision", "source_revision"]))
        .or_else(|| {
            std::env::var("LEGION_SOURCE_REVISION")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| resolve_source_revision(payload))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "source revision is missing".to_owned())?;

    let request_id = typed_id(
        first_string(source, &["requestId", "request_id"]).or_else(|| {
            first_string(
                payload,
                &[
                    "requestId",
                    "request_id",
                    "tool_use_id",
                    "toolUseId",
                    "eventId",
                    "event_id",
                ],
            )
        }),
        "native-hook-request",
        RequestId::new,
    )?;
    let task_id = typed_id(
        first_string(source, &["taskId", "task_id"])
            .or_else(|| first_string(payload, &["taskId", "task_id"])),
        "native-hook-task",
        TaskId::new,
    )?;
    let requested_by = typed_id(
        first_string(
            source,
            &["requestedBy", "requested_by", "agentId", "agent_id"],
        )
        .or_else(|| {
            first_string(
                payload,
                &["requestedBy", "requested_by", "agentId", "agent_id"],
            )
        }),
        "native-hook",
        AgentId::new,
    )?;
    let mut approval_required = first_bool(source, &["approvalRequired", "approval_required"])
        .or_else(|| first_bool(payload, &["approvalRequired", "approval_required"]))
        .unwrap_or(false);
    if matches!(effect_class, EffectClass::VCS_PUSH) && command_has_rewrite_flag(command.as_deref())
    {
        // Rewrite approvals must be explicit and target-bound. This adapter
        // has no approval store, so never turn one into an implicit allow.
        approval_required = true;
    }

    let preview = first_string(effect, &["preview"])
        .or_else(|| first_string(source, &["preview"]))
        .or_else(|| first_string(payload, &["preview"]));
    let effect = EffectRequest {
        schema_version: 1,
        request_id,
        task_id,
        requested_by,
        effect_class,
        target,
        operation,
        preview,
        source_revision,
        approval_required,
    };
    effect
        .validate()
        .map_err(|error| format!("invalid effect request: {error}"))?;
    Ok(Some(effect))
}

fn typed_id<T>(
    value: Option<String>,
    fallback: &str,
    constructor: fn(String) -> Result<T, legion_contracts::ContractError>,
) -> Result<T, String> {
    constructor(value.unwrap_or_else(|| fallback.to_owned()))
        .map_err(|error| format!("invalid hook identity: {error}"))
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

fn command_value(object: &Map<String, Value>) -> Option<String> {
    first_string(object, &["command", "cmd"])
        .or_else(|| {
            object
                .get("tool_input")
                .or_else(|| object.get("toolInput"))
                .and_then(Value::as_object)
                .and_then(|input| first_string(input, &["command", "cmd"]))
        })
        .or_else(|| {
            object
                .get("effectRequest")
                .or_else(|| object.get("effect_request"))
                .and_then(Value::as_object)
                .and_then(command_value)
        })
}

fn parse_effect_class(
    class_name: Option<&str>,
    tool_name: Option<&str>,
    command: Option<&str>,
) -> Option<EffectClass> {
    if let Some(class_name) = class_name {
        let normalized = class_name
            .trim()
            .replace(&['-', ' ', '/'][..], "_")
            .to_ascii_uppercase();
        return match normalized.as_str() {
            "FILE_WRITE" | "WRITE" => Some(EffectClass::FILE_WRITE),
            "FILE_DELETE" | "DELETE" => Some(EffectClass::FILE_DELETE),
            "FILE_MOVE" | "MOVE" => Some(EffectClass::FILE_MOVE),
            "COMMAND_EXEC" | "EXECUTE" | "SHELL" => Some(EffectClass::COMMAND_EXEC),
            "NETWORK_EGRESS" | "NETWORK" | "CONNECT" => Some(EffectClass::NETWORK_EGRESS),
            "PROCESS_SPAWN" | "SPAWN" => Some(EffectClass::PROCESS_SPAWN),
            "CREDENTIAL_ACCESS" | "CREDENTIALS" => Some(EffectClass::CREDENTIAL_ACCESS),
            "DEPENDENCY_INSTALL" | "INSTALL" => Some(EffectClass::DEPENDENCY_INSTALL),
            "VCS_COMMIT" | "COMMIT" => Some(EffectClass::VCS_COMMIT),
            "VCS_PUSH" | "PUSH" => Some(EffectClass::VCS_PUSH),
            "PUBLISH" => Some(EffectClass::PUBLISH),
            "EXTERNAL_SIDE_EFFECT" | "MCP_EXTERNAL_SIDE_EFFECT" => {
                Some(EffectClass::EXTERNAL_SIDE_EFFECT)
            }
            _ => None,
        };
    }

    let tool = tool_name.unwrap_or_default();
    match tool {
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => Some(EffectClass::FILE_WRITE),
        "WebFetch" | "WebSearch" => Some(EffectClass::NETWORK_EGRESS),
        // First-party host session tools (mcp__ccd_*) are host dispatch even
        // when their names contain a verb like "send": the verb allowlist
        // exists because third-party MCP names are untrusted, while the ccd_
        // prefix belongs to the host-registered namespace.
        name if is_mcp_external_tool(name) && !is_first_party_host_tool(name) => {
            Some(EffectClass::EXTERNAL_SIDE_EFFECT)
        }
        "shell" | "shell_command" | "Bash" | "PowerShell" | "apply_patch" => {
            Some(command_effect_class(command))
        }
        _ if command.is_some() => Some(command_effect_class(command)),
        _ => None,
    }
}

/// Claude Code Desktop exposes its own session bus (`mcp__ccd_session__*`,
/// `mcp__ccd_session_mgmt__*`, `mcp__ccd_directory__*`, `mcp__ccd_sidebar__*`)
/// through the MCP tool namespace, but it is the host itself, not a third-party
/// server: spawning a sibling session, messaging one, or listing them is host
/// dispatch, the same family as Task/Agent. Treating these as unclassified
/// third-party observations denied every cross-session orchestration call.
/// Its in-app browser is also host interaction. The browser tool name is
/// registered by Claude, so navigation and UI operations belong with host
/// dispatch rather than unclassified third-party MCP observations.
fn is_first_party_host_tool(tool_name: &str) -> bool {
    tool_name
        .get(..9)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp__ccd_"))
        || tool_name
            .get(..21)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp__Claude_Browser__"))
}

fn is_mcp_tool(tool_name: &str) -> bool {
    tool_name
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp__"))
}

/// Only MCP tools whose name or explicit operation identifies a write, send,
/// or delete are classified. Task/Agent dispatch and unrelated MCP tools stay
/// unclassified; they are not external effects in the Guard vocabulary.
fn is_mcp_external_operation(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value
        .split(|character| matches!(character, '_' | '-' | '/' | ' '))
        .any(|part| matches!(part, "write" | "send" | "delete"))
}

fn is_mcp_external_tool(tool_name: &str) -> bool {
    is_mcp_tool(tool_name) && tool_name.split("__").any(is_mcp_external_operation)
}

fn mcp_external_side_effect(
    tool_name: Option<&str>,
    operation: Option<&str>,
) -> Option<EffectClass> {
    (tool_name.is_some_and(is_mcp_tool) && operation.is_some_and(is_mcp_external_operation))
        .then_some(EffectClass::EXTERNAL_SIDE_EFFECT)
}

fn command_effect_class(command: Option<&str>) -> EffectClass {
    // The same wrapper bypass the destructive check had: `git push` is denied,
    // but `bash -c 'git push origin main'` classified as an ordinary
    // COMMAND_EXEC and was admitted. Judge the command the shell is running.
    let command = command.unwrap_or_default().trim().to_ascii_lowercase();
    let command = unwrap_shell_command(&command).to_owned();
    if contains_command_pair(&command, "git", "push") {
        EffectClass::VCS_PUSH
    } else if contains_command_pair(&command, "git", "commit") {
        EffectClass::VCS_COMMIT
    } else if contains_command_pair(&command, "npm", "install")
        || contains_command_pair(&command, "npm", "ci")
        || contains_command_pair(&command, "pnpm", "install")
        || contains_command_pair(&command, "pnpm", "add")
        || contains_command_pair(&command, "yarn", "install")
        || contains_command_pair(&command, "yarn", "add")
        || contains_command_pair(&command, "cargo", "install")
        || contains_command_pair(&command, "cargo", "add")
        || contains_command_pair(&command, "pip", "install")
        || contains_command_pair(&command, "pip3", "install")
        || contains_command_pair(&command, "gem", "install")
        || contains_command_pair(&command, "go", "install")
        || contains_command_pair(&command, "uv", "add")
        || contains_command_pair(&command, "poetry", "add")
    {
        EffectClass::DEPENDENCY_INSTALL
    } else if reads_credential_material(&command) {
        EffectClass::CREDENTIAL_ACCESS
    } else if publishes_artifact(&command) {
        EffectClass::PUBLISH
    } else {
        EffectClass::COMMAND_EXEC
    }
}

/// Well-known credential stores, by the paths and variable names they are kept
/// under.
///
/// The pack denies CREDENTIAL_ACCESS, but nothing ever produced that class
/// from a shell command, so `cat ~/.ssh/id_rsa` was admitted as an ordinary
/// COMMAND_EXEC and the rule could not fire. Matching is deliberately narrow —
/// naming a known secret store, not merely reading a file — because this class
/// denies rather than warns.
fn reads_credential_material(command: &str) -> bool {
    const SECRET_PATHS: [&str; 9] = [
        ".ssh/id_",
        "id_rsa",
        "id_ed25519",
        ".aws/credentials",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".kube/config",
    ];
    const SECRET_NAMES: [&str; 6] = [
        "_token",
        "_secret",
        "_password",
        "_api_key",
        "gh_token",
        "aws_secret_access_key",
    ];
    SECRET_PATHS.iter().any(|needle| command.contains(needle))
        || SECRET_NAMES.iter().any(|needle| command.contains(needle))
}

/// Commands that publish an artifact to somewhere other people can fetch it.
///
/// Same gap as credential access: PUBLISH existed in the pack with nothing
/// able to produce it, so `npm publish` was admitted as COMMAND_EXEC.
fn publishes_artifact(command: &str) -> bool {
    contains_command_pair(command, "npm", "publish")
        || contains_command_pair(command, "pnpm", "publish")
        || contains_command_pair(command, "yarn", "publish")
        || contains_command_pair(command, "cargo", "publish")
        || contains_command_pair(command, "twine", "upload")
        || contains_command_pair(command, "docker", "push")
        || contains_command_pair(command, "gh", "release")
}

fn contains_command_pair(command: &str, first: &str, second: &str) -> bool {
    command
        .split(|character| matches!(character, ';' | '&' | '|' | '\n'))
        .any(|segment| {
            // Tokens are matched as they appear. Stripping quotes here looked
            // like it would help the unwrapped-shell case, but then any quoted
            // mention matched: a script that merely contained the words was
            // classified as running them, and this very edit was refused by
            // the guard it was fixing. `unwrap_shell_command` already removes
            // the wrapper quotes, which is the only place they need removing.
            let mut tokens = segment.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == first && tokens.next() == Some(second) {
                    return true;
                }
            }
            false
        })
}

fn default_operation(effect_class: EffectClass) -> &'static str {
    match effect_class {
        EffectClass::FILE_WRITE => "write",
        EffectClass::FILE_DELETE => "delete",
        EffectClass::FILE_MOVE => "move",
        EffectClass::COMMAND_EXEC => "execute",
        EffectClass::NETWORK_EGRESS => "connect",
        EffectClass::PROCESS_SPAWN => "spawn",
        EffectClass::CREDENTIAL_ACCESS => "access",
        EffectClass::DEPENDENCY_INSTALL => "install",
        EffectClass::VCS_COMMIT => "commit",
        EffectClass::VCS_PUSH => "push",
        EffectClass::PUBLISH => "publish",
        EffectClass::EXTERNAL_SIDE_EFFECT => "external-side-effect",
        EffectClass::MCP_UNCLASSIFIED_OBSERVATION => "observe",
        EffectClass::MCP_KNOWN_OBSERVATION => "observe",
    }
}

/// MCP tools this Guard positively recognises as read-only.
///
/// Deliberately a list of exact names, not a verb pattern. A pattern like
/// "contains `read`" is a denylist an untrusted server dodges by naming its
/// delete tool `read_and_purge`; an exact name is a claim we make about a
/// tool we know. Anything absent here stays
/// `MCP_UNCLASSIFIED_OBSERVATION`, preserving that uncertainty in its receipt.
///
/// Only read paths belong here. `legion_m1_invoke` is deliberately absent:
/// it runs work and is not an observation.
fn is_known_read_only_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "mcp__membrane__membrane_context"
            | "mcp__legion__legion_m1_status"
            | "mcp__plugin_legion_legion__legion_m1_status"
            | "mcp__scheduled-tasks__list_tasks"
            | "mcp__scheduled-tasks__list_task_runs"
            | "mcp__scheduled-tasks__get_task"
            | "mcp__scheduled-tasks__get_task_run"
    )
}

/// Whether a `git push` is a history rewrite.
///
/// Only the push's own arguments count. Reading the whole command line meant
/// an unrelated flag elsewhere condemned the push: `git commit -q -F - && git
/// push` was refused as a force-push, because the line was lowercased before
/// tokens were compared and `-F` became `-f`. Short flags are therefore
/// matched case-sensitively -- `-f` and `-F` are different flags to git, and
/// treating them as one is what produced the false positive.
fn command_has_rewrite_flag(command: Option<&str>) -> bool {
    let command = command.unwrap_or_default();
    push_arguments(command).is_some_and(|arguments| {
        arguments.split_whitespace().any(|token| {
            let token = token.trim_matches(|c| c == '"' || c == '\'');
            token.eq_ignore_ascii_case("--force")
                || token.eq_ignore_ascii_case("--force-with-lease")
                || token.eq_ignore_ascii_case("--delete")
                || token == "-f"
                || token == "-d"
                // A refspec deleting or non-fast-forwarding a remote ref.
                || token.starts_with('+')
                || token.starts_with(':')
        })
    })
}

/// The text following `git push`, up to the next shell operator.
fn push_arguments(command: &str) -> Option<&str> {
    let lowered = command.to_ascii_lowercase();
    let start = lowered.find("push")?;
    let before = lowered[..start].trim_end();
    if !before.ends_with("git") {
        return None;
    }
    let rest = &command[start + "push".len()..];
    let end = rest.find(['|', ';', '&', '>', '<']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn rewrite_push_requires_approval(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let Some(command) = command_value(object) else {
        return false;
    };
    let command = command.trim().to_ascii_lowercase();
    contains_command_pair(&command, "git", "push") && command_has_rewrite_flag(Some(&command))
}

/// The command a shell wrapper is being asked to run, or the input unchanged.
///
/// One level only: nesting shells deeper than that is not a pattern any
/// ordinary invocation needs, and an unbounded unwrap would be its own hazard.
fn unwrap_shell_command(segment: &str) -> &str {
    const SHELLS: [&str; 7] = ["bash", "sh", "zsh", "dash", "powershell", "pwsh", "cmd"];
    let mut tokens = segment.split_whitespace();
    let Some(head) = tokens.next() else {
        return segment;
    };
    let head = head.rsplit(['/', '\\']).next().unwrap_or(head);
    let head = head.strip_suffix(".exe").unwrap_or(head);
    if !SHELLS.contains(&head) {
        return segment;
    }
    let Some(flag_start) = segment.find(|character: char| character.is_whitespace()) else {
        return segment;
    };
    let rest = segment[flag_start..].trim_start();
    for flag in ["-lc", "-c", "/c", "/d /s /c", "-command", "-Command"] {
        if let Some(payload) = rest.strip_prefix(flag) {
            return payload.trim_start().trim_matches(['"', '\''].as_ref());
        }
    }
    segment
}

/// Directories that a build or package manager recreates. Removing one by a
/// relative path inside the repository loses nothing that is not regenerable.
const REGENERABLE_DIRECTORIES: [&str; 7] = [
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".turbo",
    "__pycache__",
];

fn is_regenerable_relative_path(operand: &str) -> bool {
    let operand = operand.trim_matches(['"', '\''].as_ref());
    if operand.is_empty()
        || operand.starts_with(['/', '\\', '~'])
        || operand.contains([':', '$', '`', '*', '?', '[', '{', '>', '<'])
    {
        return false;
    }
    let normalized = operand.replace('\\', "/");
    let mut last = None;
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return false,
            other => last = Some(other),
        }
    }
    last.map_or(false, |name| REGENERABLE_DIRECTORIES.contains(&name))
}

/// A recursive `rm` is destructive unless every operand is a relative path to
/// a regenerable directory. `/`, home, the repository root (`.`), absolute
/// paths and anything with `..` or a glob stay denied.
fn rm_is_destructive(segment: &str) -> bool {
    let mut tokens = segment.split_whitespace();
    if tokens.next() != Some("rm") {
        return false;
    }
    let mut recursive = false;
    let mut operands = Vec::new();
    for token in tokens {
        if token == "--recursive"
            || (token.starts_with('-') && !token.starts_with("--") && token.contains('r'))
        {
            recursive = true;
        } else if !token.starts_with('-') {
            operands.push(token);
        }
    }
    recursive
        && !(!operands.is_empty()
            && operands
                .iter()
                .all(|operand| is_regenerable_relative_path(operand)))
}

/// `git clean -n`, `-nd`, and `--dry-run` only list what would be removed.
fn git_clean_is_dry_run(segment: &str) -> bool {
    segment.split_whitespace().any(|token| {
        token == "--dry-run"
            || (token.starts_with('-') && !token.starts_with("--") && token.contains('n'))
    })
}

/// `git restore --staged` only unstages; adding `--worktree` (or `-W`)
/// discards working-tree edits again.
fn restore_is_index_only(segment: &str) -> bool {
    segment.contains("--staged")
        && !segment
            .split_whitespace()
            .any(|token| token == "--worktree" || token == "-w")
}

fn asks_for_help(segment: &str) -> bool {
    segment
        .split_whitespace()
        .any(|token| matches!(token, "-help" | "--help" | "-h"))
}

fn is_destructive_command(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let Some(command) = command_value(object) else {
        return false;
    };
    let command = command.to_ascii_lowercase();
    let destructive_segment = |segment: &str| {
        // A shell wrapper is not a different command. `rm -rf build` was
        // denied while `bash -c 'rm -rf build'` and
        // `powershell -c "Remove-Item -Recurse -Force build"` were admitted,
        // because the segment began with the shell's name. Unwrap one level
        // and judge what is actually being run.
        let segment = unwrap_shell_command(segment.trim_start());
        let segment = segment.trim_start();
        if rm_is_destructive(segment) {
            return true;
        }
        // Windows recursive deletes are the same class as `rm -r`, and this
        // product ships Windows first: `rmdir /s` and `del /s` were admitted
        // while `rm -rf` was denied.
        let windows_recursive_delete = (segment.starts_with("rmdir ")
            || segment.starts_with("rd ")
            || segment.starts_with("del "))
            && segment
                .split_whitespace()
                .any(|token| token == "/s" || token == "-s");
        // Discarding the working tree destroys uncommitted work with no undo,
        // which is exactly what this class is for. `git reset --hard` and
        // `git checkout -- .` were both admitted.
        let git_discards_worktree = (contains_command_pair(segment, "git", "reset")
            && segment.contains("--hard"))
            || (contains_command_pair(segment, "git", "checkout")
                && (segment.contains(" -- .") || segment.trim_end().ends_with(" -- ")))
            // `git restore --staged .` only unstages; it destroys nothing.
            || (contains_command_pair(segment, "git", "restore")
                && segment.contains('.')
                && !restore_is_index_only(segment));
        (segment.starts_with("remove-item") && segment.contains("-recurse"))
            || windows_recursive_delete
            || git_discards_worktree
            || (contains_command_pair(segment, "git", "clean") && !git_clean_is_dry_run(segment))
            || segment.starts_with("dropdb")
            || (contains_command_pair(segment, "terraform", "apply") && !asks_for_help(segment))
            || (contains_command_pair(segment, "terraform", "destroy") && !asks_for_help(segment))
    };
    command
        .split(|character| matches!(character, ';' | '&' | '|'))
        .any(destructive_segment)
        || command
            .split('|')
            .collect::<Vec<_>>()
            .windows(2)
            .any(|parts| {
                let left = parts[0].trim_start();
                let is_curl = left.split_whitespace().any(|token| token == "curl");
                is_curl && {
                    let right = parts[1].trim_start();
                    right.starts_with("sh") || right.starts_with("bash")
                }
            })
}

fn resolve_source_revision(payload: &Map<String, Value>) -> Option<String> {
    // A scratch workspace has no Git HEAD. Record that fact with a stable,
    // path-bound identity so ordinary effects still reach Guard policy.
    // Never borrow a revision from the hook process when the host supplied a
    // different cwd: that would misattribute the effect to another checkout.
    if let Some(value) = first_string(payload, &["cwd", "workspace"]) {
        // Git Bash reports POSIX-style drive paths (`/d/Claude/legion`) that
        // Windows path resolution cannot follow; translate them back.
        let workspace =
            windows_path_from_posix_drive(&value).unwrap_or_else(|| PathBuf::from(value));
        return source_revision_for_workspace(&workspace);
    }
    source_revision_for_workspace(&std::env::current_dir().ok()?)
}

fn source_revision_for_workspace(workspace: &Path) -> Option<String> {
    revision_for_workspace(workspace).or_else(|| {
        legion_contracts::canonical_digest(&workspace.to_string_lossy().as_ref())
            .ok()
            .map(|digest| format!("unversioned-workspace:{digest}"))
    })
}

fn windows_path_from_posix_drive(value: &str) -> Option<PathBuf> {
    let mut chars = value.chars();
    if chars.next() != Some('/') {
        return None;
    }
    let drive = chars.next()?;
    if !drive.is_ascii_alphabetic() {
        return None;
    }
    match chars.next() {
        Some('/') => Some(PathBuf::from(format!(
            "{}:/{}",
            drive.to_ascii_uppercase(),
            chars.as_str()
        ))),
        None => Some(PathBuf::from(format!("{}:/", drive.to_ascii_uppercase()))),
        Some(_) => None,
    }
}

fn revision_for_workspace(workspace: &Path) -> Option<String> {
    let git_dir = resolve_git_dir(workspace)?;
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    if valid_revision(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference = head.strip_prefix("ref: ")?.trim();
    if !valid_git_reference(reference) {
        return None;
    }
    let common_dir = resolve_common_git_dir(&git_dir).unwrap_or_else(|| git_dir.clone());
    for root in [&git_dir, &common_dir] {
        if let Ok(value) = fs::read_to_string(root.join(reference)) {
            let value = value.trim();
            if valid_revision(value) {
                return Some(value.to_ascii_lowercase());
            }
        }
    }
    for root in [&git_dir, &common_dir] {
        if let Some(value) = revision_from_packed_refs(root, reference) {
            return Some(value);
        }
    }
    None
}

fn resolve_git_dir(workspace: &Path) -> Option<PathBuf> {
    // A tool call may run from any subdirectory of the checkout, so walk toward the
    // filesystem root until a `.git` marker appears. Resolving only `workspace/.git`
    // denied every effect raised from a subdirectory, which locked the shell out.
    workspace.ancestors().find_map(git_dir_at)
}

fn git_dir_at(workspace: &Path) -> Option<PathBuf> {
    let marker = workspace.join(".git");
    if marker.is_dir() {
        return Some(marker);
    }
    let marker_text = fs::read_to_string(&marker).ok()?;
    let relative = marker_text.trim().strip_prefix("gitdir: ")?.trim();
    let candidate = PathBuf::from(relative);
    Some(if candidate.is_absolute() {
        candidate
    } else {
        workspace.join(candidate)
    })
}

fn resolve_common_git_dir(git_dir: &Path) -> Option<PathBuf> {
    let value = fs::read_to_string(git_dir.join("commondir")).ok()?;
    let relative = PathBuf::from(value.trim());
    Some(if relative.is_absolute() {
        relative
    } else {
        git_dir.join(relative)
    })
}

fn revision_from_packed_refs(git_dir: &Path, reference: &str) -> Option<String> {
    let packed = fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            return None;
        }
        let mut fields = line.split_whitespace();
        let revision = fields.next()?;
        let name = fields.next()?;
        (name == reference && valid_revision(revision)).then(|| revision.to_ascii_lowercase())
    })
}

fn valid_git_reference(reference: &str) -> bool {
    !reference.is_empty()
        && !Path::new(reference).is_absolute()
        && reference
            .split(['/', '\\'])
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_request() -> Result<Vec<u8>, HookError> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| HookError::Io(error.to_string()))?;
    if input.iter().all(u8::is_ascii_whitespace) {
        return Err(HookError::invalid("request is empty"));
    }
    Ok(input)
}

const MAX_TRACE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const TRACE_FILE_NAME: &str = "route-outcome-trace.v1.jsonl";
/// Child launch lifecycle observed by this hook itself (SubagentStart/Stop).
/// Separate from the route-outcome trace so that schema stays unchanged.
const CHILD_TRACE_FILE_NAME: &str = "child-lifecycle-trace.v1.jsonl";
const SESSION_PROVENANCE_DIRECTORY: &str = "session-provenance";

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionProvenance {
    arcane_profile_digest: Option<String>,
    legion_canon_digest: Option<String>,
    skill_catalog_digest: Option<String>,
    guard_policy_digest: Option<String>,
}

impl SessionProvenance {
    fn to_value(&self, session_id_digest: &str) -> Value {
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-session-behavioral-provenance",
            "sessionIdDigest": session_id_digest,
            "arcaneProfileDigest": self.arcane_profile_digest,
            "legionCanonDigest": self.legion_canon_digest,
            "skillCatalogDigest": self.skill_catalog_digest,
            "guardPolicyDigest": self.guard_policy_digest,
        })
    }

    fn from_value(value: &Value, session_id_digest: &str) -> Option<Self> {
        let object = value.as_object()?;
        if object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
            || object.get("kind").and_then(Value::as_str)
                != Some("legion-session-behavioral-provenance")
            || object.get("sessionIdDigest").and_then(Value::as_str) != Some(session_id_digest)
        {
            return None;
        }
        let digest = |key: &str| match object.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(value)) if is_sha256_digest(value) => Some(Some(value.clone())),
            _ => None,
        };
        Some(Self {
            arcane_profile_digest: digest("arcaneProfileDigest")?,
            legion_canon_digest: digest("legionCanonDigest")?,
            skill_catalog_digest: digest("skillCatalogDigest")?,
            guard_policy_digest: digest("guardPolicyDigest")?,
        })
    }
}

/// Pin one behavioral epoch on first observation of a host session. A later
/// source-tree or installed-asset change cannot silently rewrite trace
/// provenance for that session. Persistence failure only suppresses automatic
/// enrichment; it never changes an allow/deny decision.
fn pinned_session_provenance(request: &HookRequest) -> Option<SessionProvenance> {
    let payload = request.payload.as_object()?;
    let session_id = first_string(payload, &["session_id", "sessionId", "conversation_id"])?;
    let session_id_digest = legion_contracts::canonical_digest(&session_id).ok()?;
    let path = receipt_root(&request.payload)?
        .join(SESSION_PROVENANCE_DIRECTORY)
        .join(format!(
            "{}.json",
            session_id_digest.trim_start_matches("sha256:")
        ));

    if let Some(pinned) = read_session_provenance(&path, &session_id_digest) {
        return Some(pinned);
    }

    let candidate = automatic_session_provenance(payload);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    let bytes = serde_json::to_vec(&candidate.to_value(&session_id_digest)).ok()?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&bytes).ok()?;
            file.write_all(b"\n").ok()?;
            Some(candidate)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_session_provenance(&path, &session_id_digest)
        }
        Err(_) => None,
    }
}

fn read_session_provenance(path: &Path, session_id_digest: &str) -> Option<SessionProvenance> {
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    SessionProvenance::from_value(&value, session_id_digest)
}

fn automatic_session_provenance(payload: &Map<String, Value>) -> SessionProvenance {
    let repository = repository_root_from_payload(payload);
    let installed_assets = installed_assets_root();
    let file_digest = |path: &Path| {
        fs::read(path)
            .ok()
            .and_then(|bytes| legion_contracts::canonical_digest(&bytes).ok())
    };
    let legion_canon_digest = repository
        .as_ref()
        .and_then(|root| file_digest(&root.join("AGENTS.md")))
        .or_else(|| {
            legion_contracts::canonical_digest(&serde_json::json!({
                "owner": "legion-routing",
                "embeddedSessionContext": SESSION_START_CONTEXT,
            }))
            .ok()
        });
    let skill_catalog_digest = repository
        .as_ref()
        .and_then(|root| file_digest(&root.join("src/registry/skills/index.json")))
        .or_else(|| {
            installed_assets
                .as_ref()
                .and_then(|root| file_digest(&root.join("registry/index.json")))
        });
    SessionProvenance {
        arcane_profile_digest: legion_contracts::canonical_digest(&serde_json::json!({
            "owner": "arcane-profile",
            "embeddedSessionContext": SESSION_START_CONTEXT,
        }))
        .ok(),
        legion_canon_digest,
        skill_catalog_digest,
        guard_policy_digest: active_guard_policy_digest(),
    }
}

fn active_guard_policy_digest() -> Option<String> {
    match std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        Ok(source) if source.trim_start().starts_with('{') => {
            let value: Value = serde_json::from_str(&source).ok()?;
            legion_contracts::canonical_digest(&value).ok()
        }
        Ok(source) if !source.trim().is_empty() => fs::read(source)
            .ok()
            .and_then(|bytes| legion_contracts::canonical_digest(&bytes).ok()),
        Ok(_) => None,
        Err(std::env::VarError::NotPresent) => legion_contracts::canonical_default_policy_pack()
            .digest()
            .ok(),
        Err(_) => None,
    }
}

fn repository_root_from_payload(payload: &Map<String, Value>) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(value) = first_string(payload, &["cwd", "workspace"]) {
        if let Some(windows) = windows_path_from_posix_drive(&value) {
            candidates.push(windows);
        }
        candidates.push(PathBuf::from(value));
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current);
    }
    candidates.into_iter().find_map(|candidate| {
        candidate
            .ancestors()
            .find(|ancestor| ancestor.join(".git").exists())
            .map(Path::to_path_buf)
    })
}

fn installed_assets_root() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    // Launched through a PATH symlink (`~/.local/bin/legion-hook`), the parent
    // of the link is not the install root. Follow the link first.
    let executable = fs::canonicalize(&executable).unwrap_or(executable);
    installed_assets_for_executable(&executable)
}

fn installed_assets_for_executable(executable: &Path) -> Option<PathBuf> {
    let current_root = executable.parent()?.parent()?;
    let assets = current_root.join("share").join("legion").join("assets");
    assets.is_dir().then_some(assets)
}

/// A derived rate. `NotEnoughData` is deliberately distinct from zero: no
/// observations cannot establish a zero rate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MetricValue {
    Value(f64),
    NotEnoughData,
}

impl MetricValue {
    fn ratio(numerator: usize, denominator: usize) -> Self {
        if denominator == 0 {
            Self::NotEnoughData
        } else {
            Self::Value(numerator as f64 / denominator as f64)
        }
    }
}

/// Metrics folded from one ordered trace sequence. The Oracle repair rate
/// uses sequence order to identify a later real repair for the same request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TraceMetrics {
    /// Sage dispatches / all traces.
    pub sage_dispatch_rate: MetricValue,
    /// blocked Oracle traces / all Oracle-attached traces.
    pub oracle_block_rate: MetricValue,
    /// blocked Oracle traces followed by a same-request `Repair` trace /
    /// blocked Oracle traces.
    pub oracle_block_to_real_fix_rate: MetricValue,
    /// L1 traces ending in NARROW or REVISE / all invoked L1 traces.
    pub challenge_yield: MetricValue,
    /// challenged, evidence-available traces ending in NARROW or REVISE /
    /// materially assumption-dependent traces.
    pub avoidable_user_challenge_rate: MetricValue,
    /// Launched role decisions / labelled eligible=true role decisions.
    pub role_adoption_rate: MetricValue,
    pub labelled_role_eligibility: usize,
    pub selected_roles: usize,
    pub bound_roles: usize,
    pub launched_roles: usize,
    pub skipped_roles: usize,
    pub unnecessary_role_launches: usize,
    pub unknown_role_launches: usize,
}

/// Fold route traces into the tracker rates without inspecting prose or
/// rerunning any validation. Denominators are stated on each result field in
/// [`TraceMetrics`]; every zero denominator returns `NotEnoughData`.
pub fn fold_trace_metrics(traces: &[RouteOutcomeTrace]) -> TraceMetrics {
    let sage_dispatches = traces
        .iter()
        .filter(|trace| trace.authority_attached == Some(AuthorityKind::Sage))
        .count();
    let oracle_traces = traces
        .iter()
        .filter(|trace| trace.authority_attached == Some(AuthorityKind::Oracle))
        .count();
    let oracle_blocks = traces
        .iter()
        .filter(|trace| {
            trace.authority_attached == Some(AuthorityKind::Oracle)
                && trace.result == OutcomeResult::Blocked
        })
        .count();
    let mut oracle_repairs = 0;
    for (index, trace) in traces.iter().enumerate() {
        if trace.authority_attached == Some(AuthorityKind::Oracle)
            && trace.result == OutcomeResult::Blocked
            && traces[index + 1..].iter().any(|later| {
                later.request_id == trace.request_id && later.result == OutcomeResult::Repair
            })
        {
            oracle_repairs += 1;
        }
    }
    let l1_invoked = traces
        .iter()
        .filter(|trace| {
            trace.challenge.invoked && trace.challenge.level == legion_contracts::ChallengeLevel::L1
        })
        .count();
    let l1_improved = traces
        .iter()
        .filter(|trace| {
            trace.challenge.invoked
                && trace.challenge.level == legion_contracts::ChallengeLevel::L1
                && matches!(
                    trace.challenge.outcome,
                    Some(
                        legion_contracts::ChallengeOutcome::Narrow
                            | legion_contracts::ChallengeOutcome::Revise
                    )
                )
        })
        .count();
    let assumption_dependent = traces
        .iter()
        .filter(|trace| trace.challenge.assumption_dependent_conclusion)
        .count();
    let avoidable_challenges = traces
        .iter()
        .filter(|trace| {
            trace.challenge.user_challenge_event
                && trace.challenge.evidence_available_at_first_answer
                && matches!(
                    trace.challenge.outcome,
                    Some(
                        legion_contracts::ChallengeOutcome::Narrow
                            | legion_contracts::ChallengeOutcome::Revise
                    )
                )
        })
        .count();
    let adoption = legion_contracts::fold_role_adoption(traces);

    TraceMetrics {
        sage_dispatch_rate: MetricValue::ratio(sage_dispatches, traces.len()),
        oracle_block_rate: MetricValue::ratio(oracle_blocks, oracle_traces),
        oracle_block_to_real_fix_rate: MetricValue::ratio(oracle_repairs, oracle_blocks),
        challenge_yield: MetricValue::ratio(l1_improved, l1_invoked),
        avoidable_user_challenge_rate: MetricValue::ratio(
            avoidable_challenges,
            assumption_dependent,
        ),
        role_adoption_rate: MetricValue::ratio(
            adoption.eligible_launches,
            adoption.labelled_eligible,
        ),
        labelled_role_eligibility: adoption.labelled_eligible,
        selected_roles: adoption.pending_selected,
        bound_roles: adoption.pending_bound,
        launched_roles: adoption.eligible_launches,
        skipped_roles: adoption.eligible_skips,
        unnecessary_role_launches: adoption.unnecessary_launches,
        unknown_role_launches: adoption.unknown_launches,
    }
}

fn emit_route_trace(
    request: &HookRequest,
    response: &HookResponse,
    latency: Duration,
    provenance: Option<&SessionProvenance>,
) {
    if !protocol::SUPPORTED_EVENT_TYPES.contains(&request.event_type.as_str()) {
        return;
    }
    // A Guard frame is not itself a cognitive route. Emit only when the host
    // supplied the required route envelope; absent fields are not guessed.
    let Some(trace) = route_trace_from_request(request, response, latency, provenance) else {
        return;
    };
    let Some(path) = trace_path(&request.payload) else {
        return;
    };
    if append_trace(&path, &trace).is_err() {
        // Telemetry never changes a decision, but a silently missing trace is
        // how the metrics ended up with no data. Leave one line behind.
        eprintln!(
            "legion-hook: route-outcome trace was not written to {}",
            path.display()
        );
    }
}

/// Hook-observed child launch counters. Unlike `roleDecisions` (host/lead
/// supplied) the launch counters come from SubagentStart/SubagentStop frames
/// the hook received, keyed by the host's child id.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChildLaunchCounters {
    /// Role decisions in state selected, bound or launched (latest per request+role).
    pub selected: usize,
    /// Distinct child ids for which a SubagentStart frame reached the hook.
    pub attempted_launch: usize,
    /// Distinct attempted child ids whose start the hook accepted.
    pub accepted_launch: usize,
    /// Distinct accepted child ids that later produced a SubagentStop.
    pub completed: usize,
    /// Distinct attempted child ids never accepted (start refused).
    pub rejected: usize,
    /// Role decisions in state skipped (latest per request+role).
    pub explicitly_skipped: usize,
}

fn child_lifecycle_event(event_type: &str) -> Option<&'static str> {
    match event_type {
        "SubagentStart" | "subagent-start" => Some("SubagentStart"),
        "SubagentStop" | "subagent-stop" => Some("SubagentStop"),
        _ => None,
    }
}

fn child_id_from_payload(payload: &Map<String, Value>) -> Option<String> {
    let source = trace_source(payload);
    first_string(
        source,
        &[
            "agent_id",
            "agentId",
            "child_id",
            "childId",
            "subagent_id",
            "subagentId",
            "request_id",
            "requestId",
            "tool_use_id",
            "toolUseId",
        ],
    )
    .or_else(|| {
        first_string(
            payload,
            &[
                "agent_id",
                "agentId",
                "child_id",
                "childId",
                "subagent_id",
                "subagentId",
                "request_id",
                "requestId",
                "tool_use_id",
                "toolUseId",
            ],
        )
    })
}

fn child_lifecycle_record(request: &HookRequest, response: &HookResponse) -> Option<Value> {
    let event = child_lifecycle_event(request.event_type.as_str())?;
    let payload = request.payload.as_object()?;
    let child_id = child_id_from_payload(payload)?;
    let mut record = Map::new();
    record.insert("schemaVersion".into(), Value::from(1));
    record.insert("kind".into(), Value::from("legion-child-lifecycle"));
    record.insert("event".into(), Value::from(event));
    record.insert("childId".into(), Value::from(child_id));
    record.insert("accepted".into(), Value::Bool(response.allowed));
    if let Some(agent) = first_string(
        payload,
        &["agent_type", "agentType", "subagent_type", "subagentType", "role"],
    ) {
        record.insert("agentType".into(), Value::from(agent));
    }
    if let Some(session) = first_string(payload, &["session_id", "sessionId"]) {
        record.insert("sessionId".into(), Value::from(session));
    }
    record.insert(
        "observedAtUnixMs".into(),
        Value::from((unix_nanos() / 1_000_000).min(u64::MAX as u128) as u64),
    );
    Some(Value::Object(record))
}

/// Test builds never fall back to the per-user receipts directory.
fn child_trace_path(payload: &Value) -> Option<PathBuf> {
    if cfg!(test) {
        let object = payload.as_object()?;
        if first_string(object, &["stateRoot", "state_root"]).is_none()
            && std::env::var_os("LEGION_STATE_ROOT").is_none()
        {
            return None;
        }
    }
    receipt_root(payload).map(|root| root.join(CHILD_TRACE_FILE_NAME))
}

fn emit_child_lifecycle(request: &HookRequest, response: &HookResponse) {
    let Some(record) = child_lifecycle_record(request, response) else {
        return;
    };
    let Some(path) = child_trace_path(&request.payload) else {
        return;
    };
    if append_json_line(&path, &record).is_err() {
        eprintln!(
            "legion-hook: child lifecycle trace was not written to {}",
            path.display()
        );
    }
}

fn append_json_line(path: &Path, value: &Value) -> Result<(), ()> {
    let mut line = serde_json::to_vec(value).map_err(|_| ())?;
    if (line.len() as u64).saturating_add(1) > MAX_TRACE_FILE_BYTES {
        return Err(());
    }
    line.push(b'\n');
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| ())?;
    }
    if fs::metadata(path)
        .ok()
        .map(|metadata| metadata.len().saturating_add(line.len() as u64) > MAX_TRACE_FILE_BYTES)
        .unwrap_or(false)
    {
        fs::rename(path, PathBuf::from(format!("{}.1", path.display()))).map_err(|_| ())?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(&line).map_err(|_| ())
}

/// Fold hook-observed child lifecycle records and route traces into the
/// separate launch counters. Records that are not well-formed are ignored.
pub fn fold_child_launch_counters(
    records: &[Value],
    traces: &[RouteOutcomeTrace],
) -> ChildLaunchCounters {
    use std::collections::BTreeSet;
    let mut attempted = BTreeSet::new();
    let mut accepted = BTreeSet::new();
    let mut stopped = BTreeSet::new();
    for record in records {
        let Some(object) = record.as_object() else {
            continue;
        };
        let Some(id) = object.get("childId").and_then(Value::as_str) else {
            continue;
        };
        match object.get("event").and_then(Value::as_str) {
            Some("SubagentStart") => {
                attempted.insert(id.to_owned());
                if object.get("accepted").and_then(Value::as_bool) == Some(true) {
                    accepted.insert(id.to_owned());
                }
            }
            Some("SubagentStop") => {
                stopped.insert(id.to_owned());
            }
            _ => {}
        }
    }
    let mut latest: Vec<(&RequestId, AuthorityKind, legion_contracts::RoleDecisionState)> =
        Vec::new();
    for trace in traces {
        let Some(decisions) = trace.role_decisions.as_ref() else {
            continue;
        };
        for decision in decisions {
            if let Some(existing) = latest.iter_mut().find(|(request, role, _)| {
                request.as_str() == trace.request_id.as_str() && *role == decision.role
            }) {
                existing.2 = decision.state;
            } else {
                latest.push((&trace.request_id, decision.role, decision.state));
            }
        }
    }
    let skipped = latest
        .iter()
        .filter(|(_, _, state)| *state == legion_contracts::RoleDecisionState::Skipped)
        .count();
    ChildLaunchCounters {
        selected: latest.len() - skipped,
        attempted_launch: attempted.len(),
        accepted_launch: accepted.len(),
        completed: stopped.intersection(&accepted).count(),
        rejected: attempted.difference(&accepted).count(),
        explicitly_skipped: skipped,
    }
}

fn route_trace_from_request(
    request: &HookRequest,
    response: &HookResponse,
    latency: Duration,
    provenance: Option<&SessionProvenance>,
) -> Option<RouteOutcomeTrace> {
    // Post-effect and child-lifecycle frames acknowledge host activity; an
    // allowed acknowledgement is not execution success or task completion.
    // Keep SessionStart/Stop route envelopes and explicit PreToolUse decisions
    // observable, while refusing false terminal success for acknowledgements.
    if request.is_post_effect()
        || (request.is_lifecycle()
            && !matches!(
                request.event_type.as_str(),
                "SessionStart" | "session-start" | "Stop" | "stop"
            ))
    {
        return None;
    }
    let payload = request.payload.as_object()?;
    let source = trace_source(payload);
    let request_id = trace_string(
        source,
        payload,
        &[
            "request_id",
            "requestId",
            "tool_use_id",
            "toolUseId",
            "event_id",
            "eventId",
        ],
    )?;
    let request_id = RequestId::new(request_id).ok()?;
    let trace_id = trace_string(source, payload, &["trace_id", "traceId"])
        .and_then(|value| TraceId::new(value).ok())
        .or_else(|| TraceId::new(format!("hook-{}-{}", request_id, unix_nanos())).ok())?;
    let task_id = trace_string(source, payload, &["task_id", "taskId"])
        .and_then(|value| TaskId::new(value).ok());
    let context = trace_context(source, payload)?;
    let capabilities = trace_capabilities(source, payload)?;
    let cost = trace_cost(source, payload)?;
    let challenge = trace_value(source, payload, &["challenge"])
        .and_then(|value| serde_json::from_value::<ChallengePass>(value.clone()).ok())?;
    // Role lifecycle data is optional and host/lead supplied. Absent data
    // preserves legacy v1 emission; invalid supplied data is rejected.
    let role_decisions = match trace_value(source, payload, &["roleDecisions", "role_decisions"]) {
        None => None,
        Some(value) => Some(serde_json::from_value::<Vec<RoleDecision>>(value.clone()).ok()?),
    };
    let supplied_trace_version =
        match trace_value(source, payload, &["schema_version", "schemaVersion"]) {
            None => None,
            Some(Value::Number(version)) => Some(
                version
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())?,
            ),
            Some(_) => return None,
        };
    if let Some(version) = supplied_trace_version {
        if !matches!(version, 1 | 2)
            || (role_decisions.is_some() && version != 2)
            || (role_decisions.is_none() && version == 2)
        {
            return None;
        }
    }
    let trace = RouteOutcomeTrace {
        schema_version: if role_decisions.is_some() { 2 } else { 1 },
        trace_id,
        request_id,
        task_id,
        arcane_profile_digest: provenance
            .and_then(|value| value.arcane_profile_digest.clone())
            .or_else(|| {
                trace_string(
                    source,
                    payload,
                    &["arcaneProfileDigest", "arcane_profile_digest"],
                )
            }),
        legion_canon_digest: provenance
            .and_then(|value| value.legion_canon_digest.clone())
            .or_else(|| {
                trace_string(
                    source,
                    payload,
                    &["legionCanonDigest", "legion_canon_digest"],
                )
            }),
        skill_catalog_digest: provenance
            .and_then(|value| value.skill_catalog_digest.clone())
            .or_else(|| {
                trace_string(
                    source,
                    payload,
                    &["skillCatalogDigest", "skill_catalog_digest"],
                )
            }),
        guard_policy_digest: provenance
            .and_then(|value| value.guard_policy_digest.clone())
            .or_else(|| {
                trace_string(
                    source,
                    payload,
                    &["guardPolicyDigest", "guard_policy_digest"],
                )
            }),
        route: parse_route(trace_string(source, payload, &["route"]).as_deref())?,
        semantic_requirement: parse_semantic_requirement(
            trace_string(
                source,
                payload,
                &["semantic_requirement", "semanticRequirement"],
            )
            .as_deref(),
        )?,
        context,
        capabilities,
        authority_attached: trace_string(
            source,
            payload,
            &["authority_attached", "authorityAttached", "authority"],
        )
        .and_then(|value| parse_authority(Some(value.as_str()))),
        compute_posture: parse_compute_posture(
            trace_string(
                source,
                payload,
                &["compute_posture", "computePosture", "compute"],
            )
            .as_deref(),
        )?,
        // The terminal result belongs to the Guard decision, never to a
        // host-supplied field that could disagree with it.
        result: if response.allowed {
            OutcomeResult::Success
        } else {
            OutcomeResult::Blocked
        },
        latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
        cost,
        challenge,
        role_decisions,
    };
    trace.validate().ok().map(|_| trace)
}

fn trace_source<'a>(payload: &'a Map<String, Value>) -> &'a Map<String, Value> {
    ["routeOutcomeTrace", "route_outcome_trace", "trace"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object))
        .unwrap_or(payload)
}

fn trace_value<'a>(
    source: &'a Map<String, Value>,
    payload: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| source.get(*key).or_else(|| payload.get(*key)))
}

fn trace_string<'a>(
    source: &'a Map<String, Value>,
    payload: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    let value = trace_value(source, payload, keys).or_else(|| {
        source
            .get("provenance")
            .and_then(Value::as_object)
            .and_then(|provenance| trace_value(provenance, payload, keys))
    });
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn trace_context(
    source: &Map<String, Value>,
    payload: &Map<String, Value>,
) -> Option<ContextUsage> {
    let object = trace_value(source, payload, &["context"])?.as_object()?;
    let sources = object
        .get("sources")?
        .as_array()?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    let size_bytes = object
        .get("size_bytes")
        .or_else(|| object.get("sizeBytes"))
        .and_then(Value::as_u64)?;
    Some(ContextUsage {
        sources,
        size_bytes,
    })
}

fn trace_capabilities(
    source: &Map<String, Value>,
    payload: &Map<String, Value>,
) -> Option<CapabilityUsage> {
    let object = trace_value(source, payload, &["capabilities"])?.as_object()?;
    let values = |key: &str| {
        object
            .get(key)?
            .as_array()?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
            })
            .collect::<Option<Vec<_>>>()
    };
    Some(CapabilityUsage {
        considered: values("considered")?,
        selected: values("selected")?,
    })
}

fn trace_cost(source: &Map<String, Value>, payload: &Map<String, Value>) -> Option<CostUsage> {
    let object = trace_value(source, payload, &["cost"])?.as_object()?;
    Some(CostUsage {
        input_tokens: object
            .get("input_tokens")
            .or_else(|| object.get("inputTokens"))?
            .as_u64()?,
        output_tokens: object
            .get("output_tokens")
            .or_else(|| object.get("outputTokens"))?
            .as_u64()?,
        cost_usd_micros: object
            .get("cost_usd_micros")
            .or_else(|| object.get("costUsdMicros"))?
            .as_u64()?,
    })
}

fn parse_route(value: Option<&str>) -> Option<Route> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "direct" => Some(Route::Direct),
        "deliberate" => Some(Route::Deliberate),
        "grounded" => Some(Route::Grounded),
        _ => None,
    }
}

fn parse_semantic_requirement(value: Option<&str>) -> Option<SemanticRequirement> {
    match value?.trim().to_ascii_uppercase().as_str() {
        "FORBIDDEN" => Some(SemanticRequirement::FORBIDDEN),
        "CONDITIONAL" => Some(SemanticRequirement::CONDITIONAL),
        "REQUIRED" => Some(SemanticRequirement::REQUIRED),
        _ => None,
    }
}

fn parse_authority(value: Option<&str>) -> Option<AuthorityKind> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "sage" => Some(AuthorityKind::Sage),
        "alchemist" => Some(AuthorityKind::Alchemist),
        "oracle" => Some(AuthorityKind::Oracle),
        _ => None,
    }
}

fn parse_compute_posture(value: Option<&str>) -> Option<ComputePosture> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "no_model" | "no-model" => Some(ComputePosture::NoModel),
        "tiny" => Some(ComputePosture::Tiny),
        "strong" => Some(ComputePosture::Strong),
        _ => None,
    }
}

fn trace_path(payload: &Value) -> Option<PathBuf> {
    receipt_root(payload).map(|root| root.join(TRACE_FILE_NAME))
}

fn receipt_root(payload: &Value) -> Option<PathBuf> {
    let object = payload.as_object()?;
    let state_root = first_string(object, &["stateRoot", "state_root"])
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LEGION_STATE_ROOT").map(PathBuf::from));
    if let Some(root) = state_root {
        return Some(root.join("receipts"));
    }
    // No explicit state root: keep receipts in one per-user directory keyed by
    // repository identity (the payload cwd), never beneath whatever directory
    // this process happened to start in.
    let identity = first_string(object, &["cwd", "workspace"]).or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|dir| dir.to_string_lossy().into_owned())
    })?;
    legion_contracts::state_root::per_user_repository_receipts_root(&identity)
}

fn append_trace(path: &Path, trace: &RouteOutcomeTrace) -> Result<(), ()> {
    trace.validate().map_err(|_| ())?;
    let mut line = serde_json::to_vec(trace).map_err(|_| ())?;
    if (line.len() as u64).saturating_add(1) > MAX_TRACE_FILE_BYTES {
        return Err(());
    }
    line.push(b'\n');
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| ())?;
    }
    if fs::metadata(path)
        .ok()
        .map(|metadata| metadata.len().saturating_add(line.len() as u64) > MAX_TRACE_FILE_BYTES)
        .unwrap_or(false)
    {
        let rotated = PathBuf::from(format!("{}.1", path.display()));
        fs::rename(path, rotated).map_err(|_| ())?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(&line).map_err(|_| ())
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn response_value(response: &HookResponse) -> Value {
    let mut value = response.to_value();
    if response.allowed && response.event_type == "SessionStart" {
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "hookSpecificOutput".into(),
                serde_json::json!({
                    "hookEventName": "SessionStart",
                    "additionalContext": SESSION_START_CONTEXT,
                }),
            );
            object.insert(
                "systemMessage".into(),
                Value::String(SESSION_START_SYSTEM_MESSAGE.into()),
            );
        }
    }
    value
}

fn write_response(value: Value) -> Result<(), HookError> {
    let bytes =
        serde_json::to_vec(&value).map_err(|error| HookError::Serialization(error.to_string()))?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout
        .write_all(&bytes)
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .flush()
        .map_err(|error| HookError::Io(error.to_string()))
}

const STOP_EVIDENCE_REMINDER: &str =
    "Legion: changes were made but the final message cites no evidence.";
const SESSION_EDIT_DIRECTORY: &str = "session-edits";
const EDIT_TOOLS: [&str; 5] = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];

fn session_marker(payload: &Value, suffix: &str) -> Option<PathBuf> {
    let object = payload.as_object()?;
    let session_id = first_string(object, &["session_id", "sessionId", "conversation_id"])?;
    let digest = legion_contracts::canonical_digest(&session_id).ok()?;
    Some(
        receipt_root(payload)?
            .join(SESSION_EDIT_DIRECTORY)
            .join(format!("{}.{suffix}", digest.trim_start_matches("sha256:"))),
    )
}

/// Remember that this session changed files, so Stop can ask for evidence.
/// Observation only: failure to record never changes a decision.
fn observe_session_edit(request: &HookRequest) {
    if !request.is_post_effect() {
        return;
    }
    let Some(object) = request.payload.as_object() else {
        return;
    };
    let Some(tool) = first_string(object, &["tool_name", "toolName"]) else {
        return;
    };
    if !EDIT_TOOLS.contains(&tool.as_str()) {
        return;
    }
    let Some(path) = session_marker(&request.payload, "edited") else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, b"1\n");
}

fn transcript_shows_edits(object: &Map<String, Value>) -> bool {
    let Some(path) = first_string(object, &["transcript_path", "transcriptPath"]) else {
        return false;
    };
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    if length > MAX_TRANSCRIPT_BYTES
        && io::Seek::seek(
            &mut file,
            io::SeekFrom::Start(length - MAX_TRANSCRIPT_BYTES),
        )
        .is_err()
    {
        return false;
    }
    let mut bytes = Vec::new();
    if Read::take(file, MAX_TRANSCRIPT_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    text.lines().any(|line| {
        line.contains("\"type\":\"tool_use\"")
            && EDIT_TOOLS
                .iter()
                .any(|tool| line.contains(&format!("\"name\":\"{tool}\"")))
    })
}

/// Does the final message point at something a reader can check: a fenced
/// command output, a test result line, `file:line`, a URL, or an explicit
/// statement that nothing was verified?
fn message_cites_evidence(message: &str) -> bool {
    let lowered = message.to_lowercase();
    if [
        "```",
        "not verified",
        "http://",
        "https://",
        "test result",
        " passed",
        " tests pass",
        "exit code",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return true;
    }
    message.split_whitespace().any(|raw| {
        let token = raw.trim_matches(|character: char| {
            matches!(
                character,
                '`' | '(' | ')' | ',' | '.' | ';' | '"' | '\'' | '[' | ']'
            )
        });
        let pieces: Vec<&str> = token.split(':').collect();
        pieces.windows(2).any(|pair| {
            !pair[1].is_empty()
                && pair[1].chars().all(|character| character.is_ascii_digit())
                && (pair[0].contains('.') || pair[0].contains('/'))
        })
    })
}

/// Non-blocking, once per session: files changed but the final message cites
/// no evidence. Stop is never blocked by this.
fn stop_evidence_reminder(request: &HookRequest, response: &HookResponse) -> Option<String> {
    if !response.allowed || !matches!(request.event_type.as_str(), "Stop" | "stop") {
        return None;
    }
    let object = request.payload.as_object()?;
    let message = first_string(object, &["last_assistant_message", "lastAssistantText"])?;
    if message.trim().is_empty() || message_cites_evidence(&message) {
        return None;
    }
    let edited = session_marker(&request.payload, "edited").map_or(false, |path| path.is_file())
        || transcript_shows_edits(object);
    if !edited {
        return None;
    }
    let reminded = session_marker(&request.payload, "reminded")?;
    if let Some(parent) = reminded.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&reminded)
        .ok()?;
    Some(STOP_EVIDENCE_REMINDER.into())
}

fn error_response(error: HookError) -> HookResponse {
    response_for_error("unknown".into(), error)
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let codex_host = arguments == ["--host", "codex"];
    if !arguments.is_empty() && !codex_host {
        eprintln!("usage: legion-hook [--host codex]");
        std::process::exit(2);
    }
    let mut parsed_request = None;
    let response = match read_request() {
        Ok(input) => match HookRequest::parse(&input) {
            Ok(request) => {
                parsed_request = Some(request.clone());
                dispatch(request)
            }
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    };
    if codex_host {
        std::process::exit(codex::emit_response(&response, parsed_request.as_ref()));
    }
    let mut value = response_value(&response);
    if let Some(request) = parsed_request.as_ref() {
        if response.allowed {
            observe_session_edit(request);
        }
        if let (Some(notice), Some(object)) = (
            stop_evidence_reminder(request, &response),
            value.as_object_mut(),
        ) {
            object.insert("systemMessage".into(), Value::String(notice));
        }
    }
    let _ = write_response(value);
}

#[cfg(test)]
mod tests {
    use legion_contracts::state_root::user_state_receipts_root;
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn current_rfc3339() -> String {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let total = elapsed.as_secs() as i64;
        let days = total.div_euclid(86_400);
        let seconds = total.rem_euclid(86_400);
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = month_prime + if month_prime < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        let hour = seconds / 3_600;
        let minute = seconds % 3_600 / 60;
        let second = seconds % 60;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    fn sample_trace() -> RouteOutcomeTrace {
        RouteOutcomeTrace {
            schema_version: 1,
            trace_id: TraceId::new("trace-test").expect("valid trace id"),
            request_id: RequestId::new("request-test").expect("valid request id"),
            task_id: Some(TaskId::new("task-test").expect("valid task id")),
            arcane_profile_digest: None,
            legion_canon_digest: None,
            skill_catalog_digest: None,
            guard_policy_digest: None,
            route: Route::Direct,
            semantic_requirement: SemanticRequirement::CONDITIONAL,
            context: ContextUsage {
                sources: Vec::new(),
                size_bytes: 0,
            },
            capabilities: CapabilityUsage {
                considered: Vec::new(),
                selected: Vec::new(),
            },
            authority_attached: None,
            compute_posture: ComputePosture::NoModel,
            result: OutcomeResult::Success,
            latency_ms: 1,
            cost: CostUsage {
                input_tokens: 0,
                output_tokens: 0,
                cost_usd_micros: 0,
            },
            challenge: ChallengePass {
                invoked: false,
                level: legion_contracts::ChallengeLevel::L0,
                trigger: None,
                outcome: None,
                assumption_dependent_conclusion: false,
                evidence_available_at_first_answer: false,
                user_challenge_event: false,
            },
            role_decisions: None,
        }
    }

    fn complete_trace_payload(trace_path: &str) -> Value {
        json!({
            "requestId": "request-test",
            "stateRoot": trace_path,
            "route": "direct",
            "semanticRequirement": "CONDITIONAL",
            "context": {"sources": [], "size_bytes": 0},
            "capabilities": {"considered": [], "selected": []},
            "computePosture": "no_model",
            "cost": {"input_tokens": 0, "output_tokens": 0, "cost_usd_micros": 0},
            "challenge": {
                "invoked": false,
                "level": "L0",
                "trigger": null,
                "outcome": null,
                "assumption_dependent_conclusion": false,
                "evidence_available_at_first_answer": false,
                "user_challenge_event": false
            }
        })
    }

    fn effect(effect_class: EffectClass) -> EffectRequest {
        EffectRequest {
            schema_version: 1,
            request_id: RequestId::new("test-request").expect("valid test request id"),
            task_id: TaskId::new("test-task").expect("valid test task id"),
            requested_by: AgentId::new("test-agent").expect("valid test agent id"),
            effect_class,
            target: "test-target".into(),
            operation: default_operation(effect_class).into(),
            preview: None,
            source_revision: "test-revision".into(),
            approval_required: false,
        }
    }

    fn pre_effect(command: &str) -> HookRequest {
        HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
        }
    }

    fn stop(payload: Value) -> HookRequest {
        HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "Stop".into(),
            payload,
        }
    }

    fn temporary_repository() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "legion-hook-source-revision-{}-{nonce}-{}",
            std::process::id(),
            {
                static NEXT: ::std::sync::atomic::AtomicU64 =
                    ::std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
            }
        ));
        fs::create_dir_all(root.join(".git/refs/heads")).expect("create test git directory");
        root
    }

    #[test]
    fn trace_round_trips_through_schema_type() {
        let trace = sample_trace();
        trace.validate().expect("sample trace is valid");
        let json = serde_json::to_string(&trace).expect("trace serializes");
        let parsed: RouteOutcomeTrace = serde_json::from_str(&json).expect("trace parses");
        assert_eq!(parsed, trace);
    }

    #[test]
    fn unobservable_provenance_is_absent_not_defaulted() {
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: complete_trace_payload("unused-trace-path"),
        };
        let response = HookResponse::allowed("SessionStart", "test");
        let trace = route_trace_from_request(&request, &response, Duration::from_millis(2), None)
            .expect("complete host route envelope emits");
        assert_eq!(trace.arcane_profile_digest, None);
        assert_eq!(trace.legion_canon_digest, None);
        assert_eq!(trace.skill_catalog_digest, None);
        assert_eq!(trace.guard_policy_digest, None);
    }

    #[test]
    fn host_acknowledgements_do_not_emit_terminal_success() {
        for event_type in [
            "PostToolUse",
            "PostToolUseFailure",
            "SubagentStart",
            "SubagentStop",
            "UserPromptSubmit",
            "PostCompact",
        ] {
            let request = HookRequest {
                schema_version: protocol::SCHEMA_VERSION,
                kind: protocol::REQUEST_KIND.into(),
                event_type: event_type.into(),
                payload: complete_trace_payload("unused-trace-path"),
            };
            let response = HookResponse::allowed(event_type, "observation accepted");
            assert!(
                route_trace_from_request(&request, &response, Duration::from_millis(2), None)
                    .is_none(),
                "{event_type} acknowledgement must not become terminal success"
            );
        }
    }

    #[test]
    fn explicit_pre_effect_refusal_remains_blocked_trace() {
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: complete_trace_payload("unused-trace-path"),
        };
        let response = HookResponse::denied("PreToolUse", "ARC_POLICY_DENIED", "blocked", "strong");
        let trace = route_trace_from_request(&request, &response, Duration::from_millis(2), None)
            .expect("explicit Guard refusal remains observable");
        assert_eq!(trace.result, OutcomeResult::Blocked);
    }

    #[test]
    fn meaningful_route_event_emits_one_json_line() {
        let path =
            std::env::temp_dir().join(format!("legion-hook-route-trace-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: complete_trace_payload(&path.to_string_lossy()),
        };
        let response = dispatch(request);
        assert!(response.allowed);
        let trace_file = path.join("receipts").join(TRACE_FILE_NAME);
        let lines = fs::read_to_string(&trace_file).expect("trace line is persisted");
        let trace: RouteOutcomeTrace =
            serde_json::from_str(lines.trim()).expect("valid trace JSON");
        assert_eq!(trace.result, OutcomeResult::Success);
        fs::remove_dir_all(path).expect("remove test trace");
    }

    #[test]
    fn session_provenance_is_pinned_and_automatically_enriches_traces() {
        let root = temporary_repository();
        fs::write(root.join("AGENTS.md"), "routing epoch one").expect("write canon source");
        fs::create_dir_all(root.join("src/registry/skills")).expect("create catalog directory");
        fs::write(
            root.join("src/registry/skills/index.json"),
            br#"{"bundles":[]}"#,
        )
        .expect("write catalog source");
        let state_root = root.join("state");
        let mut payload = complete_trace_payload(&state_root.to_string_lossy());
        let object = payload.as_object_mut().expect("trace payload object");
        object.insert("session_id".into(), Value::String("session-pinned".into()));
        object.insert(
            "cwd".into(),
            Value::String(root.to_string_lossy().into_owned()),
        );
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: payload.clone(),
        };

        let first = pinned_session_provenance(&request).expect("session epoch is pinned");
        assert!(first
            .arcane_profile_digest
            .as_deref()
            .is_some_and(is_sha256_digest));
        assert!(first
            .legion_canon_digest
            .as_deref()
            .is_some_and(is_sha256_digest));
        assert!(first
            .skill_catalog_digest
            .as_deref()
            .is_some_and(is_sha256_digest));
        assert!(first
            .guard_policy_digest
            .as_deref()
            .is_some_and(is_sha256_digest));

        fs::write(root.join("AGENTS.md"), "routing epoch two").expect("mutate canon source");
        fs::write(
            root.join("src/registry/skills/index.json"),
            br#"{"bundles":[1]}"#,
        )
        .expect("mutate catalog source");
        let current = automatic_session_provenance(payload.as_object().expect("payload object"));
        assert_ne!(current.legion_canon_digest, first.legion_canon_digest);
        assert_ne!(current.skill_catalog_digest, first.skill_catalog_digest);
        assert_eq!(pinned_session_provenance(&request), Some(first.clone()));

        let response = dispatch(request);
        assert!(response.allowed);
        let trace_file = state_root.join("receipts").join(TRACE_FILE_NAME);
        let trace: RouteOutcomeTrace = serde_json::from_str(
            fs::read_to_string(trace_file)
                .expect("trace emitted")
                .trim(),
        )
        .expect("trace parses");
        assert_eq!(trace.arcane_profile_digest, first.arcane_profile_digest);
        assert_eq!(trace.legion_canon_digest, first.legion_canon_digest);
        assert_eq!(trace.skill_catalog_digest, first.skill_catalog_digest);
        assert_eq!(trace.guard_policy_digest, first.guard_policy_digest);
        fs::remove_dir_all(root).expect("remove test repository");
    }

    #[test]
    fn failed_trace_write_does_not_change_decision() {
        let path = std::env::temp_dir().join(format!(
            "legion-hook-trace-write-failure-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create directory used as invalid trace file");
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: complete_trace_payload(&path.to_string_lossy()),
        };
        let expected = dispatch_inner(request.clone());
        let actual = dispatch(request);
        assert_eq!(actual, expected, "telemetry must not alter the decision");
        fs::remove_dir_all(path).expect("remove test directory");
    }

    #[test]
    fn zero_denominators_are_typed_as_no_data() {
        let metrics = fold_trace_metrics(&[]);
        assert_eq!(metrics.sage_dispatch_rate, MetricValue::NotEnoughData);
        assert_eq!(metrics.oracle_block_rate, MetricValue::NotEnoughData);
        assert_eq!(
            metrics.oracle_block_to_real_fix_rate,
            MetricValue::NotEnoughData
        );
        assert_eq!(metrics.challenge_yield, MetricValue::NotEnoughData);
        assert_eq!(
            metrics.avoidable_user_challenge_rate,
            MetricValue::NotEnoughData
        );
        assert_eq!(metrics.role_adoption_rate, MetricValue::NotEnoughData);
    }

    #[test]
    fn role_decision_data_emits_v2_and_rejects_invalid_extension_or_version() {
        let mut payload = complete_trace_payload("unused-trace-path");
        payload["roleDecisions"] = json!([{
            "role": "sage",
            "eligible": true,
            "state": "launched",
            "reason": "host launched sage"
        }]);
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload,
        };
        let response = dispatch_inner(request.clone());
        let trace = route_trace_from_request(&request, &response, Duration::from_millis(1), None)
            .expect("valid role data emits trace");
        assert_eq!(trace.schema_version, 2);
        assert!(trace.role_decisions.is_some());

        let mut invalid = complete_trace_payload("unused-trace-path");
        invalid["roleDecisions"] = json!([{
            "role": "sage",
            "eligible": null,
            "state": "skipped"
        }]);
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: invalid,
        };
        let response = dispatch_inner(request.clone());
        assert!(
            route_trace_from_request(&request, &response, Duration::from_millis(1), None).is_none(),
            "invalid supplied extension must not downgrade to v1"
        );

        for supplied_version in [
            json!(9),
            json!("2"),
            Value::Null,
            json!(-1),
            json!(4_294_967_297_u64),
        ] {
            let mut unknown = complete_trace_payload("unused-trace-path");
            unknown["schemaVersion"] = supplied_version;
            let request = HookRequest {
                schema_version: protocol::SCHEMA_VERSION,
                kind: protocol::REQUEST_KIND.into(),
                event_type: "SessionStart".into(),
                payload: unknown,
            };
            let response = dispatch_inner(request.clone());
            assert!(
                route_trace_from_request(&request, &response, Duration::from_millis(1), None)
                    .is_none(),
                "malformed or unknown trace version must be rejected"
            );
        }
    }

    #[test]
    fn source_revision_reads_git_metadata_without_spawning() {
        let root = temporary_repository();
        let revision = "0123456789abcdef0123456789abcdef01234567";
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write HEAD");
        fs::write(root.join(".git/refs/heads/main"), format!("{revision}\n"))
            .expect("write loose ref");
        let payload = json!({"cwd": root.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision)
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn source_revision_resolves_from_a_subdirectory() {
        let root = temporary_repository();
        let revision = "abcdef0123456789abcdef0123456789abcdef01";
        fs::write(
            root.join(".git/HEAD"),
            "ref: refs/heads/main
",
        )
        .expect("write HEAD");
        fs::write(
            root.join(".git/refs/heads/main"),
            format!(
                "{revision}
"
            ),
        )
        .expect("write loose ref");
        let nested = root.join("engine/bins/legion-hook");
        fs::create_dir_all(&nested).expect("create nested directory");
        let payload = json!({"cwd": nested.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision),
            "a tool call from a subdirectory must still resolve the checkout revision"
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn source_revision_identifies_a_scratch_workspace_without_borrowing_hook_cwd() {
        let scratch = std::env::temp_dir().join(format!(
            "legion-hook-scratch-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos(),
            {
                static NEXT: ::std::sync::atomic::AtomicU64 =
                    ::std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
            }
        ));
        fs::create_dir_all(&scratch).expect("create scratch workspace");
        let payload = json!({"cwd": scratch.to_string_lossy()});
        let revision = resolve_source_revision(payload.as_object().expect("payload object"))
            .expect("scratch workspace has a source identity");
        assert!(revision.starts_with("unversioned-workspace:sha256:"));
        assert_eq!(
            source_revision_for_workspace(&scratch).as_deref(),
            Some(revision.as_str())
        );
        fs::remove_dir_all(&scratch).expect("remove scratch workspace");
    }

    #[test]
    fn multi_edit_classifies_as_file_write() {
        assert_eq!(
            parse_effect_class(None, Some("MultiEdit"), None),
            Some(EffectClass::FILE_WRITE),
            "MultiEdit is matched in hooks.json and must classify, not fail closed"
        );
    }

    #[test]
    fn mcp_write_send_delete_tools_classify_as_denied_external_effects() {
        for tool in [
            "mcp__files__write",
            "mcp__mail__send_message",
            "mcp__records__delete_item",
        ] {
            assert_eq!(
                parse_effect_class(None, Some(tool), None),
                Some(EffectClass::EXTERNAL_SIDE_EFFECT),
                "covered MCP side effect must have a classifier arm: {tool}"
            );
        }
        assert_eq!(
            parse_effect_class(None, Some("mcp__planner__Task"), None),
            None,
            "MCP orchestration is not an external effect"
        );
    }

    #[test]
    fn explicit_mcp_operation_classifies_a_generic_mcp_tool() {
        assert_eq!(
            mcp_external_side_effect(Some("mcp__service__call"), Some("send")),
            Some(EffectClass::EXTERNAL_SIDE_EFFECT)
        );
        assert_eq!(
            mcp_external_side_effect(Some("mcp__service__call"), Some("read")),
            None
        );
    }

    #[test]
    fn unrecognized_mcp_tools_are_allowed_with_truthful_receipts() {
        // A third-party MCP tool whose name matches no positive
        // classification arm must never be silently skipped (no policy
        // object built, no receipt) and must never be relabeled as an
        // EXTERNAL_SIDE_EFFECT (that class means a *positively identified*
        // write/send/delete, and reusing it here would make the receipt lie
        // about what was actually observed). It is instead classified
        // MCP_UNCLASSIFIED_OBSERVATION, which still reaches
        // `CanonicalEffectPolicy::authorize` for an ambient, receipted decision.
        let unclassified = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({
                "tool_name": "mcp__docs__query",
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567"
            }),
        };
        let effect = effect_request(&unclassified)
            .expect("unrecognized MCP tool classification should succeed")
            .expect("unrecognized MCP tool must carry an effect to adjudicate, not be skipped");
        assert_eq!(
            effect.effect_class,
            EffectClass::MCP_UNCLASSIFIED_OBSERVATION
        );
        let response = dispatch(unclassified);
        assert!(
            response.allowed,
            "an unclassified MCP tool must follow host permissions"
        );
        assert!(
            response.reason.contains("mcp__docs__query"),
            "allow reason should name the unclassified tool: {}",
            response.reason
        );
        assert!(
            response.reason.contains("could not be classified"),
            "allow reason should state plainly that classification failed: {}",
            response.reason
        );

        let send = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({
                "tool_name": "mcp__mail__send_message",
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567"
            }),
        };
        let send_effect = effect_request(&send)
            .expect("MCP send classification should succeed")
            .expect("MCP send should carry an external effect");
        assert_eq!(send_effect.effect_class, EffectClass::EXTERNAL_SIDE_EFFECT);
        let application = NativeApplicationConfig::default_for_repository("test-repository")
            .expect("canonical default native application builds");
        let response = authorize_effect("PreToolUse".into(), &send_effect, &application);
        assert!(!response.allowed, "MCP sends must remain policy denied");
        assert_eq!(response.code.as_deref(), Some("ARC_POLICY_DENIED"));

        let non_mcp = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({"tool_name": "UnknownTool"}),
        };
        let response = dispatch(non_mcp);
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_HOST_EVENT_INVALID"));

        let explicit_unknown = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PreToolUse".into(),
            payload: json!({
                "tool_name": "mcp__docs__query",
                "effectClass": "unsupported-class"
            }),
        };
        let response = dispatch(explicit_unknown);
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_HOST_EVENT_INVALID"));
    }

    #[test]
    fn first_party_host_session_tools_are_host_dispatch_not_unclassified_mcp() {
        for tool in [
            "mcp__ccd_session__spawn_task",
            "mcp__ccd_session_mgmt__send_message",
            "mcp__ccd_session_mgmt__list_sessions",
            "mcp__ccd_session_mgmt__set_session_title",
            "mcp__Claude_Browser__navigate",
            "mcp__Claude_Browser__get_page_text",
            "mcp__Claude_Browser__javascript_tool",
            "mcp__Claude_Browser__browser_batch",
        ] {
            assert!(
                is_first_party_host_tool(tool),
                "{tool} must be recognised as host"
            );
            let request = HookRequest {
                schema_version: protocol::SCHEMA_VERSION,
                kind: protocol::REQUEST_KIND.into(),
                event_type: "PreToolUse".into(),
                payload: json!({"tool_name": tool, "tool_input": {"title": "x"}}),
            };
            let effect = effect_request(&request)
                .expect("host session tool classification should succeed")
                .expect("host session tool yields an effect");
            assert_eq!(effect.effect_class, EffectClass::COMMAND_EXEC, "{tool}");
            let response = dispatch(request);
            assert!(
                response.allowed,
                "{tool} must not fail closed: {}",
                response.reason
            );
        }
        assert!(!is_first_party_host_tool("mcp__ccdfake__spawn_task"));
        assert!(!is_first_party_host_tool(
            "mcp__Claude_Browser_fake__navigate"
        ));
        assert!(!is_first_party_host_tool("mcp__docs__query"));
    }

    #[test]
    fn source_revision_reads_packed_refs_without_spawning() {
        let root = temporary_repository();
        let revision = "89abcdef0123456789abcdef0123456789abcdef";
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write HEAD");
        fs::write(
            root.join(".git/packed-refs"),
            format!("# pack-refs with: peeled\n{revision} refs/heads/main\n"),
        )
        .expect("write packed refs");
        let payload = json!({"workspace": root.to_string_lossy()});
        assert_eq!(
            resolve_source_revision(payload.as_object().expect("payload object")).as_deref(),
            Some(revision)
        );
        fs::remove_dir_all(&root).expect("remove test repository");
    }

    #[test]
    fn canonical_default_policy_allows_ordinary_effect_classes() {
        let application =
            legion_application::NativeApplicationConfig::default_for_repository("test-repository")
                .expect("canonical default native application builds");
        for effect_class in [
            EffectClass::FILE_WRITE,
            EffectClass::FILE_MOVE,
            EffectClass::VCS_COMMIT,
            EffectClass::COMMAND_EXEC,
            EffectClass::FILE_DELETE,
        ] {
            let response =
                authorize_effect("PreToolUse".into(), &effect(effect_class), &application);
            assert!(response.allowed, "ordinary effect denied: {effect_class:?}");
            assert!(response.code.is_none());
            assert_eq!(response.enforcement_health, "strong");
        }
    }

    #[test]
    fn canonical_default_policy_denies_reserved_effect_classes() {
        let application =
            legion_application::NativeApplicationConfig::default_for_repository("test-repository")
                .expect("canonical default native application builds");
        for effect_class in [
            EffectClass::CREDENTIAL_ACCESS,
            EffectClass::EXTERNAL_SIDE_EFFECT,
        ] {
            let response =
                authorize_effect("PreToolUse".into(), &effect(effect_class), &application);
            assert!(
                !response.allowed,
                "reserved effect allowed: {effect_class:?}"
            );
            assert_eq!(response.code.as_deref(), Some("ARC_POLICY_DENIED"));
            assert_eq!(response.enforcement_health, "strong");
        }
    }

    /// These destroy nothing. Denying them stopped ordinary work in every
    /// repository here and offered no way to proceed.
    /// A named read-only MCP tool is ordinary work; an unnamed one is still
    /// unknown and still fails closed.
    #[test]
    fn a_known_read_only_mcp_tool_is_allowed_and_an_unknown_one_is_not() {
        assert!(is_known_read_only_tool("mcp__membrane__membrane_context"));
        for tool in [
            "mcp__scheduled-tasks__list_tasks",
            "mcp__scheduled-tasks__list_task_runs",
            "mcp__scheduled-tasks__get_task",
            "mcp__scheduled-tasks__get_task_run",
        ] {
            assert!(is_known_read_only_tool(tool), "{tool}");
            let request = HookRequest {
                schema_version: protocol::SCHEMA_VERSION,
                kind: protocol::REQUEST_KIND.into(),
                event_type: "PreToolUse".into(),
                payload: json!({"tool_name": tool}),
            };
            let effect = effect_request(&request).unwrap().unwrap();
            assert_eq!(effect.effect_class, EffectClass::MCP_KNOWN_OBSERVATION);
            assert!(dispatch(request).allowed, "{tool}");
        }
        assert!(!is_known_read_only_tool(
            "mcp__scheduled-tasks__delete_task"
        ));
        assert!(!is_known_read_only_tool("mcp__membrane__membrane_write"));
        assert!(
            !is_known_read_only_tool("mcp__legion__legion_m1_invoke"),
            "invoke runs work; it is not an observation"
        );

        let application =
            legion_application::NativeApplicationConfig::default_for_repository("test-repository")
                .expect("canonical default native application builds");
        let known = authorize_effect(
            "PreToolUse".into(),
            &effect(EffectClass::MCP_KNOWN_OBSERVATION),
            &application,
        );
        assert!(known.allowed, "a recognised read-only tool must be allowed");
        let unknown = authorize_effect(
            "PreToolUse".into(),
            &effect(EffectClass::MCP_UNCLASSIFIED_OBSERVATION),
            &application,
        );
        assert!(
            unknown.allowed,
            "an unknown MCP tool must follow host permissions"
        );
    }

    #[test]
    fn canonical_default_policy_allows_reversible_effect_classes() {
        let application =
            legion_application::NativeApplicationConfig::default_for_repository("test-repository")
                .expect("canonical default native application builds");
        for effect_class in [
            EffectClass::VCS_PUSH,
            EffectClass::PUBLISH,
            EffectClass::DEPENDENCY_INSTALL,
            EffectClass::NETWORK_EGRESS,
            EffectClass::PROCESS_SPAWN,
        ] {
            let response =
                authorize_effect("PreToolUse".into(), &effect(effect_class), &application);
            assert!(
                response.allowed,
                "reversible effect denied: {effect_class:?}"
            );
        }
    }

    /// An unrelated flag elsewhere on the line must not condemn the push.
    /// `git commit -q -F -` lowercased to `-f` and was read as a force-push,
    /// which refused a legitimate push of already-committed work.
    #[test]
    fn a_flag_belonging_to_another_command_is_not_a_rewrite() {
        for command in [
            "git commit -q -F - && git push origin main",
            "git push origin main 2>&1 | tail -2",
            "git diff --stat && git push origin main",
            "git push --dry-run origin main",
        ] {
            let response = dispatch(pre_effect(command));
            assert!(
                response.allowed,
                "an ordinary push was refused as a rewrite: {command}"
            );
        }
    }

    /// A rewrite destroys published history, and a prompt an operator
    /// approves without reading is not a gate. It stays refused; someone who
    /// means it can rewrite by hand.
    #[test]
    fn a_rewrite_push_stays_refused() {
        for command in [
            "git push --force origin main",
            "git  push --delete origin main",
            "git push -f origin main",
            "git push origin +main",
            "git push origin :stale-branch",
        ] {
            let response = dispatch(pre_effect(command));
            assert!(!response.allowed, "a rewrite must stay refused: {command}");
            let value = response.to_value();
            assert_eq!(
                value["hookSpecificOutput"]["permissionDecision"],
                serde_json::json!("deny"),
                "a rewrite must block, not prompt: {command}"
            );
        }
    }

    #[test]
    fn policy_is_never_absent_when_env_config_is_unset() {
        std::env::remove_var("LEGION_NATIVE_APPLICATION_CONFIG");
        let application = native_application().expect("default application composes");
        // The point is that a policy is present at all, so this has to name a
        // class the default pack denies. It used to use PUBLISH, which the
        // pack now allows -- publishing destroys nothing -- and the test would
        // then have passed only while the pack was wrong.
        let response = authorize_effect(
            "PreToolUse".into(),
            &effect(EffectClass::CREDENTIAL_ACCESS),
            &application,
        );
        assert!(
            !response.allowed,
            "policy must never fall through to ambient allow"
        );
    }

    #[test]
    fn unavailable_policy_never_claims_strong_enforcement() {
        let response = policy_unavailable_response("PreToolUse".into());
        assert!(!response.allowed);
        assert_eq!(
            response.code.as_deref(),
            Some("ARC_NATIVE_POLICY_UNAVAILABLE")
        );
        assert_eq!(response.enforcement_health, "unsupported");
    }

    #[test]
    fn hard_gates_precede_ambient_fallback() {
        for (command, code) in [
            (
                "rm -rf /tmp/legion-hook-test",
                "ARC_EFFECT_CLASS_UNAUTHORIZED",
            ),
            (
                "echo ok; rm -fr /tmp/legion-hook-test",
                "ARC_EFFECT_CLASS_UNAUTHORIZED",
            ),
            ("git push --force origin main", "ARC_APPROVAL_REQUIRED"),
            ("git  push --delete origin main", "ARC_APPROVAL_REQUIRED"),
        ] {
            let response = dispatch(pre_effect(command));
            assert!(!response.allowed, "hard gate allowed: {command}");
            assert_eq!(response.code.as_deref(), Some(code));
            assert_eq!(response.enforcement_health, "strong");
        }
    }

    #[test]
    fn session_start_response_embeds_policy_without_workspace_files() {
        let response = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: json!({}),
        });
        let value = response_value(&response);
        let context = value
            .get("hookSpecificOutput")
            .and_then(Value::as_object)
            .and_then(|output| output.get("additionalContext"))
            .and_then(Value::as_str)
            .expect("SessionStart includes embedded additionalContext");
        for rule in [
            "Complete the requested outcome within explicit constraints",
            "use a skill only when its operation and inputs fit the request",
            "choose the smallest complete repair and cheapest decisive checks",
            "contracts apply only to explicit or locked work",
            "report only states actually reached",
        ] {
            assert!(context.contains(rule), "missing session rule: {rule}");
        }
        assert!(!context.contains("Declare every new file"));
        assert!(!context.contains("BOUNDED FALSIFICATION"));
        assert_eq!(
            value.get("systemMessage").and_then(Value::as_str),
            Some("LEGION:ACTIVE")
        );
    }

    #[test]
    fn stop_prose_never_reopens_fresh_or_continued_turns() {
        for text in [
            "Changed the file. Shall I run the checks?",
            "I recommend this approach. Next step would be measuring it.",
            "The change is done. One caveat: the migration is not fixed.",
            "Build is running; verification remains to be done after completion.",
            "The build failed: cannot proceed without the missing SDK.",
        ] {
            for active in [false, true] {
                let response = dispatch(stop(json!({
                    "stop_hook_active": active,
                    "last_assistant_message": text,
                    "lastAssistantText": text,
                })));
                assert!(response.allowed, "prose must not reopen Stop: {text}");
                assert!(response.code.is_none());
            }
        }
    }

    #[test]
    fn stop_verification_is_explicit_and_proportional() {
        let ordinary = dispatch(stop(json!({
            "verificationRequirement": "none",
            "lastAssistantText": "The reversible edit is complete.",
        })));
        assert!(ordinary.allowed);

        let missing = dispatch(stop(json!({
            "verificationRequirement": {
                "kind": "oracle-completion-validation",
                "subjectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
            },
        })));
        assert!(!missing.allowed);
        assert_eq!(missing.code.as_deref(), Some("ARC_VERIFICATION_REQUIRED"));
    }

    #[test]
    fn stop_reentry_cap_precedes_optional_verification_repair() {
        let response = dispatch(stop(json!({
            "stopOrdinal": 3,
            "verificationRequirement": {
                "kind": "oracle-completion-validation",
                "subjectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
            },
        })));
        assert!(
            response.allowed,
            "re-entry cap must end optional verification repair loops"
        );
        assert_eq!(response.reason, "stop re-entry cap reached");
    }

    #[test]
    fn stop_accepts_a_bound_oracle_pass_receipt() {
        let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let validated_at = current_rfc3339();
        let response = dispatch(stop(json!({
            "verificationRequirement": {
                "kind": "oracle-completion-validation",
                "subjectDigest": digest,
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
            },
            "oracleReceipt": {
                "schemaVersion": 1,
                "kind": "legion-oracle-completion-validation",
                "validationId": "ocv_0123456789ABCDEFGHJKMNPQRS",
                "runId": "run_0123456789ABCDEFGHJKMNPQRS",
                "verdict": "PASS",
                "scope": {
                    "rawUserTurns": ["make the requested change"],
                    "reconstructedScope": "the requested change",
                },
                "subject": {"description": "the delivered change", "digest": digest},
                "sourcesInspected": ["engine/bins/legion-hook/src/main.rs"],
                "findings": [],
                "repairRecheck": {"repairCount": 0, "recheckCount": 0},
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
                "validatedAt": validated_at,
            },
            "lastAssistantText": "The requested change is complete and verified.",
        })));
        assert!(
            response.allowed,
            "a current bound Oracle PASS should permit Stop"
        );
    }

    #[test]
    fn subagent_lifecycle_is_recorded_and_counted_by_child_id() {
        let root = std::env::temp_dir().join(format!(
            "legion-hook-child-lifecycle-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        let send = |event: &str, child: &str| {
            dispatch(HookRequest {
                schema_version: protocol::SCHEMA_VERSION,
                kind: protocol::REQUEST_KIND.into(),
                event_type: event.into(),
                payload: json!({
                    "agent_id": child,
                    "agent_type": "alchemist",
                    "stateRoot": root.to_string_lossy(),
                }),
            })
        };
        assert!(send("SubagentStart", "child-1").allowed);
        assert!(send("SubagentStart", "child-2").allowed);
        assert!(send("SubagentStop", "child-1").allowed);
        let file = root.join("receipts").join(CHILD_TRACE_FILE_NAME);
        let records: Vec<Value> = fs::read_to_string(&file)
            .expect("child lifecycle trace persisted")
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid record"))
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["event"], "SubagentStart");
        assert_eq!(records[0]["childId"], "child-1");
        assert_eq!(records[2]["event"], "SubagentStop");
        let counters = fold_child_launch_counters(&records, &[]);
        assert_eq!(counters.attempted_launch, 2);
        assert_eq!(counters.accepted_launch, 2);
        assert_eq!(counters.completed, 1);
        assert_eq!(counters.rejected, 0);
        // The route-outcome trace file is untouched by child lifecycle frames.
        assert!(!root.join("receipts").join(TRACE_FILE_NAME).exists());
        fs::remove_dir_all(root).expect("remove test state");
    }

    #[test]
    fn child_counters_separate_rejected_stop_without_start_and_skips() {
        let records = vec![
            json!({"event":"SubagentStart","childId":"a","accepted":true}),
            json!({"event":"SubagentStart","childId":"a","accepted":true}),
            json!({"event":"SubagentStart","childId":"b","accepted":false}),
            json!({"event":"SubagentStop","childId":"b"}),
            json!({"event":"SubagentStop","childId":"a"}),
            json!({"event":"SubagentStop","childId":"never-started"}),
            json!({"event":"garbage"}),
        ];
        let counters = fold_child_launch_counters(&records, &[]);
        assert_eq!(
            counters,
            ChildLaunchCounters {
                selected: 0,
                attempted_launch: 2,
                accepted_launch: 1,
                completed: 1,
                rejected: 1,
                explicitly_skipped: 0,
            }
        );
    }

    #[test]
    fn child_counters_take_selected_and_skipped_from_latest_role_decisions() {
        let mut payload = complete_trace_payload("unused");
        payload["roleDecisions"] = json!([
            {"role": "sage", "eligible": true, "state": "selected"},
            {"role": "oracle", "eligible": true, "state": "skipped", "reason": "small reversible"}
        ]);
        let request = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload,
        };
        let response = HookResponse::allowed("SessionStart", "ok");
        let trace = route_trace_from_request(&request, &response, Duration::from_millis(1), None)
            .expect("v2 trace with role decisions");
        let counters = fold_child_launch_counters(&[], &[trace]);
        assert_eq!(counters.selected, 1);
        assert_eq!(counters.explicitly_skipped, 1);
        assert_eq!(counters.attempted_launch, 0);
    }

    #[test]
    fn subagent_stop_is_observation_only() {
        let response = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SubagentStop".into(),
            payload: json!({"agent_id": "agent-1"}),
        });
        assert!(response.allowed);
        assert_eq!(response.code, None);
    }

    #[test]
    fn unknown_event_dispatch_fails_closed() {
        let response = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "unknown-event".into(),
            payload: json!({}),
        });
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_HOST_EVENT_INVALID"));
        assert_eq!(response.enforcement_health, "strong");
    }

    #[test]
    fn arc_005_bounded_falsification_is_single_pass() {
        let accepted = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: json!({"challengePass":{"passCount":1,"result":"NARROW"}}),
        });
        assert!(accepted.allowed);
        let recursive = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: json!({"challengePass":{"passCount":2,"result":"KEEP"}}),
        });
        assert_eq!(recursive.code.as_deref(), Some("ARC_CHALLENGE_INVALID"));
    }

    #[test]
    fn arc_006_route_uncertainty_escalates_once_without_workflow() {
        let accepted = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: json!({"routeUncertain":true,"priorEscalations":0}),
        });
        assert!(accepted.allowed);
        assert!(accepted.reason.contains("direct response"));
        let recursive = dispatch(HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "SessionStart".into(),
            payload: json!({"routeUncertain":true,"priorEscalations":1}),
        });
        assert_eq!(recursive.code.as_deref(), Some("ARC_ESCALATION_RECURSION"));
    }

    fn destructive(command: &str) -> bool {
        is_destructive_command(&json!({"tool_name":"Bash","tool_input":{"command":command}}))
    }

    #[test]
    fn dry_runs_and_help_are_not_destructive() {
        for command in [
            "git clean -n",
            "git clean -nd",
            "git clean --dry-run -fd",
            "git restore --staged .",
            "terraform apply -help",
            "terraform destroy --help",
        ] {
            assert!(!destructive(command), "wrongly denied: {command}");
        }
    }

    #[test]
    fn regenerable_relative_directories_may_be_removed() {
        for command in [
            "rm -rf node_modules",
            "rm -rf ./target",
            "rm -r dist build",
            "rm -rf packages/web/.next",
            "bash -c 'rm -rf .turbo'",
            "rm -rf __pycache__",
        ] {
            assert!(!destructive(command), "wrongly denied: {command}");
        }
    }

    #[test]
    fn real_data_loss_stays_destructive() {
        for command in [
            "rm -rf /",
            "rm -rf ~",
            "rm -rf $HOME",
            "rm -rf .",
            "rm -rf ./",
            "rm -rf ..",
            "rm -rf src",
            "rm -rf /abs/path/node_modules",
            "rm -rf ../node_modules",
            "rm -rf node_modules src",
            "rm -rf *",
            "rm -f -r src",
            "rm --recursive docs",
            "git reset --hard",
            "git restore .",
            "git restore --staged --worktree .",
            "git clean -fd",
            "git checkout -- .",
            "terraform apply",
            "terraform destroy",
        ] {
            assert!(destructive(command), "wrongly allowed: {command}");
        }
    }

    #[test]
    fn plain_rm_force_is_not_recursive() {
        assert!(!destructive("rm --force stale.lock"));
    }

    #[test]
    fn force_push_still_requires_approval() {
        assert!(rewrite_push_requires_approval(
            &json!({"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}})
        ));
    }

    #[test]
    fn fallback_receipts_live_in_one_per_user_directory() {
        let home = Some(PathBuf::from("/Users/a"));
        assert_eq!(
            user_state_receipts_root(true, false, home.clone(), None, None, None),
            Some(PathBuf::from(
                "/Users/a/Library/Application Support/Orthic Labs/Legion/state/receipts"
            ))
        );
        assert_eq!(
            user_state_receipts_root(
                false,
                true,
                None,
                Some(PathBuf::from("C:/Users/a")),
                Some(PathBuf::from("C:/Local")),
                None
            ),
            Some(PathBuf::from("C:/Local/Orthic Labs/Legion/state/receipts"))
        );
        assert_eq!(
            user_state_receipts_root(false, false, home.clone(), None, None, None),
            Some(PathBuf::from("/Users/a/.local/state/legion/receipts"))
        );
        assert_eq!(
            user_state_receipts_root(false, false, home, None, None, Some(PathBuf::from("/xdg"))),
            Some(PathBuf::from("/xdg/legion/receipts"))
        );
        assert_eq!(
            user_state_receipts_root(false, false, None, None, None, None),
            None
        );
    }

    #[test]
    fn explicit_state_root_precedes_the_user_fallback() {
        let root = receipt_root(&json!({"stateRoot": "/explicit", "cwd": "/repo"}));
        assert_eq!(root, Some(PathBuf::from("/explicit").join("receipts")));
    }

    #[test]
    fn fallback_receipts_are_keyed_by_payload_cwd_not_process_cwd() {
        if std::env::var_os("LEGION_STATE_ROOT").is_some() {
            return;
        }
        let first = receipt_root(&json!({"cwd": "/repo/one"}));
        let second = receipt_root(&json!({"cwd": "/repo/two"}));
        let again = receipt_root(&json!({"cwd": "/repo/one"}));
        assert_eq!(first, again);
        if let (Some(first), Some(second)) = (first, second) {
            assert_ne!(first, second);
            assert_eq!(first.parent(), second.parent());
            assert!(!first.starts_with(std::env::current_dir().unwrap().join(".audit")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn installed_assets_resolve_through_a_path_symlink() {
        let root = temporary_repository();
        let bin = root.join("current").join("bin");
        fs::create_dir_all(&bin).expect("create bin");
        fs::create_dir_all(root.join("current/share/legion/assets")).expect("create assets");
        let real = bin.join("legion-hook");
        fs::write(&real, b"").expect("write executable stand-in");
        let linked_dir = root.join("local-bin");
        fs::create_dir_all(&linked_dir).expect("create link dir");
        let link = linked_dir.join("legion-hook");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");
        assert!(installed_assets_for_executable(&link).is_none());
        let resolved = fs::canonicalize(&link).expect("canonicalize");
        assert!(installed_assets_for_executable(&resolved).is_some());
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn evidence_pointers_are_recognised() {
        for message in [
            "Done.\n```\ncargo test\n```",
            "All 12 tests passed.",
            "See src/main.rs:120 for the change.",
            "Fixed in (engine/lib.rs:7).",
            "Merged: https://github.com/a/b/pull/1",
            "Nothing was run; not verified.",
        ] {
            assert!(message_cites_evidence(message), "missed: {message}");
        }
        for message in [
            "Done.",
            "I updated the file and it works.",
            "Meet at 10:30 today.",
        ] {
            assert!(
                !message_cites_evidence(message),
                "false evidence: {message}"
            );
        }
    }

    #[test]
    fn stop_reminder_is_nonblocking_and_once_per_session() {
        let root = temporary_repository();
        let session = format!("session-{}", unix_nanos());
        let state = root.to_string_lossy().into_owned();
        let post = HookRequest {
            schema_version: protocol::SCHEMA_VERSION,
            kind: protocol::REQUEST_KIND.into(),
            event_type: "PostToolUse".into(),
            payload: json!({"session_id": session, "stateRoot": state, "tool_name": "Edit"}),
        };
        let stop_request = |text: &str| {
            stop(json!({
                "session_id": session,
                "stateRoot": state,
                "last_assistant_message": text,
            }))
        };
        let unedited = stop(json!({
            "session_id": "never-edited",
            "stateRoot": state,
            "last_assistant_message": "Done.",
        }));
        assert!(stop_evidence_reminder(&unedited, &dispatch_inner(unedited.clone())).is_none());

        observe_session_edit(&post);
        let evidenced = stop_request("Verified: src/main.rs:5");
        assert!(stop_evidence_reminder(&evidenced, &dispatch_inner(evidenced.clone())).is_none());

        let bare = stop_request("Done.");
        let response = dispatch_inner(bare.clone());
        assert!(response.allowed, "the reminder must never block Stop");
        assert_eq!(
            stop_evidence_reminder(&bare, &response).as_deref(),
            Some(STOP_EVIDENCE_REMINDER)
        );
        assert!(stop_evidence_reminder(&bare, &response).is_none());
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
